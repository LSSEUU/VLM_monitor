"""SQLite-backed append-only M8 knowledge catalogs, bytes, and answer receipts."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_knowledge_workflow import (
    build_knowledge_answer_commit,
    build_knowledge_catalog_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_knowledge import M8KnowledgeAnswerV1, M8KnowledgeCatalogAuthorityV1
from labcourt.contracts.m8_knowledge_persistence import (
    M8KnowledgeAnswerCommitReceiptV1,
    M8KnowledgeCatalogCommitReceiptV1,
    M8KnowledgeDocumentCommitReceiptV1,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, EvidenceMissing

from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_int,
    _row_optional_str,
    _row_str,
    _validate_busy_timeout,
)

_M8_KNOWLEDGE_REQUIRED_OBJECTS = frozenset(
    {
        "m8_knowledge_raw_contents",
        "m8_knowledge_catalog_versions",
        "idx_m8_knowledge_catalogs_current",
        "m8_knowledge_catalog_documents",
        "m8_knowledge_answer_receipts",
        "idx_m8_knowledge_answers_actor",
        "m8_knowledge_catalog_versions_validate_contiguous",
        "m8_knowledge_raw_contents_no_update",
        "m8_knowledge_raw_contents_no_delete",
        "m8_knowledge_raw_contents_no_replace",
        "m8_knowledge_catalog_versions_no_update",
        "m8_knowledge_catalog_versions_no_delete",
        "m8_knowledge_catalog_versions_no_replace",
        "m8_knowledge_catalog_documents_no_update",
        "m8_knowledge_catalog_documents_no_delete",
        "m8_knowledge_catalog_documents_no_replace",
        "m8_knowledge_answer_receipts_no_update",
        "m8_knowledge_answer_receipts_no_delete",
        "m8_knowledge_answer_receipts_no_replace",
    }
)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


def _validate_expected_revision(value: int | None) -> int | None:
    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
        raise ValueError("M8 knowledge expected prior revision must be a positive integer")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class SQLiteM8KnowledgeRepository:
    """Persist exact knowledge authorities in the isolated M8 operations database."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._repository_manifest_id = _validate_sha256(
            repository_manifest_id,
            "knowledge repository manifest",
        )
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8KnowledgeRepository:
        MigrationRunner(database_path, busy_timeout_ms, M8_MIGRATIONS).apply_all()
        return cls(database_path, busy_timeout_ms, repository_manifest_id)

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = _open_connection(
            self._database_path,
            self._busy_timeout_ms,
            allow_create=False,
        )
        try:
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(
                self._database_path,
                self._busy_timeout_ms,
                allow_create=False,
            )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException as error:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(error, sqlite3.OperationalError) and _is_sqlite_concurrency_error(error):
                raise ConcurrentModification(
                    "M8 knowledge SQLite writer lock could not be acquired"
                ) from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migrations = connection.execute(
                """
                SELECT version, name FROM schema_migrations
                WHERE version IN (1, 2, 3, 4, 5) ORDER BY version
                """
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 knowledge migration ledger is invalid") from error
        observed_migrations = tuple(
            (_row_int(row, "version"), _row_str(row, "name")) for row in migrations
        )
        if observed_migrations != (
            (1, "m8_actor_case_authority"),
            (2, "m8_campus_inventory"),
            (3, "m8_sensor_cache"),
            (4, "m8_notification_outbox"),
            (5, "m8_knowledge"),
        ):
            raise RepositoryIntegrityError("M8 knowledge migrations 0001-0005 are not installed")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _M8_KNOWLEDGE_REQUIRED_OBJECTS)
                ),
                tuple(sorted(_M8_KNOWLEDGE_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _M8_KNOWLEDGE_REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 knowledge persistence layout is incomplete")

    def publish_catalog(
        self,
        catalog: M8KnowledgeCatalogAuthorityV1,
        raw_contents: tuple[bytes, ...],
        expected_prior_revision: int | None,
        raw_storage_manifest_id: str,
    ) -> M8KnowledgeCatalogCommitReceiptV1:
        if not isinstance(catalog, M8KnowledgeCatalogAuthorityV1):
            raise TypeError("M8 knowledge publication requires a typed catalog")
        if not isinstance(raw_contents, tuple) or any(
            not isinstance(item, bytes) for item in raw_contents
        ):
            raise TypeError("M8 knowledge raw contents must be a tuple of exact bytes")
        expected = _validate_expected_revision(expected_prior_revision)
        raw_manifest = _validate_sha256(
            raw_storage_manifest_id,
            "knowledge raw storage manifest",
        )
        with self._immediate() as connection:
            existing_row = connection.execute(
                """
                SELECT * FROM m8_knowledge_catalog_versions
                WHERE catalog_id = ? AND catalog_revision = ?
                """,
                (catalog.catalog_id, catalog.catalog_revision),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_catalog_row(connection, existing_row)
                retry_expected = (
                    None if catalog.catalog_revision == 1 else catalog.catalog_revision - 1
                )
                if existing.catalog == catalog and expected == retry_expected:
                    self._verify_retry_contents(existing, raw_contents, raw_manifest)
                    return existing
                raise ConcurrentModification("M8 knowledge catalog revision already exists")
            prior_row = connection.execute(
                """
                SELECT * FROM m8_knowledge_catalog_versions
                WHERE catalog_id = ? ORDER BY catalog_revision DESC LIMIT 1
                """,
                (catalog.catalog_id,),
            ).fetchone()
            prior = self._load_catalog_row(connection, prior_row) if prior_row is not None else None
            observed_revision = prior.catalog.catalog_revision if prior is not None else None
            if observed_revision != expected:
                raise ConcurrentModification("M8 knowledge catalog prior revision is stale")
            try:
                candidate = build_knowledge_catalog_commit(
                    catalog,
                    raw_contents,
                    prior,
                    raw_manifest,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            for receipt, raw in zip(candidate.document_receipts, raw_contents, strict=True):
                self._insert_or_verify_content(connection, receipt, raw)
            self._insert_catalog(connection, candidate)
            return candidate

    def get_current_catalog(self, catalog_id: str) -> M8KnowledgeCatalogCommitReceiptV1:
        require_reference_token(catalog_id, "M8 knowledge catalog_id")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_knowledge_catalog_versions
                WHERE catalog_id = ? ORDER BY catalog_revision DESC LIMIT 1
                """,
                (catalog_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 knowledge catalog was not found")
            return self._load_catalog_row(connection, row)

    def read_content(self, content_ref: str) -> bytes:
        require_reference_token(content_ref, "M8 knowledge content_ref")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_knowledge_raw_contents WHERE content_ref = ?",
                (content_ref,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 knowledge content was not found")
            receipt, raw = self._load_content_row(row)
            if receipt.document.content_ref != content_ref:
                raise RepositoryIntegrityError("M8 knowledge content reference conflicts")
            return raw

    def commit_answer(self, answer: M8KnowledgeAnswerV1) -> M8KnowledgeAnswerCommitReceiptV1:
        if not isinstance(answer, M8KnowledgeAnswerV1):
            raise TypeError("M8 knowledge answer commit requires M8KnowledgeAnswerV1")
        query = answer.query
        with self._immediate() as connection:
            existing_row = connection.execute(
                "SELECT * FROM m8_knowledge_answer_receipts WHERE query_id = ?",
                (query.query_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_answer_row(connection, existing_row)
                if existing.answer == answer:
                    return existing
                raise ConcurrentModification("M8 knowledge query already has another answer")
            catalog_row = connection.execute(
                """
                SELECT * FROM m8_knowledge_catalog_versions
                WHERE catalog_id = ? ORDER BY catalog_revision DESC LIMIT 1
                """,
                (answer.catalog.catalog_id,),
            ).fetchone()
            if catalog_row is None:
                raise EvidenceMissing("M8 knowledge answer catalog was not found")
            resolved_catalog = self._load_catalog_row(connection, catalog_row)
            if resolved_catalog.catalog != answer.catalog:
                raise ConcurrentModification("M8 knowledge answer catalog is no longer current")
            actor = self._load_current_actor(connection, query.requester_actor_id)
            try:
                candidate = build_knowledge_answer_commit(
                    answer,
                    actor,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_answer(connection, candidate)
            return candidate

    def get_answer(self, query_id: str) -> M8KnowledgeAnswerCommitReceiptV1:
        require_reference_token(query_id, "M8 knowledge query_id")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_knowledge_answer_receipts WHERE query_id = ?",
                (query_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 knowledge answer was not found")
            return self._load_answer_row(connection, row)

    def _load_current_actor(
        self,
        connection: sqlite3.Connection,
        actor_id: str,
    ) -> M8ActorAuthorityCommitReceiptV1:
        row = connection.execute(
            """
            SELECT * FROM m8_actor_authorities
            WHERE actor_id = ? ORDER BY authority_revision DESC LIMIT 1
            """,
            (actor_id,),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 knowledge requester actor was not found")
        return self._load_actor_row(row, verify_repository_manifest=False)

    def _load_actor_row(
        self,
        row: sqlite3.Row,
        *,
        verify_repository_manifest: bool = True,
    ) -> M8ActorAuthorityCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8ActorAuthorityCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 knowledge actor is invalid") from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.authority.actor_id != _row_str(row, "actor_id")
            or receipt.authority.authority_revision != _row_int(row, "authority_revision")
            or receipt.authority.actor_authority_id != _row_str(row, "actor_authority_id")
            or receipt.authority_document_sha256 != _row_str(row, "authority_document_sha256")
            or (
                verify_repository_manifest
                and receipt.repository_manifest_id != self._repository_manifest_id
            )
        ):
            raise RepositoryIntegrityError("M8 knowledge actor index conflicts with receipt")
        return receipt

    def _load_content_row(
        self,
        row: sqlite3.Row,
    ) -> tuple[M8KnowledgeDocumentCommitReceiptV1, bytes]:
        raw_receipt = _row_str(row, "receipt_json")
        try:
            receipt = M8KnowledgeDocumentCommitReceiptV1.model_validate_json(raw_receipt)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 knowledge content receipt is invalid"
            ) from error
        raw = row["content_bytes"]
        if not isinstance(raw, bytes):
            raise RepositoryIntegrityError("M8 knowledge content column must contain bytes")
        document = receipt.document
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw_receipt
            or document.content_ref != _row_str(row, "content_ref")
            or document.document_authority_id != _row_str(row, "document_authority_id")
            or document.content_sha256 != _row_str(row, "content_sha256")
            or document.content_size_bytes != _row_int(row, "content_size_bytes")
            or len(raw) != document.content_size_bytes
            or hashlib.sha256(raw).hexdigest() != document.content_sha256
            or receipt.raw_storage_manifest_id != _row_str(row, "raw_storage_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.commit_receipt_id != _row_str(row, "document_commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 knowledge content index conflicts with receipt")
        return receipt, raw

    def _load_catalog_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M8KnowledgeCatalogCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8KnowledgeCatalogCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 knowledge catalog is invalid") from error
        catalog = receipt.catalog
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or canonical_json(catalog.model_dump(mode="json")) != _row_str(row, "catalog_json")
            or catalog.catalog_id != _row_str(row, "catalog_id")
            or catalog.catalog_revision != _row_int(row, "catalog_revision")
            or catalog.catalog_authority_id != _row_str(row, "catalog_authority_id")
            or receipt.catalog_document_sha256 != _row_str(row, "catalog_document_sha256")
            or receipt.content_inventory_sha256 != _row_str(row, "content_inventory_sha256")
            or receipt.total_content_size_bytes != _row_int(row, "total_content_size_bytes")
            or receipt.prior_catalog_authority_id
            != _row_optional_str(row, "prior_catalog_authority_id")
            or receipt.prior_catalog_document_sha256
            != _row_optional_str(row, "prior_catalog_document_sha256")
            or receipt.raw_storage_manifest_id != _row_str(row, "raw_storage_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 knowledge catalog index conflicts with receipt")
        links = connection.execute(
            """
            SELECT position, document_authority_id, content_ref
            FROM m8_knowledge_catalog_documents
            WHERE catalog_id = ? AND catalog_revision = ? ORDER BY position
            """,
            (catalog.catalog_id, catalog.catalog_revision),
        ).fetchall()
        observed_links = tuple(
            (
                _row_int(link, "position"),
                _row_str(link, "document_authority_id"),
                _row_str(link, "content_ref"),
            )
            for link in links
        )
        expected_links = tuple(
            (position, document.document_authority_id, document.content_ref)
            for position, document in enumerate(catalog.documents)
        )
        if observed_links != expected_links:
            raise RepositoryIntegrityError("M8 knowledge catalog document links are incomplete")
        for expected_receipt in receipt.document_receipts:
            content_row = connection.execute(
                "SELECT * FROM m8_knowledge_raw_contents WHERE content_ref = ?",
                (expected_receipt.document.content_ref,),
            ).fetchone()
            if content_row is None:
                raise RepositoryIntegrityError("M8 knowledge catalog content is missing")
            observed_receipt, _ = self._load_content_row(content_row)
            if observed_receipt != expected_receipt:
                raise RepositoryIntegrityError("M8 knowledge document receipt conflicts")
        return receipt

    def _load_answer_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M8KnowledgeAnswerCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8KnowledgeAnswerCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 knowledge answer is invalid") from error
        answer = receipt.answer
        query = answer.query
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or canonical_json(answer.model_dump(mode="json")) != _row_str(row, "answer_json")
            or receipt.query_id != _row_str(row, "query_id")
            or receipt.answer_id != _row_str(row, "answer_id")
            or answer.catalog.catalog_authority_id != _row_str(row, "catalog_authority_id")
            or query.requester_actor_id != _row_str(row, "requester_actor_id")
            or query.requester_actor_authority_id != _row_str(row, "requester_actor_authority_id")
            or receipt.resolved_actor_document_sha256
            != _row_str(row, "resolved_actor_document_sha256")
            or _canonical_utc(query.as_of) != _row_str(row, "query_as_of")
            or answer.outcome.value != _row_str(row, "outcome")
            or answer.adapter_manifest_id != _row_str(row, "adapter_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 knowledge answer index conflicts with receipt")
        catalog_row = connection.execute(
            """
            SELECT * FROM m8_knowledge_catalog_versions WHERE catalog_authority_id = ?
            """,
            (answer.catalog.catalog_authority_id,),
        ).fetchone()
        if (
            catalog_row is None
            or self._load_catalog_row(connection, catalog_row).catalog != answer.catalog
        ):
            raise RepositoryIntegrityError("M8 knowledge answer catalog is missing")
        actor_row = connection.execute(
            """
            SELECT * FROM m8_actor_authorities WHERE actor_authority_id = ?
            """,
            (query.requester_actor_authority_id,),
        ).fetchone()
        if actor_row is None:
            raise RepositoryIntegrityError("M8 knowledge answer requester authority is missing")
        actor = self._load_actor_row(actor_row, verify_repository_manifest=False)
        if (
            actor.authority.actor_id != query.requester_actor_id
            or actor.authority.actor_authority_id != query.requester_actor_authority_id
            or actor.authority_document_sha256 != receipt.resolved_actor_document_sha256
        ):
            raise RepositoryIntegrityError("M8 knowledge answer requester authority conflicts")
        return receipt

    def _insert_or_verify_content(
        self,
        connection: sqlite3.Connection,
        receipt: M8KnowledgeDocumentCommitReceiptV1,
        raw: bytes,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM m8_knowledge_raw_contents WHERE content_ref = ?",
            (receipt.document.content_ref,),
        ).fetchone()
        if row is not None:
            observed, observed_raw = self._load_content_row(row)
            if observed != receipt or observed_raw != raw:
                raise ConcurrentModification("M8 knowledge content reference conflicts")
            return
        document = receipt.document
        try:
            connection.execute(
                """
                INSERT INTO m8_knowledge_raw_contents(
                    content_ref, document_authority_id, content_sha256, content_size_bytes,
                    content_bytes, raw_storage_manifest_id, repository_manifest_id,
                    document_commit_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    document.content_ref,
                    document.document_authority_id,
                    document.content_sha256,
                    document.content_size_bytes,
                    raw,
                    receipt.raw_storage_manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 knowledge content append was rejected") from error

    def _insert_catalog(
        self,
        connection: sqlite3.Connection,
        receipt: M8KnowledgeCatalogCommitReceiptV1,
    ) -> None:
        catalog = receipt.catalog
        try:
            connection.execute(
                """
                INSERT INTO m8_knowledge_catalog_versions(
                    catalog_id, catalog_revision, catalog_authority_id,
                    catalog_document_sha256, content_inventory_sha256,
                    total_content_size_bytes, prior_catalog_authority_id,
                    prior_catalog_document_sha256, raw_storage_manifest_id,
                    repository_manifest_id, commit_receipt_id, catalog_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    catalog.catalog_id,
                    catalog.catalog_revision,
                    catalog.catalog_authority_id,
                    receipt.catalog_document_sha256,
                    receipt.content_inventory_sha256,
                    receipt.total_content_size_bytes,
                    receipt.prior_catalog_authority_id,
                    receipt.prior_catalog_document_sha256,
                    receipt.raw_storage_manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(catalog.model_dump(mode="json")),
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
            connection.executemany(
                """
                INSERT INTO m8_knowledge_catalog_documents(
                    catalog_id, catalog_revision, position,
                    document_authority_id, content_ref
                ) VALUES (?, ?, ?, ?, ?)
                """,
                tuple(
                    (
                        catalog.catalog_id,
                        catalog.catalog_revision,
                        position,
                        document.document_authority_id,
                        document.content_ref,
                    )
                    for position, document in enumerate(catalog.documents)
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 knowledge catalog append was rejected") from error

    def _insert_answer(
        self,
        connection: sqlite3.Connection,
        receipt: M8KnowledgeAnswerCommitReceiptV1,
    ) -> None:
        answer = receipt.answer
        query = answer.query
        try:
            connection.execute(
                """
                INSERT INTO m8_knowledge_answer_receipts(
                    query_id, answer_id, catalog_authority_id, requester_actor_id,
                    requester_actor_authority_id, resolved_actor_document_sha256,
                    query_as_of, outcome, adapter_manifest_id, repository_manifest_id,
                    commit_receipt_id, answer_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    query.query_id,
                    answer.answer_id,
                    answer.catalog.catalog_authority_id,
                    query.requester_actor_id,
                    query.requester_actor_authority_id,
                    receipt.resolved_actor_document_sha256,
                    _canonical_utc(query.as_of),
                    answer.outcome.value,
                    answer.adapter_manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(answer.model_dump(mode="json")),
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 knowledge answer append was rejected") from error

    @staticmethod
    def _verify_retry_contents(
        receipt: M8KnowledgeCatalogCommitReceiptV1,
        raw_contents: tuple[bytes, ...],
        raw_storage_manifest_id: str,
    ) -> None:
        if len(receipt.document_receipts) != len(raw_contents):
            raise ConcurrentModification("M8 knowledge retry content inventory conflicts")
        for document_receipt, raw in zip(
            receipt.document_receipts,
            raw_contents,
            strict=True,
        ):
            document = document_receipt.document
            if (
                document_receipt.raw_storage_manifest_id != raw_storage_manifest_id
                or len(raw) != document.content_size_bytes
                or hashlib.sha256(raw).hexdigest() != document.content_sha256
            ):
                raise ConcurrentModification("M8 knowledge retry content bytes conflict")


__all__ = ["SQLiteM8KnowledgeRepository"]
