"""Append-only SQLite persistence for verified Feishu inbound message evidence."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_inbound import (
    M8FeishuInboundMessageCommitReceiptV1,
    M8FeishuInboundMessageVerificationReceiptV1,
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
    _row_str,
    _validate_busy_timeout,
)

_REQUIRED_OBJECTS = frozenset(
    {
        "m8_feishu_inbound_message_commits",
        "idx_m8_feishu_inbound_messages_parent",
        "m8_feishu_inbound_raw_artifacts",
        "m8_feishu_inbound_message_commits_no_update",
        "m8_feishu_inbound_message_commits_no_delete",
        "m8_feishu_inbound_message_commits_no_replace",
        "m8_feishu_inbound_raw_artifacts_no_update",
        "m8_feishu_inbound_raw_artifacts_no_delete",
        "m8_feishu_inbound_raw_artifacts_no_replace",
    }
)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu inbound {name} must be lowercase SHA-256 hex")
    return value


def _require_utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu inbound {name} must be timezone-aware UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class SQLiteM8FeishuInboundRepository:
    """Store exact verified raw inventory with provider message-id uniqueness."""

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
            "repository manifest",
        )
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8FeishuInboundRepository:
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
                    "M8 Feishu inbound SQLite writer lock could not be acquired"
                ) from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 9"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError(
                "M8 Feishu inbound migration ledger is invalid"
            ) from error
        if migration is None or _row_str(migration, "name") != "m8_feishu_inbound_messages":
            raise RepositoryIntegrityError("M8 Feishu inbound migration 0009 is absent")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _REQUIRED_OBJECTS)
                ),
                tuple(sorted(_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 Feishu inbound persistence layout is incomplete")

    def commit_verification(
        self,
        verification_receipt: M8FeishuInboundMessageVerificationReceiptV1,
        raw_artifacts: tuple[bytes, bytes, bytes],
        raw_storage_manifest_id: str,
        committed_at: datetime,
        commit_manifest_id: str,
    ) -> M8FeishuInboundMessageCommitReceiptV1:
        if not isinstance(
            verification_receipt,
            M8FeishuInboundMessageVerificationReceiptV1,
        ):
            raise TypeError("M8 Feishu inbound commit requires a typed verification receipt")
        if (
            not isinstance(raw_artifacts, tuple)
            or len(raw_artifacts) != 3
            or any(not isinstance(raw, bytes) for raw in raw_artifacts)
        ):
            raise TypeError("M8 Feishu inbound commit requires three exact raw artifacts")
        raw_manifest = _validate_sha256(raw_storage_manifest_id, "raw storage manifest")
        commit_time = _require_utc(committed_at, "committed_at")
        commit_manifest = _validate_sha256(commit_manifest_id, "commit manifest")
        candidate = M8FeishuInboundMessageCommitReceiptV1(
            verification_receipt=verification_receipt,
            committed_at=commit_time,
            raw_storage_manifest_id=raw_manifest,
            commit_manifest_id=commit_manifest,
            repository_manifest_id=self._repository_manifest_id,
        )
        self._verify_raw_inventory(candidate, raw_artifacts)
        with self._immediate() as connection:
            retry_row = connection.execute(
                "SELECT * FROM m8_feishu_inbound_message_commits WHERE provider_message_id = ?",
                (candidate.provider_message_id,),
            ).fetchone()
            if retry_row is not None:
                existing = self._load_commit_row(connection, retry_row)
                if existing == candidate:
                    self._verify_persisted_raw(connection, existing, raw_artifacts)
                    return existing
                raise ConcurrentModification(
                    "M8 Feishu inbound provider message was already committed differently"
                )
            try:
                for ordinal, (raw_ref, raw_sha, raw_size, raw) in enumerate(
                    zip(
                        candidate.raw_artifact_refs,
                        candidate.raw_artifact_sha256s,
                        candidate.raw_artifact_sizes_bytes,
                        raw_artifacts,
                        strict=True,
                    )
                ):
                    connection.execute(
                        """
                        INSERT INTO m8_feishu_inbound_raw_artifacts(
                            raw_artifact_ref, commit_receipt_id, artifact_ordinal,
                            raw_artifact_sha256, raw_artifact_size_bytes, raw_bytes,
                            raw_storage_manifest_id, repository_manifest_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            raw_ref,
                            candidate.commit_receipt_id,
                            ordinal,
                            raw_sha,
                            raw_size,
                            raw,
                            candidate.raw_storage_manifest_id,
                            candidate.repository_manifest_id,
                        ),
                    )
                verified = candidate.verification_receipt
                connection.execute(
                    """
                    INSERT INTO m8_feishu_inbound_message_commits(
                        commit_receipt_id, verification_receipt_id, inbound_profile_id,
                        ingress_request_id, provider_message_id, provider_event_id,
                        provider_parent_message_id, committed_at,
                        raw_artifact_inventory_sha256, total_raw_artifact_size_bytes,
                        raw_storage_manifest_id, commit_manifest_id,
                        repository_manifest_id, receipt_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        candidate.commit_receipt_id,
                        verified.verification_receipt_id,
                        verified.profile.inbound_profile_id,
                        verified.ingress_request.ingress_request_id,
                        candidate.provider_message_id,
                        verified.provider_event_id,
                        verified.provider_parent_message_id,
                        _canonical_utc(candidate.committed_at),
                        candidate.raw_artifact_inventory_sha256,
                        candidate.total_raw_artifact_size_bytes,
                        candidate.raw_storage_manifest_id,
                        candidate.commit_manifest_id,
                        candidate.repository_manifest_id,
                        canonical_json(candidate.model_dump(mode="json")),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ConcurrentModification("M8 Feishu inbound append was rejected") from error
            return candidate

    def get_by_provider_message_id(
        self,
        provider_message_id: str,
    ) -> M8FeishuInboundMessageCommitReceiptV1:
        message_id = require_reference_token(
            provider_message_id,
            "M8 Feishu inbound provider message ID",
        )
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_feishu_inbound_message_commits WHERE provider_message_id = ?",
                (message_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 Feishu inbound provider message was not found")
            return self._load_commit_row(connection, row)

    def read_raw_artifact(self, raw_artifact_ref: str) -> bytes:
        reference = require_reference_token(
            raw_artifact_ref,
            "M8 Feishu inbound raw artifact",
        )
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_feishu_inbound_raw_artifacts WHERE raw_artifact_ref = ?",
                (reference,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 Feishu inbound raw artifact was not found")
            commit_row = connection.execute(
                """
                SELECT * FROM m8_feishu_inbound_message_commits
                WHERE commit_receipt_id = ?
                """,
                (_row_str(row, "commit_receipt_id"),),
            ).fetchone()
            if commit_row is None:
                raise RepositoryIntegrityError(
                    "M8 Feishu inbound raw artifact lacks its commit"
                )
            receipt = self._load_commit_row(connection, commit_row)
            if reference not in receipt.raw_artifact_refs:
                raise RepositoryIntegrityError(
                    "M8 Feishu inbound raw artifact is outside its commit inventory"
                )
            return self._load_raw_row(row)

    def _load_commit_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M8FeishuInboundMessageCommitReceiptV1:
        raw_json = _row_str(row, "receipt_json")
        try:
            receipt = M8FeishuInboundMessageCommitReceiptV1.model_validate_json(raw_json)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 Feishu inbound commit is invalid"
            ) from error
        verified = receipt.verification_receipt
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw_json
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
            or verified.verification_receipt_id != _row_str(row, "verification_receipt_id")
            or verified.profile.inbound_profile_id != _row_str(row, "inbound_profile_id")
            or verified.ingress_request.ingress_request_id
            != _row_str(row, "ingress_request_id")
            or receipt.provider_message_id != _row_str(row, "provider_message_id")
            or verified.provider_event_id != _row_str(row, "provider_event_id")
            or verified.provider_parent_message_id
            != _row_str(row, "provider_parent_message_id")
            or _canonical_utc(receipt.committed_at) != _row_str(row, "committed_at")
            or receipt.raw_artifact_inventory_sha256
            != _row_str(row, "raw_artifact_inventory_sha256")
            or receipt.total_raw_artifact_size_bytes
            != _row_int(row, "total_raw_artifact_size_bytes")
            or receipt.raw_storage_manifest_id != _row_str(row, "raw_storage_manifest_id")
            or receipt.commit_manifest_id != _row_str(row, "commit_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
        ):
            raise RepositoryIntegrityError("M8 Feishu inbound commit index conflicts with receipt")
        raw_rows = connection.execute(
            """
            SELECT * FROM m8_feishu_inbound_raw_artifacts
            WHERE commit_receipt_id = ? ORDER BY artifact_ordinal
            """,
            (receipt.commit_receipt_id,),
        ).fetchall()
        if len(raw_rows) != 3:
            raise RepositoryIntegrityError("M8 Feishu inbound raw inventory is incomplete")
        for ordinal, (raw_row, expected_ref, expected_sha, expected_size) in enumerate(
            zip(
                raw_rows,
                receipt.raw_artifact_refs,
                receipt.raw_artifact_sha256s,
                receipt.raw_artifact_sizes_bytes,
                strict=True,
            )
        ):
            raw = self._load_raw_row(raw_row)
            if (
                _row_int(raw_row, "artifact_ordinal") != ordinal
                or _row_str(raw_row, "raw_artifact_ref") != expected_ref
                or hashlib.sha256(raw).hexdigest() != expected_sha
                or len(raw) != expected_size
                or _row_str(raw_row, "commit_receipt_id") != receipt.commit_receipt_id
                or _row_str(raw_row, "raw_storage_manifest_id")
                != receipt.raw_storage_manifest_id
                or _row_str(raw_row, "repository_manifest_id")
                != receipt.repository_manifest_id
            ):
                raise RepositoryIntegrityError(
                    "M8 Feishu inbound raw inventory conflicts with receipt"
                )
        return receipt

    @staticmethod
    def _load_raw_row(row: sqlite3.Row) -> bytes:
        raw = row["raw_bytes"]
        if not isinstance(raw, bytes):
            raise RepositoryIntegrityError("M8 Feishu inbound raw column must contain bytes")
        if (
            len(raw) != _row_int(row, "raw_artifact_size_bytes")
            or hashlib.sha256(raw).hexdigest() != _row_str(row, "raw_artifact_sha256")
        ):
            raise RepositoryIntegrityError("M8 Feishu inbound raw artifact is invalid")
        return raw

    @staticmethod
    def _verify_raw_inventory(
        receipt: M8FeishuInboundMessageCommitReceiptV1,
        raw_artifacts: tuple[bytes, bytes, bytes],
    ) -> None:
        for expected_sha, expected_size, raw in zip(
            receipt.raw_artifact_sha256s,
            receipt.raw_artifact_sizes_bytes,
            raw_artifacts,
            strict=True,
        ):
            if (
                not raw
                or len(raw) != expected_size
                or hashlib.sha256(raw).hexdigest() != expected_sha
            ):
                raise ConcurrentModification("M8 Feishu inbound raw artifact changed")

    def _verify_persisted_raw(
        self,
        connection: sqlite3.Connection,
        receipt: M8FeishuInboundMessageCommitReceiptV1,
        raw_artifacts: tuple[bytes, bytes, bytes],
    ) -> None:
        rows = connection.execute(
            """
            SELECT * FROM m8_feishu_inbound_raw_artifacts
            WHERE commit_receipt_id = ? ORDER BY artifact_ordinal
            """,
            (receipt.commit_receipt_id,),
        ).fetchall()
        if len(rows) != 3:
            raise RepositoryIntegrityError("M8 Feishu inbound retry raw inventory is incomplete")
        persisted = tuple(self._load_raw_row(row) for row in rows)
        if persisted != raw_artifacts:
            raise ConcurrentModification("M8 Feishu inbound retry raw artifacts changed")


__all__ = ["SQLiteM8FeishuInboundRepository"]
