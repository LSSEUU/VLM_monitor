"""SQLite-backed append-only M8 production-adapter commissioning evidence."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_adapter_commissioning_workflow import (
    build_adapter_candidate_commit,
    build_commissioning_evidence_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceCommitReceiptV1,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterCandidateCommitReceiptV1,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing

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

MAX_M8_COMMISSIONING_EVIDENCE_QUERY = 10_000

_M8_COMMISSIONING_REQUIRED_OBJECTS = frozenset(
    {
        "m8_production_adapter_candidates",
        "idx_m8_adapter_candidates_campus_kind",
        "m8_commissioning_evidence",
        "idx_m8_commissioning_evidence_candidate",
        "m8_production_adapter_candidates_no_update",
        "m8_production_adapter_candidates_no_delete",
        "m8_production_adapter_candidates_no_replace",
        "m8_commissioning_evidence_no_update",
        "m8_commissioning_evidence_no_delete",
        "m8_commissioning_evidence_no_replace",
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


def _validate_limit(value: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= MAX_M8_COMMISSIONING_EVIDENCE_QUERY
    ):
        raise ValueError("M8 commissioning evidence limit is outside the bounded range")
    return value


def _canonical_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class SQLiteM8AdapterCommissioningRepository:
    """Persist candidate and evidence receipts without ever activating an adapter."""

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
            "commissioning repository manifest",
        )
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8AdapterCommissioningRepository:
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
                    "M8 commissioning SQLite writer lock could not be acquired"
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
                WHERE version BETWEEN 1 AND 6 ORDER BY version
                """
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError(
                "M8 commissioning migration ledger is invalid"
            ) from error
        observed_migrations = tuple(
            (_row_int(row, "version"), _row_str(row, "name")) for row in migrations
        )
        if observed_migrations != (
            (1, "m8_actor_case_authority"),
            (2, "m8_campus_inventory"),
            (3, "m8_sensor_cache"),
            (4, "m8_notification_outbox"),
            (5, "m8_knowledge"),
            (6, "m8_adapter_commissioning"),
        ):
            raise RepositoryIntegrityError("M8 commissioning migrations 0001-0006 are absent")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _M8_COMMISSIONING_REQUIRED_OBJECTS)
                ),
                tuple(sorted(_M8_COMMISSIONING_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _M8_COMMISSIONING_REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 commissioning persistence layout is incomplete")

    def register_candidate(
        self,
        candidate: M8ProductionAdapterCandidateAuthorityV1,
        registrar_actor_id: str,
    ) -> M8ProductionAdapterCandidateCommitReceiptV1:
        if not isinstance(candidate, M8ProductionAdapterCandidateAuthorityV1):
            raise TypeError("M8 candidate registration requires a typed candidate")
        actor_id = require_reference_token(registrar_actor_id, "M8 candidate registrar actor")
        with self._immediate() as connection:
            existing_row = connection.execute(
                "SELECT * FROM m8_production_adapter_candidates WHERE candidate_authority_id = ?",
                (candidate.candidate_authority_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_candidate_row(existing_row)
                if existing.candidate == candidate:
                    return existing
                raise ConcurrentModification("M8 candidate identity already contains other content")
            slot_row = connection.execute(
                """
                SELECT * FROM m8_production_adapter_candidates
                WHERE adapter_id = ? AND adapter_revision = ?
                """,
                (candidate.adapter_id, candidate.adapter_revision),
            ).fetchone()
            if slot_row is not None:
                raise ConcurrentModification("M8 adapter revision already has another candidate")
            registrar = self._load_current_actor(connection, actor_id)
            try:
                receipt = build_adapter_candidate_commit(
                    candidate,
                    registrar,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_candidate(connection, receipt)
            return receipt

    def get_candidate(
        self,
        candidate_authority_id: str,
    ) -> M8ProductionAdapterCandidateCommitReceiptV1:
        candidate_id = _validate_sha256(candidate_authority_id, "candidate authority ID")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_production_adapter_candidates WHERE candidate_authority_id = ?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 adapter candidate was not found")
            return self._load_candidate_row(row)

    def list_candidates(
        self,
        limit: int,
    ) -> tuple[M8ProductionAdapterCandidateCommitReceiptV1, ...]:
        bounded = _validate_limit(limit)
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM m8_production_adapter_candidates
                ORDER BY adapter_id ASC, adapter_revision DESC, candidate_authority_id ASC
                LIMIT ?
                """,
                (bounded,),
            ).fetchall()
            return tuple(self._load_candidate_row(row) for row in rows)

    def commit_evidence(
        self,
        evidence: M8CommissioningEvidenceAuthorityV1,
        artifact_bytes: bytes,
        artifact_storage_manifest_id: str,
    ) -> M8CommissioningEvidenceCommitReceiptV1:
        if not isinstance(evidence, M8CommissioningEvidenceAuthorityV1):
            raise TypeError("M8 commissioning commit requires typed evidence")
        if not isinstance(artifact_bytes, bytes):
            raise TypeError("M8 commissioning artifact must be exact bytes")
        storage_manifest = _validate_sha256(
            artifact_storage_manifest_id,
            "commissioning artifact storage manifest",
        )
        with self._immediate() as connection:
            existing_row = connection.execute(
                "SELECT * FROM m8_commissioning_evidence WHERE evidence_authority_id = ?",
                (evidence.evidence_authority_id,),
            ).fetchone()
            if existing_row is not None:
                existing, persisted = self._load_evidence_row(connection, existing_row)
                if (
                    existing.evidence == evidence
                    and existing.artifact_storage_manifest_id == storage_manifest
                    and persisted == artifact_bytes
                ):
                    return existing
                raise ConcurrentModification("M8 commissioning evidence retry conflicts")
            ref_row = connection.execute(
                """
                SELECT evidence_authority_id FROM m8_commissioning_evidence
                WHERE artifact_ref = ?
                """,
                (evidence.artifact_ref,),
            ).fetchone()
            if ref_row is not None:
                raise ConcurrentModification("M8 commissioning artifact ref is already committed")
            candidate_row = connection.execute(
                "SELECT * FROM m8_production_adapter_candidates WHERE candidate_authority_id = ?",
                (evidence.candidate.candidate_authority_id,),
            ).fetchone()
            if candidate_row is None:
                raise EvidenceMissing("M8 commissioning candidate was not registered")
            candidate_receipt = self._load_candidate_row(candidate_row)
            reviewer = self._load_current_actor(
                connection,
                evidence.reviewer_actor_receipt.authority.actor_id,
            )
            try:
                receipt = build_commissioning_evidence_commit(
                    evidence,
                    artifact_bytes,
                    candidate_receipt,
                    reviewer,
                    storage_manifest,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_evidence(connection, receipt, artifact_bytes)
            return receipt

    def get_evidence(
        self,
        evidence_authority_id: str,
    ) -> M8CommissioningEvidenceCommitReceiptV1:
        evidence_id = _validate_sha256(evidence_authority_id, "commissioning evidence ID")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_commissioning_evidence WHERE evidence_authority_id = ?",
                (evidence_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 commissioning evidence was not found")
            receipt, _artifact = self._load_evidence_row(connection, row)
            return receipt

    def list_candidate_evidence(
        self,
        candidate_authority_id: str,
        limit: int,
    ) -> tuple[M8CommissioningEvidenceCommitReceiptV1, ...]:
        candidate_id = _validate_sha256(candidate_authority_id, "candidate authority ID")
        bounded_limit = _validate_limit(limit)
        with self._read() as connection:
            candidate_row = connection.execute(
                "SELECT * FROM m8_production_adapter_candidates WHERE candidate_authority_id = ?",
                (candidate_id,),
            ).fetchone()
            if candidate_row is None:
                raise EvidenceMissing("M8 adapter candidate was not found")
            self._load_candidate_row(candidate_row)
            rows = connection.execute(
                """
                SELECT * FROM m8_commissioning_evidence
                WHERE candidate_authority_id = ?
                ORDER BY evidence_kind, reviewed_at, evidence_authority_id
                LIMIT ?
                """,
                (candidate_id, bounded_limit + 1),
            ).fetchall()
            if len(rows) > bounded_limit:
                raise BudgetExceeded("M8 commissioning evidence query exceeds its limit")
            return tuple(self._load_evidence_row(connection, row)[0] for row in rows)

    def read_artifact(self, artifact_ref: str) -> bytes:
        controlled_ref = require_reference_token(
            artifact_ref,
            "M8 commissioning artifact reference",
        )
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_commissioning_evidence WHERE artifact_ref = ?",
                (controlled_ref,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 commissioning artifact was not found")
            _receipt, artifact = self._load_evidence_row(connection, row)
            return artifact

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
            raise EvidenceMissing("M8 commissioning actor authority was not found")
        return self._load_actor_row(row)

    def _load_actor_row(self, row: sqlite3.Row) -> M8ActorAuthorityCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8ActorAuthorityCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 commissioning actor is invalid") from error
        authority = receipt.authority
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or authority.actor_id != _row_str(row, "actor_id")
            or authority.authority_revision != _row_int(row, "authority_revision")
            or authority.actor_authority_id != _row_str(row, "actor_authority_id")
            or receipt.authority_document_sha256 != _row_str(row, "authority_document_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 commissioning actor index conflicts with receipt")
        return receipt

    def _load_candidate_row(
        self,
        row: sqlite3.Row,
    ) -> M8ProductionAdapterCandidateCommitReceiptV1:
        raw_receipt = _row_str(row, "receipt_json")
        try:
            receipt = M8ProductionAdapterCandidateCommitReceiptV1.model_validate_json(raw_receipt)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 adapter candidate is invalid") from error
        candidate = receipt.candidate
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw_receipt
            or canonical_json(candidate.model_dump(mode="json")) != _row_str(row, "candidate_json")
            or candidate.candidate_authority_id != _row_str(row, "candidate_authority_id")
            or candidate.adapter_id != _row_str(row, "adapter_id")
            or candidate.adapter_revision != _row_str(row, "adapter_revision")
            or candidate.adapter_kind.value != _row_str(row, "adapter_kind")
            or candidate.campus_id != _row_str(row, "campus_id")
            or candidate.scope_kind.value != _row_str(row, "scope_kind")
            or receipt.candidate_document_sha256 != _row_str(row, "candidate_document_sha256")
            or receipt.registered_by_actor_receipt.authority.actor_authority_id
            != _row_str(row, "registrar_actor_authority_id")
            or receipt.registered_by_actor_receipt.authority_document_sha256
            != _row_str(row, "registrar_actor_document_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 adapter candidate index conflicts with receipt")
        return receipt

    def _load_evidence_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> tuple[M8CommissioningEvidenceCommitReceiptV1, bytes]:
        raw_receipt = _row_str(row, "receipt_json")
        try:
            receipt = M8CommissioningEvidenceCommitReceiptV1.model_validate_json(raw_receipt)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 commissioning evidence is invalid"
            ) from error
        evidence = receipt.evidence
        artifact = row["artifact_bytes"]
        if not isinstance(artifact, bytes):
            raise RepositoryIntegrityError("M8 commissioning artifact column must contain bytes")
        candidate_row = connection.execute(
            "SELECT * FROM m8_production_adapter_candidates WHERE candidate_authority_id = ?",
            (evidence.candidate.candidate_authority_id,),
        ).fetchone()
        if candidate_row is None:
            raise RepositoryIntegrityError("M8 commissioning evidence candidate is missing")
        candidate_receipt = self._load_candidate_row(candidate_row)
        if (
            candidate_receipt.candidate != evidence.candidate
            or canonical_json(receipt.model_dump(mode="json")) != raw_receipt
            or canonical_json(evidence.model_dump(mode="json")) != _row_str(row, "evidence_json")
            or evidence.evidence_authority_id != _row_str(row, "evidence_authority_id")
            or evidence.candidate.candidate_authority_id != _row_str(row, "candidate_authority_id")
            or evidence.evidence_kind.value != _row_str(row, "evidence_kind")
            or evidence.outcome.value != _row_str(row, "outcome")
            or evidence.reviewer_actor_receipt.authority.actor_authority_id
            != _row_str(row, "reviewer_actor_authority_id")
            or evidence.reviewer_actor_receipt.authority_document_sha256
            != _row_str(row, "reviewer_actor_document_sha256")
            or _canonical_utc(evidence.reviewed_at) != _row_str(row, "reviewed_at")
            or _canonical_utc(evidence.valid_through) != _row_optional_str(row, "valid_through")
            or int(evidence.simulated) != _row_int(row, "simulated")
            or evidence.artifact_ref != _row_str(row, "artifact_ref")
            or evidence.artifact_sha256 != _row_str(row, "artifact_sha256")
            or evidence.artifact_size_bytes != _row_int(row, "artifact_size_bytes")
            or len(artifact) != evidence.artifact_size_bytes
            or hashlib.sha256(artifact).hexdigest() != evidence.artifact_sha256
            or receipt.artifact_storage_manifest_id != _row_str(row, "artifact_storage_manifest_id")
            or receipt.evidence_document_sha256 != _row_str(row, "evidence_document_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 commissioning evidence index conflicts with receipt")
        return receipt, artifact

    def _insert_candidate(
        self,
        connection: sqlite3.Connection,
        receipt: M8ProductionAdapterCandidateCommitReceiptV1,
    ) -> None:
        candidate = receipt.candidate
        try:
            connection.execute(
                """
                INSERT INTO m8_production_adapter_candidates(
                    candidate_authority_id, adapter_id, adapter_revision, adapter_kind,
                    campus_id, scope_kind, candidate_document_sha256,
                    registrar_actor_authority_id, registrar_actor_document_sha256,
                    repository_manifest_id, commit_receipt_id, candidate_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate.candidate_authority_id,
                    candidate.adapter_id,
                    candidate.adapter_revision,
                    candidate.adapter_kind.value,
                    candidate.campus_id,
                    candidate.scope_kind.value,
                    receipt.candidate_document_sha256,
                    receipt.registered_by_actor_receipt.authority.actor_authority_id,
                    receipt.registered_by_actor_receipt.authority_document_sha256,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(candidate.model_dump(mode="json")),
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 adapter candidate append was rejected") from error

    def _insert_evidence(
        self,
        connection: sqlite3.Connection,
        receipt: M8CommissioningEvidenceCommitReceiptV1,
        artifact_bytes: bytes,
    ) -> None:
        evidence = receipt.evidence
        try:
            connection.execute(
                """
                INSERT INTO m8_commissioning_evidence(
                    evidence_authority_id, candidate_authority_id, evidence_kind, outcome,
                    reviewer_actor_authority_id, reviewer_actor_document_sha256,
                    reviewed_at, valid_through, simulated, artifact_ref, artifact_sha256,
                    artifact_size_bytes, artifact_bytes, artifact_storage_manifest_id,
                    evidence_document_sha256, repository_manifest_id, commit_receipt_id,
                    evidence_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.evidence_authority_id,
                    evidence.candidate.candidate_authority_id,
                    evidence.evidence_kind.value,
                    evidence.outcome.value,
                    evidence.reviewer_actor_receipt.authority.actor_authority_id,
                    evidence.reviewer_actor_receipt.authority_document_sha256,
                    _canonical_utc(evidence.reviewed_at),
                    _canonical_utc(evidence.valid_through),
                    int(evidence.simulated),
                    evidence.artifact_ref,
                    evidence.artifact_sha256,
                    evidence.artifact_size_bytes,
                    artifact_bytes,
                    receipt.artifact_storage_manifest_id,
                    receipt.evidence_document_sha256,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(evidence.model_dump(mode="json")),
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 commissioning evidence append was rejected") from error


__all__ = [
    "MAX_M8_COMMISSIONING_EVIDENCE_QUERY",
    "SQLiteM8AdapterCommissioningRepository",
]
