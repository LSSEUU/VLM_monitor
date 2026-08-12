"""Isolated SQLite authority for M8 actors and operational Case transitions."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_case_workflow import (
    build_actor_authority_commit,
    build_operational_case_create_commit,
    build_operational_case_transition_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseTransitionCommandV1,
)
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing

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

M8_MIGRATIONS = Path(__file__).with_name("m8_migrations")
_M8_REQUIRED_OBJECTS = frozenset(
    {
        "m8_actor_authorities",
        "m8_operational_case_versions",
        "idx_m8_actor_authorities_current",
        "idx_m8_operational_cases_current",
        "idx_m8_operational_cases_status_location",
        "m8_actor_authorities_validate_contiguous",
        "m8_actor_authorities_no_update",
        "m8_actor_authorities_no_delete",
        "m8_actor_authorities_no_replace",
        "m8_operational_case_versions_validate_contiguous",
        "m8_operational_case_versions_no_update",
        "m8_operational_case_versions_no_delete",
        "m8_operational_case_versions_no_replace",
    }
)


class SQLiteM8OperationsRepository:
    """Append-only M8 repository with repository-resolved actor authority."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        if not isinstance(repository_manifest_id, str) or len(repository_manifest_id) != 64:
            raise ValueError("M8 repository_manifest_id must be a SHA-256 hex digest")
        if any(character not in "0123456789abcdef" for character in repository_manifest_id):
            raise ValueError("M8 repository_manifest_id must be lowercase SHA-256 hex")
        self._repository_manifest_id = repository_manifest_id
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8OperationsRepository:
        MigrationRunner(
            database_path,
            busy_timeout_ms,
            migrations_path=M8_MIGRATIONS,
        ).apply_all()
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
                    "M8 SQLite writer lock could not be acquired"
                ) from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 1"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 operations migration ledger is invalid") from error
        if migration is None or _row_str(migration, "name") != "m8_actor_case_authority":
            raise RepositoryIntegrityError("M8 operations migration 0001 is not installed")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _M8_REQUIRED_OBJECTS)
                ),
                tuple(sorted(_M8_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _M8_REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 operations authority layout is incomplete")

    def publish_actor_authority(
        self,
        authority: M8ActorAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8ActorAuthorityCommitReceiptV1:
        if not isinstance(authority, M8ActorAuthorityV1):
            raise TypeError("M8 actor publication requires M8ActorAuthorityV1")
        if expected_prior_revision is not None and (
            not isinstance(expected_prior_revision, int)
            or isinstance(expected_prior_revision, bool)
            or expected_prior_revision < 1
        ):
            raise ValueError("M8 expected_prior_revision must be a positive strict integer")
        with self._immediate() as connection:
            existing_revision = connection.execute(
                """
                SELECT * FROM m8_actor_authorities
                WHERE actor_id = ? AND authority_revision = ?
                """,
                (authority.actor_id, authority.authority_revision),
            ).fetchone()
            if existing_revision is not None:
                existing = self._load_actor_row(existing_revision)
                expected_for_existing = authority.authority_revision - 1 or None
                if (
                    existing.authority == authority
                    and expected_prior_revision == expected_for_existing
                ):
                    return existing
                raise ConcurrentModification("M8 actor authority revision already exists")

            prior_row = connection.execute(
                """
                SELECT * FROM m8_actor_authorities
                WHERE actor_id = ? ORDER BY authority_revision DESC LIMIT 1
                """,
                (authority.actor_id,),
            ).fetchone()
            prior = self._load_actor_row(prior_row) if prior_row is not None else None
            observed_prior = prior.authority.authority_revision if prior else None
            if expected_prior_revision != observed_prior:
                raise ConcurrentModification("M8 actor authority expected revision is stale")
            try:
                receipt = build_actor_authority_commit(
                    authority,
                    prior,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_actor(connection, receipt)
            return receipt

    def get_current_actor_authority(
        self,
        actor_id: str,
    ) -> M8ActorAuthorityCommitReceiptV1:
        require_reference_token(actor_id, "M8 actor_id")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_actor_authorities
                WHERE actor_id = ? ORDER BY authority_revision DESC LIMIT 1
                """,
                (actor_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 actor authority was not found")
            return self._load_actor_row(row)

    def create_operational_case(
        self,
        command: M8OperationalCaseCreateCommandV1,
        subject_actor_id: str | None,
        case_manifest_id: str,
        audit_manifest_id: str,
    ) -> M8OperationalCaseCommitReceiptV1:
        if not isinstance(command, M8OperationalCaseCreateCommandV1):
            raise TypeError("M8 Case creation requires M8OperationalCaseCreateCommandV1")
        candidate = build_operational_case_create_commit(
            command,
            subject_actor_id,
            case_manifest_id,
            audit_manifest_id,
            self._repository_manifest_id,
        )
        with self._immediate() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_operational_case_versions
                WHERE case_id = ? AND case_version = 1
                """,
                (candidate.case_id,),
            ).fetchone()
            if row is not None:
                existing = self._load_case_row(row)
                if existing == candidate:
                    return existing
                raise ConcurrentModification("M8 operational Case already exists")
            self._insert_case(connection, candidate)
            return candidate

    def get_current_operational_case(
        self,
        case_id: str,
    ) -> M8OperationalCaseCommitReceiptV1:
        require_reference_token(case_id, "M8 case_id")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_operational_case_versions
                WHERE case_id = ? ORDER BY case_version DESC LIMIT 1
                """,
                (case_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 operational Case was not found")
            return self._load_case_row(row)

    def list_current_operational_cases(
        self,
        limit: int,
    ) -> tuple[M8OperationalCaseCommitReceiptV1, ...]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise ValueError("M8 current Case limit must be from 1 through 10000")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT current.* FROM m8_operational_case_versions AS current
                WHERE NOT EXISTS (
                    SELECT 1 FROM m8_operational_case_versions AS newer
                    WHERE newer.case_id = current.case_id
                      AND newer.case_version > current.case_version
                )
                ORDER BY current.case_id LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
            if len(rows) > limit:
                raise BudgetExceeded("M8 current Case inventory exceeds the requested limit")
            return tuple(self._load_case_row(row) for row in rows)

    def transition_operational_case(
        self,
        command: M8OperationalCaseTransitionCommandV1,
        case_manifest_id: str,
        audit_manifest_id: str,
    ) -> M8OperationalCaseCommitReceiptV1:
        if not isinstance(command, M8OperationalCaseTransitionCommandV1):
            raise TypeError("M8 Case transition requires M8OperationalCaseTransitionCommandV1")
        with self._immediate() as connection:
            committed_row = connection.execute(
                """
                SELECT * FROM m8_operational_case_versions
                WHERE transition_command_id = ?
                """,
                (command.command_id,),
            ).fetchone()
            if committed_row is not None:
                committed = self._load_case_row(committed_row)
                committed_intent = committed.audit_event.transition_intent
                if (
                    committed_intent is not None
                    and committed_intent.command == command
                    and committed.audit_event.case_authority.case_manifest_id == case_manifest_id
                    and committed.audit_event.audit_manifest_id == audit_manifest_id
                ):
                    return committed
                raise ConcurrentModification(
                    "M8 transition command already committed with different authority"
                )

            case_row = connection.execute(
                """
                SELECT * FROM m8_operational_case_versions
                WHERE case_id = ? ORDER BY case_version DESC LIMIT 1
                """,
                (command.case_id,),
            ).fetchone()
            if case_row is None:
                raise EvidenceMissing("M8 operational Case was not found")
            before = self._load_case_row(case_row)

            actor_row = connection.execute(
                """
                SELECT * FROM m8_actor_authorities
                WHERE actor_id = ? ORDER BY authority_revision DESC LIMIT 1
                """,
                (command.actor_authority.actor_id,),
            ).fetchone()
            if actor_row is None:
                raise EvidenceMissing("M8 transition actor authority was not found")
            actor = self._load_actor_row(actor_row)
            try:
                receipt = build_operational_case_transition_commit(
                    before,
                    command,
                    actor,
                    case_manifest_id,
                    audit_manifest_id,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_case(connection, receipt)
            return receipt

    def list_operational_case_audit(
        self,
        case_id: str,
    ) -> tuple[M8OperationalCaseAuditEventV1, ...]:
        require_reference_token(case_id, "M8 case_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM m8_operational_case_versions
                WHERE case_id = ? ORDER BY case_version
                """,
                (case_id,),
            ).fetchall()
            if not rows:
                raise EvidenceMissing("M8 operational Case audit was not found")
            receipts = tuple(self._load_case_row(row) for row in rows)
            for index, receipt in enumerate(receipts):
                if receipt.case_version != index + 1:
                    raise RepositoryIntegrityError("M8 persisted Case versions are not contiguous")
                if index and receipt.audit_event.prior_audit_event_sha256 != (
                    receipts[index - 1].audit_event.audit_event_sha256
                ):
                    raise RepositoryIntegrityError("M8 persisted audit chain is broken")
            return tuple(receipt.audit_event for receipt in receipts)

    def _insert_actor(
        self,
        connection: sqlite3.Connection,
        receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> None:
        authority = receipt.authority
        try:
            connection.execute(
                """
                INSERT INTO m8_actor_authorities(
                    actor_id, authority_revision, actor_authority_id,
                    authority_document_sha256, role, active,
                    prior_authority_id, prior_document_sha256,
                    repository_manifest_id, commit_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authority.actor_id,
                    authority.authority_revision,
                    authority.actor_authority_id,
                    receipt.authority_document_sha256,
                    authority.role.value,
                    int(authority.active),
                    receipt.prior_authority_id,
                    receipt.prior_document_sha256,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 actor authority append was rejected") from error

    def _insert_case(
        self,
        connection: sqlite3.Connection,
        receipt: M8OperationalCaseCommitReceiptV1,
    ) -> None:
        event = receipt.audit_event
        authority = event.case_authority
        transition_command = event.transition_intent.command if event.transition_intent else None
        try:
            connection.execute(
                """
                INSERT INTO m8_operational_case_versions(
                    case_id, case_version, status, location_id, subject_actor_id,
                    case_authority_id, case_document_sha256,
                    prior_case_document_sha256, create_command_id,
                    transition_command_id, actor_authority_id,
                    resolved_actor_document_sha256, audit_event_id,
                    audit_event_sha256, prior_audit_event_sha256,
                    commit_receipt_id, repository_manifest_id,
                    case_json, audit_event_json, commit_receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.case_id,
                    receipt.case_version,
                    receipt.status.value,
                    authority.location_id,
                    authority.subject_actor_id,
                    receipt.case_authority_id,
                    receipt.case_document_sha256,
                    authority.prior_case_document_sha256,
                    authority.create_command.create_command_id,
                    transition_command.command_id if transition_command else None,
                    authority.last_actor_authority_id,
                    event.resolved_actor_document_sha256,
                    event.audit_event_id,
                    event.audit_event_sha256,
                    event.prior_audit_event_sha256,
                    receipt.commit_receipt_id,
                    receipt.repository_manifest_id,
                    canonical_json(authority.model_dump(mode="json")),
                    canonical_json(event.model_dump(mode="json")),
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 operational Case append was rejected") from error

    def _load_actor_row(self, row: sqlite3.Row) -> M8ActorAuthorityCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8ActorAuthorityCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 actor authority is invalid") from error
        authority = receipt.authority
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or authority.actor_id != _row_str(row, "actor_id")
            or authority.authority_revision != _row_int(row, "authority_revision")
            or authority.actor_authority_id != _row_str(row, "actor_authority_id")
            or receipt.authority_document_sha256 != _row_str(row, "authority_document_sha256")
            or authority.role.value != _row_str(row, "role")
            or authority.active is not bool(_row_int(row, "active"))
            or receipt.prior_authority_id != _row_optional_str(row, "prior_authority_id")
            or receipt.prior_document_sha256 != _row_optional_str(row, "prior_document_sha256")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 actor authority index columns conflict with receipt")
        return receipt

    def _load_case_row(self, row: sqlite3.Row) -> M8OperationalCaseCommitReceiptV1:
        raw_receipt = _row_str(row, "commit_receipt_json")
        try:
            receipt = M8OperationalCaseCommitReceiptV1.model_validate_json(raw_receipt)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 operational Case is invalid") from error
        event = receipt.audit_event
        authority = event.case_authority
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw_receipt
            or canonical_json(authority.model_dump(mode="json")) != _row_str(row, "case_json")
            or canonical_json(event.model_dump(mode="json")) != _row_str(row, "audit_event_json")
            or receipt.case_id != _row_str(row, "case_id")
            or receipt.case_version != _row_int(row, "case_version")
            or receipt.status.value != _row_str(row, "status")
            or authority.location_id != _row_str(row, "location_id")
            or authority.subject_actor_id != _row_optional_str(row, "subject_actor_id")
            or receipt.case_authority_id != _row_str(row, "case_authority_id")
            or receipt.case_document_sha256 != _row_str(row, "case_document_sha256")
            or authority.prior_case_document_sha256
            != _row_optional_str(row, "prior_case_document_sha256")
            or authority.create_command.create_command_id != _row_str(row, "create_command_id")
            or authority.last_transition_command_id
            != _row_optional_str(row, "transition_command_id")
            or authority.last_actor_authority_id != _row_optional_str(row, "actor_authority_id")
            or event.resolved_actor_document_sha256
            != _row_optional_str(row, "resolved_actor_document_sha256")
            or event.audit_event_id != _row_str(row, "audit_event_id")
            or event.audit_event_sha256 != _row_str(row, "audit_event_sha256")
            or event.prior_audit_event_sha256 != _row_str(row, "prior_audit_event_sha256")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 Case index columns conflict with receipt")
        return receipt


__all__ = ["M8_MIGRATIONS", "SQLiteM8OperationsRepository"]
