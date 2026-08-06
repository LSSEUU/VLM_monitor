"""Atomic SQLite persistence for deterministic M6 locked-replay candidates."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    CaseStatus,
)
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidateWrite,
    M6ReplayLockedM4CandidateWrite,
    M6ReplayLockedStoredCandidateCase,
)

from .sqlite_repository import (
    Clock,
    FaultInjector,
    MigrationIntegrityError,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
    _audit_entry_from_row,
    _row_int,
    _row_str,
)

_FailureCode = M6ReplayLockedCandidateFailureCode
_FAST_TABLE = "m6_replay_locked_candidate_cases"
_M4_TABLE = "m6_replay_locked_m4_candidate_cases"
_CANDIDATE_COLUMNS = """
    candidate_run_id, execution_scope_authority_id, ledger_sequence,
    sample_id, execution_entry_id, source_catalog_entry_id,
    pending_commitment_authority_id, route, case_id, event_id,
    case_revision, manifest_id, status, case_json,
    case_document_sha256, case_document_size_bytes,
    case_audit_sequence, case_audit_entry_hash
"""
_CANDIDATE_UNION = f"""
    SELECT {_CANDIDATE_COLUMNS} FROM {_FAST_TABLE}
    UNION ALL
    SELECT {_CANDIDATE_COLUMNS} FROM {_M4_TABLE}
"""
_CandidateWrite = M6ReplayLockedCandidateWrite | M6ReplayLockedM4CandidateWrite


def _error(code: _FailureCode) -> M6ReplayLockedCandidateError:
    return M6ReplayLockedCandidateError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_0017_layout(connection: sqlite3.Connection) -> None:
    installed = connection.execute(
        """
        SELECT COUNT(*) AS object_count
        FROM sqlite_master
        WHERE (type = 'table' AND name IN (
                  'm6_replay_locked_candidate_cases',
                  'm6_replay_locked_m4_candidate_cases'
              ))
           OR (type = 'trigger' AND name IN (
               'm6_replay_locked_candidate_cases_validate',
               'm6_replay_locked_candidate_cases_no_replace',
               'm6_replay_locked_candidate_cases_cross_route_no_replace',
               'm6_replay_locked_candidate_cases_no_update',
               'm6_replay_locked_candidate_cases_no_delete',
               'm6_replay_locked_m4_candidate_cases_validate',
               'm6_replay_locked_m4_candidate_cases_no_replace',
               'm6_replay_locked_m4_candidate_cases_cross_route_no_replace',
               'm6_replay_locked_m4_candidate_cases_no_update',
               'm6_replay_locked_m4_candidate_cases_no_delete'
           ))
        """
    ).fetchone()
    migration = connection.execute("SELECT 1 FROM schema_migrations WHERE version = 17").fetchone()
    if installed is None or _row_int(installed, "object_count") != 12 or migration is None:
        raise MigrationIntegrityError(
            "SQLite M6 replay-locked candidate layout is incomplete; apply migration 0017"
        )


def _canonical_scope(value: object) -> M6ReplayLockedExecutionScopeAuthority:
    if type(value) is not M6ReplayLockedExecutionScopeAuthority:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedExecutionScopeAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


def _canonical_pending(value: object) -> M6ReplayLockedPendingSampleCommitmentAuthority:
    if type(value) is not M6ReplayLockedPendingSampleCommitmentAuthority:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedPendingSampleCommitmentAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


def _canonical_write(
    value: object,
    expected_route: M6ReplayLockedExecutionRoute,
) -> _CandidateWrite:
    try:
        if expected_route == M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE:
            if type(value) is not M6ReplayLockedCandidateWrite:
                _fail(_FailureCode.INVALID_ARGUMENT)
            return M6ReplayLockedCandidateWrite(
                case=value.case,
                canonical_document=value.canonical_document,
            )
        if expected_route == M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
            if type(value) is not M6ReplayLockedM4CandidateWrite:
                _fail(_FailureCode.INVALID_ARGUMENT)
            return M6ReplayLockedM4CandidateWrite(
                case=value.case,
                canonical_document=value.canonical_document,
            )
    except M6ReplayLockedCandidateError:
        raise
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    _fail(_FailureCode.INVALID_ARGUMENT)


def _require_scope_binding(
    scope: M6ReplayLockedExecutionScopeAuthority,
    pending: M6ReplayLockedPendingSampleCommitmentAuthority,
    candidate: _CandidateWrite,
    expected_route: M6ReplayLockedExecutionRoute,
) -> None:
    sequence = pending.ledger_sequence
    if sequence >= len(scope.execution_dataset.entries):
        _fail(_FailureCode.CANDIDATE_CONFLICT)
    expected_entry = scope.execution_dataset.entries[sequence]
    if (
        pending.execution_scope_authority_id != scope.execution_scope_authority_id
        or pending.candidate_run_id != scope.candidate_run_id
        or pending.command_id != scope.command.command_id
        or pending.execution_dataset_snapshot_id
        != scope.execution_dataset.execution_dataset_snapshot_id
        or pending.execution_component_authority_id
        != scope.execution_component.component_authority_id
        or pending.source_catalog_entry_id != scope.source_catalog_entry_ids[sequence]
        or pending.execution_entry != expected_entry
        or pending.route != expected_route
        or pending.route not in scope.execution_component.supported_routes
        or candidate.case.run_id != scope.candidate_run_id
        or candidate.case.manifest_id != scope.locked_manifest.manifest_id
    ):
        _fail(_FailureCode.CANDIDATE_CONFLICT)


def _document_identity(document: str) -> tuple[str, int]:
    try:
        payload = document.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail(_FailureCode.INVALID_ARGUMENT)
    size_bytes = len(payload)
    if size_bytes > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
        _fail(_FailureCode.DOCUMENT_TOO_LARGE)
    if size_bytes == 0:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return hashlib.sha256(payload).hexdigest(), size_bytes


def _stored_from_row(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> M6ReplayLockedStoredCandidateCase:
    try:
        document = _row_str(row, "case_json")
        claimed_size = _row_int(row, "case_document_size_bytes")
        payload = document.encode("utf-8", errors="strict")
        if (
            claimed_size <= 0
            or claimed_size > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            or len(payload) != claimed_size
        ):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        case = Case.model_validate_json(document)
        document_sha256 = hashlib.sha256(payload).hexdigest()
        if canonical_json(case.model_dump(mode="json")) != document:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        route = M6ReplayLockedExecutionRoute(_row_str(row, "route"))
        stored = M6ReplayLockedStoredCandidateCase(
            candidate_run_id=_row_str(row, "candidate_run_id"),
            execution_scope_authority_id=_row_str(row, "execution_scope_authority_id"),
            ledger_sequence=_row_int(row, "ledger_sequence"),
            sample_id=_row_str(row, "sample_id"),
            execution_entry_id=_row_str(row, "execution_entry_id"),
            source_catalog_entry_id=_row_str(row, "source_catalog_entry_id"),
            pending_commitment_authority_id=_row_str(
                row,
                "pending_commitment_authority_id",
            ),
            route=route,
            case=case,
            canonical_document=document,
            case_document_sha256=_row_str(row, "case_document_sha256"),
            case_document_size_bytes=claimed_size,
            case_audit_sequence=_row_int(row, "case_audit_sequence"),
            case_audit_entry_hash=_row_str(row, "case_audit_entry_hash"),
        )
    except M6ReplayLockedCandidateError:
        raise
    except (
        IndexError,
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        ValidationError,
        RepositoryIntegrityError,
    ):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    if (
        stored.case_document_sha256 != document_sha256
        or stored.case.run_id != stored.candidate_run_id
        or stored.case.case_id != _row_str(row, "case_id")
        or stored.case.event.event_id != _row_str(row, "event_id")
        or stored.case.manifest_id != _row_str(row, "manifest_id")
        or stored.case.status.value != _row_str(row, "status")
        or stored.case.status not in {CaseStatus.READY_FOR_ALERT_POLICY, CaseStatus.REWORK_REQUIRED}
        or _row_int(row, "case_revision") != 1
        or stored.case_audit_sequence != stored.ledger_sequence
        or not _is_sha256(stored.execution_scope_authority_id)
        or not _is_sha256(stored.execution_entry_id)
        or not _is_sha256(stored.source_catalog_entry_id)
        or not _is_sha256(stored.pending_commitment_authority_id)
        or not _is_sha256(stored.case_audit_entry_hash)
    ):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    audit_row = connection.execute(
        "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
        (stored.candidate_run_id, stored.case_audit_sequence),
    ).fetchone()
    if audit_row is None:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        audit = _audit_entry_from_row(audit_row)
    except (TypeError, ValueError, ValidationError, RepositoryIntegrityError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    if not _audit_matches(stored, audit):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    return stored


def _audit_matches(stored: M6ReplayLockedStoredCandidateCase, audit: AuditEntry) -> bool:
    return (
        audit.run_id == stored.candidate_run_id
        and audit.sequence == stored.case_audit_sequence
        and audit.manifest_id == stored.case.manifest_id
        and audit.actor == AuditActorRole.SYSTEM.value
        and audit.action == AuditAction.CASE_CREATED
        and audit.object_ref == ArtifactRef(kind=ArtifactKind.CASE, artifact_id=stored.case.case_id)
        and audit.before_sha256 is None
        and audit.after_sha256 == stored.case_document_sha256
        and audit.entry_hash == stored.case_audit_entry_hash
    )


def _expected_stored(
    scope: M6ReplayLockedExecutionScopeAuthority,
    pending: M6ReplayLockedPendingSampleCommitmentAuthority,
    candidate: _CandidateWrite,
    *,
    audit_sequence: int,
    audit_entry_hash: str,
) -> M6ReplayLockedStoredCandidateCase:
    document_sha256, size_bytes = _document_identity(candidate.canonical_document)
    return M6ReplayLockedStoredCandidateCase(
        candidate_run_id=scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
        ledger_sequence=pending.ledger_sequence,
        sample_id=pending.sample_id,
        execution_entry_id=pending.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        route=pending.route,
        case=candidate.case,
        canonical_document=candidate.canonical_document,
        case_document_sha256=document_sha256,
        case_document_size_bytes=size_bytes,
        case_audit_sequence=audit_sequence,
        case_audit_entry_hash=audit_entry_hash,
    )


class SQLiteM6ReplayLockedCandidateRepository(SQLiteEvidenceRepository):
    """Publish one candidate and its audit atomically; retries never append."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        *,
        clock: Clock | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        if fault_injector is not None and not callable(fault_injector):
            raise TypeError("fault_injector must be callable or None")
        super().__init__(
            database_path,
            busy_timeout_ms,
            clock=clock,
            fault_injector=fault_injector,
        )

    def _connection(
        self,
        *,
        require_hardening: bool = False,
        require_m4: bool = False,
    ) -> sqlite3.Connection:
        connection = super()._connection(
            require_hardening=require_hardening,
            require_m4=require_m4,
        )
        try:
            _require_0017_layout(connection)
            return connection
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def _load_row_for_sequence(
        connection: sqlite3.Connection,
        candidate_run_id: str,
        ledger_sequence: int,
    ) -> M6ReplayLockedStoredCandidateCase | None:
        preflight = connection.execute(
            f"""
            WITH candidates AS ({_CANDIDATE_UNION})
            SELECT COUNT(*) AS item_count,
                   COALESCE(MAX(case_document_size_bytes), 0) AS max_claimed_bytes,
                   COALESCE(MAX(length(CAST(case_json AS BLOB))), 0) AS max_actual_bytes
            FROM candidates
            WHERE candidate_run_id = ? AND ledger_sequence = ?
            """,
            (candidate_run_id, ledger_sequence),
        ).fetchone()
        if preflight is None:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        try:
            count = _row_int(preflight, "item_count")
            claimed = _row_int(preflight, "max_claimed_bytes")
            actual = _row_int(preflight, "max_actual_bytes")
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if count > 1:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if max(claimed, actual) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            _fail(_FailureCode.DOCUMENT_TOO_LARGE)
        if count == 0:
            return None
        row = connection.execute(
            f"""
            WITH candidates AS ({_CANDIDATE_UNION})
            SELECT * FROM candidates
            WHERE candidate_run_id = ? AND ledger_sequence = ?
            """,
            (candidate_run_id, ledger_sequence),
        ).fetchone()
        if row is None:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        return _stored_from_row(connection, row)

    @classmethod
    def _validated_candidate_prefix(
        cls,
        connection: sqlite3.Connection,
        head: AuditHead,
    ) -> tuple[M6ReplayLockedStoredCandidateCase, ...]:
        preflight = connection.execute(
            f"""
            WITH candidates AS ({_CANDIDATE_UNION})
            SELECT COUNT(*) AS item_count,
                   COALESCE(MAX(case_document_size_bytes), 0) AS max_claimed_bytes,
                   COALESCE(MAX(length(CAST(case_json AS BLOB))), 0) AS max_actual_bytes,
                   COALESCE(SUM(case_document_size_bytes), 0) AS total_claimed_bytes,
                   COALESCE(SUM(length(CAST(case_json AS BLOB))), 0) AS total_actual_bytes,
                   COALESCE(SUM(CASE
                       WHEN typeof(case_document_size_bytes) <> 'integer'
                         OR typeof(case_json) <> 'text'
                         OR case_document_size_bytes < 1
                         OR case_document_size_bytes
                            <> length(CAST(case_json AS BLOB))
                       THEN 1 ELSE 0 END), 0) AS invalid_count
            FROM candidates
            WHERE candidate_run_id = ?
            """,
            (head.run_id,),
        ).fetchone()
        if preflight is None:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        try:
            count = _row_int(preflight, "item_count")
            bounds = (
                _row_int(preflight, "max_claimed_bytes"),
                _row_int(preflight, "max_actual_bytes"),
                _row_int(preflight, "total_claimed_bytes"),
                _row_int(preflight, "total_actual_bytes"),
            )
            invalid_count = _row_int(preflight, "invalid_count")
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if any(value > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES for value in bounds):
            _fail(_FailureCode.DOCUMENT_TOO_LARGE)
        if invalid_count or count != head.run_revision or count != head.sequence + 1:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        rows = connection.execute(
            f"""
            WITH candidates AS ({_CANDIDATE_UNION})
            SELECT ledger_sequence
            FROM candidates
            WHERE candidate_run_id = ?
            ORDER BY ledger_sequence
            """,
            (head.run_id,),
        ).fetchall()
        try:
            sequences = tuple(_row_int(row, "ledger_sequence") for row in rows)
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if sequences != tuple(range(count)):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        prefix = tuple(
            cls._load_row_for_sequence(connection, head.run_id, sequence) for sequence in sequences
        )
        if any(item is None for item in prefix):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        controlled = tuple(item for item in prefix if item is not None)
        if controlled and len({item.execution_scope_authority_id for item in controlled}) != 1:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        return controlled

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        stored: M6ReplayLockedStoredCandidateCase,
    ) -> None:
        case = stored.case
        if stored.route == M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE:
            table = _FAST_TABLE
        elif stored.route == M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
            table = _M4_TABLE
        else:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        connection.execute(
            f"""
            INSERT INTO {table}(
                candidate_run_id, execution_scope_authority_id, ledger_sequence,
                sample_id, execution_entry_id, source_catalog_entry_id,
                pending_commitment_authority_id, route, case_id, event_id,
                case_revision, manifest_id, status, case_json,
                case_document_sha256, case_document_size_bytes,
                case_audit_sequence, case_audit_entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored.candidate_run_id,
                stored.execution_scope_authority_id,
                stored.ledger_sequence,
                stored.sample_id,
                stored.execution_entry_id,
                stored.source_catalog_entry_id,
                stored.pending_commitment_authority_id,
                stored.route.value,
                case.case_id,
                case.event.event_id,
                1,
                case.manifest_id,
                case.status.value,
                stored.canonical_document,
                stored.case_document_sha256,
                stored.case_document_size_bytes,
                stored.case_audit_sequence,
                stored.case_audit_entry_hash,
            ),
        )

    def _attempt_publish(
        self,
        execution_scope: object,
        pending_commitment: object,
        candidate: object,
        expected_route: M6ReplayLockedExecutionRoute,
    ) -> None:
        scope = _canonical_scope(execution_scope)
        pending = _canonical_pending(pending_commitment)
        controlled = _canonical_write(candidate, expected_route)
        _require_scope_binding(scope, pending, controlled, expected_route)
        with self._immediate() as connection:
            head = self._validated_head(connection, scope.candidate_run_id)
            prefix = self._validated_candidate_prefix(connection, head)
            manifest = self._load_run_manifest(connection, scope.candidate_run_id)
            if manifest != scope.locked_manifest:
                _fail(_FailureCode.CANDIDATE_CONFLICT)
            existing = self._load_row_for_sequence(
                connection,
                scope.candidate_run_id,
                pending.ledger_sequence,
            )
            if existing is not None:
                expected = _expected_stored(
                    scope,
                    pending,
                    controlled,
                    audit_sequence=existing.case_audit_sequence,
                    audit_entry_hash=existing.case_audit_entry_hash,
                )
                if existing != expected:
                    _fail(_FailureCode.CANDIDATE_CONFLICT)
                if prefix[pending.ledger_sequence] != existing:
                    _fail(_FailureCode.STORED_AUTHORITY_INVALID)
                return
            if (
                head.sequence != pending.ledger_sequence - 1
                or head.run_revision != pending.ledger_sequence
            ):
                _fail(_FailureCode.CANDIDATE_CONFLICT)
            document_sha256, candidate_size_bytes = _document_identity(
                controlled.canonical_document
            )
            if (
                sum(item.case_document_size_bytes for item in prefix) + candidate_size_bytes
                > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            ):
                _fail(_FailureCode.DOCUMENT_TOO_LARGE)
            row_count = connection.execute(
                f"""
                WITH candidates AS ({_CANDIDATE_UNION})
                SELECT COUNT(*) FROM candidates
                WHERE candidate_run_id = ?
                """,
                (scope.candidate_run_id,),
            ).fetchone()
            if row_count is None or int(row_count[0]) != pending.ledger_sequence:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            audit, _new_head = self._append_audit(
                connection,
                head,
                action=AuditAction.CASE_CREATED,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.CASE,
                    artifact_id=controlled.case.case_id,
                ),
                before_sha256=None,
                after_sha256=document_sha256,
                actor=AuditActorRole.SYSTEM,
            )
            if audit.sequence != pending.ledger_sequence:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            self._fault("m6_replay_locked_candidate.after_audit")
            expected = _expected_stored(
                scope,
                pending,
                controlled,
                audit_sequence=audit.sequence,
                audit_entry_hash=audit.entry_hash,
            )
            self._insert(connection, expected)
            self._fault("m6_replay_locked_candidate.after_candidate")
            observed = self._load_row_for_sequence(
                connection,
                scope.candidate_run_id,
                pending.ledger_sequence,
            )
            if observed != expected:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            self._fault("m6_replay_locked_candidate.before_commit")

    def publish_candidate(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        candidate: M6ReplayLockedCandidateWrite,
    ) -> None:
        """Atomically append the candidate audit and immutable Case row."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            self._attempt_publish(
                execution_scope,
                pending_commitment,
                candidate,
                M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
            )
            return
        except M6ReplayLockedCandidateError as error:
            failure = error.reason_code
        except (ConcurrentModification, MigrationIntegrityError, sqlite3.DatabaseError):
            failure = _FailureCode.STORAGE_REJECTED
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, execution_scope, pending_commitment, candidate
        raise _error(failure) from None

    def publish_m4_candidate(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        candidate: M6ReplayLockedM4CandidateWrite,
    ) -> None:
        """Atomically append one M4 hearing-plus-Gate candidate and its audit."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            self._attempt_publish(
                execution_scope,
                pending_commitment,
                candidate,
                M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
            )
            return
        except M6ReplayLockedCandidateError as error:
            failure = error.reason_code
        except (ConcurrentModification, MigrationIntegrityError, sqlite3.DatabaseError):
            failure = _FailureCode.STORAGE_REJECTED
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, execution_scope, pending_commitment, candidate
        raise _error(failure) from None

    def _attempt_load(
        self,
        candidate_run_id: object,
        sample_id: object,
    ) -> M6ReplayLockedStoredCandidateCase:
        try:
            if not isinstance(candidate_run_id, str) or not isinstance(sample_id, str):
                raise TypeError
            run_id = require_portable_run_id(
                candidate_run_id,
                "M6 locked candidate run_id",
            )
            controlled_sample = require_reference_token(
                sample_id,
                "M6 locked candidate sample_id",
            )
        except (TypeError, ValueError):
            _fail(_FailureCode.INVALID_ARGUMENT)
        connection = self._connection()
        try:
            connection.execute("BEGIN")
            if (
                connection.execute(
                    "SELECT 1 FROM runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                is None
            ):
                _fail(_FailureCode.NOT_FOUND)
            head = self._validated_head(connection, run_id)
            self._validated_candidate_prefix(connection, head)
            row = connection.execute(
                f"""
                WITH candidates AS ({_CANDIDATE_UNION})
                SELECT ledger_sequence FROM candidates
                WHERE candidate_run_id = ? AND sample_id = ?
                """,
                (run_id, controlled_sample),
            ).fetchone()
            if row is None:
                _fail(_FailureCode.NOT_FOUND)
            stored = self._load_row_for_sequence(
                connection,
                run_id,
                _row_int(row, "ledger_sequence"),
            )
            if (
                stored is None
                or stored.sample_id != controlled_sample
                or stored.case_audit_sequence > head.sequence
            ):
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            connection.commit()
            return stored
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def load_stored_candidate_case(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedStoredCandidateCase:
        """Read one canonical row for independent semantic reconstruction."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_load(candidate_run_id, sample_id)
        except M6ReplayLockedCandidateError as error:
            failure = error.reason_code
        except (MigrationIntegrityError, sqlite3.DatabaseError):
            failure = _FailureCode.STORAGE_REJECTED
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, candidate_run_id, sample_id
        raise _error(failure) from None

    def load_candidate_audit_head(self, candidate_run_id: str) -> AuditHead:
        """Return a fully validated audit head through the candidate error boundary."""

        failure = _FailureCode.STORAGE_REJECTED
        connection: sqlite3.Connection | None = None
        try:
            if not isinstance(candidate_run_id, str):
                _fail(_FailureCode.INVALID_ARGUMENT)
            run_id = require_portable_run_id(
                candidate_run_id,
                "M6 locked candidate run_id",
            )
            connection = self._connection()
            connection.execute("BEGIN")
            if (
                connection.execute(
                    "SELECT 1 FROM runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                is None
            ):
                _fail(_FailureCode.NOT_FOUND)
            head = self._validated_head(connection, run_id)
            self._validated_candidate_prefix(connection, head)
            connection.commit()
            return head
        except M6ReplayLockedCandidateError as error:
            failure = error.reason_code
        except (TypeError, ValueError):
            failure = _FailureCode.INVALID_ARGUMENT
        except (MigrationIntegrityError, sqlite3.DatabaseError):
            failure = _FailureCode.STORAGE_REJECTED
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
        del self, candidate_run_id
        raise _error(failure) from None


__all__ = [
    "SQLiteM6ReplayLockedCandidateRepository",
]
