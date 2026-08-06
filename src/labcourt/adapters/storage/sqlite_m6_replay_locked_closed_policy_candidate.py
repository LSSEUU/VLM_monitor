"""Atomic SQLite persistence for final M6 CLOSED-policy candidates."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, AuditAction, AuditActorRole, CaseStatus
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    M6ReplayLockedExecutionRoute,
)
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateError,
    M6ReplayLockedClosedCandidateFailureCode,
    M6ReplayLockedClosedCandidateWrite,
    M6ReplayLockedStoredClosedCandidate,
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

_FailureCode = M6ReplayLockedClosedCandidateFailureCode
_TABLE = "m6_replay_locked_closed_policy_candidate_cases"


def _error(code: _FailureCode) -> M6ReplayLockedClosedCandidateError:
    return M6ReplayLockedClosedCandidateError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _require_0018_layout(connection: sqlite3.Connection) -> None:
    installed = connection.execute(
        """
        SELECT COUNT(*) AS object_count
        FROM sqlite_master
        WHERE (type = 'table'
               AND name = 'm6_replay_locked_closed_policy_candidate_cases')
           OR (type = 'trigger' AND name IN (
               'm6_replay_locked_closed_policy_candidate_cases_validate',
               'm6_replay_locked_closed_policy_candidate_cases_no_replace',
               'm6_replay_locked_closed_policy_candidate_cases_no_update',
               'm6_replay_locked_closed_policy_candidate_cases_no_delete',
               'm6_replay_locked_candidate_cases_closed_policy_budget',
               'm6_replay_locked_m4_candidate_cases_closed_policy_budget',
               'm6_replay_locked_closed_policy_candidate_cases_cross_route_no_replace',
               'm6_replay_locked_candidate_cases_closed_policy_no_replace',
               'm6_replay_locked_m4_candidate_cases_closed_policy_no_replace'
           ))
        """
    ).fetchone()
    migration = connection.execute("SELECT 1 FROM schema_migrations WHERE version = 18").fetchone()
    if installed is None or _row_int(installed, "object_count") != 10 or migration is None:
        raise MigrationIntegrityError(
            "SQLite M6 CLOSED-policy candidate layout is incomplete; apply migration 0018"
        )


def _canonical_scope(
    value: object,
) -> M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2:
    if type(value) is not M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


def _canonical_pending(
    value: object,
) -> M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2:
    if type(value) is not M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


def _canonical_write(value: object) -> M6ReplayLockedClosedCandidateWrite:
    if type(value) is not M6ReplayLockedClosedCandidateWrite:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        return M6ReplayLockedClosedCandidateWrite(
            transient_ready_case=value.transient_ready_case,
            candidate_alert_policy=value.candidate_alert_policy,
            closed_candidate_case=value.closed_candidate_case,
            canonical_alert_policy_document=value.canonical_alert_policy_document,
            canonical_closed_case_document=value.canonical_closed_case_document,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)


def _document_identity(document: str) -> tuple[str, int]:
    try:
        payload = document.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail(_FailureCode.INVALID_ARGUMENT)
    if not payload:
        _fail(_FailureCode.INVALID_ARGUMENT)
    if len(payload) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
        _fail(_FailureCode.DOCUMENT_TOO_LARGE)
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _require_bindings(
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    candidate: M6ReplayLockedClosedCandidateWrite,
) -> None:
    sequence = pending.ledger_sequence
    pre_scope = scope.pre_policy_execution_scope
    if sequence >= len(pre_scope.execution_dataset.entries):
        _fail(_FailureCode.CANDIDATE_CONFLICT)
    if (
        pending.execution_scope_authority_id != scope.execution_scope_authority_id
        or pending.execution_component_authority_id
        != scope.execution_component.component_authority_id
        or pending.pre_policy_execution_scope_authority_id != pre_scope.execution_scope_authority_id
        or pending.pre_policy_execution_component_authority_id
        != pre_scope.execution_component.component_authority_id
        or pending.candidate_run_id != scope.candidate_run_id
        or pending.command_id != scope.command_id
        or pending.execution_dataset_snapshot_id != scope.execution_dataset_snapshot_id
        or pending.pre_policy_pending_commitment.execution_entry
        != pre_scope.execution_dataset.entries[sequence]
        or pending.source_catalog_entry_id != pre_scope.source_catalog_entry_ids[sequence]
        or pending.locked_config_sha256 != scope.locked_config_sha256
        or pending.pre_policy_route not in pre_scope.execution_component.supported_routes
        or candidate.transient_ready_case.run_id != scope.candidate_run_id
        or candidate.transient_ready_case.manifest_id != scope.candidate_manifest_id
        or candidate.closed_candidate_case.run_id != scope.candidate_run_id
        or candidate.closed_candidate_case.manifest_id != scope.candidate_manifest_id
        or candidate.candidate_alert_policy.request.config_sha256 != scope.locked_config_sha256
        or candidate.candidate_alert_policy.request.prior_cooldown
        != pending.source_binding.cooldown_causal_head.prior_authority
        or candidate.candidate_alert_policy.request.prior_emergency_delivery is not None
    ):
        _fail(_FailureCode.CANDIDATE_CONFLICT)


def _expected_stored(
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    candidate: M6ReplayLockedClosedCandidateWrite,
    *,
    audit_sequence: int,
    audit_entry_hash: str,
) -> M6ReplayLockedStoredClosedCandidate:
    policy_sha, policy_size = _document_identity(candidate.canonical_alert_policy_document)
    case_sha, case_size = _document_identity(candidate.canonical_closed_case_document)
    return M6ReplayLockedStoredClosedCandidate(
        candidate_run_id=scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
        pre_policy_execution_scope_authority_id=(scope.pre_policy_execution_scope_authority_id),
        ledger_sequence=pending.ledger_sequence,
        sample_id=pending.sample_id,
        execution_entry_id=pending.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        pre_policy_pending_commitment_authority_id=(
            pending.pre_policy_pending_commitment.pending_commitment_authority_id
        ),
        source_binding_authority_id=pending.source_binding_authority_id,
        policy_causal_cut_authority_id=pending.policy_causal_cut_authority_id,
        locked_config_sha256=pending.locked_config_sha256,
        pre_policy_route=pending.pre_policy_route,
        candidate_alert_policy=candidate.candidate_alert_policy,
        canonical_alert_policy_document=candidate.canonical_alert_policy_document,
        candidate_alert_policy_document_sha256=policy_sha,
        candidate_alert_policy_size_bytes=policy_size,
        closed_candidate_case=candidate.closed_candidate_case,
        canonical_closed_case_document=candidate.canonical_closed_case_document,
        closed_candidate_case_document_sha256=case_sha,
        closed_candidate_case_size_bytes=case_size,
        case_audit_sequence=audit_sequence,
        case_audit_entry_hash=audit_entry_hash,
    )


def _audit_matches(
    stored: M6ReplayLockedStoredClosedCandidate,
    audit: AuditEntry,
) -> bool:
    return (
        audit.run_id == stored.candidate_run_id
        and audit.sequence == stored.case_audit_sequence
        and audit.manifest_id == stored.closed_candidate_case.manifest_id
        and audit.actor == AuditActorRole.SYSTEM.value
        and audit.action == AuditAction.CASE_CREATED
        and audit.object_ref
        == ArtifactRef(
            kind=ArtifactKind.CASE,
            artifact_id=stored.closed_candidate_case.case_id,
        )
        and audit.before_sha256 is None
        and audit.after_sha256 == stored.closed_candidate_case_document_sha256
        and audit.entry_hash == stored.case_audit_entry_hash
    )


def _stored_from_row(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> M6ReplayLockedStoredClosedCandidate:
    try:
        case_document = _row_str(row, "case_json")
        policy_document = _row_str(row, "alert_policy_json")
        case_size = _row_int(row, "case_document_size_bytes")
        policy_size = _row_int(row, "alert_policy_document_size_bytes")
        case_payload = case_document.encode("utf-8", errors="strict")
        policy_payload = policy_document.encode("utf-8", errors="strict")
        if (
            case_size != len(case_payload)
            or policy_size != len(policy_payload)
            or case_size <= 0
            or policy_size <= 0
            or case_size + policy_size > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
        ):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        case = Case.model_validate_json(case_document)
        policy = AlertPolicyAuthority.model_validate_json(policy_document)
        pending_route = M6ReplayLockedExecutionRoute(_row_str(row, "pre_policy_route"))
        if (
            canonical_json(case.model_dump(mode="json")) != case_document
            or canonical_json(policy.model_dump(mode="json")) != policy_document
        ):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        stored = M6ReplayLockedStoredClosedCandidate(
            candidate_run_id=_row_str(row, "candidate_run_id"),
            execution_scope_authority_id=_row_str(row, "execution_scope_authority_id"),
            pre_policy_execution_scope_authority_id=_row_str(
                row, "pre_policy_execution_scope_authority_id"
            ),
            ledger_sequence=_row_int(row, "ledger_sequence"),
            sample_id=_row_str(row, "sample_id"),
            execution_entry_id=_row_str(row, "execution_entry_id"),
            source_catalog_entry_id=_row_str(row, "source_catalog_entry_id"),
            pending_commitment_authority_id=_row_str(row, "pending_commitment_authority_id"),
            pre_policy_pending_commitment_authority_id=_row_str(
                row, "pre_policy_pending_commitment_authority_id"
            ),
            source_binding_authority_id=_row_str(row, "source_binding_authority_id"),
            policy_causal_cut_authority_id=_row_str(row, "policy_causal_cut_authority_id"),
            locked_config_sha256=_row_str(row, "locked_config_sha256"),
            pre_policy_route=pending_route,
            candidate_alert_policy=policy,
            canonical_alert_policy_document=policy_document,
            candidate_alert_policy_document_sha256=_row_str(row, "alert_policy_document_sha256"),
            candidate_alert_policy_size_bytes=policy_size,
            closed_candidate_case=case,
            canonical_closed_case_document=case_document,
            closed_candidate_case_document_sha256=_row_str(row, "case_document_sha256"),
            closed_candidate_case_size_bytes=case_size,
            case_audit_sequence=_row_int(row, "case_audit_sequence"),
            case_audit_entry_hash=_row_str(row, "case_audit_entry_hash"),
        )
    except M6ReplayLockedClosedCandidateError:
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
        pending_route.value != _row_str(row, "pre_policy_route")
        or _row_str(row, "route") != "ALERT_POLICY_CLOSED"
        or _row_int(row, "case_revision") != 1
        or stored.closed_candidate_case.status != CaseStatus.CLOSED
        or stored.closed_candidate_case.case_id != _row_str(row, "case_id")
        or stored.closed_candidate_case.event.event_id != _row_str(row, "event_id")
        or stored.closed_candidate_case.manifest_id != _row_str(row, "manifest_id")
        or stored.candidate_alert_policy.authority_id
        != _row_str(row, "candidate_alert_policy_authority_id")
        or hashlib.sha256(case_payload).hexdigest() != stored.closed_candidate_case_document_sha256
        or hashlib.sha256(policy_payload).hexdigest()
        != stored.candidate_alert_policy_document_sha256
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


class SQLiteM6ReplayLockedClosedPolicyCandidateRepository(SQLiteEvidenceRepository):
    """Append only final CLOSED Case + policy in the CASE_CREATED transaction."""

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
            _require_0018_layout(connection)
            return connection
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def _load_sequence(
        connection: sqlite3.Connection,
        candidate_run_id: str,
        ledger_sequence: int,
    ) -> M6ReplayLockedStoredClosedCandidate | None:
        preflight = connection.execute(
            f"""
            SELECT COUNT(*) AS item_count,
                   COALESCE(MAX(case_document_size_bytes
                                + alert_policy_document_size_bytes), 0)
                       AS max_claimed_bytes,
                   COALESCE(MAX(length(CAST(case_json AS BLOB))
                                + length(CAST(alert_policy_json AS BLOB))), 0)
                       AS max_actual_bytes
            FROM {_TABLE}
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
            f"SELECT * FROM {_TABLE} WHERE candidate_run_id = ? AND ledger_sequence = ?",
            (candidate_run_id, ledger_sequence),
        ).fetchone()
        if row is None:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        return _stored_from_row(connection, row)

    @classmethod
    def _validated_prefix(
        cls,
        connection: sqlite3.Connection,
        head: AuditHead,
    ) -> tuple[M6ReplayLockedStoredClosedCandidate, ...]:
        preflight = connection.execute(
            f"""
            SELECT COUNT(*) AS item_count,
                   COALESCE(SUM(case_document_size_bytes
                                + alert_policy_document_size_bytes), 0)
                       AS total_claimed_bytes,
                   COALESCE(SUM(length(CAST(case_json AS BLOB))
                                + length(CAST(alert_policy_json AS BLOB))), 0)
                       AS total_actual_bytes,
                   COALESCE(SUM(CASE
                       WHEN typeof(case_document_size_bytes) <> 'integer'
                         OR typeof(alert_policy_document_size_bytes) <> 'integer'
                         OR typeof(case_json) <> 'text'
                         OR typeof(alert_policy_json) <> 'text'
                         OR case_document_size_bytes
                            <> length(CAST(case_json AS BLOB))
                         OR alert_policy_document_size_bytes
                            <> length(CAST(alert_policy_json AS BLOB))
                       THEN 1 ELSE 0 END), 0) AS invalid_count
            FROM {_TABLE}
            WHERE candidate_run_id = ?
            """,
            (head.run_id,),
        ).fetchone()
        mixed = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM m6_replay_locked_candidate_cases
                 WHERE candidate_run_id = ?)
              + (SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases
                 WHERE candidate_run_id = ?) AS mixed_count
            """,
            (head.run_id, head.run_id),
        ).fetchone()
        if preflight is None or mixed is None:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        try:
            count = _row_int(preflight, "item_count")
            claimed = _row_int(preflight, "total_claimed_bytes")
            actual = _row_int(preflight, "total_actual_bytes")
            invalid = _row_int(preflight, "invalid_count")
            mixed_count = _row_int(mixed, "mixed_count")
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if max(claimed, actual) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            _fail(_FailureCode.DOCUMENT_TOO_LARGE)
        if mixed_count or invalid or count != head.run_revision or count != head.sequence + 1:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        rows = connection.execute(
            f"""
            SELECT ledger_sequence
            FROM {_TABLE}
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
            cls._load_sequence(connection, head.run_id, sequence) for sequence in sequences
        )
        if any(item is None for item in prefix):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        controlled = tuple(item for item in prefix if item is not None)
        if controlled and (
            len({item.execution_scope_authority_id for item in controlled}) != 1
            or len({item.pre_policy_execution_scope_authority_id for item in controlled}) != 1
        ):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        return controlled

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        stored: M6ReplayLockedStoredClosedCandidate,
    ) -> None:
        case = stored.closed_candidate_case
        policy = stored.candidate_alert_policy
        connection.execute(
            f"""
            INSERT INTO {_TABLE}(
                candidate_run_id, execution_scope_authority_id,
                pre_policy_execution_scope_authority_id, ledger_sequence,
                sample_id, execution_entry_id, source_catalog_entry_id,
                pending_commitment_authority_id,
                pre_policy_pending_commitment_authority_id,
                source_binding_authority_id, policy_causal_cut_authority_id,
                locked_config_sha256, route, pre_policy_route, case_id, event_id,
                case_revision, manifest_id, status, case_json,
                case_document_sha256, case_document_size_bytes,
                candidate_alert_policy_authority_id, alert_policy_json,
                alert_policy_document_sha256, alert_policy_document_size_bytes,
                case_audit_sequence, case_audit_entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored.candidate_run_id,
                stored.execution_scope_authority_id,
                stored.pre_policy_execution_scope_authority_id,
                stored.ledger_sequence,
                stored.sample_id,
                stored.execution_entry_id,
                stored.source_catalog_entry_id,
                stored.pending_commitment_authority_id,
                stored.pre_policy_pending_commitment_authority_id,
                stored.source_binding_authority_id,
                stored.policy_causal_cut_authority_id,
                stored.locked_config_sha256,
                "ALERT_POLICY_CLOSED",
                stored.pre_policy_route.value,
                case.case_id,
                case.event.event_id,
                1,
                case.manifest_id,
                case.status.value,
                stored.canonical_closed_case_document,
                stored.closed_candidate_case_document_sha256,
                stored.closed_candidate_case_size_bytes,
                policy.authority_id,
                stored.canonical_alert_policy_document,
                stored.candidate_alert_policy_document_sha256,
                stored.candidate_alert_policy_size_bytes,
                stored.case_audit_sequence,
                stored.case_audit_entry_hash,
            ),
        )

    def _attempt_publish(
        self,
        execution_scope: object,
        pending_commitment: object,
        candidate: object,
    ) -> None:
        scope = _canonical_scope(execution_scope)
        pending = _canonical_pending(pending_commitment)
        controlled = _canonical_write(candidate)
        _require_bindings(scope, pending, controlled)
        with self._immediate() as connection:
            head = self._validated_head(connection, scope.candidate_run_id)
            prefix = self._validated_prefix(connection, head)
            manifest = self._load_run_manifest(connection, scope.candidate_run_id)
            if manifest != scope.pre_policy_execution_scope.locked_manifest:
                _fail(_FailureCode.CANDIDATE_CONFLICT)
            existing = self._load_sequence(
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
                if existing != expected or prefix[pending.ledger_sequence] != existing:
                    _fail(_FailureCode.CANDIDATE_CONFLICT)
                return
            if (
                head.sequence != pending.ledger_sequence - 1
                or head.run_revision != pending.ledger_sequence
            ):
                _fail(_FailureCode.CANDIDATE_CONFLICT)
            case_sha, case_size = _document_identity(controlled.canonical_closed_case_document)
            _, policy_size = _document_identity(controlled.canonical_alert_policy_document)
            if (
                sum(
                    item.closed_candidate_case_size_bytes + item.candidate_alert_policy_size_bytes
                    for item in prefix
                )
                + case_size
                + policy_size
                > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            ):
                _fail(_FailureCode.DOCUMENT_TOO_LARGE)
            audit, _new_head = self._append_audit(
                connection,
                head,
                action=AuditAction.CASE_CREATED,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.CASE,
                    artifact_id=controlled.closed_candidate_case.case_id,
                ),
                before_sha256=None,
                after_sha256=case_sha,
                actor=AuditActorRole.SYSTEM,
            )
            if audit.sequence != pending.ledger_sequence:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            self._fault("m6_replay_locked_closed_policy_candidate.after_audit")
            expected = _expected_stored(
                scope,
                pending,
                controlled,
                audit_sequence=audit.sequence,
                audit_entry_hash=audit.entry_hash,
            )
            self._insert(connection, expected)
            self._fault("m6_replay_locked_closed_policy_candidate.after_candidate")
            observed = self._load_sequence(
                connection,
                scope.candidate_run_id,
                pending.ledger_sequence,
            )
            if observed != expected:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            self._fault("m6_replay_locked_closed_policy_candidate.before_commit")

    def publish_closed_candidate(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        candidate: M6ReplayLockedClosedCandidateWrite,
    ) -> None:
        failure = _FailureCode.STORAGE_REJECTED
        try:
            self._attempt_publish(execution_scope, pending_commitment, candidate)
            return
        except M6ReplayLockedClosedCandidateError as error:
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
    ) -> M6ReplayLockedStoredClosedCandidate:
        try:
            if not isinstance(candidate_run_id, str) or not isinstance(sample_id, str):
                raise TypeError
            run_id = require_portable_run_id(candidate_run_id, "M6 CLOSED candidate run_id")
            controlled_sample = require_reference_token(sample_id, "M6 CLOSED candidate sample_id")
        except (TypeError, ValueError):
            _fail(_FailureCode.INVALID_ARGUMENT)
        connection = self._connection()
        try:
            connection.execute("BEGIN")
            if (
                connection.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
                is None
            ):
                _fail(_FailureCode.NOT_FOUND)
            head = self._validated_head(connection, run_id)
            self._validated_prefix(connection, head)
            row = connection.execute(
                f"""
                SELECT ledger_sequence
                FROM {_TABLE}
                WHERE candidate_run_id = ? AND sample_id = ?
                """,
                (run_id, controlled_sample),
            ).fetchone()
            if row is None:
                _fail(_FailureCode.NOT_FOUND)
            stored = self._load_sequence(
                connection,
                run_id,
                _row_int(row, "ledger_sequence"),
            )
            if stored is None or stored.sample_id != controlled_sample:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            connection.commit()
            return stored
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def load_stored_closed_candidate(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedStoredClosedCandidate:
        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_load(candidate_run_id, sample_id)
        except M6ReplayLockedClosedCandidateError as error:
            failure = error.reason_code
        except (MigrationIntegrityError, sqlite3.DatabaseError):
            failure = _FailureCode.STORAGE_REJECTED
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, candidate_run_id, sample_id
        raise _error(failure) from None

    def load_closed_candidate_audit_head(self, candidate_run_id: str) -> AuditHead:
        failure = _FailureCode.STORAGE_REJECTED
        connection: sqlite3.Connection | None = None
        try:
            if not isinstance(candidate_run_id, str):
                _fail(_FailureCode.INVALID_ARGUMENT)
            run_id = require_portable_run_id(candidate_run_id, "M6 CLOSED candidate run_id")
            connection = self._connection()
            connection.execute("BEGIN")
            if (
                connection.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
                is None
            ):
                _fail(_FailureCode.NOT_FOUND)
            head = self._validated_head(connection, run_id)
            self._validated_prefix(connection, head)
            connection.commit()
            return head
        except M6ReplayLockedClosedCandidateError as error:
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


__all__ = ["SQLiteM6ReplayLockedClosedPolicyCandidateRepository"]
