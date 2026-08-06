"""Trusted construction of M6 locked Pending, Record, and terminal Seal facts."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6LockedRetrievalOutcomeKind,
    M6ProviderCapabilityCounters,
    M6ReplayAuthorityKind,
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedCandidateCaseBinding,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    M6ReplayLockedRunTrapSealAuthority,
    M6ReplayLockedSampleExecutionRecord,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateObservation,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedExecutionErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_CATALOG_MISMATCH = "SCOPE_CATALOG_MISMATCH"
    UNSUPPORTED_ROUTE = "UNSUPPORTED_ROUTE"
    PENDING_REJECTED = "PENDING_REJECTED"
    CANDIDATE_OBSERVATION_REJECTED = "CANDIDATE_OBSERVATION_REJECTED"
    RECORD_REJECTED = "RECORD_REJECTED"
    AUDIT_HEAD_MISMATCH = "AUDIT_HEAD_MISMATCH"
    SEAL_REJECTED = "SEAL_REJECTED"


class M6ReplayLockedExecutionError(LabCourtError):
    """Payload-free locked execution fact construction failure."""

    def __init__(self, code: M6ReplayLockedExecutionErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedExecutionErrorCode):
            raise TypeError("code must be an M6 locked execution error code")
        self.code = code
        super().__init__(f"M6 locked execution fact construction failed: {code.value}")


def _fail(code: M6ReplayLockedExecutionErrorCode) -> NoReturn:
    raise M6ReplayLockedExecutionError(code) from None


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    return controlled


def _identity(value: BaseModel) -> tuple[str, int]:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _controlled_catalog(value: object) -> M6StoredRegressionExecutionSourceCatalog:
    if type(value) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    try:
        return M6StoredRegressionExecutionSourceCatalog(
            source_catalog=value.source_catalog,
            canonical_document=value.canonical_document,
            content_sha256=value.content_sha256,
            size_bytes=value.size_bytes,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)


def _require_scope_catalog(
    scope: M6ReplayLockedExecutionScopeAuthority,
    stored: M6StoredRegressionExecutionSourceCatalog,
) -> None:
    catalog = stored.source_catalog
    dataset = scope.execution_dataset
    catalog_bindings = tuple(
        (
            item.sample_id,
            item.input_authority_id,
            item.input_authority_document_sha256,
            item.replay_input_closure.replay_input_closure_authority_id,
            item.replay_input_closure.replay_input_closure_document_sha256,
        )
        for item in catalog.entries
    )
    dataset_bindings = tuple(
        (
            item.sample_id,
            item.input_authority_id,
            item.input_authority_document_sha256,
            item.replay_input_closure_authority_id,
            item.replay_input_closure_document_sha256,
        )
        for item in dataset.entries
    )
    if (
        catalog.source_catalog_authority_id != dataset.source_catalog_authority_id
        or stored.content_sha256 != scope.source_catalog_content_sha256
        or stored.size_bytes != scope.source_catalog_size_bytes
        or catalog.entry_count != scope.source_catalog_entry_count
        or tuple(item.catalog_entry_id for item in catalog.entries)
        != scope.source_catalog_entry_ids
        or tuple(sorted({item.replay_input_closure.source_run_id for item in catalog.entries}))
        != scope.source_run_ids
        or catalog_bindings != dataset_bindings
    ):
        _fail(M6ReplayLockedExecutionErrorCode.SCOPE_CATALOG_MISMATCH)


def _require_sequence(value: object, entry_count: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value >= entry_count:
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    return value


def _require_sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    return value


def _is_fast_terminal_closure(closure: M6ReplayInputClosureAuthority) -> bool:
    calls = closure.model_calls
    return (
        closure.source_case_id is not None
        and bool(calls)
        and not closure.embeddings
        and not closure.tool_results
        and not closure.historical_cut.retrieval_cycles
        and all(
            item.layer == M6LockedModelCallLayer.SCREENING
            and item.role == M6LockedModelRole.SCREENING
            for item in calls
        )
        and any(
            item.result_kind == M6LockedModelCallResultKind.RESPONSE
            and item.parsed_output_ref is not None
            for item in calls
        )
    )


def _is_m4_hearing_gate_terminal_closure(
    closure: M6ReplayInputClosureAuthority,
) -> bool:
    expected_calls = (
        (M6LockedModelCallLayer.SCREENING, M6LockedModelRole.SCREENING),
        (M6LockedModelCallLayer.HEARING, M6LockedModelRole.PROSECUTOR),
        (M6LockedModelCallLayer.HEARING, M6LockedModelRole.DEFENDER),
        (M6LockedModelCallLayer.HEARING, M6LockedModelRole.JUDGE),
    )
    calls = closure.model_calls
    cycles = closure.historical_cut.retrieval_cycles
    return (
        closure.source_case_id is not None
        and tuple((item.layer, item.role) for item in calls) == expected_calls
        and all(
            item.attempt_index == 0
            and item.result_kind == M6LockedModelCallResultKind.RESPONSE
            and item.parsed_output_ref is not None
            for item in calls
        )
        and not closure.embeddings
        and not closure.tool_results
        and len(cycles) == 1
        and cycles[0].cycle_index == 1
        and cycles[0].outcome == M6LockedRetrievalOutcomeKind.DEGRADED
        and cycles[0].authority_ref.kind == M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT
    )


def _classify_route(
    closure: M6ReplayInputClosureAuthority,
) -> M6ReplayLockedExecutionRoute:
    if _is_fast_terminal_closure(closure):
        return M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE
    if _is_m4_hearing_gate_terminal_closure(closure):
        return M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    _fail(M6ReplayLockedExecutionErrorCode.UNSUPPORTED_ROUTE)


def build_m6_replay_locked_pending_commitment(
    *,
    execution_scope: object,
    stored_source_catalog: object,
    ledger_sequence: object,
    previous_ledger_entry_hash: object,
) -> M6ReplayLockedPendingSampleCommitmentAuthority:
    """Derive one pre-materialization intent from the exact next blinded entry."""

    scope = _canonical(execution_scope, M6ReplayLockedExecutionScopeAuthority)
    stored = _controlled_catalog(stored_source_catalog)
    _require_scope_catalog(scope, stored)
    sequence = _require_sequence(ledger_sequence, len(scope.execution_dataset.entries))
    previous = _require_sha256(previous_ledger_entry_hash)
    source_entry = stored.source_catalog.entries[sequence]
    route = _classify_route(source_entry.replay_input_closure)
    if route not in scope.execution_component.supported_routes:
        _fail(M6ReplayLockedExecutionErrorCode.UNSUPPORTED_ROUTE)
    entry = scope.execution_dataset.entries[sequence]
    try:
        return M6ReplayLockedPendingSampleCommitmentAuthority(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            execution_component_authority_id=(scope.execution_component.component_authority_id),
            source_catalog_entry_id=source_entry.catalog_entry_id,
            route=route,
            execution_entry=entry,
            ledger_sequence=sequence,
            previous_ledger_entry_hash=previous,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedExecutionErrorCode.PENDING_REJECTED)


def _controlled_observation(value: object) -> M6ReplayLockedCandidateObservation:
    if type(value) is not M6ReplayLockedCandidateObservation:
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    try:
        return M6ReplayLockedCandidateObservation(
            case=value.case,
            canonical_document=value.canonical_document,
            case_revision=value.case_revision,
            case_audit_sequence=value.case_audit_sequence,
            case_audit_entry_hash=value.case_audit_entry_hash,
            candidate_snapshot=value.candidate_snapshot,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ReplayLockedExecutionErrorCode.CANDIDATE_OBSERVATION_REJECTED)


def build_m6_replay_locked_sample_record(
    *,
    execution_scope: object,
    stored_source_catalog: object,
    pending_commitment: object,
    source_determinism: object,
    candidate_observation: object,
) -> M6ReplayLockedSampleExecutionRecord:
    """Build a Record only from one durable Pending and freshly observed candidate state."""

    scope = _canonical(execution_scope, M6ReplayLockedExecutionScopeAuthority)
    stored = _controlled_catalog(stored_source_catalog)
    _require_scope_catalog(scope, stored)
    pending = _canonical(
        pending_commitment,
        M6ReplayLockedPendingSampleCommitmentAuthority,
    )
    proof = _canonical(
        source_determinism,
        M6ReplayLockedSourceDeterminismAuthority,
    )
    observation = _controlled_observation(candidate_observation)
    expected_pending = build_m6_replay_locked_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored,
        ledger_sequence=pending.ledger_sequence,
        previous_ledger_entry_hash=pending.previous_ledger_entry_hash,
    )
    if pending != expected_pending:
        _fail(M6ReplayLockedExecutionErrorCode.PENDING_REJECTED)
    case = observation.case
    if (
        case.run_id != scope.candidate_run_id
        or case.manifest_id != scope.locked_manifest.manifest_id
        or observation.candidate_snapshot.sample_id != pending.sample_id
    ):
        _fail(M6ReplayLockedExecutionErrorCode.CANDIDATE_OBSERVATION_REJECTED)
    case_payload = observation.canonical_document.encode("utf-8")
    candidate_case = M6ReplayLockedCandidateCaseBinding(
        candidate_run_id=scope.candidate_run_id,
        sample_id=pending.sample_id,
        case_id=case.case_id,
        case_revision=observation.case_revision,
        case_document_sha256=hashlib.sha256(case_payload).hexdigest(),
        case_document_size_bytes=len(case_payload),
        case_audit_sequence=observation.case_audit_sequence,
        case_audit_entry_hash=observation.case_audit_entry_hash,
    )
    source_entry = stored.source_catalog.entries[pending.ledger_sequence]
    try:
        return M6ReplayLockedSampleExecutionRecord(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            candidate_manifest_id=scope.locked_manifest.manifest_id,
            route=pending.route,
            execution_entry=pending.execution_entry,
            pending_commitment=pending,
            replay_input_closure=source_entry.replay_input_closure,
            source_determinism=proof,
            candidate_case=candidate_case,
            candidate_snapshot=observation.candidate_snapshot,
            ledger_sequence=pending.ledger_sequence,
            previous_ledger_entry_hash=pending.previous_ledger_entry_hash,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedExecutionErrorCode.RECORD_REJECTED)


def _controlled_audit_head(value: object) -> AuditHead:
    if type(value) is not AuditHead:
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    try:
        return AuditHead(
            run_id=value.run_id,
            manifest_id=value.manifest_id,
            run_revision=value.run_revision,
            sequence=value.sequence,
            entry_hash=value.entry_hash,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)


def build_m6_replay_locked_execution_seal(
    *,
    execution_scope: object,
    stored_source_catalog: object,
    sample_records: object,
    candidate_audit_head: object,
) -> M6ReplayLockedExecutionSealAuthority:
    """Seal receipts after all records; callers cannot supply a trap or counters."""

    scope = _canonical(execution_scope, M6ReplayLockedExecutionScopeAuthority)
    stored = _controlled_catalog(stored_source_catalog)
    _require_scope_catalog(scope, stored)
    if not isinstance(sample_records, tuple) or any(
        type(item) is not M6ReplayLockedSampleExecutionRecord for item in sample_records
    ):
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    try:
        records = tuple(
            M6ReplayLockedSampleExecutionRecord.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in sample_records
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT)
    head = _controlled_audit_head(candidate_audit_head)
    if (
        len(records) != len(scope.execution_dataset.entries)
        or head.run_id != scope.candidate_run_id
        or head.manifest_id != scope.locked_manifest.manifest_id
        or head.run_revision != len(records)
        or head.sequence != len(records) - 1
        or not records
        or head.entry_hash != records[-1].candidate_case.case_audit_entry_hash
    ):
        _fail(M6ReplayLockedExecutionErrorCode.AUDIT_HEAD_MISMATCH)
    inventory_root = sha256_hex(
        [
            "m6-replay-locked-sample-execution-inventory",
            1,
            [item.sample_execution_record_id for item in records],
        ]
    )
    trap = M6ReplayLockedRunTrapSealAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        command_id=scope.command.command_id,
        candidate_run_id=scope.candidate_run_id,
        execution_component_authority_id=(scope.execution_component.component_authority_id),
        counters=M6ProviderCapabilityCounters(),
        sealed_sample_execution_count=len(records),
        sealed_sample_execution_inventory_root_sha256=inventory_root,
        terminal_ledger_sequence=len(records) - 1,
        terminal_sample_execution_record_id=records[-1].sample_execution_record_id,
    )
    scope_sha256, scope_size = _identity(scope)
    try:
        return M6ReplayLockedExecutionSealAuthority(
            execution_scope=scope,
            execution_scope_content_sha256=scope_sha256,
            execution_scope_size_bytes=scope_size,
            candidate_audit_head_sequence=head.sequence,
            candidate_audit_head_hash=head.entry_hash,
            sample_executions=records,
            run_trap_seal=trap,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedExecutionErrorCode.SEAL_REJECTED)


__all__ = [
    "M6ReplayLockedExecutionError",
    "M6ReplayLockedExecutionErrorCode",
    "build_m6_replay_locked_execution_seal",
    "build_m6_replay_locked_pending_commitment",
    "build_m6_replay_locked_sample_record",
]
