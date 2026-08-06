"""Trusted start-cut builders for additive M6 CLOSED-policy replay."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_execution import (
    M6ReplayLockedExecutionError,
    build_m6_replay_locked_pending_commitment,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogEntry,
)
from labcourt.contracts.m6_replay_locked import (
    M6ProviderCapabilityCounters,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2,
    M6ReplayLockedClosedPolicySampleExecutionRecordV2,
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedAlertPolicyCausalCutAuthority,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateObservation,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedClosedPolicyExecutionErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_REJECTED = "SCOPE_REJECTED"
    SOURCE_CATALOG_MISMATCH = "SOURCE_CATALOG_MISMATCH"
    POLICY_CAUSAL_CUT_MISMATCH = "POLICY_CAUSAL_CUT_MISMATCH"
    PENDING_REJECTED = "PENDING_REJECTED"
    CANDIDATE_OBSERVATION_REJECTED = "CANDIDATE_OBSERVATION_REJECTED"
    RECORD_REJECTED = "RECORD_REJECTED"
    AUDIT_HEAD_MISMATCH = "AUDIT_HEAD_MISMATCH"
    SEAL_REJECTED = "SEAL_REJECTED"


class M6ReplayLockedClosedPolicyExecutionError(LabCourtError):
    """Payload-free failure from the trusted CLOSED-policy start builders."""

    def __init__(self, code: M6ReplayLockedClosedPolicyExecutionErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedClosedPolicyExecutionErrorCode):
            raise TypeError("code must be an M6 CLOSED-policy execution error code")
        self.code = code
        super().__init__(f"M6 CLOSED-policy execution construction failed: {code.value}")


def _fail(code: M6ReplayLockedClosedPolicyExecutionErrorCode) -> NoReturn:
    raise M6ReplayLockedClosedPolicyExecutionError(code) from None


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)
    return controlled


def _identity(value: BaseModel) -> tuple[str, int]:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _controlled_catalog(
    value: object,
) -> M6StoredRegressionExecutionSourceCatalog:
    if type(value) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)
    try:
        return M6StoredRegressionExecutionSourceCatalog(
            source_catalog=value.source_catalog,
            canonical_document=value.canonical_document,
            content_sha256=value.content_sha256,
            size_bytes=value.size_bytes,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)


def build_m6_replay_locked_closed_policy_execution_scope(
    *,
    pre_policy_execution_scope: object,
    execution_component: object,
) -> M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2:
    """Wrap one frozen V1 pre-policy scope without exposing evaluator truth."""

    pre_policy = _canonical(
        pre_policy_execution_scope,
        M6ReplayLockedExecutionScopeAuthority,
    )
    component = _canonical(
        execution_component,
        M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
    )
    pre_policy_sha, pre_policy_size = _identity(pre_policy)
    component_sha, component_size = _identity(component)
    try:
        return M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2(
            pre_policy_execution_scope=pre_policy,
            pre_policy_execution_scope_content_sha256=pre_policy_sha,
            pre_policy_execution_scope_size_bytes=pre_policy_size,
            execution_component=component,
            execution_component_content_sha256=component_sha,
            execution_component_size_bytes=component_size,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.SCOPE_REJECTED)


def build_m6_replay_locked_closed_policy_source_binding(
    *,
    pre_policy_pending_commitment: object,
    source_catalog_entry: object,
    policy_causal_cut: object,
) -> M6ReplayLockedClosedPolicySourceBindingAuthority:
    """Project a full evaluator cut into the exact candidate-safe binding."""

    pending = _canonical(
        pre_policy_pending_commitment,
        M6ReplayLockedPendingSampleCommitmentAuthority,
    )
    source = _canonical(
        source_catalog_entry,
        M6RegressionExecutionSourceCatalogEntry,
    )
    cut = _canonical(
        policy_causal_cut,
        M6ReplayLockedAlertPolicyCausalCutAuthority,
    )
    entry = pending.execution_entry
    closure = source.replay_input_closure
    entry_identity = (
        entry.sample_id,
        entry.input_authority_id,
        entry.input_authority_document_sha256,
        entry.replay_input_closure_authority_id,
        entry.replay_input_closure_document_sha256,
    )
    closure_identity = (
        closure.sample_id,
        closure.input_authority_id,
        closure.input_authority_document_sha256,
        closure.replay_input_closure_authority_id,
        closure.replay_input_closure_document_sha256,
    )
    if (
        source.catalog_entry_id != pending.source_catalog_entry_id
        or entry_identity != closure_identity
    ):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.SOURCE_CATALOG_MISMATCH)
    if (
        cut.sample_id != closure.sample_id
        or cut.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
        or cut.replay_input_closure_document_sha256 != closure.replay_input_closure_document_sha256
        or closure.source_case_id is None
        or closure.source_case_revision is None
        or closure.source_case_document_sha256 is None
        or cut.source_closed_case.run_id != closure.source_run_id
        or cut.source_closed_case.case_id != closure.source_case_id
        or cut.source_closed_case_revision != closure.source_case_revision
        or cut.source_closed_case_content_sha256 != closure.source_case_document_sha256
        or cut.source_closed_case.manifest_id != closure.source_manifest_id
        or cut.source_validation_report_id != closure.source_validation_report_id
        or cut.source_validation_report_document_sha256
        != closure.source_validation_report_document_sha256
    ):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.POLICY_CAUSAL_CUT_MISMATCH)
    cut_sha, cut_size = _identity(cut)
    try:
        return M6ReplayLockedClosedPolicySourceBindingAuthority(
            source_catalog_entry_id=source.catalog_entry_id,
            sample_id=entry.sample_id,
            execution_entry_id=entry.execution_entry_id,
            replay_input_closure_authority_id=(entry.replay_input_closure_authority_id),
            replay_input_closure_document_sha256=(entry.replay_input_closure_document_sha256),
            pre_policy_route=pending.route,
            source_config_sha256=cut.source_config_sha256,
            policy_causal_cut_authority_id=cut.policy_causal_cut_authority_id,
            policy_causal_cut_content_sha256=cut_sha,
            policy_causal_cut_size_bytes=cut_size,
            cooldown_causal_head=cut.cooldown_causal_head,
            emergency_causal_basis=cut.emergency_causal_basis,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.POLICY_CAUSAL_CUT_MISMATCH)


def build_m6_replay_locked_closed_policy_pending_commitment(
    *,
    execution_scope: object,
    stored_source_catalog: object,
    policy_causal_cut: object,
    ledger_sequence: object,
    previous_ledger_entry_hash: object,
) -> M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2:
    """Freeze the exact source cut before any CLOSED candidate is executed."""

    scope = _canonical(
        execution_scope,
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    )
    stored = _controlled_catalog(stored_source_catalog)
    try:
        pre_policy_pending = build_m6_replay_locked_pending_commitment(
            execution_scope=scope.pre_policy_execution_scope,
            stored_source_catalog=stored,
            ledger_sequence=ledger_sequence,
            previous_ledger_entry_hash=previous_ledger_entry_hash,
        )
    except M6ReplayLockedExecutionError:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.PENDING_REJECTED)
    source_entries = stored.source_catalog.entries
    if pre_policy_pending.ledger_sequence >= len(source_entries):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.SOURCE_CATALOG_MISMATCH)
    binding = build_m6_replay_locked_closed_policy_source_binding(
        pre_policy_pending_commitment=pre_policy_pending,
        source_catalog_entry=source_entries[pre_policy_pending.ledger_sequence],
        policy_causal_cut=policy_causal_cut,
    )
    if binding.source_config_sha256 != scope.locked_config_sha256:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.POLICY_CAUSAL_CUT_MISMATCH)
    try:
        return M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            execution_component_authority_id=(scope.execution_component.component_authority_id),
            locked_config_sha256=scope.locked_config_sha256,
            pre_policy_pending_commitment=pre_policy_pending,
            source_binding=binding,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.PENDING_REJECTED)


def _controlled_observation(
    value: object,
) -> M6ReplayLockedClosedCandidateObservation:
    if type(value) is not M6ReplayLockedClosedCandidateObservation:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.CANDIDATE_OBSERVATION_REJECTED)
    try:
        return M6ReplayLockedClosedCandidateObservation(
            closed_candidate_binding=value.closed_candidate_binding,
            candidate_snapshot=value.candidate_snapshot,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.CANDIDATE_OBSERVATION_REJECTED)


def build_m6_replay_locked_closed_policy_sample_record(
    *,
    execution_scope: object,
    stored_source_catalog: object,
    pending_commitment: object,
    source_determinism: object,
    policy_causal_cut: object,
    candidate_observation: object,
) -> M6ReplayLockedClosedPolicySampleExecutionRecordV2:
    """Join the evaluator-only cut only after the CLOSED candidate is durable."""

    scope = _canonical(
        execution_scope,
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    )
    stored = _controlled_catalog(stored_source_catalog)
    pending = _canonical(
        pending_commitment,
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    )
    proof = _canonical(
        source_determinism,
        M6ReplayLockedSourceDeterminismAuthority,
    )
    cut = _canonical(
        policy_causal_cut,
        M6ReplayLockedAlertPolicyCausalCutAuthority,
    )
    observation = _controlled_observation(candidate_observation)
    expected_pending = build_m6_replay_locked_closed_policy_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored,
        policy_causal_cut=cut,
        ledger_sequence=pending.ledger_sequence,
        previous_ledger_entry_hash=pending.previous_ledger_entry_hash,
    )
    if pending != expected_pending:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.PENDING_REJECTED)
    source_entries = stored.source_catalog.entries
    if pending.ledger_sequence >= len(source_entries):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.SOURCE_CATALOG_MISMATCH)
    source = source_entries[pending.ledger_sequence]
    try:
        return M6ReplayLockedClosedPolicySampleExecutionRecordV2(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command_id,
            execution_dataset_snapshot_id=scope.execution_dataset_snapshot_id,
            candidate_manifest_id=scope.candidate_manifest_id,
            execution_entry=pending.pre_policy_pending_commitment.execution_entry,
            pending_commitment=pending,
            replay_input_closure=source.replay_input_closure,
            source_determinism=proof,
            policy_causal_cut=cut,
            closed_candidate_binding=observation.closed_candidate_binding,
            candidate_snapshot=observation.candidate_snapshot,
            ledger_sequence=pending.ledger_sequence,
            previous_ledger_entry_hash=pending.previous_ledger_entry_hash,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.RECORD_REJECTED)


def _controlled_audit_head(value: object) -> AuditHead:
    if type(value) is not AuditHead:
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)
    try:
        return AuditHead(
            run_id=value.run_id,
            manifest_id=value.manifest_id,
            run_revision=value.run_revision,
            sequence=value.sequence,
            entry_hash=value.entry_hash,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)


def build_m6_replay_locked_closed_policy_execution_seal(
    *,
    execution_scope: object,
    sample_records: object,
    candidate_audit_head: object,
) -> M6ReplayLockedClosedPolicyExecutionSealAuthorityV2:
    """Seal the complete record chain with derived zero-capability counters."""

    scope = _canonical(
        execution_scope,
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    )
    if not isinstance(sample_records, tuple) or any(
        type(item) is not M6ReplayLockedClosedPolicySampleExecutionRecordV2
        for item in sample_records
    ):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)
    try:
        records = tuple(
            M6ReplayLockedClosedPolicySampleExecutionRecordV2.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in sample_records
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT)
    head = _controlled_audit_head(candidate_audit_head)
    if (
        not records
        or len(records) != len(scope.pre_policy_execution_scope.execution_dataset.entries)
        or head.run_id != scope.candidate_run_id
        or head.manifest_id != scope.candidate_manifest_id
        or head.run_revision != len(records)
        or head.sequence != len(records) - 1
        or head.entry_hash
        != records[-1].closed_candidate_binding.persisted_candidate_case.case_audit_entry_hash
    ):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.AUDIT_HEAD_MISMATCH)
    inventory_root = sha256_hex(
        [
            "m6-replay-locked-closed-policy-sample-execution-inventory",
            2,
            [item.sample_execution_record_id for item in records],
        ]
    )
    trap = M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        command_id=scope.command_id,
        candidate_run_id=scope.candidate_run_id,
        execution_component_authority_id=(scope.execution_component.component_authority_id),
        counters=M6ProviderCapabilityCounters(),
        sealed_sample_execution_count=len(records),
        sealed_sample_execution_inventory_root_sha256=inventory_root,
        terminal_ledger_sequence=len(records) - 1,
        terminal_sample_execution_record_id=records[-1].sample_execution_record_id,
    )
    scope_sha, scope_size = _identity(scope)
    try:
        return M6ReplayLockedClosedPolicyExecutionSealAuthorityV2(
            execution_scope=scope,
            execution_scope_content_sha256=scope_sha,
            execution_scope_size_bytes=scope_size,
            candidate_audit_head_sequence=head.sequence,
            candidate_audit_head_hash=head.entry_hash,
            sample_executions=records,
            run_trap_seal=trap,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedClosedPolicyExecutionErrorCode.SEAL_REJECTED)


__all__ = [
    "M6ReplayLockedClosedPolicyExecutionError",
    "M6ReplayLockedClosedPolicyExecutionErrorCode",
    "build_m6_replay_locked_closed_policy_execution_scope",
    "build_m6_replay_locked_closed_policy_execution_seal",
    "build_m6_replay_locked_closed_policy_pending_commitment",
    "build_m6_replay_locked_closed_policy_sample_record",
    "build_m6_replay_locked_closed_policy_source_binding",
]
