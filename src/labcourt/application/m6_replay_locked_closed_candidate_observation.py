"""Rebuild one CLOSED replay observation from durable policy and Case bytes."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedCandidateBindingAuthority,
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedCandidateCaseBinding,
)
from labcourt.domain.m6_semantic_projection import (
    build_m6_closed_policy_case_replay_snapshot,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateError,
    M6ReplayLockedClosedCandidateFailureCode,
    M6ReplayLockedClosedCandidateObservation,
    M6ReplayLockedStoredClosedCandidate,
)

_FailureCode = M6ReplayLockedClosedCandidateFailureCode
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(code: _FailureCode) -> M6ReplayLockedClosedCandidateError:
    return M6ReplayLockedClosedCandidateError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


def _controlled_stored(value: object) -> M6ReplayLockedStoredClosedCandidate:
    if type(value) is not M6ReplayLockedStoredClosedCandidate:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return M6ReplayLockedStoredClosedCandidate(
            candidate_run_id=value.candidate_run_id,
            execution_scope_authority_id=value.execution_scope_authority_id,
            pre_policy_execution_scope_authority_id=(value.pre_policy_execution_scope_authority_id),
            ledger_sequence=value.ledger_sequence,
            sample_id=value.sample_id,
            execution_entry_id=value.execution_entry_id,
            source_catalog_entry_id=value.source_catalog_entry_id,
            pending_commitment_authority_id=(value.pending_commitment_authority_id),
            pre_policy_pending_commitment_authority_id=(
                value.pre_policy_pending_commitment_authority_id
            ),
            source_binding_authority_id=value.source_binding_authority_id,
            policy_causal_cut_authority_id=value.policy_causal_cut_authority_id,
            locked_config_sha256=value.locked_config_sha256,
            pre_policy_route=value.pre_policy_route,
            candidate_alert_policy=value.candidate_alert_policy,
            canonical_alert_policy_document=(value.canonical_alert_policy_document),
            candidate_alert_policy_document_sha256=(value.candidate_alert_policy_document_sha256),
            candidate_alert_policy_size_bytes=(value.candidate_alert_policy_size_bytes),
            closed_candidate_case=value.closed_candidate_case,
            canonical_closed_case_document=value.canonical_closed_case_document,
            closed_candidate_case_document_sha256=(value.closed_candidate_case_document_sha256),
            closed_candidate_case_size_bytes=(value.closed_candidate_case_size_bytes),
            case_audit_sequence=value.case_audit_sequence,
            case_audit_entry_hash=value.case_audit_entry_hash,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def _restore_transient_ready_case(
    policy: AlertPolicyAuthority,
    closed: Case,
) -> Case:
    decision = policy.decision
    alerts = closed.alerts
    if decision is not None:
        if not alerts or alerts[-1] != decision:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        alerts = alerts[:-1]
    if not closed.timeline:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return closed.model_copy(
            update={
                "status": CaseStatus.READY_FOR_ALERT_POLICY,
                "alerts": alerts,
                "final_decision": None,
                "timeline": closed.timeline[:-1],
            }
        )
    except (TypeError, ValueError, ValidationError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def build_m6_replay_locked_closed_candidate_observation(
    *,
    execution_scope: object,
    pending_commitment: object,
    stored_candidate: object,
    pre_policy_candidate_snapshot: object,
) -> M6ReplayLockedClosedCandidateObservation:
    """Recover the final observation without rerunning policy or trusting a snapshot."""

    scope = _canonical(
        execution_scope,
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    )
    pending = _canonical(
        pending_commitment,
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    )
    stored = _controlled_stored(stored_candidate)
    pre_policy_snapshot = _canonical(
        pre_policy_candidate_snapshot,
        M6CaseReplaySnapshot,
    )
    pre_pending = pending.pre_policy_pending_commitment
    if (
        pending.execution_scope_authority_id != scope.execution_scope_authority_id
        or stored.candidate_run_id != scope.candidate_run_id
        or stored.execution_scope_authority_id != scope.execution_scope_authority_id
        or stored.pre_policy_execution_scope_authority_id
        != scope.pre_policy_execution_scope_authority_id
        or stored.ledger_sequence != pending.ledger_sequence
        or stored.sample_id != pending.sample_id
        or stored.execution_entry_id != pending.execution_entry_id
        or stored.source_catalog_entry_id != pending.source_catalog_entry_id
        or stored.pending_commitment_authority_id != pending.pending_commitment_authority_id
        or stored.pre_policy_pending_commitment_authority_id
        != pre_pending.pending_commitment_authority_id
        or stored.source_binding_authority_id != pending.source_binding_authority_id
        or stored.policy_causal_cut_authority_id != pending.policy_causal_cut_authority_id
        or stored.locked_config_sha256 != pending.locked_config_sha256
        or stored.pre_policy_route != pending.pre_policy_route
        or stored.candidate_alert_policy.request.prior_cooldown
        != pending.source_binding.cooldown_causal_head.prior_authority
        or stored.candidate_alert_policy.request.prior_emergency_delivery is not None
    ):
        _fail(_FailureCode.CANDIDATE_CONFLICT)
    ready = _restore_transient_ready_case(
        stored.candidate_alert_policy,
        stored.closed_candidate_case,
    )
    persisted = M6ReplayLockedCandidateCaseBinding(
        candidate_run_id=stored.candidate_run_id,
        sample_id=stored.sample_id,
        case_id=stored.closed_candidate_case.case_id,
        case_revision=1,
        case_document_sha256=stored.closed_candidate_case_document_sha256,
        case_document_size_bytes=stored.closed_candidate_case_size_bytes,
        case_audit_sequence=stored.case_audit_sequence,
        case_audit_entry_hash=stored.case_audit_entry_hash,
    )
    try:
        binding = M6ReplayLockedClosedCandidateBindingAuthority(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            pending_commitment_authority_id=(pending.pending_commitment_authority_id),
            source_binding_authority_id=pending.source_binding_authority_id,
            policy_causal_cut_authority_id=pending.policy_causal_cut_authority_id,
            pre_policy_route=pending.pre_policy_route,
            locked_config_sha256=pending.locked_config_sha256,
            transient_ready_case=ready,
            candidate_alert_policy=stored.candidate_alert_policy,
            closed_candidate_case=stored.closed_candidate_case,
            persisted_candidate_case=persisted,
        )
        snapshot = build_m6_closed_policy_case_replay_snapshot(
            pre_policy_snapshot=pre_policy_snapshot,
            transient_ready_case=ready,
            candidate_alert_policy=stored.candidate_alert_policy,
            closed_candidate_case=stored.closed_candidate_case,
        )
        return M6ReplayLockedClosedCandidateObservation(
            closed_candidate_binding=binding,
            candidate_snapshot=snapshot,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


__all__ = ["build_m6_replay_locked_closed_candidate_observation"]
