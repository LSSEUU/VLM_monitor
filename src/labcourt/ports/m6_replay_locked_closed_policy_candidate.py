"""Atomic CLOSED candidate boundary for additive M6 policy replay."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from labcourt.contracts.alert_policy import AlertPolicyAuthority
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import AuditAction, CaseStatus
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedCandidateBindingAuthority,
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    M6ReplayLockedExecutionRoute,
)
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import AuditHead


class M6ReplayLockedClosedCandidateFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NOT_FOUND = "NOT_FOUND"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    CANDIDATE_CONFLICT = "CANDIDATE_CONFLICT"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6ReplayLockedClosedCandidateError(ContractViolation):
    """Payload-free failure at the CLOSED candidate persistence boundary."""

    def __init__(self, reason_code: M6ReplayLockedClosedCandidateFailureCode) -> None:
        if not isinstance(reason_code, M6ReplayLockedClosedCandidateFailureCode):
            raise TypeError("reason_code must be an M6 CLOSED candidate failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 CLOSED candidate persistence failed: {reason_code.value}")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_case(value: Case) -> Case:
    return Case.model_validate(value.model_dump(mode="json", exclude_computed_fields=True))


def _canonical_policy(value: AlertPolicyAuthority) -> AlertPolicyAuthority:
    return AlertPolicyAuthority.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )


def _expected_closed_case(ready: Case, policy: AlertPolicyAuthority) -> Case:
    decision = policy.decision
    alert_id = decision.alert_id if decision is not None else "NONE"
    object_ref = decision.alert_id if decision is not None else ready.case_id
    alerts = ready.alerts if decision is None else (*ready.alerts, decision)
    return ready.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": alerts,
            "final_decision": policy.final_decision,
            "timeline": (
                *ready.timeline,
                TimelineEntry(
                    sequence=len(ready.timeline),
                    action=AuditAction.CASE_CLOSED.value,
                    stage="ALERT_POLICY",
                    object_ref=object_ref,
                    details={
                        "alert_id": alert_id,
                        "disposition": policy.disposition.value,
                        "status": CaseStatus.CLOSED.value,
                    },
                ),
            ),
        }
    )


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedCandidateWrite:
    """Validated in-memory READY -> policy -> CLOSED unit.

    Only the policy and final CLOSED documents are eligible for persistence;
    the transient READY Case is used for validation and is never a stored body.
    """

    transient_ready_case: Case
    candidate_alert_policy: AlertPolicyAuthority
    closed_candidate_case: Case
    canonical_alert_policy_document: str
    canonical_closed_case_document: str

    def __post_init__(self) -> None:
        if (
            type(self.transient_ready_case) is not Case
            or type(self.candidate_alert_policy) is not AlertPolicyAuthority
            or type(self.closed_candidate_case) is not Case
        ):
            raise TypeError("M6 CLOSED candidate write requires exact contract types")
        try:
            ready = _canonical_case(self.transient_ready_case)
            policy = _canonical_policy(self.candidate_alert_policy)
            closed = _canonical_case(self.closed_candidate_case)
            policy_payload = self.canonical_alert_policy_document.encode("utf-8", errors="strict")
            closed_payload = self.canonical_closed_case_document.encode("utf-8", errors="strict")
        except (AttributeError, TypeError, ValueError, UnicodeError, ValidationError):
            raise ValueError("M6 CLOSED candidate write is not canonical") from None
        if (
            ready != self.transient_ready_case
            or policy != self.candidate_alert_policy
            or closed != self.closed_candidate_case
            or ready.status != CaseStatus.READY_FOR_ALERT_POLICY
            or _expected_closed_case(ready, policy) != closed
            or policy.request.run_id != ready.run_id
            or policy.request.case_id != ready.case_id
            or policy.request.manifest_id != ready.manifest_id
            or canonical_json(policy.model_dump(mode="json"))
            != self.canonical_alert_policy_document
            or canonical_json(closed.model_dump(mode="json")) != self.canonical_closed_case_document
            or not policy_payload
            or not closed_payload
            or len(policy_payload) + len(closed_payload)
            > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
        ):
            raise ValueError("M6 CLOSED candidate write bindings differ")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedStoredClosedCandidate:
    """Canonical durable policy and final CLOSED Case, with no READY body."""

    candidate_run_id: str
    execution_scope_authority_id: str
    pre_policy_execution_scope_authority_id: str
    ledger_sequence: int
    sample_id: str
    execution_entry_id: str
    source_catalog_entry_id: str
    pending_commitment_authority_id: str
    pre_policy_pending_commitment_authority_id: str
    source_binding_authority_id: str
    policy_causal_cut_authority_id: str
    locked_config_sha256: str
    pre_policy_route: M6ReplayLockedExecutionRoute
    candidate_alert_policy: AlertPolicyAuthority
    canonical_alert_policy_document: str
    candidate_alert_policy_document_sha256: str
    candidate_alert_policy_size_bytes: int
    closed_candidate_case: Case
    canonical_closed_case_document: str
    closed_candidate_case_document_sha256: str
    closed_candidate_case_size_bytes: int
    case_audit_sequence: int
    case_audit_entry_hash: str

    def __post_init__(self) -> None:
        if (
            type(self.pre_policy_route) is not M6ReplayLockedExecutionRoute
            or type(self.candidate_alert_policy) is not AlertPolicyAuthority
            or type(self.closed_candidate_case) is not Case
        ):
            raise TypeError("M6 stored CLOSED candidate requires exact contract types")
        try:
            run_id = require_portable_run_id(
                self.candidate_run_id,
                "M6 stored CLOSED candidate run_id",
            )
            sample_id = require_reference_token(
                self.sample_id,
                "M6 stored CLOSED candidate sample_id",
            )
            policy = _canonical_policy(self.candidate_alert_policy)
            closed = _canonical_case(self.closed_candidate_case)
            policy_payload = self.canonical_alert_policy_document.encode("utf-8", errors="strict")
            closed_payload = self.canonical_closed_case_document.encode("utf-8", errors="strict")
        except (AttributeError, TypeError, ValueError, UnicodeError, ValidationError):
            raise ValueError("M6 stored CLOSED candidate is not canonical") from None
        if (
            run_id != self.candidate_run_id
            or sample_id != self.sample_id
            or policy != self.candidate_alert_policy
            or closed != self.closed_candidate_case
            or closed.status != CaseStatus.CLOSED
            or closed.run_id != self.candidate_run_id
            or policy.request.run_id != self.candidate_run_id
            or policy.request.case_id != closed.case_id
            or policy.request.manifest_id != closed.manifest_id
            or policy.request.config_sha256 != self.locked_config_sha256
            or canonical_json(policy.model_dump(mode="json"))
            != self.canonical_alert_policy_document
            or canonical_json(closed.model_dump(mode="json")) != self.canonical_closed_case_document
            or hashlib.sha256(policy_payload).hexdigest()
            != self.candidate_alert_policy_document_sha256
            or len(policy_payload) != self.candidate_alert_policy_size_bytes
            or hashlib.sha256(closed_payload).hexdigest()
            != self.closed_candidate_case_document_sha256
            or len(closed_payload) != self.closed_candidate_case_size_bytes
            or len(policy_payload) + len(closed_payload)
            > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            or not isinstance(self.ledger_sequence, int)
            or isinstance(self.ledger_sequence, bool)
            or self.ledger_sequence < 0
            or self.case_audit_sequence != self.ledger_sequence
            or any(
                not _is_sha256(value)
                for value in (
                    self.execution_scope_authority_id,
                    self.pre_policy_execution_scope_authority_id,
                    self.execution_entry_id,
                    self.source_catalog_entry_id,
                    self.pending_commitment_authority_id,
                    self.pre_policy_pending_commitment_authority_id,
                    self.source_binding_authority_id,
                    self.policy_causal_cut_authority_id,
                    self.locked_config_sha256,
                    self.candidate_alert_policy_document_sha256,
                    self.closed_candidate_case_document_sha256,
                    self.case_audit_entry_hash,
                )
            )
        ):
            raise ValueError("M6 stored CLOSED candidate bindings differ")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedCandidateObservation:
    """Trusted reconstruction of one persisted CLOSED candidate output."""

    closed_candidate_binding: M6ReplayLockedClosedCandidateBindingAuthority
    candidate_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if (
            type(self.closed_candidate_binding) is not M6ReplayLockedClosedCandidateBindingAuthority
            or type(self.candidate_snapshot) is not M6CaseReplaySnapshot
        ):
            raise TypeError("M6 CLOSED candidate observation requires exact authorities")
        try:
            binding = M6ReplayLockedClosedCandidateBindingAuthority.model_validate(
                self.closed_candidate_binding.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            snapshot = M6CaseReplaySnapshot.model_validate(
                self.candidate_snapshot.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 CLOSED candidate observation is not canonical") from None
        persisted = binding.persisted_candidate_case
        if (
            binding != self.closed_candidate_binding
            or snapshot != self.candidate_snapshot
            or snapshot.sample_id != binding.sample_id
            or snapshot.source_run_id != binding.candidate_run_id
            or snapshot.source_case_id != binding.case_id
            or snapshot.source_case_revision != persisted.case_revision
            or snapshot.source_case_document_sha256 != persisted.case_document_sha256
            or snapshot.manifest_id != binding.closed_candidate_case.manifest_id
            or snapshot.case_status != CaseStatus.CLOSED
        ):
            raise ValueError("M6 CLOSED candidate observation bindings differ")


@runtime_checkable
class M6ReplayLockedClosedCandidatePublisher(Protocol):
    def publish_closed_candidate(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        candidate: M6ReplayLockedClosedCandidateWrite,
    ) -> None: ...


@runtime_checkable
class M6ReplayLockedStoredClosedCandidateProvider(Protocol):
    def load_stored_closed_candidate(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedStoredClosedCandidate: ...


@runtime_checkable
class M6ReplayLockedClosedCandidateObservationProvider(Protocol):
    def load_closed_candidate_observation(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedClosedCandidateObservation: ...


@runtime_checkable
class M6ReplayLockedClosedCandidateAuditHeadProvider(Protocol):
    def load_closed_candidate_audit_head(
        self,
        candidate_run_id: str,
    ) -> AuditHead: ...


__all__ = [
    "M6ReplayLockedClosedCandidateAuditHeadProvider",
    "M6ReplayLockedClosedCandidateError",
    "M6ReplayLockedClosedCandidateFailureCode",
    "M6ReplayLockedClosedCandidateObservation",
    "M6ReplayLockedClosedCandidateObservationProvider",
    "M6ReplayLockedClosedCandidatePublisher",
    "M6ReplayLockedClosedCandidateWrite",
    "M6ReplayLockedStoredClosedCandidate",
    "M6ReplayLockedStoredClosedCandidateProvider",
]
