"""Trusted candidate-state observation boundary for M6 locked replay."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, UsageSummary
from labcourt.contracts.enums import CaseStatus, ScreeningDecision
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import AuditHead


class M6ReplayLockedCandidateFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NOT_FOUND = "NOT_FOUND"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    CANDIDATE_CONFLICT = "CANDIDATE_CONFLICT"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6ReplayLockedCandidateError(ContractViolation):
    """Payload-free candidate-state observation failure."""

    def __init__(self, reason_code: M6ReplayLockedCandidateFailureCode) -> None:
        if not isinstance(reason_code, M6ReplayLockedCandidateFailureCode):
            raise TypeError("reason_code must be an M6 locked candidate failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 locked candidate observation failed: {reason_code.value}")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_fast_terminal_case(case: Case) -> bool:
    if (
        len(case.evidence_packs) != 1
        or len(case.screening_results) != 1
        or len(case.verdicts) != 1
        or len(case.procedural_reviews) != 1
        or case.alerts
        or case.appeals
        or case.final_decision is not None
        or case.current_backlog_item_id is not None
        or case.timeline
        or case.usage != UsageSummary()
    ):
        return False
    pack = case.evidence_packs[0]
    screening = case.screening_results[0]
    verdict = case.verdicts[0]
    review = case.procedural_reviews[0]
    expected_status = (
        CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
    )
    return (
        case.status == expected_status
        and pack.version == 1
        and not pack.tool_results
        and screening.decision != ScreeningDecision.ESCALATE
        and screening.evidence_pack_id == pack.pack_id
        and verdict.screening_id == screening.screening_id
        and verdict.evidence_pack_id == pack.pack_id
        and review.reviewed_verdict_id == verdict.verdict_id
        and review.evidence_pack_id == pack.pack_id
    )


def _is_m4_hearing_gate_terminal_case(case: Case) -> bool:
    if (
        len(case.evidence_packs) != 1
        or len(case.screening_results) != 1
        or len(case.verdicts) != 1
        or len(case.procedural_reviews) != 1
        or case.alerts
        or case.appeals
        or case.final_decision is not None
        or case.current_backlog_item_id is not None
        or case.timeline
        or case.usage != UsageSummary()
    ):
        return False
    pack = case.evidence_packs[0]
    screening = case.screening_results[0]
    verdict = case.verdicts[0]
    review = case.procedural_reviews[0]
    expected_status = (
        CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
    )
    return (
        case.status == expected_status
        and pack.version == 1
        and not pack.tool_results
        and screening.decision == ScreeningDecision.ESCALATE
        and screening.evidence_pack_id == pack.pack_id
        and screening.evidence_pack_version == pack.version
        and verdict.screening_id == screening.screening_id
        and verdict.evidence_pack_id == pack.pack_id
        and verdict.evidence_pack_version == pack.version
        and review.reviewed_verdict_id == verdict.verdict_id
        and review.reviewed_verdict_version == verdict.version
        and review.reviewed_verdict_sha256 == verdict.verdict_sha256
        and review.evidence_pack_id == pack.pack_id
        and review.evidence_pack_version == pack.version
    )


def _matches_route_case_shape(
    route: M6ReplayLockedExecutionRoute,
    case: Case,
) -> bool:
    if route == M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE:
        return _is_fast_terminal_case(case)
    if route == M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
        return _is_m4_hearing_gate_terminal_case(case)
    return False


@dataclass(frozen=True, slots=True)
class M6ReplayLockedCandidateWrite:
    """Canonical candidate bytes accepted by the isolated persistence boundary.

    A replay snapshot is deliberately absent: it is neither persisted nor trusted
    for idempotency and is rebuilt independently by the observation service.
    """

    case: Case
    canonical_document: str

    def __post_init__(self) -> None:
        if type(self.case) is not Case:
            raise TypeError("M6 locked candidate write requires an exact Case")
        try:
            case = Case.model_validate(
                self.case.model_dump(mode="json", exclude_computed_fields=True)
            )
            payload = self.canonical_document.encode("utf-8", errors="strict")
        except (AttributeError, TypeError, ValueError, UnicodeError, ValidationError):
            raise ValueError("M6 locked candidate write is not canonical") from None
        if (
            case != self.case
            or not payload
            or len(payload) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            or canonical_json(case.model_dump(mode="json")) != self.canonical_document
            or not _is_fast_terminal_case(case)
        ):
            raise ValueError("M6 locked candidate write bindings differ")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedM4CandidateWrite:
    """Canonical atomic M4 hearing-plus-Gate candidate persistence input."""

    case: Case
    canonical_document: str

    def __post_init__(self) -> None:
        if type(self.case) is not Case:
            raise TypeError("M6 locked M4 candidate write requires an exact Case")
        try:
            case = Case.model_validate(
                self.case.model_dump(mode="json", exclude_computed_fields=True)
            )
            payload = self.canonical_document.encode("utf-8", errors="strict")
        except (AttributeError, TypeError, ValueError, UnicodeError, ValidationError):
            raise ValueError("M6 locked M4 candidate write is not canonical") from None
        if (
            case != self.case
            or not payload
            or len(payload) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            or canonical_json(case.model_dump(mode="json")) != self.canonical_document
            or not _is_m4_hearing_gate_terminal_case(case)
        ):
            raise ValueError("M6 locked M4 candidate write bindings differ")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedCandidateObservation:
    """One canonical persisted candidate Case and its independently rebuilt snapshot."""

    case: Case
    canonical_document: str
    case_revision: int
    case_audit_sequence: int
    case_audit_entry_hash: str
    candidate_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if type(self.case) is not Case or type(self.candidate_snapshot) is not M6CaseReplaySnapshot:
            raise TypeError("M6 locked candidate observation requires exact contract types")
        if (
            not isinstance(self.canonical_document, str)
            or not self.canonical_document
            or not isinstance(self.case_revision, int)
            or isinstance(self.case_revision, bool)
            or self.case_revision != 1
            or not isinstance(self.case_audit_sequence, int)
            or isinstance(self.case_audit_sequence, bool)
            or self.case_audit_sequence < 0
            or not _is_sha256(self.case_audit_entry_hash)
        ):
            raise ValueError("M6 locked candidate observation metadata is invalid")
        try:
            case = Case.model_validate(
                self.case.model_dump(mode="json", exclude_computed_fields=True)
            )
            snapshot = M6CaseReplaySnapshot.model_validate(
                self.candidate_snapshot.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            payload = self.canonical_document.encode("utf-8", errors="strict")
        except (AttributeError, TypeError, ValueError, UnicodeError, ValidationError):
            raise ValueError("M6 locked candidate observation is not canonical") from None
        document_sha256 = hashlib.sha256(payload).hexdigest()
        if (
            case != self.case
            or snapshot != self.candidate_snapshot
            or len(payload) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            or canonical_json(case.model_dump(mode="json")) != self.canonical_document
            or snapshot.source_run_id != case.run_id
            or snapshot.source_case_id != case.case_id
            or snapshot.source_case_revision != self.case_revision
            or snapshot.source_case_document_sha256 != document_sha256
            or snapshot.manifest_id != case.manifest_id
            or snapshot.case_status != case.status
        ):
            raise ValueError("M6 locked candidate observation bindings differ")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedStoredCandidateCase:
    """Canonical persisted Case metadata, intentionally excluding any snapshot claim."""

    candidate_run_id: str
    execution_scope_authority_id: str
    ledger_sequence: int
    sample_id: str
    execution_entry_id: str
    source_catalog_entry_id: str
    pending_commitment_authority_id: str
    route: M6ReplayLockedExecutionRoute
    case: Case
    canonical_document: str
    case_document_sha256: str
    case_document_size_bytes: int
    case_audit_sequence: int
    case_audit_entry_hash: str

    def __post_init__(self) -> None:
        if type(self.case) is not Case or type(self.route) is not M6ReplayLockedExecutionRoute:
            raise TypeError("M6 locked stored candidate requires exact contract types")
        try:
            run_id = require_portable_run_id(
                self.candidate_run_id,
                "M6 locked stored candidate run_id",
            )
            sample_id = require_reference_token(
                self.sample_id,
                "M6 locked stored candidate sample_id",
            )
            case = Case.model_validate(
                self.case.model_dump(mode="json", exclude_computed_fields=True)
            )
            payload = self.canonical_document.encode("utf-8", errors="strict")
        except (AttributeError, TypeError, ValueError, UnicodeError, ValidationError):
            raise ValueError("M6 locked stored candidate is not canonical") from None
        document_sha256 = hashlib.sha256(payload).hexdigest()
        if (
            case != self.case
            or run_id != self.candidate_run_id
            or sample_id != self.sample_id
            or not payload
            or len(payload) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES
            or canonical_json(case.model_dump(mode="json")) != self.canonical_document
            or self.case_document_sha256 != document_sha256
            or self.case_document_size_bytes != len(payload)
            or not isinstance(self.ledger_sequence, int)
            or isinstance(self.ledger_sequence, bool)
            or self.ledger_sequence < 0
            or self.case_audit_sequence != self.ledger_sequence
            or case.run_id != self.candidate_run_id
            or not _matches_route_case_shape(self.route, case)
            or any(
                not _is_sha256(value)
                for value in (
                    self.execution_scope_authority_id,
                    self.execution_entry_id,
                    self.source_catalog_entry_id,
                    self.pending_commitment_authority_id,
                    self.case_audit_entry_hash,
                )
            )
        ):
            raise ValueError("M6 locked stored candidate bindings differ")


@runtime_checkable
class M6ReplayLockedCandidateObservationProvider(Protocol):
    def load_candidate_observation(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedCandidateObservation: ...


@runtime_checkable
class M6ReplayLockedStoredCandidateProvider(Protocol):
    def load_stored_candidate_case(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedStoredCandidateCase: ...


@runtime_checkable
class M6ReplayLockedCandidatePublisher(Protocol):
    def publish_candidate(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        candidate: M6ReplayLockedCandidateWrite,
    ) -> None: ...


@runtime_checkable
class M6ReplayLockedM4CandidatePublisher(Protocol):
    def publish_m4_candidate(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        candidate: M6ReplayLockedM4CandidateWrite,
    ) -> None: ...


@runtime_checkable
class M6ReplayLockedCandidateAuditHeadProvider(Protocol):
    def load_candidate_audit_head(
        self,
        candidate_run_id: str,
    ) -> AuditHead: ...


__all__ = [
    "M6ReplayLockedCandidateAuditHeadProvider",
    "M6ReplayLockedCandidateError",
    "M6ReplayLockedCandidateFailureCode",
    "M6ReplayLockedCandidateObservation",
    "M6ReplayLockedCandidateObservationProvider",
    "M6ReplayLockedCandidatePublisher",
    "M6ReplayLockedCandidateWrite",
    "M6ReplayLockedM4CandidatePublisher",
    "M6ReplayLockedM4CandidateWrite",
    "M6ReplayLockedStoredCandidateCase",
    "M6ReplayLockedStoredCandidateProvider",
]
