"""Typed persistence boundary for the append-only M4 hearing authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import AcquisitionExecutionMode
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import Crop, CropRequest, EvidencePack
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    HearingCheckpoint,
    HearingCycleScope,
    HearingHumanReviewReceipt,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRecord,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingUsageReceipt,
    HearingVerdictBinding,
    ToolExecutionReceipt,
)
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.evidence_authority import EvidenceAuthority
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot


class HearingPersistenceConflict(ContractViolation):
    """An immutable M4 identity was replayed with different canonical bytes."""


class HearingModelCallClaimStatus(StrEnum):
    """Observable state of one durable M4 request-level claim."""

    ACQUIRED = "ACQUIRED"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    EXPIRED_REQUIRES_RECOVERY = "EXPIRED_REQUIRES_RECOVERY"


class AcquisitionExecutionClaimStatus(StrEnum):
    """Observable state of one durable acquisition execution fence."""

    ACQUIRED = "ACQUIRED"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    EXPIRED_REQUIRES_RECOVERY = "EXPIRED_REQUIRES_RECOVERY"
    ABANDONED = "ABANDONED"


@dataclass(frozen=True, slots=True)
class AcquisitionExecutionClaim:
    """Secret-free claim state for one request-id idempotency boundary."""

    status: AcquisitionExecutionClaimStatus
    request_id: str
    execution_mode: AcquisitionExecutionMode
    idempotency_key: str
    owner_fence: int
    lease_expires_at: datetime | None = None
    publication_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, AcquisitionExecutionClaimStatus):
            raise TypeError("status must be an AcquisitionExecutionClaimStatus")
        if not isinstance(self.execution_mode, AcquisitionExecutionMode):
            raise TypeError("execution_mode must be an AcquisitionExecutionMode")
        if self.idempotency_key != self.request_id:
            raise ValueError("acquisition claim idempotency key must equal request ID")
        if (
            not isinstance(self.owner_fence, int)
            or isinstance(self.owner_fence, bool)
            or self.owner_fence <= 0
        ):
            raise ValueError("acquisition claim owner fence must be positive")
        if self.status in {
            AcquisitionExecutionClaimStatus.ACQUIRED,
            AcquisitionExecutionClaimStatus.WAITING,
            AcquisitionExecutionClaimStatus.EXPIRED_REQUIRES_RECOVERY,
        }:
            if self.lease_expires_at is None or self.publication_id is not None:
                raise ValueError("active acquisition claim has invalid closure fields")
            if (
                self.lease_expires_at.tzinfo is None
                or self.lease_expires_at.utcoffset() is None
                or self.lease_expires_at.utcoffset() != timedelta(0)
            ):
                raise ValueError("acquisition claim expiry must use timezone-aware UTC")
            return
        if self.lease_expires_at is not None:
            raise ValueError("closed acquisition claim cannot retain a lease")
        if self.status == AcquisitionExecutionClaimStatus.COMPLETED:
            if self.publication_id is None:
                raise ValueError("completed acquisition claim requires publication")
        elif self.publication_id is not None:
            raise ValueError("abandoned acquisition claim cannot carry publication")


@dataclass(frozen=True, slots=True)
class HearingModelCallClaim:
    """Minimum non-secret state exposed by an M4 singleflight claim."""

    status: HearingModelCallClaimStatus
    request_id: str
    lease_expires_at: datetime | None = None
    response_id: str | None = None
    takeover_count: int = 0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.takeover_count, int)
            or isinstance(self.takeover_count, bool)
            or self.takeover_count < 0
        ):
            raise ValueError("hearing model claim takeover_count must be non-negative")
        if self.status == HearingModelCallClaimStatus.COMPLETED:
            if self.response_id is None or self.lease_expires_at is not None:
                raise ValueError("completed hearing model claim has invalid fields")
            return
        expiry = self.lease_expires_at
        if self.response_id is not None or expiry is None:
            raise ValueError("active hearing model claim has invalid fields")
        if (
            expiry.tzinfo is None
            or expiry.utcoffset() is None
            or expiry.utcoffset() != timedelta(0)
        ):
            raise ValueError("hearing model claim expiry must use timezone-aware UTC")


@dataclass(frozen=True, slots=True)
class AcquisitionOutputBundle:
    """Exact typed objects materialized by one bounded acquisition execution."""

    frames: tuple[FrameRef, ...] = ()
    crops: tuple[Crop, ...] = ()
    objective_facts: tuple[ObjectiveFact, ...] = ()
    detections: tuple[Detection, ...] = ()
    crop_request: CropRequest | None = None


@dataclass(frozen=True, slots=True)
class AcquisitionPublishResult:
    """Atomic successor publication plus its durable tool receipt."""

    case: CaseSnapshot
    pack: EvidencePack
    receipt: ToolExecutionReceipt
    created: bool


@dataclass(frozen=True, slots=True)
class AcquisitionExecutionCommit:
    """Durable pre-pack execution publication and idempotent replay flag."""

    publication: AcquisitionExecutionPublication
    created: bool

    def __post_init__(self) -> None:
        if not isinstance(self.publication, AcquisitionExecutionPublication):
            raise TypeError("publication must be an AcquisitionExecutionPublication")
        if not isinstance(self.created, bool):
            raise TypeError("created must be a bool")


@dataclass(frozen=True, slots=True)
class HearingStartResult:
    """Atomic Case transition plus the exact immutable hearing roots."""

    case: CaseSnapshot
    session: HearingSession
    cycle: HearingCycleScope
    checkpoint: HearingCheckpoint
    created: bool


@dataclass(frozen=True, slots=True)
class HearingVerdictReviewResult:
    """Atomic terminal proposal, L5 result, checkpoint, and Case revision."""

    case: CaseSnapshot
    binding: HearingVerdictBinding
    review: ProceduralReview
    checkpoint: HearingCheckpoint
    created: bool


@dataclass(frozen=True, slots=True)
class HearingReworkResult:
    """Atomic failed-review successor cycle and DELIBERATING Case revision."""

    case: CaseSnapshot
    receipt: HearingReworkReceipt
    cycle: HearingCycleScope
    checkpoint: HearingCheckpoint
    created: bool


@dataclass(frozen=True, slots=True)
class HearingHumanReviewResult:
    """Atomic bounded transfer to human review."""

    case: CaseSnapshot
    receipt: HearingHumanReviewReceipt
    checkpoint: HearingCheckpoint
    created: bool


@dataclass(frozen=True, slots=True)
class HearingBudgetUsage:
    """Trusted cumulative reservation/response budget state for one hearing."""

    hearing_session_id: str
    request_count: int
    reserved_images: int
    reserved_pixels: int
    output_tokens: int
    manifest_id: str

    def __post_init__(self) -> None:
        for name in (
            "request_count",
            "reserved_images",
            "reserved_pixels",
            "output_tokens",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


class HearingRepository(Protocol):
    """Run-scoped immutable hearing persistence with typed reloads."""

    def begin_hearing_case(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingStartResult: ...

    def append_hearing_cycle(
        self,
        run_id: str,
        cycle_scope: HearingCycleScope,
    ) -> None: ...

    def append_hearing_checkpoint(
        self,
        run_id: str,
        checkpoint: HearingCheckpoint,
    ) -> None: ...

    def append_precedent_retrieval(
        self,
        run_id: str,
        receipt: HearingPrecedentRetrievalReceipt,
    ) -> None: ...

    def claim_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> HearingModelCallClaim: ...

    def complete_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
        owner_token: str,
    ) -> HearingModelCacheEntry: ...

    def append_hearing_parse_receipt(
        self,
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None = None,
    ) -> HearingModelParseReceipt: ...

    def complete_hearing_round(
        self,
        run_id: str,
        hearing_round: HearingRound,
    ) -> None: ...

    def commit_hearing_verdict_review(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        review: ProceduralReview,
        checkpoint: HearingCheckpoint,
    ) -> HearingVerdictReviewResult: ...

    def begin_hearing_rework(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingReworkReceipt,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingReworkResult: ...

    def commit_hearing_human_review(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingHumanReviewReceipt,
        checkpoint: HearingCheckpoint,
    ) -> HearingHumanReviewResult: ...

    def claim_acquisition_execution(
        self,
        run_id: str,
        request: AcquisitionRequest,
        execution_mode: AcquisitionExecutionMode,
        owner_token: str,
    ) -> AcquisitionExecutionClaim: ...

    def claim_acquisition_recovery(
        self,
        run_id: str,
        request: AcquisitionRequest,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim: ...

    def complete_acquisition_execution(
        self,
        run_id: str,
        publication: AcquisitionExecutionPublication,
        owner_token: str,
    ) -> AcquisitionExecutionCommit: ...

    def abandon_acquisition_execution(
        self,
        run_id: str,
        request: AcquisitionRequest,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim: ...

    def load_acquisition_execution(
        self,
        run_id: str,
        request_id: str,
    ) -> AcquisitionExecutionPublication | None: ...

    def persist_acquisition_successor(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        request: AcquisitionRequest,
        publication: AcquisitionExecutionPublication,
    ) -> AcquisitionPublishResult: ...

    def load_hearing_session(self, run_id: str, hearing_id: str) -> HearingSession: ...

    def load_active_hearing(self, run_id: str, case_id: str) -> HearingSession | None: ...

    def load_latest_hearing_checkpoint(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingCheckpoint: ...

    def list_hearing_cycles(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingCycleScope, ...]: ...

    def list_hearing_rounds(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingRound, ...]: ...

    def load_hearing_record(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingRecord | None: ...

    def load_hearing_budget_usage(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingBudgetUsage: ...

    def list_hearing_model_requests(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelRequest, ...]: ...

    def list_hearing_model_responses(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelResponse, ...]: ...

    def list_hearing_parse_receipts(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelParseReceipt, ...]: ...

    def list_hearing_role_outputs(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingRoleOutput, ...]: ...

    def list_hearing_usage_receipts(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingUsageReceipt, ...]: ...

    def list_hearing_failure_authorities(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelCallFailureAuthority, ...]: ...

    def load_hearing_evidence_authority(
        self,
        run_id: str,
        hearing_id: str,
        current_pack_id: str,
    ) -> EvidenceAuthority: ...

    def load_hearing_cycle(self, run_id: str, cycle_id: str) -> HearingCycleScope: ...

    def load_precedent_retrieval(
        self,
        run_id: str,
        receipt_id: str,
    ) -> HearingPrecedentRetrievalReceipt: ...

    def load_hearing_checkpoint(
        self,
        run_id: str,
        checkpoint_id: str,
    ) -> HearingCheckpoint: ...

    def load_hearing_round(self, run_id: str, round_id: str) -> HearingRound: ...

    def load_hearing_model_request(
        self,
        run_id: str,
        request_id: str,
    ) -> HearingModelRequest: ...

    def load_hearing_model_response(
        self,
        run_id: str,
        response_id: str,
    ) -> HearingModelResponse: ...

    def load_hearing_model_cache_entry(
        self,
        run_id: str,
        cache_key: str,
    ) -> HearingModelCacheEntry | None: ...

    def load_hearing_parse_receipt(
        self,
        run_id: str,
        parse_receipt_id: str,
    ) -> HearingModelParseReceipt: ...

    def load_hearing_role_output(
        self,
        run_id: str,
        output_id: str,
    ) -> HearingRoleOutput: ...

    def load_hearing_usage_receipt(
        self,
        run_id: str,
        usage_receipt_id: str,
    ) -> HearingUsageReceipt: ...


__all__ = [
    "AcquisitionExecutionClaim",
    "AcquisitionExecutionClaimStatus",
    "AcquisitionExecutionCommit",
    "AcquisitionOutputBundle",
    "AcquisitionPublishResult",
    "HearingBudgetUsage",
    "HearingHumanReviewResult",
    "HearingModelCallClaim",
    "HearingModelCallClaimStatus",
    "HearingPersistenceConflict",
    "HearingRepository",
    "HearingReworkResult",
    "HearingStartResult",
    "HearingVerdictReviewResult",
]
