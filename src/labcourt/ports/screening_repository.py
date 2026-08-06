"""Persistence boundary for M3 screening, review, and durable recovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryFailure,
    BacklogRetrySuccess,
)
from labcourt.contracts.enums import BacklogReasonCode, BacklogStatus
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.storage import ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.ports.backlog import BacklogStore
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.vlm import VLMDeliveryCertainty, VLMProviderFailureCode, VLMResponseCache


@dataclass(frozen=True, slots=True)
class M3CaseCommit:
    """A newly committed or idempotently replayed M3 Case transition."""

    case: CaseSnapshot
    created: bool


@dataclass(frozen=True, slots=True)
class M3BacklogRetryCommit:
    """Atomic retry result; exact replays keep the receipt and set created false."""

    case: CaseSnapshot
    item: BacklogItem
    receipt: BacklogCompletionReceipt
    created: bool

    def __post_init__(self) -> None:
        if type(self.created) is not bool:
            raise TypeError("backlog retry commit created flag must be a boolean")
        lease = self.receipt.outcome.lease
        if (
            self.item.run_id != lease.run_id
            or self.item.item_id != lease.item_id
            or self.item.attempt_count != lease.attempt_count
            or self.item.manifest_id != self.receipt.manifest_id
        ):
            raise ValueError("backlog retry commit item conflicts with its exact lease")
        expected_generation = (
            self.receipt.outcome.next_retry_generation
            if isinstance(self.receipt.outcome, BacklogRetryFailure)
            else lease.retry_generation
        )
        if self.item.retry_generation != expected_generation:
            raise ValueError("backlog retry commit item has the wrong retry generation")
        if self.item.status != self.receipt.backlog_status:
            raise ValueError("backlog retry commit item conflicts with its receipt status")
        if (
            self.case.revision != self.receipt.completion_case_revision
            or self.case.case.run_id != self.item.run_id
            or self.case.case.case_id != self.item.case_id
            or self.case.case.manifest_id != self.receipt.manifest_id
            or self.case.case.status != self.receipt.completion_case_status
        ):
            raise ValueError("backlog retry commit Case conflicts with its receipt")
        expected_binding = self.item.item_id if self.item.status == BacklogStatus.PENDING else None
        if self.case.case.current_backlog_item_id != expected_binding:
            raise ValueError("backlog retry commit has an invalid current retry binding")


class ModelCallClaimStatus(StrEnum):
    """Observable state of one durable request-level singleflight claim."""

    ACQUIRED = "ACQUIRED"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    EXPIRED_REQUIRES_RECOVERY = "EXPIRED_REQUIRES_RECOVERY"


@dataclass(frozen=True, slots=True)
class ModelCallClaim:
    """Result of claiming or observing an exact canonical model request.

    The caller-held owner token is intentionally absent.  Adapters persist only
    its SHA-256 digest, while this value exposes the minimum state needed by an
    orchestrator to call, wait, or consume an already completed response.
    """

    status: ModelCallClaimStatus
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
            raise ValueError("model call claim takeover_count must be non-negative")
        if self.status == ModelCallClaimStatus.COMPLETED:
            if self.response_id is None or self.lease_expires_at is not None:
                raise ValueError("completed model call claim has invalid observable fields")
            return
        if self.response_id is not None or self.lease_expires_at is None:
            raise ValueError("active model call claim has invalid observable fields")
        if (
            self.lease_expires_at.tzinfo is None
            or self.lease_expires_at.utcoffset() is None
            or self.lease_expires_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("model call claim lease expiry must use timezone-aware UTC")


@dataclass(frozen=True, slots=True, repr=False)
class ModelCallFailureIntent:
    """Secret-bearing in-process intent; persistence derives a public authority."""

    request: VLMCallRequest
    owner_token: str = field(repr=False)
    claim_lease_expires_at: datetime
    claim_takeover_count: int
    failure_code: VLMProviderFailureCode
    delivery_certainty: VLMDeliveryCertainty
    backlog_reason_code: BacklogReasonCode

    def __post_init__(self) -> None:
        if not isinstance(self.request, (VLMRequest, StructureRepairRequest)):
            raise TypeError("model call failure intent requires a VLM request")
        if not isinstance(self.owner_token, str) or not 32 <= len(self.owner_token) <= 512:
            raise ValueError("model call failure owner token has an invalid length")
        if (
            self.claim_lease_expires_at.tzinfo is None
            or self.claim_lease_expires_at.utcoffset() is None
            or self.claim_lease_expires_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("model call failure lease expiry must use timezone-aware UTC")
        if (
            not isinstance(self.claim_takeover_count, int)
            or isinstance(self.claim_takeover_count, bool)
            or self.claim_takeover_count < 0
        ):
            raise ValueError("model call failure takeover_count must be non-negative")
        if not isinstance(self.failure_code, VLMProviderFailureCode):
            raise TypeError("model call failure code has the wrong type")
        if (
            not isinstance(self.delivery_certainty, VLMDeliveryCertainty)
            or self.delivery_certainty == VLMDeliveryCertainty.UNKNOWN
        ):
            raise ValueError("only a known provider delivery outcome may authorize retry")
        if not isinstance(self.backlog_reason_code, BacklogReasonCode):
            raise TypeError("model call failure backlog reason has the wrong type")


class ScreeningRepository(VLMResponseCache, BacklogStore, Protocol):
    """Coordinator-facing M3 authority without an adapter dependency.

    Cache and ordinary backlog operations are inherited from their focused
    capability ports.  The methods below add the durable T1/T2 recovery and
    aggregate-commit boundaries used by the M3 coordinator.
    """

    def load_raw_response(self, run_id: str, response_id: str) -> VLMResponse: ...

    def load_raw_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> VLMResponse | None: ...

    def claim_model_call(
        self,
        run_id: str,
        request: VLMCallRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> ModelCallClaim: ...

    def complete_model_call(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
        owner_token: str,
    ) -> CachedModelResponse:
        """Converge an authorized response only; never advance Case or usage."""

        ...

    def append_parse_receipt(
        self,
        receipt: ModelParseReceipt,
        parsed_output: ParsedScreeningOutput | None = None,
    ) -> ModelParseReceipt: ...

    def load_parse_receipt(
        self,
        run_id: str,
        parse_receipt_id: str,
    ) -> ModelParseReceipt: ...

    def load_parse_receipt_for_output(
        self,
        run_id: str,
        parsed_output_id: str,
    ) -> ModelParseReceipt: ...

    def load_parse_history_for_output(
        self,
        run_id: str,
        parsed_output_id: str,
    ) -> tuple[ModelParseReceipt, ...]: ...

    def load_parsed_output(
        self,
        run_id: str,
        parsed_output_id: str,
    ) -> ParsedScreeningOutput: ...

    def commit_screening(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        screening: ScreeningResult,
    ) -> M3CaseCommit: ...

    def commit_verdict_review(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        verdict: Verdict,
        review: ProceduralReview,
    ) -> M3CaseCommit: ...

    def commit_backlog(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        item: BacklogItem,
        response_ids: tuple[str, ...] = (),
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> M3CaseCommit: ...

    def commit_backlog_screening_success(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        success: BacklogRetrySuccess,
        screening: ScreeningResult,
    ) -> M3BacklogRetryCommit: ...

    def commit_backlog_verdict_review_success(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        success: BacklogRetrySuccess,
        verdict: Verdict,
        review: ProceduralReview,
        screening: ScreeningResult | None = None,
    ) -> M3BacklogRetryCommit: ...

    def commit_backlog_retry_failure(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        failure: BacklogRetryFailure,
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> M3BacklogRetryCommit: ...

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot: ...

    def load_screening(self, run_id: str, screening_id: str) -> ScreeningResult: ...

    def load_verdict(self, run_id: str, verdict_id: str) -> Verdict: ...

    def load_procedural_review(
        self,
        run_id: str,
        review_id: str,
    ) -> ProceduralReview: ...

    def load_backlog_item(self, run_id: str, item_id: str) -> BacklogItem: ...


__all__ = [
    "M3BacklogRetryCommit",
    "M3CaseCommit",
    "ModelCallClaim",
    "ModelCallClaimStatus",
    "ModelCallFailureIntent",
    "ScreeningRepository",
]
