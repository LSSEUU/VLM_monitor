"""Narrow M4 persistence boundary for exact-role hearing backlog retries.

The M3 backlog worker deliberately remains stage-limited.  M4 uses this
separate authority surface because a hearing lease must be closed together
with its exact checkpoint, Case revision, audit head, and M4 completion
receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import isfinite
from typing import Protocol

from labcourt.contracts.backlog import BacklogItem, BacklogLeaseIdentity
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    ModelParseStatus,
    VlmRole,
)
from labcourt.contracts.hearing import (
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryFailure,
    HearingBacklogRetryOutcome,
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingCycleScope,
    HearingInitialStrictParseFailureProof,
    HearingModelCallFailureAuthority,
    HearingModelRequest,
    HearingSession,
)
from labcourt.contracts.model_call_failures import (
    ModelCallFailureClosureKind,
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import HearingCallClosure
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot


def hearing_request_document_sha256(request: HearingModelRequest) -> str:
    """Hash the complete canonical request document used as stage input."""

    if not isinstance(request, HearingModelRequest):
        raise TypeError("request must be a HearingModelRequest")
    return sha256_hex(request.model_dump(mode="json"))


def _lease_for(item: BacklogItem) -> BacklogLeaseIdentity:
    if item.lease_id is None:
        raise ValueError("leased hearing backlog item lacks a lease identity")
    return BacklogLeaseIdentity(
        run_id=item.run_id,
        item_id=item.item_id,
        lease_id=item.lease_id,
        attempt_count=item.attempt_count,
        retry_generation=item.retry_generation,
    )


_PENDING_ROLE = {
    HearingCheckpointPhase.PROSECUTOR_PENDING: VlmRole.PROSECUTOR,
    HearingCheckpointPhase.DEFENDER_PENDING: VlmRole.DEFENDER,
    HearingCheckpointPhase.JUDGE_PENDING: VlmRole.JUDGE,
}

_DEFINITELY_NOT_SENT_FAILURES = frozenset(
    {
        VLMProviderFailureCode.FIXTURE_MISSING,
        VLMProviderFailureCode.PROVIDER_OUTAGE,
        VLMProviderFailureCode.PROVIDER_TIMEOUT,
        VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH,
        VLMProviderFailureCode.PROMPT_MISSING,
        VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE,
        VLMProviderFailureCode.MEDIA_POLICY_REJECTED,
        VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE,
    }
)
_COMPLETED_FAILURES = frozenset(
    {
        VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID,
        VLMProviderFailureCode.RESPONSE_TOO_LARGE,
        VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
        VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
        VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE,
    }
)


def _backlog_reason_for_provider_failure(
    failure_code: VLMProviderFailureCode,
) -> BacklogReasonCode:
    if failure_code in {
        VLMProviderFailureCode.FIXTURE_MISSING,
        VLMProviderFailureCode.PROVIDER_OUTAGE,
        VLMProviderFailureCode.PROVIDER_TIMEOUT,
    }:
        return BacklogReasonCode.PROVIDER_UNAVAILABLE
    if failure_code in {
        VLMProviderFailureCode.RESPONSE_TOO_LARGE,
        VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
        VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
    }:
        return BacklogReasonCode.BUDGET_EXCEEDED
    return BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE


def _require_request_checkpoint_scope(
    request: HearingModelRequest,
    checkpoint: HearingCheckpoint,
    expected_role: VlmRole,
) -> None:
    if (
        request.run_id != checkpoint.run_id
        or request.case_id != checkpoint.case_id
        or request.hearing_session_id != checkpoint.hearing_session_id
        or request.cycle_scope_id != checkpoint.cycle_scope_id
        or request.cycle_scope_sha256 != checkpoint.cycle_scope_sha256
        or request.round_index != checkpoint.judge_cycle
        or request.prior_acquisition_rounds != checkpoint.prior_acquisition_rounds
        or request.prior_rework_rounds != checkpoint.prior_rework_rounds
        or request.current_evidence_pack_id != checkpoint.cycle_evidence_pack_id
        or request.current_evidence_pack_version != checkpoint.cycle_evidence_pack_version
        or request.role != expected_role
        or request.manifest_id != checkpoint.manifest_id
    ):
        raise ValueError("hearing request conflicts with the exact pending checkpoint")


@dataclass(frozen=True, slots=True, repr=False)
class HearingModelCallFailureIntent:
    """Secret-bearing exact provider failure closed at a backlog boundary.

    Unknown delivery is intentionally unrepresentable.  It must converge via
    provider-free response recovery before any business state can advance.
    The owner token is a transient fencing capability and is never serialized
    into the durable authority or completion outcome.
    """

    request: HearingModelRequest
    owner_token: str = field(repr=False)
    claim_lease_expires_at: datetime
    claim_takeover_count: int
    failure_code: VLMProviderFailureCode
    delivery_certainty: VLMDeliveryCertainty
    backlog_reason_code: BacklogReasonCode
    provider_response_content_sha256: str | None = None
    disclosed_images: int = 0
    disclosed_pixels: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    estimated_cost: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.request, HearingModelRequest):
            raise TypeError("hearing failure intent requires a HearingModelRequest")
        if not isinstance(self.owner_token, str) or not 32 <= len(self.owner_token) <= 512:
            raise ValueError("hearing failure owner token has an invalid length")
        expiry = self.claim_lease_expires_at
        if (
            not isinstance(expiry, datetime)
            or expiry.tzinfo is None
            or expiry.utcoffset() is None
            or expiry.utcoffset() != timedelta(0)
        ):
            raise ValueError("hearing failure lease expiry must use timezone-aware UTC")
        if (
            not isinstance(self.claim_takeover_count, int)
            or isinstance(self.claim_takeover_count, bool)
            or self.claim_takeover_count < 0
        ):
            raise ValueError("hearing failure takeover_count must be non-negative")
        if not isinstance(self.failure_code, VLMProviderFailureCode):
            raise TypeError("hearing failure code has the wrong type")
        if not isinstance(self.delivery_certainty, VLMDeliveryCertainty):
            raise TypeError("hearing delivery certainty has the wrong type")
        if not isinstance(self.backlog_reason_code, BacklogReasonCode):
            raise TypeError("hearing backlog reason has the wrong type")
        known_failures = _DEFINITELY_NOT_SENT_FAILURES | _COMPLETED_FAILURES
        if self.failure_code not in known_failures:
            raise ValueError("unknown delivery cannot grant hearing backlog authority")
        expected_certainty = (
            VLMDeliveryCertainty.DEFINITELY_NOT_SENT
            if self.failure_code in _DEFINITELY_NOT_SENT_FAILURES
            else VLMDeliveryCertainty.COMPLETED
        )
        if self.delivery_certainty != expected_certainty:
            raise ValueError("hearing failure code conflicts with delivery certainty")
        if self.backlog_reason_code != _backlog_reason_for_provider_failure(self.failure_code):
            raise ValueError("hearing failure code conflicts with backlog reason")
        for value, name in (
            (self.disclosed_images, "disclosed_images"),
            (self.disclosed_pixels, "disclosed_pixels"),
            (self.input_tokens, "input_tokens"),
            (self.output_tokens, "output_tokens"),
            (self.latency_ms, "latency_ms"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if (
            not isinstance(self.estimated_cost, float)
            or not isfinite(self.estimated_cost)
            or not 0 <= self.estimated_cost <= 1_000_000
        ):
            raise ValueError("estimated_cost must be a finite non-negative float")
        sha = self.provider_response_content_sha256
        if sha is not None and (
            not isinstance(sha, str)
            or len(sha) != 64
            or any(char not in "0123456789abcdef" for char in sha)
        ):
            raise ValueError("provider_response_content_sha256 must be lowercase SHA-256")
        metrics = (
            self.disclosed_images,
            self.disclosed_pixels,
            self.input_tokens,
            self.output_tokens,
            self.latency_ms,
            self.estimated_cost,
        )
        if self.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT:
            if sha is not None or any(metrics):
                raise ValueError("definitely-not-sent failure cannot claim disclosure or usage")
            return
        expected_images = len(self.request.media)
        expected_pixels = sum(item.width * item.height for item in self.request.media)
        if (
            sha is None
            or self.disclosed_images != expected_images
            or self.disclosed_pixels != expected_pixels
        ):
            raise ValueError("completed hearing failure must account its exact disclosure")


@dataclass(frozen=True, slots=True)
class HearingBacklogEnqueueIntent:
    """Exact initial role failure to close with one new HEARING item."""

    item: BacklogItem
    checkpoint: HearingCheckpoint
    stage_request: HearingModelRequest
    model_call_failure: HearingModelCallFailureIntent | None = None
    strict_parse_failure: HearingInitialStrictParseFailureProof | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.item, BacklogItem):
            raise TypeError("item must be a BacklogItem")
        if not isinstance(self.checkpoint, HearingCheckpoint):
            raise TypeError("checkpoint must be a HearingCheckpoint")
        if not isinstance(self.stage_request, HearingModelRequest):
            raise TypeError("stage_request must be a HearingModelRequest")
        if self.model_call_failure is not None and not isinstance(
            self.model_call_failure, HearingModelCallFailureIntent
        ):
            raise TypeError("model_call_failure has the wrong intent type")
        if self.strict_parse_failure is not None and not isinstance(
            self.strict_parse_failure, HearingInitialStrictParseFailureProof
        ):
            raise TypeError("strict_parse_failure has the wrong proof type")
        if (self.model_call_failure is None) == (self.strict_parse_failure is None):
            raise ValueError("hearing enqueue requires exactly one initial failure authority")

        item = self.item
        checkpoint = self.checkpoint
        request = self.stage_request
        expected_role = _PENDING_ROLE.get(checkpoint.phase)
        if (
            item.stage != BacklogStage.HEARING
            or item.status != BacklogStatus.PENDING
            or item.attempt_count != 0
            or expected_role is None
            or item.role != expected_role
        ):
            raise ValueError("hearing enqueue requires one pending exact-role backlog item")
        if (
            item.run_id != checkpoint.run_id
            or item.case_id != checkpoint.case_id
            or item.manifest_id != checkpoint.manifest_id
            or item.stage_input_ref.kind != ArtifactKind.MODEL_REQUEST
            or item.stage_input_ref.artifact_id != request.request_id
            or item.stage_input_sha256 != hearing_request_document_sha256(request)
        ):
            raise ValueError("hearing enqueue item does not bind its exact request/checkpoint")
        _require_request_checkpoint_scope(request, checkpoint, expected_role)

        provider = self.model_call_failure
        if provider is not None:
            if (
                provider.request != request
                or request.backlog_retry_context is not None
                or item.reason_code != provider.backlog_reason_code
                or item.retry_generation != 0
            ):
                raise ValueError("provider enqueue conflicts with its exact unfinished call")
            return

        proof = self.strict_parse_failure
        assert proof is not None
        if (
            item.reason_code != BacklogReasonCode.MODEL_OUTPUT_INVALID
            or item.retry_generation != 1
            or proof.backlog_item_id != item.item_id
            or proof.source_checkpoint_id != checkpoint.checkpoint_id
            or proof.source_checkpoint_sha256 != checkpoint.checkpoint_sha256
            or proof.source_checkpoint_version != checkpoint.version
            or proof.role != expected_role
            or proof.attempts[0].request != request
        ):
            raise ValueError("strict-failure enqueue lacks exact generation-one authority")


@dataclass(frozen=True, slots=True)
class HearingBacklogEnqueueCommit:
    """Atomic initial failure closure and its unchanged role checkpoint."""

    item: BacklogItem
    case: CaseSnapshot
    checkpoint: HearingCheckpoint
    stage_request: HearingModelRequest
    audit_head: AuditHead
    failure_authority: HearingModelCallFailureAuthority | None = None
    strict_parse_failure: HearingInitialStrictParseFailureProof | None = None
    created: bool = True

    def __post_init__(self) -> None:
        expected_types = (
            (self.item, BacklogItem, "item"),
            (self.case, CaseSnapshot, "case"),
            (self.checkpoint, HearingCheckpoint, "checkpoint"),
            (self.stage_request, HearingModelRequest, "stage_request"),
            (self.audit_head, AuditHead, "audit_head"),
        )
        for value, kind, name in expected_types:
            if not isinstance(value, kind):
                raise TypeError(f"{name} has the wrong commit type")
        if self.failure_authority is not None and not isinstance(
            self.failure_authority, HearingModelCallFailureAuthority
        ):
            raise TypeError("failure_authority has the wrong contract type")
        if self.strict_parse_failure is not None and not isinstance(
            self.strict_parse_failure, HearingInitialStrictParseFailureProof
        ):
            raise TypeError("strict_parse_failure has the wrong contract type")
        if (self.failure_authority is None) == (self.strict_parse_failure is None):
            raise ValueError("hearing enqueue commit requires exactly one persisted failure proof")
        if type(self.created) is not bool:
            raise TypeError("created must be a boolean")

        item = self.item
        case = self.case.case
        checkpoint = self.checkpoint
        expected_role = _PENDING_ROLE.get(checkpoint.phase)
        if (
            item.stage != BacklogStage.HEARING
            or item.status != BacklogStatus.PENDING
            or item.attempt_count != 0
            or expected_role is None
            or item.role != expected_role
            or item.stage_input_ref.kind != ArtifactKind.MODEL_REQUEST
            or item.stage_input_ref.artifact_id != self.stage_request.request_id
            or item.stage_input_sha256 != hearing_request_document_sha256(self.stage_request)
        ):
            raise ValueError("hearing enqueue commit has an invalid backlog head")
        _require_request_checkpoint_scope(self.stage_request, checkpoint, expected_role)
        if (
            case.run_id != item.run_id
            or case.case_id != item.case_id
            or case.status != CaseStatus.BACKLOGGED
            or case.current_backlog_item_id != item.item_id
            or case.manifest_id != item.manifest_id
            or self.case.revision <= 0
            or checkpoint.run_id != item.run_id
            or checkpoint.case_id != item.case_id
            or checkpoint.manifest_id != item.manifest_id
            or self.audit_head.run_id != item.run_id
            or self.audit_head.manifest_id != item.manifest_id
        ):
            raise ValueError("hearing enqueue Case/checkpoint/audit closure is inconsistent")

        authority = self.failure_authority
        if authority is not None:
            if (
                authority.request != self.stage_request
                or authority.role != expected_role
                or authority.source_checkpoint_id != checkpoint.checkpoint_id
                or authority.source_checkpoint_sha256 != checkpoint.checkpoint_sha256
                or authority.source_checkpoint_version != checkpoint.version
                or authority.backlog_item_id != item.item_id
                or authority.backlog_reason_code != item.reason_code
                or authority.backlog_version != 1
                or authority.backlog_status != BacklogStatus.PENDING
                or authority.backlog_attempt_count != 0
                or authority.retry_generation != 0
                or authority.closure_kind != ModelCallFailureClosureKind.INITIAL_BACKLOG
                or authority.closure_case_revision != self.case.revision
                or authority.closure_audit_sequence != self.audit_head.sequence
                or authority.closure_audit_entry_hash != self.audit_head.entry_hash
            ):
                raise ValueError("hearing provider failure authority does not close its enqueue")
            return

        proof = self.strict_parse_failure
        assert proof is not None
        if (
            item.reason_code != BacklogReasonCode.MODEL_OUTPUT_INVALID
            or item.retry_generation != 1
            or proof.backlog_item_id != item.item_id
            or proof.source_checkpoint_id != checkpoint.checkpoint_id
            or proof.source_checkpoint_sha256 != checkpoint.checkpoint_sha256
            or proof.source_checkpoint_version != checkpoint.version
            or proof.role != expected_role
            or proof.attempts[0].request != self.stage_request
        ):
            raise ValueError("initial strict proof does not close its exact enqueue")


@dataclass(frozen=True, slots=True)
class HearingBacklogRetryAuthority:
    """One fully reconstructed lease and its immutable hearing boundary.

    ``stage_request`` is the immutable request document named by the backlog
    item.  ``unfinished_request`` is present only when the current generation
    must resume an exact provider-boundary call.  It is absent after two strict
    parse failures, because that proof authorizes a fresh primary request for
    the new generation.
    """

    item: BacklogItem
    case: CaseSnapshot
    audit_head: AuditHead
    session: HearingSession
    cycle_scope: HearingCycleScope
    checkpoint: HearingCheckpoint
    stage_request: HearingModelRequest
    primary_template_request: HearingModelRequest
    unfinished_request: HearingModelRequest | None
    # Full durable session aggregates include the current generation's
    # persisted request/call accounting.  The before-primary values are an
    # independently reconstructed cut of that same canonical history and are
    # the only budget authority a retry plan may receive.
    reserved_images: int
    accounted_output_tokens: int
    reserved_images_before_primary: int
    accounted_output_tokens_before_primary: int
    prior_primary_failure: HearingCallClosure | None = None
    latest_completion: HearingBacklogCompletionReceipt | None = None
    latest_failure_authority: HearingModelCallFailureAuthority | None = None

    def __post_init__(self) -> None:
        expected_types = (
            (self.item, BacklogItem, "item"),
            (self.case, CaseSnapshot, "case"),
            (self.audit_head, AuditHead, "audit_head"),
            (self.session, HearingSession, "session"),
            (self.cycle_scope, HearingCycleScope, "cycle_scope"),
            (self.checkpoint, HearingCheckpoint, "checkpoint"),
            (self.stage_request, HearingModelRequest, "stage_request"),
            (
                self.primary_template_request,
                HearingModelRequest,
                "primary_template_request",
            ),
        )
        for value, kind, name in expected_types:
            if not isinstance(value, kind):
                raise TypeError(f"{name} has the wrong authority type")
        if self.unfinished_request is not None and not isinstance(
            self.unfinished_request, HearingModelRequest
        ):
            raise TypeError("unfinished_request must be a HearingModelRequest or None")
        if self.prior_primary_failure is not None and not isinstance(
            self.prior_primary_failure, HearingCallClosure
        ):
            raise TypeError("prior_primary_failure must be a HearingCallClosure or None")
        if self.latest_completion is not None and not isinstance(
            self.latest_completion, HearingBacklogCompletionReceipt
        ):
            raise TypeError("latest_completion has the wrong receipt type")
        if self.latest_failure_authority is not None and not isinstance(
            self.latest_failure_authority,
            HearingModelCallFailureAuthority,
        ):
            raise TypeError("latest_failure_authority has the wrong contract type")
        for count, name in (
            (self.reserved_images, "reserved_images"),
            (self.accounted_output_tokens, "accounted_output_tokens"),
            (
                self.reserved_images_before_primary,
                "reserved_images_before_primary",
            ),
            (
                self.accounted_output_tokens_before_primary,
                "accounted_output_tokens_before_primary",
            ),
        ):
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise TypeError(f"{name} must be a non-negative integer")
        if (
            self.reserved_images_before_primary > self.reserved_images
            or self.accounted_output_tokens_before_primary > self.accounted_output_tokens
        ):
            raise ValueError("before-primary budget cannot exceed its durable aggregate")

        item = self.item
        case = self.case.case
        checkpoint = self.checkpoint
        stage_request = self.stage_request
        expected_role = _PENDING_ROLE.get(checkpoint.phase)
        if (
            item.stage != BacklogStage.HEARING
            or item.status != BacklogStatus.LEASED
            or item.lease_id is None
            or expected_role is None
            or item.role != expected_role
        ):
            raise ValueError("hearing retry authority requires one exact active role lease")
        if (
            case.run_id != item.run_id
            or case.case_id != item.case_id
            or case.status != CaseStatus.BACKLOGGED
            or case.current_backlog_item_id != item.item_id
            or case.manifest_id != item.manifest_id
            or self.case.revision <= 0
        ):
            raise ValueError("hearing retry Case is not bound to the active backlog item")
        if (
            self.audit_head.run_id != item.run_id
            or self.audit_head.manifest_id != item.manifest_id
            or self.audit_head.run_revision < self.case.revision
        ):
            raise ValueError("hearing retry audit head conflicts with the Case authority")
        if (
            self.session.run_id != item.run_id
            or self.session.case_id != item.case_id
            or self.session.manifest_id != item.manifest_id
            or checkpoint.run_id != item.run_id
            or checkpoint.case_id != item.case_id
            or checkpoint.hearing_session_id != self.session.session_id
            or checkpoint.hearing_session_sha256 != self.session.session_sha256
            or checkpoint.manifest_id != item.manifest_id
        ):
            raise ValueError("hearing retry session or checkpoint is outside the lease scope")
        if (
            checkpoint.cycle_scope_id != self.cycle_scope.cycle_id
            or checkpoint.cycle_scope_sha256 != self.cycle_scope.cycle_sha256
            or self.cycle_scope.run_id != item.run_id
            or self.cycle_scope.case_id != item.case_id
            or self.cycle_scope.hearing_session_id != self.session.session_id
            or self.cycle_scope.manifest_id != item.manifest_id
        ):
            raise ValueError("hearing retry cycle is not the checkpoint's exact cycle")
        if (
            item.stage_input_ref.kind != ArtifactKind.MODEL_REQUEST
            or item.stage_input_ref.artifact_id != stage_request.request_id
            or item.stage_input_sha256 != hearing_request_document_sha256(stage_request)
        ):
            raise ValueError("hearing backlog stage input is not its complete request document")
        self._validate_request_scope(stage_request, expected_role)
        self._validate_request_scope(self.primary_template_request, expected_role)
        if self.primary_template_request.attempt_index != 0:
            raise ValueError("hearing generation template must be the role's primary request")
        if stage_request.attempt_index == 0:
            if self.primary_template_request != stage_request:
                raise ValueError("primary stage input must be its own generation template")
        elif stage_request.original_request_id != self.primary_template_request.request_id:
            raise ValueError("repair stage input does not bind its primary generation template")
        self._validate_history()
        self._validate_unfinished_call(expected_role)

    @property
    def lease(self) -> BacklogLeaseIdentity:
        return _lease_for(self.item)

    @property
    def restarts_primary(self) -> bool:
        return self.unfinished_request is None

    def _validate_request_scope(
        self,
        request: HearingModelRequest,
        expected_role: VlmRole,
    ) -> None:
        _require_request_checkpoint_scope(request, self.checkpoint, expected_role)

    def _validate_history(self) -> None:
        latest = self.latest_completion
        item = self.item
        if latest is None:
            if self.latest_failure_authority is not None:
                raise ValueError("initial hearing lease cannot import a retry failure authority")
            expected_restart = item.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID
            if item.attempt_count != 1:
                raise ValueError("later hearing leases require their latest completion receipt")
            if expected_restart != (self.unfinished_request is None):
                raise ValueError("initial hearing retry mode conflicts with its failure reason")
            return

        outcome = latest.outcome
        if not isinstance(outcome, HearingBacklogRetryFailure):
            raise ValueError("a leased hearing item cannot follow a successful completion")
        if (
            outcome.lease.item_id != item.item_id
            or outcome.lease.run_id != item.run_id
            or outcome.lease.attempt_count + 1 != item.attempt_count
            or latest.backlog_status != BacklogStatus.PENDING
            or outcome.next_status != BacklogStatus.PENDING
            or outcome.next_retry_generation != item.retry_generation
            or latest.source_checkpoint_id != self.checkpoint.checkpoint_id
            or latest.source_checkpoint_sha256 != self.checkpoint.checkpoint_sha256
            or latest.source_checkpoint_version != self.checkpoint.version
            or latest.resulting_checkpoint_id != self.checkpoint.checkpoint_id
            or latest.resulting_checkpoint_sha256 != self.checkpoint.checkpoint_sha256
            or latest.resulting_checkpoint_version != self.checkpoint.version
            or latest.manifest_id != item.manifest_id
        ):
            raise ValueError("latest hearing completion does not authorize this next lease")
        failure_authority = self.latest_failure_authority
        if failure_authority is not None and (
            failure_authority.closure_kind != ModelCallFailureClosureKind.RETRY_FAILURE
            or failure_authority.lease != outcome.lease
            or failure_authority.request != outcome.request
            or failure_authority.backlog_reason_code != outcome.reason_code
            or failure_authority.completion_receipt_id != latest.receipt_id
            or failure_authority.source_checkpoint_id != outcome.source_checkpoint_id
            or failure_authority.source_checkpoint_sha256 != outcome.source_checkpoint_sha256
            or failure_authority.source_checkpoint_version != outcome.source_checkpoint_version
            or failure_authority.closure_case_revision != latest.completion_case_revision
            or failure_authority.closure_audit_sequence != latest.completion_audit_sequence
            or failure_authority.closure_audit_entry_hash != latest.completion_audit_entry_hash
        ):
            raise ValueError("latest provider failure authority crosses its completion receipt")
        generation_advanced = outcome.next_retry_generation != outcome.lease.retry_generation
        if outcome.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED:
            expected_resume_ref = (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_REQUEST,
                    artifact_id=self.unfinished_request.request_id,
                )
                if self.unfinished_request is not None
                else None
            )
            if (
                generation_advanced
                or outcome.request != self.stage_request
                or outcome.request_binding != "BACKLOG_STAGE_INPUT"
                or outcome.lease_expiry_resume_request_ref != expected_resume_ref
            ):
                raise ValueError("hearing lease-expiry closure did not preserve retry mode")
            return
        if generation_advanced != (self.unfinished_request is None):
            raise ValueError("hearing retry mode conflicts with the latest generation closure")
        if not generation_advanced and self.unfinished_request != outcome.request:
            raise ValueError("provider failure must resume its exact unfinished request")

    def _validate_unfinished_call(self, expected_role: VlmRole) -> None:
        request = self.unfinished_request
        primary = self.prior_primary_failure
        if request is None:
            if primary is not None:
                raise ValueError("a new generation cannot import an earlier primary closure")
            return
        self._validate_request_scope(request, expected_role)
        context = request.backlog_retry_context
        if self.item.retry_generation == 0:
            if context is not None:
                raise ValueError("generation zero must reuse a context-free request")
        elif (
            context is None
            or context.backlog_item_id != self.item.item_id
            or context.retry_generation != self.item.retry_generation
        ):
            raise ValueError("unfinished hearing request belongs to another retry generation")
        if request.attempt_index == 0:
            if primary is not None:
                raise ValueError("primary resume cannot carry a prior primary closure")
            return
        if primary is None:
            raise ValueError("repair resume requires the already persisted primary failure")
        self._validate_request_scope(primary.request, expected_role)
        if (
            primary.request.attempt_index != 0
            or primary.request.role != request.role
            or primary.parse_receipt.status != ModelParseStatus.REPAIR_REQUIRED
            or primary.parse_receipt.repair_request_id != request.request_id
            or request.original_request_id != primary.request.request_id
            or request.original_response_id != primary.response.response_id
            or request.original_response_content_sha256 != primary.response.content_sha256
            or primary.request.backlog_retry_context != request.backlog_retry_context
        ):
            raise ValueError("repair resume lacks its exact persisted primary failure")


@dataclass(frozen=True, slots=True)
class HearingBacklogRetryCommit:
    """Repository result proving both sides of one atomic lease exit."""

    item: BacklogItem
    receipt: HearingBacklogCompletionReceipt
    case: CaseSnapshot
    checkpoint: HearingCheckpoint
    audit_head: AuditHead
    created: bool
    failure_authority: HearingModelCallFailureAuthority | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.item, BacklogItem):
            raise TypeError("item must be a BacklogItem")
        if not isinstance(self.receipt, HearingBacklogCompletionReceipt):
            raise TypeError("receipt must be a HearingBacklogCompletionReceipt")
        if not isinstance(self.case, CaseSnapshot):
            raise TypeError("case must be a CaseSnapshot")
        if not isinstance(self.checkpoint, HearingCheckpoint):
            raise TypeError("checkpoint must be a HearingCheckpoint")
        if not isinstance(self.audit_head, AuditHead):
            raise TypeError("audit_head must be an AuditHead")
        if type(self.created) is not bool:
            raise TypeError("created must be a boolean")
        if self.failure_authority is not None and not isinstance(
            self.failure_authority,
            HearingModelCallFailureAuthority,
        ):
            raise TypeError("failure_authority has the wrong contract type")

        outcome: HearingBacklogRetryOutcome = self.receipt.outcome
        case = self.case.case
        expected_status = (
            BacklogStatus.COMPLETED
            if not isinstance(outcome, HearingBacklogRetryFailure)
            else outcome.next_status
        )
        expected_generation = (
            outcome.lease.retry_generation
            if not isinstance(outcome, HearingBacklogRetryFailure)
            else outcome.next_retry_generation
        )
        if (
            self.item.item_id != outcome.lease.item_id
            or self.item.run_id != outcome.lease.run_id
            or self.item.status != expected_status
            or self.item.retry_generation != expected_generation
            or self.item.attempt_count != outcome.lease.attempt_count
            or any(
                value is not None
                for value in (
                    self.item.lease_id,
                    self.item.lease_owner_sha256,
                    self.item.lease_expires_at,
                )
            )
            or self.receipt.backlog_status != expected_status
        ):
            raise ValueError("hearing backlog head and completion receipt are not closed")
        if (
            self.checkpoint.checkpoint_id != self.receipt.resulting_checkpoint_id
            or self.checkpoint.checkpoint_sha256 != self.receipt.resulting_checkpoint_sha256
            or self.checkpoint.version != self.receipt.resulting_checkpoint_version
            or self.case.revision != self.receipt.completion_case_revision
            or case.status != self.receipt.completion_case_status
            or case.run_id != self.item.run_id
            or case.case_id != self.item.case_id
            or case.manifest_id != self.receipt.manifest_id
            or self.audit_head.run_id != self.item.run_id
            or self.audit_head.manifest_id != self.receipt.manifest_id
            or self.audit_head.sequence != self.receipt.completion_audit_sequence
            or self.audit_head.entry_hash != self.receipt.completion_audit_entry_hash
        ):
            raise ValueError("hearing Case/checkpoint/audit do not close the completion receipt")
        expected_current_item = (
            self.item.item_id if expected_status == BacklogStatus.PENDING else None
        )
        if case.current_backlog_item_id != expected_current_item:
            raise ValueError("hearing completion left the wrong current backlog boundary")
        failure_authority = self.failure_authority
        if failure_authority is not None and (
            not isinstance(outcome, HearingBacklogRetryFailure)
            or failure_authority.closure_kind != ModelCallFailureClosureKind.RETRY_FAILURE
            or failure_authority.lease != outcome.lease
            or failure_authority.request != outcome.request
            or failure_authority.backlog_reason_code != outcome.reason_code
            or failure_authority.backlog_status != self.item.status
            or failure_authority.backlog_attempt_count != self.item.attempt_count
            or failure_authority.retry_generation != outcome.lease.retry_generation
            or failure_authority.completion_receipt_id != self.receipt.receipt_id
            or failure_authority.closure_case_revision != self.case.revision
            or failure_authority.closure_audit_sequence != self.audit_head.sequence
            or failure_authority.closure_audit_entry_hash != self.audit_head.entry_hash
        ):
            raise ValueError("provider failure authority does not close this retry commit")


class HearingBacklogRepository(Protocol):
    """Stage-specific lease/CAS operations; never available to the M3 worker."""

    def commit_hearing_backlog(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        intent: HearingBacklogEnqueueIntent,
    ) -> HearingBacklogEnqueueCommit:
        """Atomically close an initial failure and preserve its pending role.

        Exact replay returns the same item, failure proof/authority, Case,
        checkpoint, and audit closure with ``created=False``.  A conflicting
        request, proof, claim, checkpoint, Case revision, or audit head fails
        without a partial write.
        """

        ...

    def lease_next_hearing_backlog(
        self,
        run_id: str,
        lease_owner_sha256: str,
        lease_expires_at: datetime,
    ) -> BacklogItem | None: ...

    def load_hearing_backlog_retry_authority(
        self,
        run_id: str,
        lease: BacklogLeaseIdentity,
    ) -> HearingBacklogRetryAuthority: ...

    def commit_hearing_backlog_retry(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        outcome: HearingBacklogRetryOutcome,
        model_call_failure: HearingModelCallFailureIntent | None = None,
    ) -> HearingBacklogRetryCommit:
        """Atomically close a lease after its exact call artifacts may exist.

        Implementations must revalidate the active lease, expected Case/audit
        head, source checkpoint, and every durable request/response/parse/output
        or provider-failure fence referenced by ``outcome`` in the same write
        transaction.  The hearing budget aggregate may legitimately have
        advanced since the caller's pre-provider authority snapshot.
        """

        ...

    def reclaim_expired_hearing_backlog(
        self,
        run_id: str,
        not_after: datetime,
        limit: int,
    ) -> tuple[HearingBacklogRetryCommit, ...]: ...


__all__ = [
    "HearingBacklogEnqueueCommit",
    "HearingBacklogEnqueueIntent",
    "HearingBacklogRepository",
    "HearingBacklogRetryAuthority",
    "HearingBacklogRetryCommit",
    "HearingModelCallFailureIntent",
    "hearing_request_document_sha256",
]
