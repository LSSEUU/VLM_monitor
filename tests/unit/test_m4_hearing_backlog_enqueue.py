from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from labcourt.application.hearing_request import HearingRequestGeneration
from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.hearing import (
    HearingInitialStrictParseFailureProof,
    HearingModelCallFailureAuthority,
    HearingStrictParseFailureAttempt,
)
from labcourt.contracts.model_call_failures import (
    ModelCallFailureClosureKind,
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.hearing_backlog import (
    HearingBacklogEnqueueCommit,
    HearingBacklogEnqueueIntent,
    HearingModelCallFailureIntent,
    hearing_request_document_sha256,
)
from tests.unit.test_m4_hearing_backlog_retry import (
    _context,
    _pending_checkpoint,
    _strict_error,
)
from tests.unit.test_m4_hearing_request import _prepare, _scenario

_OWNER_TOKEN = "hearing-enqueue-owner-token-1234567890"
_LEASE_EXPIRES_AT = datetime(2026, 7, 28, 8, 2, tzinfo=UTC)


def _item(request, reason: BacklogReasonCode, retry_generation: int) -> BacklogItem:
    return BacklogItem(
        run_id=request.run_id,
        case_id=request.case_id,
        stage=BacklogStage.HEARING,
        role=request.role,
        reason_code=reason,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        stage_input_sha256=hearing_request_document_sha256(request),
        max_attempts=3,
        retry_generation=retry_generation,
        status=BacklogStatus.PENDING,
        manifest_id=request.manifest_id,
    )


def _provider_intent(request) -> HearingModelCallFailureIntent:
    return HearingModelCallFailureIntent(
        request=request,
        owner_token=_OWNER_TOKEN,
        claim_lease_expires_at=_LEASE_EXPIRES_AT,
        claim_takeover_count=0,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )


def _strict_proof(item: BacklogItem, checkpoint, prepared, scenario):
    calls = _strict_error(prepared, _context(scenario)).failed_calls
    return HearingInitialStrictParseFailureProof(
        backlog_item_id=item.item_id,
        source_checkpoint_id=checkpoint.checkpoint_id,
        source_checkpoint_sha256=checkpoint.checkpoint_sha256,
        source_checkpoint_version=checkpoint.version,
        role=prepared.request.role,
        attempts=tuple(
            HearingStrictParseFailureAttempt(
                request=call.request,
                response=call.response,
                parse_receipt=call.parse_receipt,
            )
            for call in calls
        ),
    )


def test_provider_enqueue_intent_binds_exact_request_checkpoint_and_generation_zero() -> None:
    scenario = _scenario()
    checkpoint = _pending_checkpoint(scenario)
    request = _prepare(scenario, VlmRole.PROSECUTOR).request
    item = _item(request, BacklogReasonCode.PROVIDER_UNAVAILABLE, 0)

    intent = HearingBacklogEnqueueIntent(
        item=item,
        checkpoint=checkpoint,
        stage_request=request,
        model_call_failure=_provider_intent(request),
    )

    assert intent.item.item_id == item.item_id
    assert intent.stage_request == request


def test_initial_strict_pair_is_distinct_no_lease_generation_one_authority() -> None:
    scenario = _scenario()
    checkpoint = _pending_checkpoint(scenario)
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    item = _item(prepared.request, BacklogReasonCode.MODEL_OUTPUT_INVALID, 1)
    proof = _strict_proof(item, checkpoint, prepared, scenario)

    intent = HearingBacklogEnqueueIntent(
        item=item,
        checkpoint=checkpoint,
        stage_request=prepared.request,
        strict_parse_failure=proof,
    )

    assert intent.strict_parse_failure == proof
    assert proof.attempts[0].request.backlog_retry_context is None
    assert proof.attempts[1].request.backlog_retry_context is None


def test_initial_strict_enqueue_rejects_generation_zero_item() -> None:
    scenario = _scenario()
    checkpoint = _pending_checkpoint(scenario)
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)
    valid_item = _item(prepared.request, BacklogReasonCode.MODEL_OUTPUT_INVALID, 1)
    proof = _strict_proof(valid_item, checkpoint, prepared, scenario)
    invalid_item = BacklogItem.model_validate(
        {
            **valid_item.model_dump(mode="json", exclude_computed_fields=True),
            "reason_code": BacklogReasonCode.PROVIDER_UNAVAILABLE.value,
            "retry_generation": 0,
        }
    )

    with pytest.raises(ValueError, match="generation-one"):
        HearingBacklogEnqueueIntent(
            item=invalid_item,
            checkpoint=checkpoint,
            stage_request=prepared.request,
            strict_parse_failure=proof,
        )


def test_unknown_delivery_cannot_authorize_hearing_enqueue() -> None:
    scenario = _scenario()
    request = _prepare(scenario, VlmRole.PROSECUTOR).request

    with pytest.raises(ValueError, match="unknown delivery"):
        HearingModelCallFailureIntent(
            request=request,
            owner_token=_OWNER_TOKEN,
            claim_lease_expires_at=_LEASE_EXPIRES_AT,
            claim_takeover_count=0,
            failure_code=VLMProviderFailureCode.TRANSPORT_UNAVAILABLE,
            delivery_certainty=VLMDeliveryCertainty.UNKNOWN,
            backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        )


def test_exact_provider_failure_intent_supports_retry_generation_but_not_initial_enqueue() -> None:
    scenario = _scenario()
    retry = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        generation=HearingRequestGeneration(
            retry_generation=1,
            backlog_item_id="b" * 64,
        ),
    ).request
    provider = _provider_intent(retry)
    assert provider.request.backlog_retry_context is not None

    item = _item(retry, BacklogReasonCode.PROVIDER_UNAVAILABLE, 0)
    with pytest.raises(ValueError, match="provider enqueue"):
        HearingBacklogEnqueueIntent(
            item=item,
            checkpoint=_pending_checkpoint(scenario),
            stage_request=retry,
            model_call_failure=provider,
        )


def test_enqueue_commit_closes_provider_authority_case_checkpoint_and_audit() -> None:
    scenario = _scenario()
    checkpoint = _pending_checkpoint(scenario)
    request = _prepare(scenario, VlmRole.PROSECUTOR).request
    item = _item(request, BacklogReasonCode.PROVIDER_UNAVAILABLE, 0)
    audit = AuditHead(
        run_id=item.run_id,
        manifest_id=item.manifest_id,
        run_revision=4,
        sequence=8,
        entry_hash="a" * 64,
    )
    authority = HearingModelCallFailureAuthority(
        run_id=item.run_id,
        case_id=item.case_id,
        hearing_session_id=request.hearing_session_id,
        role=request.role,
        request=request,
        source_checkpoint_id=checkpoint.checkpoint_id,
        source_checkpoint_sha256=checkpoint.checkpoint_sha256,
        source_checkpoint_version=checkpoint.version,
        claim_owner_sha256=hashlib.sha256(_OWNER_TOKEN.encode()).hexdigest(),
        claim_lease_expires_at=_LEASE_EXPIRES_AT,
        claim_takeover_count=0,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        reserved_images=len(request.media),
        reserved_pixels=sum(media.width * media.height for media in request.media),
        disclosed_images=0,
        disclosed_pixels=0,
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        estimated_cost=0.0,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        backlog_item_id=item.item_id,
        backlog_version=1,
        backlog_status=BacklogStatus.PENDING,
        backlog_attempt_count=0,
        retry_generation=0,
        closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
        closure_case_revision=4,
        closure_audit_sequence=audit.sequence,
        closure_audit_entry_hash=audit.entry_hash,
        manifest_id=item.manifest_id,
        recorded_at=datetime(2026, 7, 28, 8, 1, tzinfo=UTC),
    )
    case = CaseSnapshot(
        case=Case(
            run_id=item.run_id,
            status=CaseStatus.BACKLOGGED,
            event=scenario.pack.event,
            evidence_packs=(scenario.pack,),
            current_backlog_item_id=item.item_id,
            manifest_id=item.manifest_id,
        ),
        revision=4,
    )

    commit = HearingBacklogEnqueueCommit(
        item=item,
        case=case,
        checkpoint=checkpoint,
        stage_request=request,
        audit_head=audit,
        failure_authority=authority,
        created=True,
    )

    assert commit.failure_authority == authority
    assert commit.case.case.current_backlog_item_id == item.item_id
