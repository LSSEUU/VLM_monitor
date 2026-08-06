from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

import pytest

from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    ModelParseStatus,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
)
from labcourt.contracts.hearing import (
    HearingHumanReviewReason,
    HearingInitialStrictParseFailureProof,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingRound,
    HearingStrictParseFailureAttempt,
    HearingUsageReceipt,
    derive_hearing_model_response_id,
)
from labcourt.contracts.model_call_failures import (
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ProceduralDefect
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingCallTrace,
    complete_defender,
    complete_judge,
    complete_precedent_retrieval,
    complete_prosecutor,
    transfer_to_human_review,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.hearing_backlog import (
    HearingBacklogEnqueueIntent,
    HearingModelCallFailureIntent,
    hearing_request_document_sha256,
)
from labcourt.ports.hearing_repository import HearingModelCallClaim
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_readonly_projection import (
    _hearing_retrieval,
    _persist_hearing_call,
    _scan,
    _started_hearing,
)
from tests.unit.test_m4_hearing_domain import _payloads


@dataclass(frozen=True, slots=True)
class _ClaimCaptured(Exception):
    request: HearingModelRequest
    owner_token: str
    claim: HearingModelCallClaim


@dataclass(frozen=True, slots=True)
class _ParseCaptured(Exception):
    receipt: HearingModelParseReceipt
    output: HearingRoleOutput


def test_initial_hearing_evidence_authority_needs_no_acquisition_receipt(
    tmp_path: Path,
) -> None:
    started = _started_hearing(tmp_path)

    authority = started.repository.load_hearing_evidence_authority(
        RUN_ID,
        started.session.session_id,
        started.pack_id,
    )

    assert authority.pack == started.pack
    assert authority.receipts == ()
    assert authority.loaded_objects.crops == started.pack.crops
    assert authority.crops == started.pack.crops


def test_initial_hearing_can_transfer_to_human_when_evidence_is_unavailable(
    tmp_path: Path,
) -> None:
    started = _started_hearing(tmp_path)
    checkpoint = started.repository.load_latest_hearing_checkpoint(
        RUN_ID,
        started.session.session_id,
    )
    transition = transfer_to_human_review(
        started.session,
        checkpoint,
        HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
    )
    assert transition.human_review_receipt is not None
    before = started.repository.load_case(RUN_ID, started.session.case_id)
    head = started.repository.get_audit_head(RUN_ID)

    committed = started.repository.commit_hearing_human_review(
        RUN_ID,
        before.revision,
        head,
        transition.human_review_receipt,
        transition.checkpoint,
    )
    replay = started.repository.commit_hearing_human_review(
        RUN_ID,
        before.revision,
        head,
        transition.human_review_receipt,
        transition.checkpoint,
    )

    assert committed.created is True
    assert replay.created is False
    assert committed.case.case.status == CaseStatus.HUMAN_REVIEW
    assert committed.checkpoint == transition.checkpoint
    assert _scan(started.database).failures == ()


def test_initial_provider_failure_enqueue_is_atomic_dual_cas_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = _started_hearing(tmp_path)
    checkpoint = started.repository.load_latest_hearing_checkpoint(
        RUN_ID,
        started.session.session_id,
    )
    retrieval = _hearing_retrieval(started)
    started.repository.append_precedent_retrieval(RUN_ID, retrieval)
    checkpoint = complete_precedent_retrieval(started.session, checkpoint, retrieval)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    prosecutor_payload, _, _ = _payloads(
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.CROP,
            artifact_id=started.pack.crops[0].crop_id,
        )
    )

    original_claim = started.repository.claim_hearing_model_call

    def capture_claim(
        run_id: str,
        request: HearingModelRequest,
        owner_token: str,
    ) -> NoReturn:
        claim = original_claim(run_id, request, owner_token)
        raise _ClaimCaptured(request=request, owner_token=owner_token, claim=claim)

    monkeypatch.setattr(started.repository, "claim_hearing_model_call", capture_claim)
    with pytest.raises(_ClaimCaptured) as captured:
        _persist_hearing_call(started, checkpoint, retrieval, prosecutor_payload)
    request = captured.value.request
    owner_token = captured.value.owner_token
    claim = captured.value.claim
    assert claim.lease_expires_at is not None

    item = BacklogItem(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        stage=BacklogStage.HEARING,
        role=request.role,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        stage_input_sha256=hearing_request_document_sha256(request),
        max_attempts=3,
        retry_generation=0,
        status=BacklogStatus.PENDING,
        manifest_id=started.session.manifest_id,
    )
    intent = HearingBacklogEnqueueIntent(
        item=item,
        checkpoint=checkpoint,
        stage_request=request,
        model_call_failure=HearingModelCallFailureIntent(
            request=request,
            owner_token=owner_token,
            claim_lease_expires_at=claim.lease_expires_at,
            claim_takeover_count=0,
            failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
            delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        ),
    )
    before = started.repository.load_case(RUN_ID, started.session.case_id)
    head = started.repository.get_audit_head(RUN_ID)
    stale_audit_only = AuditHead(
        run_id=head.run_id,
        manifest_id=head.manifest_id,
        run_revision=head.run_revision,
        sequence=head.sequence,
        entry_hash="f" * 64 if head.entry_hash != "f" * 64 else "e" * 64,
    )

    with pytest.raises(ConcurrentModification, match="audit head"):
        started.repository.commit_hearing_backlog(
            RUN_ID,
            before.revision,
            stale_audit_only,
            intent,
        )
    with sqlite3.connect(started.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM backlog_items").fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_model_call_failure_authorities"
        ).fetchone() == (0,)

    committed = started.repository.commit_hearing_backlog(
        RUN_ID,
        before.revision,
        head,
        intent,
    )
    replay = started.repository.commit_hearing_backlog(
        RUN_ID,
        before.revision,
        head,
        intent,
    )

    assert committed.created is True
    assert replay.created is False
    assert replay == committed.__class__(
        item=committed.item,
        case=committed.case,
        checkpoint=committed.checkpoint,
        stage_request=committed.stage_request,
        audit_head=committed.audit_head,
        failure_authority=committed.failure_authority,
        created=False,
    )
    assert committed.case.case.status == CaseStatus.BACKLOGGED
    assert committed.case.case.current_backlog_item_id == item.item_id
    assert committed.checkpoint == checkpoint
    assert committed.failure_authority is not None
    assert committed.failure_authority.claim_lease_expires_at == datetime.fromisoformat(
        claim.lease_expires_at.isoformat()
    )
    assert started.repository.list_hearing_failure_authorities(
        RUN_ID,
        started.session.session_id,
    ) == (committed.failure_authority,)
    with sqlite3.connect(started.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM backlog_items").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_model_call_failure_authorities"
        ).fetchone() == (1,)


def test_hearing_record_reload_includes_malformed_primary_and_valid_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = _started_hearing(tmp_path)
    checkpoint = started.repository.load_latest_hearing_checkpoint(
        RUN_ID,
        started.session.session_id,
    )
    retrieval = _hearing_retrieval(started)
    started.repository.append_precedent_retrieval(RUN_ID, retrieval)
    checkpoint = complete_precedent_retrieval(started.session, checkpoint, retrieval)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    evidence_ref = ArtifactRef(
        kind=ArtifactKind.CROP,
        artifact_id=started.pack.crops[0].crop_id,
    )
    prosecutor_payload, defender_payload, judge_payload = _payloads(evidence_ref=evidence_ref)

    original_append = started.repository.append_hearing_parse_receipt

    def capture_parse(
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None = None,
    ) -> NoReturn:
        assert output is not None
        raise _ParseCaptured(receipt=receipt, output=output)

    monkeypatch.setattr(started.repository, "append_hearing_parse_receipt", capture_parse)
    with pytest.raises(_ParseCaptured) as captured:
        _persist_hearing_call(started, checkpoint, retrieval, prosecutor_payload)
    monkeypatch.setattr(
        started.repository,
        "append_hearing_parse_receipt",
        original_append,
    )

    parsed_primary = captured.value.receipt
    primary_output_template = captured.value.output
    primary_request = started.repository.load_hearing_model_request(
        RUN_ID,
        parsed_primary.request_id,
    )
    primary_response = started.repository.load_hearing_model_response(
        RUN_ID,
        parsed_primary.response_id,
    )
    primary_usage = next(
        item
        for item in started.repository.list_hearing_usage_receipts(
            RUN_ID,
            started.session.session_id,
        )
        if item.request_ref.artifact_id == primary_request.request_id
    )

    repair_request_payload = primary_request.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    repair_request_payload.update(
        {
            "attempt_index": 1,
            "rendered_prompt_sha256": _sha(f"sqlite repair rendered {primary_request.request_id}"),
            "hearing_context_sha256": _sha(f"sqlite repair context {primary_request.request_id}"),
            "media": (),
            "original_request_id": primary_request.request_id,
            "original_response_id": primary_response.response_id,
            "original_response_content_sha256": primary_response.content_sha256,
            "repair_context_sha256": _sha(
                f"sqlite repair authority {primary_response.response_id}"
            ),
            "budget": primary_request.budget.model_copy(
                update={"max_images": 0, "max_input_pixels": 0}
            ),
        }
    )
    repair_request = HearingModelRequest.model_validate(repair_request_payload)
    repair_owner = _sha("sqlite repair owner token")
    started.repository.claim_hearing_model_call(RUN_ID, repair_request, repair_owner)
    defect = ProceduralDefect(
        code=ProceduralDefectCode.MALFORMED_STRUCTURE,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.MALFORMED_JSON,
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=primary_response.response_id,
        ),
        field=ProceduralField.JSON_ROOT,
    )
    failed_parse_payload = parsed_primary.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    failed_parse_payload.update(
        {
            "status": ModelParseStatus.REPAIR_REQUIRED,
            "defects": (defect,),
            "parsed_payload_sha256": None,
            "repair_request_id": repair_request.request_id,
        }
    )
    failed_primary_parse = HearingModelParseReceipt.model_validate(failed_parse_payload)
    started.repository.append_hearing_parse_receipt(failed_primary_parse)

    repair_content_sha256 = _sha(f"sqlite repair raw {repair_request.request_id}")
    repair_response_id = derive_hearing_model_response_id(
        RUN_ID,
        repair_request.request_id,
        repair_content_sha256,
    )
    repair_response = HearingModelResponse(
        run_id=repair_request.run_id,
        case_id=repair_request.case_id,
        hearing_session_id=repair_request.hearing_session_id,
        round_index=repair_request.round_index,
        prior_acquisition_rounds=repair_request.prior_acquisition_rounds,
        prior_rework_rounds=repair_request.prior_rework_rounds,
        current_evidence_pack_id=repair_request.current_evidence_pack_id,
        current_evidence_pack_version=repair_request.current_evidence_pack_version,
        role=repair_request.role,
        attempt_index=1,
        request_id=repair_request.request_id,
        request_sha256=repair_request.request_sha256,
        cache_key=repair_request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{repair_response_id}.json",
        content_sha256=repair_content_sha256,
        size_bytes=64,
        input_tokens=4,
        output_tokens=6,
        latency_ms=8,
        model_manifest_id=repair_request.model_manifest_id,
        manifest_id=repair_request.manifest_id,
    )
    repair_request_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_REQUEST,
        artifact_id=repair_request.request_id,
    )
    repair_response_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_RESPONSE,
        artifact_id=repair_response.response_id,
    )
    repair_usage = HearingUsageReceipt(
        run_id=repair_request.run_id,
        case_id=repair_request.case_id,
        hearing_session_id=repair_request.hearing_session_id,
        round_index=repair_request.round_index,
        role=repair_request.role,
        request_ref=repair_request_ref,
        response_ref=repair_response_ref,
        input_images=0,
        input_pixels=0,
        input_tokens=repair_response.input_tokens,
        output_tokens=repair_response.output_tokens,
        latency_ms=repair_response.latency_ms,
        retry_count=0,
        estimated_cost=0.0,
        manifest_id=repair_request.manifest_id,
    )
    repair_parse = HearingModelParseReceipt(
        run_id=repair_request.run_id,
        case_id=repair_request.case_id,
        hearing_session_id=repair_request.hearing_session_id,
        round_index=repair_request.round_index,
        role=repair_request.role,
        attempt_index=1,
        request_id=repair_request.request_id,
        request_sha256=repair_request.request_sha256,
        response_id=repair_response.response_id,
        response_content_sha256=repair_response.content_sha256,
        parser_version="strict-v1",
        output_schema_sha256=repair_request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=prosecutor_payload.payload_sha256,
        manifest_id=repair_request.manifest_id,
    )
    repair_parse_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_PARSE_RECEIPT,
        artifact_id=repair_parse.parse_receipt_id,
    )
    repaired_output_payload = primary_output_template.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    repaired_output_payload.update(
        {
            "request_ref": repair_request_ref,
            "response_ref": repair_response_ref,
            "parse_receipt_ref": repair_parse_ref,
        }
    )
    repaired_output = HearingRoleOutput.model_validate(repaired_output_payload)
    started.repository.complete_hearing_model_call(
        RUN_ID,
        repair_request,
        repair_response,
        repair_usage,
        repair_owner,
    )
    started.repository.append_hearing_parse_receipt(repair_parse, repaired_output)

    prosecutor_trace = HearingCallTrace(
        calls=(
            HearingCallClosure(
                request=primary_request,
                response=primary_response,
                parse_receipt=failed_primary_parse,
                usage=primary_usage,
            ),
            HearingCallClosure(
                request=repair_request,
                response=repair_response,
                parse_receipt=repair_parse,
                usage=repair_usage,
            ),
        )
    )
    checkpoint = complete_prosecutor(
        started.session,
        checkpoint,
        repaired_output,
        prosecutor_trace,
    )
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    defender, defender_trace = _persist_hearing_call(
        started,
        checkpoint,
        retrieval,
        defender_payload,
        prosecutor_output_id=repaired_output.output_id,
    )
    checkpoint = complete_defender(
        started.session,
        checkpoint,
        defender,
        defender_trace,
    )
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    judge, judge_trace = _persist_hearing_call(
        started,
        checkpoint,
        retrieval,
        judge_payload,
        prosecutor_output_id=repaired_output.output_id,
        defender_output_id=defender.output_id,
    )
    transition = complete_judge(started.session, checkpoint, judge, judge_trace)
    checkpoint = transition.checkpoint
    assert checkpoint.prosecutor_output is not None
    assert checkpoint.defender_output is not None
    assert checkpoint.judge_output is not None
    hearing_round = HearingRound(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        hearing_session_id=started.session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=started.pack_id,
        current_evidence_pack_version=started.pack_version,
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt=retrieval,
        prosecutor_output=checkpoint.prosecutor_output,
        defender_output=checkpoint.defender_output,
        judge_output=checkpoint.judge_output,
        manifest_id=started.session.manifest_id,
    )
    started.repository.complete_hearing_round(RUN_ID, hearing_round)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)

    record = started.repository.load_hearing_record(
        RUN_ID,
        started.session.session_id,
    )
    assert record is not None
    assert len(record.model_request_refs) == 4
    assert len(record.model_response_refs) == 4
    assert len(record.parse_receipt_refs) == 4
    assert len(record.usage_receipts) == 4
    assert {ref.artifact_id for ref in record.model_request_refs} == {
        primary_request.request_id,
        repair_request.request_id,
        defender_trace.calls[-1].request.request_id,
        judge_trace.calls[-1].request.request_id,
    }


def _sha(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_initial_double_strict_failure_persists_no_lease_generation_one_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = _started_hearing(tmp_path)
    checkpoint = started.repository.load_latest_hearing_checkpoint(
        RUN_ID,
        started.session.session_id,
    )
    retrieval = _hearing_retrieval(started)
    started.repository.append_precedent_retrieval(RUN_ID, retrieval)
    checkpoint = complete_precedent_retrieval(started.session, checkpoint, retrieval)
    started.repository.append_hearing_checkpoint(RUN_ID, checkpoint)
    prosecutor_payload, _, _ = _payloads(
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.CROP,
            artifact_id=started.pack.crops[0].crop_id,
        )
    )

    original_append = started.repository.append_hearing_parse_receipt

    def capture_parse(
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None = None,
    ) -> NoReturn:
        assert output is not None
        raise _ParseCaptured(receipt=receipt, output=output)

    monkeypatch.setattr(started.repository, "append_hearing_parse_receipt", capture_parse)
    with pytest.raises(_ParseCaptured) as captured:
        _persist_hearing_call(started, checkpoint, retrieval, prosecutor_payload)
    monkeypatch.setattr(
        started.repository,
        "append_hearing_parse_receipt",
        original_append,
    )
    parsed_primary = captured.value.receipt
    primary_request = started.repository.load_hearing_model_request(
        RUN_ID,
        parsed_primary.request_id,
    )
    primary_response = started.repository.load_hearing_model_response(
        RUN_ID,
        parsed_primary.response_id,
    )
    repair_payload = primary_request.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    repair_payload.update(
        {
            "attempt_index": 1,
            "rendered_prompt_sha256": _sha(f"strict repair rendered {primary_request.request_id}"),
            "hearing_context_sha256": _sha(f"strict repair context {primary_request.request_id}"),
            "media": (),
            "original_request_id": primary_request.request_id,
            "original_response_id": primary_response.response_id,
            "original_response_content_sha256": primary_response.content_sha256,
            "repair_context_sha256": _sha(
                f"strict repair authority {primary_response.response_id}"
            ),
            "budget": primary_request.budget.model_copy(
                update={"max_images": 0, "max_input_pixels": 0}
            ),
        }
    )
    repair_request = HearingModelRequest.model_validate(repair_payload)
    repair_owner = _sha("strict repair owner token")
    started.repository.claim_hearing_model_call(RUN_ID, repair_request, repair_owner)
    primary_defect = ProceduralDefect(
        code=ProceduralDefectCode.MALFORMED_STRUCTURE,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.MALFORMED_JSON,
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=primary_response.response_id,
        ),
        field=ProceduralField.JSON_ROOT,
    )
    primary_parse_payload = parsed_primary.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    primary_parse_payload.update(
        {
            "status": ModelParseStatus.REPAIR_REQUIRED,
            "defects": (primary_defect,),
            "parsed_payload_sha256": None,
            "repair_request_id": repair_request.request_id,
        }
    )
    primary_parse = HearingModelParseReceipt.model_validate(primary_parse_payload)
    started.repository.append_hearing_parse_receipt(primary_parse)

    repair_content_sha256 = _sha(f"strict repair raw {repair_request.request_id}")
    repair_response_id = derive_hearing_model_response_id(
        RUN_ID,
        repair_request.request_id,
        repair_content_sha256,
    )
    repair_response = HearingModelResponse(
        run_id=repair_request.run_id,
        case_id=repair_request.case_id,
        hearing_session_id=repair_request.hearing_session_id,
        round_index=repair_request.round_index,
        prior_acquisition_rounds=repair_request.prior_acquisition_rounds,
        prior_rework_rounds=repair_request.prior_rework_rounds,
        current_evidence_pack_id=repair_request.current_evidence_pack_id,
        current_evidence_pack_version=repair_request.current_evidence_pack_version,
        role=repair_request.role,
        attempt_index=1,
        request_id=repair_request.request_id,
        request_sha256=repair_request.request_sha256,
        cache_key=repair_request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{repair_response_id}.json",
        content_sha256=repair_content_sha256,
        size_bytes=64,
        input_tokens=4,
        output_tokens=6,
        latency_ms=8,
        model_manifest_id=repair_request.model_manifest_id,
        manifest_id=repair_request.manifest_id,
    )
    repair_request_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_REQUEST,
        artifact_id=repair_request.request_id,
    )
    repair_response_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_RESPONSE,
        artifact_id=repair_response.response_id,
    )
    repair_usage = HearingUsageReceipt(
        run_id=repair_request.run_id,
        case_id=repair_request.case_id,
        hearing_session_id=repair_request.hearing_session_id,
        round_index=repair_request.round_index,
        role=repair_request.role,
        request_ref=repair_request_ref,
        response_ref=repair_response_ref,
        input_images=0,
        input_pixels=0,
        input_tokens=repair_response.input_tokens,
        output_tokens=repair_response.output_tokens,
        latency_ms=repair_response.latency_ms,
        retry_count=0,
        estimated_cost=0.0,
        manifest_id=repair_request.manifest_id,
    )
    repair_defect = ProceduralDefect(
        code=ProceduralDefectCode.MALFORMED_STRUCTURE,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.MALFORMED_JSON,
        artifact_ref=repair_response_ref,
        field=ProceduralField.JSON_ROOT,
    )
    repair_parse = HearingModelParseReceipt(
        run_id=repair_request.run_id,
        case_id=repair_request.case_id,
        hearing_session_id=repair_request.hearing_session_id,
        round_index=repair_request.round_index,
        role=repair_request.role,
        attempt_index=1,
        request_id=repair_request.request_id,
        request_sha256=repair_request.request_sha256,
        response_id=repair_response.response_id,
        response_content_sha256=repair_response.content_sha256,
        parser_version="strict-v1",
        output_schema_sha256=repair_request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.INVALID_FINAL,
        defects=(repair_defect,),
        manifest_id=repair_request.manifest_id,
    )
    started.repository.complete_hearing_model_call(
        RUN_ID,
        repair_request,
        repair_response,
        repair_usage,
        repair_owner,
    )
    started.repository.append_hearing_parse_receipt(repair_parse)
    attempts = (
        HearingStrictParseFailureAttempt(
            request=primary_request,
            response=primary_response,
            parse_receipt=primary_parse,
        ),
        HearingStrictParseFailureAttempt(
            request=repair_request,
            response=repair_response,
            parse_receipt=repair_parse,
        ),
    )
    item = BacklogItem(
        run_id=RUN_ID,
        case_id=started.session.case_id,
        stage=BacklogStage.HEARING,
        role=primary_request.role,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=primary_request.request_id,
        ),
        stage_input_sha256=hearing_request_document_sha256(primary_request),
        max_attempts=3,
        retry_generation=1,
        status=BacklogStatus.PENDING,
        manifest_id=started.session.manifest_id,
    )
    proof = HearingInitialStrictParseFailureProof(
        backlog_item_id=item.item_id,
        source_checkpoint_id=checkpoint.checkpoint_id,
        source_checkpoint_sha256=checkpoint.checkpoint_sha256,
        source_checkpoint_version=checkpoint.version,
        role=primary_request.role,
        attempts=attempts,
    )
    intent = HearingBacklogEnqueueIntent(
        item=item,
        checkpoint=checkpoint,
        stage_request=primary_request,
        strict_parse_failure=proof,
    )
    before = started.repository.load_case(RUN_ID, started.session.case_id)
    head = started.repository.get_audit_head(RUN_ID)
    committed = started.repository.commit_hearing_backlog(
        RUN_ID,
        before.revision,
        head,
        intent,
    )
    replay = started.repository.commit_hearing_backlog(
        RUN_ID,
        before.revision,
        head,
        intent,
    )

    assert committed.created is True
    assert replay.created is False
    assert committed.strict_parse_failure == proof
    assert committed.failure_authority is None
    assert committed.item.retry_generation == 1
    assert committed.case.case.status == CaseStatus.BACKLOGGED
    with sqlite3.connect(started.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_hearing_strict_parse_failure_attempts"
        ).fetchone() == (2,)
        assert connection.execute(
            """
            SELECT closure_kind, lease_id, retry_generation
            FROM m4_hearing_strict_parse_failure_proofs
            """
        ).fetchone() == ("INITIAL_BACKLOG", None, 0)
    scan = _scan(started.database)
    assert scan.failures == (), [
        (failure.inventory_kind.value, failure.artifact_id, failure.reason_code)
        for failure in scan.failures
    ]
