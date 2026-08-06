import hashlib

import pytest

import labcourt.domain.hearing_fsm as hearing_fsm
from labcourt.application.hearing_acquisition_request import (
    AcquisitionRequestBuildError,
    AcquisitionRequestBuildFailureCode,
    build_acquisition_request,
)
from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.enums import (
    AcquisitionAction,
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    JudgeDisposition,
    MediaAccess,
    ModelParseStatus,
    PrivacyPolicy,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    VerdictDecision,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.evidence import RequestMoreFramesParameters, ToolResult
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    AcquisitionRequestPayload,
    DefenderModelPayload,
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingHumanReviewReason,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRecord,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingSessionEntryStatus,
    HearingUsageReceipt,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
    ToolExecutionManifest,
    ToolExecutionReceipt,
    derive_hearing_model_response_id,
    derive_m4_tool_result_id,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import (
    Argument,
    JudgeResponse,
    ProceduralDefect,
    ProceduralReview,
)
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingCallTrace,
    HearingTransitionError,
    begin_hearing,
    complete_acquisition,
    complete_defender,
    complete_judge,
    complete_precedent_retrieval,
    complete_prosecutor,
    record_procedural_review,
    start_cycle_after_acquisition,
    start_rework_cycle,
    transfer_to_human_review,
)
from labcourt.domain.hearing_verdict_builder import (
    HearingReviewClosure,
    HearingVerdictBuildError,
    build_hearing_verdict,
    validate_hearing_verdict_binding,
)

RUN_ID = "run-m4-domain"
CASE_ID = "case-m4-domain"
VIOLATION = ViolationType.REAGENT_CONTAINER_OPEN


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


MANIFEST_ID = _sha("manifest")
INITIAL_PACK_ID = _sha("initial-pack")
SCREENING_ID = _sha("screening")


def _ref(kind: ArtifactKind, label: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=_sha(label))


def _session(
    *,
    entry_status: HearingSessionEntryStatus = HearingSessionEntryStatus.ESCALATED,
    initial_trigger_review_ref: ArtifactRef | None = None,
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = (),
) -> HearingSession:
    return HearingSession(
        run_id=RUN_ID,
        case_id=CASE_ID,
        screening_id=SCREENING_ID,
        entry_status=entry_status,
        initial_evidence_pack_id=INITIAL_PACK_ID,
        initial_evidence_pack_version=1,
        initial_trigger_review_ref=initial_trigger_review_ref,
        initial_defect_codes=initial_defect_codes,
        acquisition_round_limit=2,
        rework_round_limit=2,
        max_total_images=100,
        max_total_output_tokens=100_000,
        hearing_prompt_bundle_sha256=_sha("hearing-prompt-bundle"),
        prosecutor_model_manifest_id=_sha("model-PROSECUTOR"),
        defender_model_manifest_id=_sha("model-DEFENDER"),
        judge_model_manifest_id=_sha("model-JUDGE"),
        manifest_id=MANIFEST_ID,
    )


def _assert_successor(parent: HearingCheckpoint, child: HearingCheckpoint) -> None:
    assert child.version == parent.version + 1
    assert child.previous_checkpoint_id == parent.checkpoint_id
    assert child.previous_checkpoint_sha256 == parent.checkpoint_sha256
    assert child.previous_phase == parent.phase


def _retrieval(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
) -> HearingPrecedentRetrievalReceipt:
    return HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=VIOLATION,
        rule_version="rule-v1",
        top_k=0,
        query_sha256=_sha(f"query-{checkpoint.judge_cycle}"),
        initial_trigger_review_ref=checkpoint.initial_trigger_review_ref,
        initial_defect_codes=checkpoint.initial_defect_codes,
        rework_review_ref=checkpoint.cycle_trigger_review_ref,
        rework_defect_codes=checkpoint.cycle_trigger_defect_codes,
        candidate_snapshot_sha256=_sha("empty-candidate-snapshot"),
        visible_snapshot_sha256=_sha("empty-visible-snapshot"),
        status=HearingPrecedentRetrievalStatus.DEGRADED,
        degraded_reason=HearingPrecedentDegradedReason.PRECEDENT_INDEX_UNAVAILABLE,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_sha("retriever-manifest"),
        manifest_id=MANIFEST_ID,
    )


def _prompt(role: VlmRole) -> PromptManifest:
    return PromptManifest(
        prompt_id=f"{role.value.lower()}-v1",
        role=role,
        template_sha256=_sha(f"template-{role.value}"),
        output_schema_sha256=_sha(f"schema-{role.value}"),
        prompt_bundle_sha256=_sha("hearing-prompt-bundle"),
        renderer_version="jinja-v1",
    )


def _argument(
    stance: ArgumentStance,
    label: str,
    evidence_ref: ArtifactRef,
) -> Argument:
    return Argument(
        stance=stance,
        claim=f"Auditable {label} claim.",
        evidence_refs=(evidence_ref,),
        uncertainty=0.2,
    )


def _payloads(
    *,
    evidence_ref: ArtifactRef,
    decision: VerdictDecision = VerdictDecision.ESTABLISHED,
    acquisition_payload: AcquisitionRequestPayload | None = None,
    include_judge_response: bool = True,
) -> tuple[ProsecutorModelPayload, DefenderModelPayload, JudgeModelPayload]:
    prosecution = _argument(ArgumentStance.PROSECUTION, "prosecution", evidence_ref)
    defense = _argument(ArgumentStance.DEFENSE, "defense", evidence_ref)
    prosecutor = ProsecutorModelPayload(
        arguments=(prosecution,),
        case_summary="The prosecution cites its structured claim.",
    )
    defender = DefenderModelPayload(
        arguments=(defense,),
        case_summary="The defense preserves its structured objection.",
    )
    responses = (
        (
            JudgeResponse(
                defense_argument_id=defense.argument_id,
                disposition=JudgeDisposition.REJECTED,
                response_summary="The Judge addresses the exact defense argument.",
            ),
        )
        if include_judge_response
        else ()
    )
    if acquisition_payload is None:
        outcome = JudgeFinalDecisionPayload(
            decision=decision,
            confidence=0.8,
            recommended_alert_level=AlertLevel.CONFIRMED,
            rationale_summary="The terminal proposal preserves the structured record.",
        )
    else:
        outcome = JudgeAcquisitionDecisionPayload(request=acquisition_payload)
    judge = JudgeModelPayload(judge_responses=responses, outcome=outcome)
    return prosecutor, defender, judge


def _role_output(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    retrieval: HearingPrecedentRetrievalReceipt,
    payload: ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
    *,
    prosecutor_output_id: str | None = None,
    defender_output_id: str | None = None,
) -> tuple[HearingRoleOutput, HearingCallTrace]:
    role = payload.role
    prefix = f"cycle-{checkpoint.judge_cycle}-{role.value}"
    evidence_ref = _ref(ArtifactKind.CROP, f"cycle-{checkpoint.judge_cycle}-visible-crop")
    media_sha256 = _sha(f"{prefix}-media")
    prosecutor_output_ref = (
        ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=prosecutor_output_id,
        )
        if prosecutor_output_id is not None
        else None
    )
    defender_output_ref = (
        ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=defender_output_id,
        )
        if defender_output_id is not None
        else None
    )
    prompt = _prompt(role)
    request = HearingModelRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        screening_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=SCREENING_ID,
        ),
        violation_type=VIOLATION,
        evidence_class=EvidenceClass.PRESENCE,
        role=role,
        provider_profile="fake-offline",
        provider="fake",
        model="fake-hearing",
        revision="v1",
        model_manifest_id=_sha(f"model-{role.value}"),
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=prompt,
        hearing_prompt_bundle_sha256=session.hearing_prompt_bundle_sha256,
        rendered_prompt_sha256=_sha(f"{prefix}-rendered-prompt"),
        hearing_context_sha256=_sha(f"{prefix}-context"),
        media=(
            VLMMediaRef(
                crop_id=evidence_ref.artifact_id,
                media_sha256=media_sha256,
                local_path=f"{RUN_ID}/frames/{media_sha256}.png",
                source=CropSource.SUBJECT,
                media_access=MediaAccess.LOCAL_ONLY,
                privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
                privacy_transform_version="privacy-v1",
                width=10,
                height=10,
            ),
        ),
        allowed_evidence_refs=(evidence_ref,),
        allowed_precedent_refs=(),
        prosecutor_output_ref=prosecutor_output_ref,
        defender_output_ref=defender_output_ref,
        precedent_retrieval_degraded=True,
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        initial_trigger_review_ref=checkpoint.initial_trigger_review_ref,
        initial_defect_codes=checkpoint.initial_defect_codes,
        rework_review_ref=checkpoint.cycle_trigger_review_ref,
        rework_defect_codes=checkpoint.cycle_trigger_defect_codes,
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=100,
            max_input_tokens=100,
            max_output_tokens=100,
            pricing_currency="USD",
            input_cost_per_million_tokens=500.0,
            output_cost_per_million_tokens=500.0,
            max_estimated_cost=1.0,
            max_response_bytes=10_000,
            max_json_depth=20,
            max_json_fields=100,
            max_string_chars=10_000,
            timeout_seconds=1.0,
        ),
        manifest_id=MANIFEST_ID,
    )
    content_sha256 = _sha(f"{prefix}-raw-response")
    response_id = derive_hearing_model_response_id(
        RUN_ID,
        request.request_id,
        content_sha256,
    )
    response = HearingModelResponse(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        role=role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=100,
        input_tokens=10,
        output_tokens=10,
        latency_ms=1,
        model_manifest_id=request.model_manifest_id,
        manifest_id=MANIFEST_ID,
    )
    parse_receipt = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=checkpoint.judge_cycle,
        role=role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-v1",
        output_schema_sha256=prompt.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=payload.payload_sha256,
        manifest_id=MANIFEST_ID,
    )
    request_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_REQUEST,
        artifact_id=request.request_id,
    )
    response_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_RESPONSE,
        artifact_id=response.response_id,
    )
    parse_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_PARSE_RECEIPT,
        artifact_id=parse_receipt.parse_receipt_id,
    )
    output = HearingRoleOutput(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        prompt_manifest=prompt,
        model_manifest_id=_sha(f"model-{role.value}"),
        request_ref=request_ref,
        response_ref=response_ref,
        parse_receipt_ref=parse_ref,
        prosecutor_output_id=prosecutor_output_id,
        defender_output_id=defender_output_id,
        precedent_retrieval_degraded=True,
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        initial_trigger_review_ref=checkpoint.initial_trigger_review_ref,
        initial_defect_codes=checkpoint.initial_defect_codes,
        rework_review_ref=checkpoint.cycle_trigger_review_ref,
        rework_defect_codes=checkpoint.cycle_trigger_defect_codes,
        payload=payload,
        manifest_id=MANIFEST_ID,
    )
    usage = HearingUsageReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=checkpoint.judge_cycle,
        role=role,
        request_ref=request_ref,
        response_ref=response_ref,
        input_images=1,
        input_pixels=100,
        input_tokens=10,
        output_tokens=10,
        latency_ms=1,
        retry_count=0,
        estimated_cost=0.01,
        manifest_id=MANIFEST_ID,
    )
    trace = HearingCallTrace(
        calls=(
            HearingCallClosure(
                request=request,
                response=response,
                parse_receipt=parse_receipt,
                usage=usage,
            ),
        ),
    )
    return output, trace


def _repair_trace(
    primary: HearingCallClosure,
    payload: ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
) -> HearingCallTrace:
    request_payload = primary.request.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    request_payload.update(
        {
            "attempt_index": 1,
            "rendered_prompt_sha256": _sha(f"repair-rendered-{primary.request.request_id}"),
            "hearing_context_sha256": _sha(f"repair-context-{primary.request.request_id}"),
            "media": (),
            "original_request_id": primary.request.request_id,
            "original_response_id": primary.response.response_id,
            "original_response_content_sha256": primary.response.content_sha256,
            "repair_context_sha256": _sha(f"repair-authority-{primary.response.response_id}"),
            "budget": primary.request.budget.model_copy(
                update={"max_images": 0, "max_input_pixels": 0}
            ),
        }
    )
    repair_request = HearingModelRequest.model_validate(request_payload)
    parse_defect = ProceduralDefect(
        code=ProceduralDefectCode.MALFORMED_STRUCTURE,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.MALFORMED_JSON,
        artifact_ref=primary.response_ref,
        field=ProceduralField.JSON_ROOT,
    )
    primary_parse_payload = primary.parse_receipt.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    primary_parse_payload.update(
        {
            "status": ModelParseStatus.REPAIR_REQUIRED,
            "defects": (parse_defect,),
            "parsed_payload_sha256": None,
            "repair_request_id": repair_request.request_id,
        }
    )
    failed_primary = HearingCallClosure(
        request=primary.request,
        response=primary.response,
        parse_receipt=HearingModelParseReceipt.model_validate(primary_parse_payload),
        usage=primary.usage,
    )
    repair_content_sha256 = _sha(f"repair-response-{repair_request.request_id}")
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
        size_bytes=80,
        input_tokens=5,
        output_tokens=6,
        latency_ms=2,
        model_manifest_id=repair_request.model_manifest_id,
        manifest_id=MANIFEST_ID,
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
        parsed_payload_sha256=payload.payload_sha256,
        manifest_id=MANIFEST_ID,
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
        estimated_cost=repair_request.budget.estimate_cost(
            input_tokens=repair_response.input_tokens,
            output_tokens=repair_response.output_tokens,
        ),
        manifest_id=MANIFEST_ID,
    )
    repaired = HearingCallClosure(
        request=repair_request,
        response=repair_response,
        parse_receipt=repair_parse,
        usage=repair_usage,
    )
    return HearingCallTrace(calls=(failed_primary, repaired))


def _acquisition_payload(cycle: int) -> AcquisitionRequestPayload:
    return AcquisitionRequestPayload(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        validated_parameters=RequestMoreFramesParameters(
            action=AcquisitionAction.REQUEST_MORE_FRAMES,
            camera_id="camera-01",
            stream_id="stream-01",
            start_frame=cycle * 10,
            end_frame_exclusive=cycle * 10 + 1,
        ),
        reason_summary="One additional typed frame may resolve the visible ambiguity.",
    )


def _acquisition_request(
    checkpoint: HearingCheckpoint,
    judge_output: HearingRoleOutput,
    payload: AcquisitionRequestPayload,
) -> AcquisitionRequest:
    return AcquisitionRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=checkpoint.hearing_session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        source_judge_output_id=judge_output.output_id,
        source_model_request_ref=judge_output.request_ref,
        source_model_response_ref=judge_output.response_ref,
        request_payload=payload,
        manifest_id=MANIFEST_ID,
    )


def _tool_receipt(request: AcquisitionRequest) -> ToolExecutionReceipt:
    execution = ToolExecutionManifest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=request.hearing_session_id,
        acquisition_request_id=request.request_id,
        action=request.action,
        tool_id="request-more-frames",
        tool_revision="tool-v1",
        parameters_schema_sha256=_sha("request-more-frames-schema"),
        component_manifest_id=_sha("request-more-frames-component"),
        manifest_id=MANIFEST_ID,
    )
    parameters = request.validated_parameters
    assert isinstance(parameters, RequestMoreFramesParameters)
    input_refs = (
        ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=request.current_evidence_pack_id,
        ),
    )
    output_refs = (
        ArtifactRef(
            kind=ArtifactKind.FRAME,
            artifact_id=f"{parameters.camera_id}:{parameters.stream_id}:{parameters.start_frame}",
        ),
    )
    result = ToolResult(
        tool_result_id=derive_m4_tool_result_id(
            request.action,
            input_refs,
            output_refs,
            parameters,
            execution.execution_manifest_id,
        ),
        action=request.action,
        input_refs=input_refs,
        output_refs=output_refs,
        validated_parameters=parameters,
        execution_manifest_id=execution.execution_manifest_id,
    )
    return ToolExecutionReceipt(
        request=request,
        execution_manifest=execution,
        tool_result=result,
        resulting_evidence_pack_id=_sha(f"pack-after-cycle-{request.round_index}"),
        resulting_evidence_pack_version=request.current_evidence_pack_version + 1,
    )


def _complete_role_cycle(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    *,
    decision: VerdictDecision = VerdictDecision.ESTABLISHED,
    acquire: bool = False,
    include_judge_response: bool = True,
) -> tuple[HearingCheckpoint, HearingRound | None]:
    retrieval = _retrieval(session, checkpoint)
    checkpoint = complete_precedent_retrieval(session, checkpoint, retrieval)
    acquisition_payload = _acquisition_payload(checkpoint.judge_cycle) if acquire else None
    prosecutor_payload, defender_payload, judge_payload = _payloads(
        evidence_ref=_ref(
            ArtifactKind.CROP,
            f"cycle-{checkpoint.judge_cycle}-visible-crop",
        ),
        decision=decision,
        acquisition_payload=acquisition_payload,
        include_judge_response=include_judge_response,
    )
    prosecutor, prosecutor_trace = _role_output(
        session,
        checkpoint,
        retrieval,
        prosecutor_payload,
    )
    checkpoint = complete_prosecutor(session, checkpoint, prosecutor, prosecutor_trace)
    defender, defender_trace = _role_output(
        session,
        checkpoint,
        retrieval,
        defender_payload,
        prosecutor_output_id=prosecutor.output_id,
    )
    checkpoint = complete_defender(session, checkpoint, defender, defender_trace)
    judge, judge_trace = _role_output(
        session,
        checkpoint,
        retrieval,
        judge_payload,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    request = (
        build_acquisition_request(session, checkpoint, judge)
        if acquisition_payload is not None
        and checkpoint.prior_acquisition_rounds < session.acquisition_round_limit
        else None
    )
    transition = complete_judge(
        session,
        checkpoint,
        judge,
        judge_trace,
        acquisition_request=request,
    )
    checkpoint = transition.checkpoint
    if checkpoint.phase == HearingCheckpointPhase.HUMAN_REVIEW:
        return checkpoint, None
    if request is not None:
        checkpoint = complete_acquisition(session, checkpoint, _tool_receipt(request))
    assert checkpoint.prosecutor_output is not None
    assert checkpoint.defender_output is not None
    assert checkpoint.judge_output is not None
    round_ = HearingRound(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        precedent_retrieval_degraded=True,
        precedent_retrieval_receipt=retrieval,
        initial_trigger_review_ref=checkpoint.initial_trigger_review_ref,
        initial_defect_codes=checkpoint.initial_defect_codes,
        rework_review_ref=checkpoint.cycle_trigger_review_ref,
        rework_defect_codes=checkpoint.cycle_trigger_defect_codes,
        prosecutor_output=checkpoint.prosecutor_output,
        defender_output=checkpoint.defender_output,
        judge_output=checkpoint.judge_output,
        acquisition_request=checkpoint.acquisition_request,
        tool_execution_receipt=checkpoint.tool_execution_receipt,
        manifest_id=MANIFEST_ID,
    )
    return checkpoint, round_


def _record(
    session: HearingSession,
    rounds: tuple[HearingRound, ...],
    checkpoints: tuple[HearingCheckpoint, ...],
) -> HearingRecord:
    request_refs = tuple(
        sorted(
            (ref for checkpoint in checkpoints for ref in checkpoint.model_request_refs),
            key=lambda ref: ref.sort_key,
        )
    )
    response_refs = tuple(
        sorted(
            (ref for checkpoint in checkpoints for ref in checkpoint.model_response_refs),
            key=lambda ref: ref.sort_key,
        )
    )
    parse_refs = tuple(
        sorted(
            (ref for checkpoint in checkpoints for ref in checkpoint.parse_receipt_refs),
            key=lambda ref: ref.sort_key,
        )
    )
    usage = tuple(
        sorted(
            (item for checkpoint in checkpoints for item in checkpoint.usage_receipts),
            key=lambda item: (
                item.round_index,
                item.role.value,
                item.request_ref.artifact_id,
            ),
        )
    )
    return HearingRecord(
        run_id=RUN_ID,
        case_id=CASE_ID,
        version=len(rounds),
        session=session,
        screening_id=SCREENING_ID,
        initial_evidence_pack_id=INITIAL_PACK_ID,
        initial_evidence_pack_version=1,
        acquisition_round_limit=2,
        rework_round_limit=2,
        rounds=rounds,
        model_request_refs=request_refs,
        model_response_refs=response_refs,
        parse_receipt_refs=parse_refs,
        usage_receipts=usage,
        manifest_id=MANIFEST_ID,
    )


def _review_closure(
    session: HearingSession,
    rounds: tuple[HearingRound, ...],
    checkpoints: tuple[HearingCheckpoint, ...],
    label: str,
    *,
    passed: bool = False,
) -> HearingReviewClosure:
    record = _record(session, rounds, checkpoints)
    verdict, binding = build_hearing_verdict(
        record,
        VIOLATION,
        version=len(rounds),
    )
    defects = (
        ()
        if passed
        else (
            ProceduralDefect(
                code=ProceduralDefectCode.UNANSWERED_DEFENSE_POINT,
                origin=ProceduralDefectOrigin.PROCEDURAL_GATE,
                reason_code=ProceduralReasonCode.DEFENSE_RESPONSE_CARDINALITY,
                artifact_ref=ArtifactRef(
                    kind=ArtifactKind.VERDICT,
                    artifact_id=verdict.verdict_id,
                ),
                field=ProceduralField.DEFENSE_ARGUMENTS,
                value_sha256=_sha(f"{label}-unanswered-defense"),
            ),
        )
    )
    review = ProceduralReview(
        run_id=RUN_ID,
        case_id=CASE_ID,
        version=len(rounds),
        evidence_pack_id=verdict.evidence_pack_id,
        evidence_pack_version=verdict.evidence_pack_version,
        reviewed_verdict_id=verdict.verdict_id,
        reviewed_verdict_version=verdict.version,
        reviewed_verdict_sha256=verdict.verdict_sha256,
        gate_version="procedural-gate-v1",
        defects=defects,
        manifest_id=MANIFEST_ID,
    )
    return HearingReviewClosure(
        record=record,
        verdict=verdict,
        binding=binding,
        review=review,
    )


def test_normal_final_builds_exact_verdict_and_binding() -> None:
    session = _session()
    checkpoint, round_ = _complete_role_cycle(session, begin_hearing(session))
    assert round_ is not None
    record = _record(session, (round_,), (checkpoint,))

    verdict, binding = build_hearing_verdict(record, VIOLATION)

    assert checkpoint.phase == HearingCheckpointPhase.ROUND_COMPLETE
    assert checkpoint.acquisition_request is None
    assert checkpoint.tool_execution_receipt is None
    assert verdict.decision == VerdictDecision.ESTABLISHED
    assert verdict.prosecution_arguments == round_.prosecutor_output.payload.arguments
    assert verdict.defense_arguments == round_.defender_output.payload.arguments
    assert verdict.model_response_refs == record.model_response_refs
    assert binding.model_request_refs == record.model_request_refs
    assert binding.model_response_refs == record.model_response_refs
    assert binding.parse_receipt_refs == record.parse_receipt_refs
    validate_hearing_verdict_binding(record, verdict, binding, violation_type=VIOLATION)


def test_initial_rework_trigger_binds_first_cycle_then_is_cleared() -> None:
    initial_review = _ref(ArtifactKind.PROCEDURAL_REVIEW, "initial-failed-review")
    initial_codes = (ProceduralDefectCode.UNANSWERED_DEFENSE_POINT,)
    session = _session(
        entry_status=HearingSessionEntryStatus.REWORK_REQUIRED,
        initial_trigger_review_ref=initial_review,
        initial_defect_codes=initial_codes,
    )
    opened = begin_hearing(session)

    acquired, hearing_round = _complete_role_cycle(session, opened, acquire=True)

    assert hearing_round is not None
    assert hearing_round.initial_trigger_review_ref == initial_review
    assert hearing_round.initial_defect_codes == initial_codes
    assert hearing_round.precedent_retrieval_receipt.initial_trigger_review_ref == initial_review
    assert hearing_round.prosecutor_output.initial_trigger_review_ref == initial_review
    assert hearing_round.defender_output.initial_trigger_review_ref == initial_review
    assert hearing_round.judge_output.initial_trigger_review_ref == initial_review
    next_cycle = start_cycle_after_acquisition(session, acquired).checkpoint
    assert next_cycle.initial_trigger_review_ref is None
    assert next_cycle.initial_defect_codes == ()


def test_checkpoint_lineage_and_in_cycle_call_trace_are_exact_prefixes() -> None:
    session = _session()
    opened = begin_hearing(session)
    retrieval = _retrieval(session, opened)
    prosecutor_pending = complete_precedent_retrieval(session, opened, retrieval)
    _assert_successor(opened, prosecutor_pending)

    prosecutor_payload, defender_payload, judge_payload = _payloads(
        evidence_ref=_ref(ArtifactKind.CROP, "cycle-1-visible-crop")
    )
    prosecutor, prosecutor_trace = _role_output(
        session,
        prosecutor_pending,
        retrieval,
        prosecutor_payload,
    )
    defender_pending = complete_prosecutor(
        session,
        prosecutor_pending,
        prosecutor,
        prosecutor_trace,
    )
    _assert_successor(prosecutor_pending, defender_pending)
    assert defender_pending.model_request_refs == prosecutor_trace.model_request_refs

    defender, defender_trace = _role_output(
        session,
        defender_pending,
        retrieval,
        defender_payload,
        prosecutor_output_id=prosecutor.output_id,
    )
    judge_pending = complete_defender(
        session,
        defender_pending,
        defender,
        defender_trace,
    )
    _assert_successor(defender_pending, judge_pending)
    assert set(defender_pending.model_request_refs) < set(judge_pending.model_request_refs)
    assert set(defender_pending.model_response_refs) < set(judge_pending.model_response_refs)
    assert set(defender_pending.parse_receipt_refs) < set(judge_pending.parse_receipt_refs)

    judge, judge_trace = _role_output(
        session,
        judge_pending,
        retrieval,
        judge_payload,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    invalid_acquisition = _acquisition_request(
        judge_pending,
        judge,
        _acquisition_payload(judge_pending.judge_cycle),
    )
    with pytest.raises(HearingTransitionError, match="FINAL"):
        complete_judge(
            session,
            judge_pending,
            judge,
            judge_trace,
            acquisition_request=invalid_acquisition,
        )
    complete = complete_judge(session, judge_pending, judge, judge_trace).checkpoint
    _assert_successor(judge_pending, complete)
    assert set(judge_pending.model_request_refs) < set(complete.model_request_refs)
    assert set(judge_pending.model_response_refs) < set(complete.model_response_refs)
    assert set(judge_pending.parse_receipt_refs) < set(complete.parse_receipt_refs)
    assert tuple(
        checkpoint.version
        for checkpoint in (opened, prosecutor_pending, defender_pending, judge_pending, complete)
    ) == (1, 2, 3, 4, 5)


def test_typed_call_closure_rejects_usage_or_response_drift() -> None:
    session = _session()
    opened = begin_hearing(session)
    retrieval = _retrieval(session, opened)
    checkpoint = complete_precedent_retrieval(session, opened, retrieval)
    prosecutor_payload, _, _ = _payloads(
        evidence_ref=_ref(ArtifactKind.CROP, "cycle-1-visible-crop")
    )
    _, trace = _role_output(session, checkpoint, retrieval, prosecutor_payload)
    call = trace.successful_call

    with pytest.raises(ValueError, match="usage does not exactly account"):
        HearingCallClosure(
            request=call.request,
            response=call.response,
            parse_receipt=call.parse_receipt,
            usage=call.usage.model_copy(update={"input_pixels": 101}),
        )
    with pytest.raises(ValueError, match="usage does not exactly account"):
        HearingCallClosure(
            request=call.request,
            response=call.response.model_copy(update={"latency_ms": 2}),
            parse_receipt=call.parse_receipt,
            usage=call.usage,
        )


def test_typed_repair_trace_is_media_free_and_only_terminal_call_can_back_output() -> None:
    session = _session()
    opened = begin_hearing(session)
    retrieval = _retrieval(session, opened)
    checkpoint = complete_precedent_retrieval(session, opened, retrieval)
    prosecutor_payload, _, _ = _payloads(
        evidence_ref=_ref(ArtifactKind.CROP, "cycle-1-visible-crop")
    )
    primary_output, primary_trace = _role_output(
        session,
        checkpoint,
        retrieval,
        prosecutor_payload,
    )
    repaired_trace = _repair_trace(primary_trace.successful_call, prosecutor_payload)
    repair = repaired_trace.successful_call

    assert repair.request.attempt_index == 1
    assert repair.request.media == ()
    assert repair.usage.input_images == 0
    assert repair.usage.input_pixels == 0
    with pytest.raises(HearingTransitionError, match="not closed"):
        complete_prosecutor(session, checkpoint, primary_output, repaired_trace)

    repaired_output = primary_output.model_copy(
        update={
            "request_ref": repair.request_ref,
            "response_ref": repair.response_ref,
            "parse_receipt_ref": repair.parse_receipt_ref,
        }
    )
    advanced = complete_prosecutor(session, checkpoint, repaired_output, repaired_trace)
    assert advanced.phase == HearingCheckpointPhase.DEFENDER_PENDING
    assert len(advanced.model_request_refs) == 2
    assert len(advanced.model_response_refs) == 2
    assert len(advanced.parse_receipt_refs) == 2


def test_human_transfer_dispatch_rejects_wrong_phase_and_binds_exact_backlog_role() -> None:
    session = _session()
    opened = begin_hearing(session)
    evidence_exit = transfer_to_human_review(
        session,
        opened,
        HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
    )
    assert evidence_exit.checkpoint.phase == HearingCheckpointPhase.HUMAN_REVIEW
    assert evidence_exit.human_review_receipt is not None

    prosecutor_pending = complete_precedent_retrieval(
        session,
        opened,
        _retrieval(session, opened),
    )
    with pytest.raises(HearingTransitionError, match="not allowed from this phase"):
        transfer_to_human_review(
            session,
            prosecutor_pending,
            HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
        )
    backlog = BacklogItem(
        run_id=RUN_ID,
        case_id=CASE_ID,
        stage=BacklogStage.HEARING,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=INITIAL_PACK_ID,
        ),
        stage_input_sha256=_sha("initial-pack-document"),
        attempt_count=1,
        max_attempts=1,
        status=BacklogStatus.EXHAUSTED,
        manifest_id=MANIFEST_ID,
    )
    backlog_exit = transfer_to_human_review(
        session,
        prosecutor_pending,
        HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED,
        backlog_item=backlog,
    )
    assert backlog_exit.human_review_receipt is not None
    assert backlog_exit.human_review_receipt.backlog_item_ref == ArtifactRef(
        kind=ArtifactKind.BACKLOG_ITEM,
        artifact_id=backlog.item_id,
    )

    with pytest.raises(HearingTransitionError, match="owned by the exact Judge"):
        transfer_to_human_review(
            session,
            prosecutor_pending,
            HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED,
            acquisition_request_ref=_ref(ArtifactKind.MODEL_REQUEST, "forged-judge-request"),
        )


def test_acquisition_then_final_preserves_global_log_and_all_call_refs() -> None:
    session = _session()
    acquired, round_one = _complete_role_cycle(
        session,
        begin_hearing(session),
        acquire=True,
    )
    assert round_one is not None
    next_cycle = start_cycle_after_acquisition(session, acquired).checkpoint
    _assert_successor(acquired, next_cycle)
    assert next_cycle.current_evidence_pack_id == (
        round_one.tool_execution_receipt.resulting_evidence_pack_id
    )
    assert next_cycle.current_evidence_pack_version == (
        round_one.tool_execution_receipt.resulting_evidence_pack_version
    )
    assert next_cycle.cycle_evidence_pack_id == next_cycle.current_evidence_pack_id
    assert next_cycle.cycle_evidence_pack_version == next_cycle.current_evidence_pack_version
    assert next_cycle.cycle_trigger_review_ref == acquired.cycle_trigger_review_ref
    assert next_cycle.cycle_trigger_defect_codes == acquired.cycle_trigger_defect_codes
    final, round_two = _complete_role_cycle(session, next_cycle)
    assert round_two is not None
    record = _record(session, (round_one, round_two), (acquired, final))

    verdict, binding = build_hearing_verdict(record, VIOLATION)

    assert verdict.evidence_pack_id == round_two.current_evidence_pack_id
    assert len(verdict.acquisition_log) == 1
    assert verdict.acquisition_log[0].round_index == 1
    assert verdict.acquisition_log[0].tool_result_ref == ArtifactRef(
        kind=ArtifactKind.TOOL_RESULT,
        artifact_id=round_one.tool_execution_receipt.tool_result.tool_result_id,
    )
    assert len(verdict.model_response_refs) == 6
    assert binding.model_response_refs == record.model_response_refs


def test_binding_preserves_primary_and_structure_repair_call_refs() -> None:
    session = _session()
    checkpoint, round_ = _complete_role_cycle(session, begin_hearing(session))
    assert round_ is not None
    record = _record(session, (round_,), (checkpoint,))
    primary_request = _ref(ArtifactKind.MODEL_REQUEST, "judge-failed-primary-request")
    primary_response = _ref(ArtifactKind.MODEL_RESPONSE, "judge-failed-primary-response")
    primary_parse = _ref(ArtifactKind.MODEL_PARSE_RECEIPT, "judge-failed-primary-parse")
    primary_usage = HearingUsageReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        role=VlmRole.JUDGE,
        request_ref=primary_request,
        response_ref=primary_response,
        input_images=1,
        input_pixels=100,
        input_tokens=10,
        output_tokens=10,
        latency_ms=1,
        retry_count=0,
        estimated_cost=0.01,
        manifest_id=MANIFEST_ID,
    )
    payload = record.model_dump(mode="python", exclude_computed_fields=True)
    payload.update(
        {
            "model_request_refs": tuple(
                sorted((*record.model_request_refs, primary_request), key=lambda ref: ref.sort_key)
            ),
            "model_response_refs": tuple(
                sorted(
                    (*record.model_response_refs, primary_response),
                    key=lambda ref: ref.sort_key,
                )
            ),
            "parse_receipt_refs": tuple(
                sorted((*record.parse_receipt_refs, primary_parse), key=lambda ref: ref.sort_key)
            ),
            "usage_receipts": tuple(
                sorted(
                    (*record.usage_receipts, primary_usage),
                    key=lambda item: (
                        item.round_index,
                        item.role.value,
                        item.request_ref.artifact_id,
                    ),
                )
            ),
        }
    )
    repaired_record = HearingRecord.model_validate(payload)

    verdict, binding = build_hearing_verdict(repaired_record, VIOLATION)

    assert primary_response in verdict.model_response_refs
    assert binding.model_request_refs == repaired_record.model_request_refs
    assert binding.model_response_refs == repaired_record.model_response_refs
    assert binding.parse_receipt_refs == repaired_record.parse_receipt_refs


def test_missing_defense_response_is_preserved_for_l5() -> None:
    session = _session()
    checkpoint, round_ = _complete_role_cycle(
        session,
        begin_hearing(session),
        include_judge_response=False,
    )
    assert round_ is not None
    verdict, binding = build_hearing_verdict(
        _record(session, (round_,), (checkpoint,)),
        VIOLATION,
    )

    assert len(verdict.defense_arguments) == 1
    assert verdict.judge_responses == ()
    assert binding.verdict_id == verdict.verdict_id


def _pending_judge_output(
    session: HearingSession,
    *,
    acquisition_payload: AcquisitionRequestPayload | None,
) -> tuple[HearingCheckpoint, HearingRoleOutput]:
    checkpoint = begin_hearing(session)
    retrieval = _retrieval(session, checkpoint)
    checkpoint = complete_precedent_retrieval(session, checkpoint, retrieval)
    prosecutor_payload, defender_payload, judge_payload = _payloads(
        evidence_ref=_ref(ArtifactKind.CROP, "builder-visible-crop"),
        acquisition_payload=acquisition_payload,
    )
    prosecutor, prosecutor_trace = _role_output(
        session,
        checkpoint,
        retrieval,
        prosecutor_payload,
    )
    checkpoint = complete_prosecutor(session, checkpoint, prosecutor, prosecutor_trace)
    defender, defender_trace = _role_output(
        session,
        checkpoint,
        retrieval,
        defender_payload,
        prosecutor_output_id=prosecutor.output_id,
    )
    checkpoint = complete_defender(session, checkpoint, defender, defender_trace)
    judge, _ = _role_output(
        session,
        checkpoint,
        retrieval,
        judge_payload,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    return checkpoint, judge


def test_acquisition_request_builder_derives_only_the_exact_judge_proposal() -> None:
    session = _session()
    payload = _acquisition_payload(1)
    checkpoint, judge = _pending_judge_output(
        session,
        acquisition_payload=payload,
    )

    request = build_acquisition_request(session, checkpoint, judge)

    assert request.request_payload is judge.payload.outcome.request
    assert request.source_judge_output_id == judge.output_id
    assert request.source_model_request_ref == judge.request_ref
    assert request.source_model_response_ref == judge.response_ref
    assert request.current_evidence_pack_id == checkpoint.cycle_evidence_pack_id
    assert request.manifest_id == session.manifest_id


def test_acquisition_request_builder_rejects_final_or_drifted_judge_output() -> None:
    session = _session()
    checkpoint, final_judge = _pending_judge_output(
        session,
        acquisition_payload=None,
    )
    with pytest.raises(AcquisitionRequestBuildError) as terminal_error:
        build_acquisition_request(session, checkpoint, final_judge)
    assert (
        terminal_error.value.reason_code
        == AcquisitionRequestBuildFailureCode.JUDGE_OUTCOME_NOT_ACQUISITION
    )

    checkpoint, acquisition_judge = _pending_judge_output(
        session,
        acquisition_payload=_acquisition_payload(1),
    )
    drifted = acquisition_judge.model_copy(
        update={"prosecutor_output_id": _sha("wrong-prosecutor-output")}
    )
    with pytest.raises(AcquisitionRequestBuildError) as drift_error:
        build_acquisition_request(session, checkpoint, drifted)
    assert (
        drift_error.value.reason_code
        == AcquisitionRequestBuildFailureCode.JUDGE_OUTPUT_BINDING_MISMATCH
    )


def test_two_reworks_then_third_failed_review_moves_to_typed_human_review() -> None:
    session = _session()
    checkpoint = begin_hearing(session)
    rounds: list[HearingRound] = []
    checkpoints: list[HearingCheckpoint] = []
    for index in range(3):
        checkpoint, hearing_round = _complete_role_cycle(session, checkpoint)
        assert hearing_round is not None
        rounds.append(hearing_round)
        checkpoints.append(checkpoint)
        closure = _review_closure(
            session,
            tuple(rounds),
            tuple(checkpoints),
            f"failed-review-{index}",
        )
        checkpoint = record_procedural_review(session, checkpoint, closure)
        assert checkpoint.phase == HearingCheckpointPhase.REWORK_READY
        source = checkpoint
        transition = start_rework_cycle(session, checkpoint, closure)
        checkpoint = transition.checkpoint
        _assert_successor(source, checkpoint)
        if index < 2:
            assert transition.human_review_receipt is None
            assert checkpoint.phase == HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING
            assert checkpoint.prior_rework_rounds == index + 1
            assert checkpoint.cycle_trigger_review_ref == ArtifactRef(
                kind=ArtifactKind.PROCEDURAL_REVIEW,
                artifact_id=closure.review.review_id,
            )
            assert checkpoint.cycle_trigger_defect_codes == tuple(
                defect.code for defect in closure.review.defects
            )
        else:
            assert transition.human_review_receipt is not None
            assert checkpoint.phase == HearingCheckpointPhase.HUMAN_REVIEW
            assert transition.human_review_receipt.reason == (
                HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED
            )
            assert transition.human_review_receipt.source_checkpoint_id == source.checkpoint_id
            assert (
                transition.human_review_receipt.source_checkpoint_sha256 == source.checkpoint_sha256
            )
            assert transition.human_review_receipt.source_checkpoint_version == source.version
            assert checkpoint.judge_cycle == 3


def test_passed_review_can_only_complete_and_cannot_start_rework() -> None:
    session = _session()
    checkpoint, hearing_round = _complete_role_cycle(session, begin_hearing(session))
    assert hearing_round is not None
    closure = _review_closure(
        session,
        (hearing_round,),
        (checkpoint,),
        "passed-review",
        passed=True,
    )

    complete = record_procedural_review(session, checkpoint, closure)

    assert closure.review.passed is True
    assert complete.phase == HearingCheckpointPhase.COMPLETE
    assert complete.procedural_review_ref == ArtifactRef(
        kind=ArtifactKind.PROCEDURAL_REVIEW,
        artifact_id=closure.review.review_id,
    )
    with pytest.raises(HearingTransitionError, match="expected REWORK_READY"):
        start_rework_cycle(session, complete, closure)


def test_rework_trigger_survives_an_acquisition_cycle_without_substitution() -> None:
    session = _session()
    first_complete, first_round = _complete_role_cycle(session, begin_hearing(session))
    assert first_round is not None
    closure = _review_closure(
        session,
        (first_round,),
        (first_complete,),
        "rework-before-acquisition",
    )
    reviewed = record_procedural_review(session, first_complete, closure)
    rework_cycle = start_rework_cycle(session, reviewed, closure).checkpoint
    trigger_ref = rework_cycle.cycle_trigger_review_ref
    trigger_codes = rework_cycle.cycle_trigger_defect_codes

    acquired, acquired_round = _complete_role_cycle(session, rework_cycle, acquire=True)
    assert acquired_round is not None
    continued = start_cycle_after_acquisition(session, acquired).checkpoint

    assert continued.prior_rework_rounds == 1
    assert continued.prior_acquisition_rounds == 1
    assert continued.judge_cycle == 3
    assert continued.cycle_trigger_review_ref == trigger_ref
    assert continued.cycle_trigger_defect_codes == trigger_codes


def test_third_acquisition_proposal_goes_human_without_round_or_cycle_four() -> None:
    session = _session()
    checkpoint = begin_hearing(session)
    for expected_used in (1, 2):
        checkpoint, round_ = _complete_role_cycle(session, checkpoint, acquire=True)
        assert round_ is not None
        checkpoint = start_cycle_after_acquisition(session, checkpoint).checkpoint
        assert checkpoint.prior_acquisition_rounds == expected_used

    checkpoint, forbidden_round = _complete_role_cycle(session, checkpoint, acquire=True)

    assert forbidden_round is None
    assert checkpoint.phase == HearingCheckpointPhase.HUMAN_REVIEW
    assert checkpoint.human_review_receipt_id is not None
    assert checkpoint.acquisition_request is None
    assert checkpoint.tool_execution_receipt is None
    assert checkpoint.judge_cycle == 3


def test_additive_global_budgets_reach_cycle_five_but_never_cycle_six() -> None:
    session = _session()
    checkpoint = begin_hearing(session)
    rounds: list[HearingRound] = []
    checkpoints: list[HearingCheckpoint] = []
    for _ in range(2):
        checkpoint, hearing_round = _complete_role_cycle(session, checkpoint, acquire=True)
        assert hearing_round is not None
        rounds.append(hearing_round)
        checkpoints.append(checkpoint)
        checkpoint = start_cycle_after_acquisition(session, checkpoint).checkpoint

    for rework_index in range(3):
        checkpoint, hearing_round = _complete_role_cycle(session, checkpoint)
        assert hearing_round is not None
        rounds.append(hearing_round)
        checkpoints.append(checkpoint)
        closure = _review_closure(
            session,
            tuple(rounds),
            tuple(checkpoints),
            f"mixed-failed-review-{rework_index}",
        )
        checkpoint = record_procedural_review(session, checkpoint, closure)
        transition = start_rework_cycle(session, checkpoint, closure)
        checkpoint = transition.checkpoint

    assert checkpoint.phase == HearingCheckpointPhase.HUMAN_REVIEW
    assert checkpoint.prior_acquisition_rounds == 2
    assert checkpoint.prior_rework_rounds == 2
    assert checkpoint.judge_cycle == 5
    assert transition.human_review_receipt is not None
    assert transition.human_review_receipt.reason == (
        HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED
    )


def test_insufficient_evidence_decision_is_not_rewritten() -> None:
    session = _session()
    checkpoint, round_ = _complete_role_cycle(
        session,
        begin_hearing(session),
        decision=VerdictDecision.INSUFFICIENT_EVIDENCE,
    )
    assert round_ is not None

    verdict, _ = build_hearing_verdict(
        _record(session, (round_,), (checkpoint,)),
        VIOLATION,
    )

    assert verdict.decision == VerdictDecision.INSUFFICIENT_EVIDENCE


def test_binding_tamper_is_rejected_even_when_model_copy_bypasses_validation() -> None:
    session = _session()
    checkpoint, round_ = _complete_role_cycle(session, begin_hearing(session))
    assert round_ is not None
    record = _record(session, (round_,), (checkpoint,))
    verdict, binding = build_hearing_verdict(record, VIOLATION)
    tampered = binding.model_copy(update={"judge_round_id": _sha("forged-round")})

    with pytest.raises(HearingVerdictBuildError, match="does not exactly match"):
        validate_hearing_verdict_binding(record, verdict, tampered)

    closure = _review_closure(
        session,
        (round_,),
        (checkpoint,),
        "binding-tamper-review",
    )._replace(binding=tampered)
    with pytest.raises(HearingTransitionError, match="does not exactly match"):
        record_procedural_review(session, checkpoint, closure)


def _unchecked_call(
    source: HearingCallClosure,
    **updates: object,
) -> HearingCallClosure:
    """Forge a typed in-memory closure to exercise the FSM's trust-boundary guards."""

    forged = object.__new__(HearingCallClosure)
    for name in ("request", "response", "parse_receipt", "usage"):
        object.__setattr__(forged, name, updates.get(name, getattr(source, name)))
    return forged


def _unchecked_trace(*calls: HearingCallClosure) -> HearingCallTrace:
    forged = object.__new__(HearingCallTrace)
    object.__setattr__(forged, "calls", calls)
    return forged


def _unchecked_model_copy(model: object, **updates: object) -> object:
    payload = dict(model.__dict__)
    payload.update(updates)
    return type(model).model_construct(**payload)  # type: ignore[attr-defined,no-any-return]


def _prosecutor_authority() -> tuple[
    HearingSession,
    HearingCheckpoint,
    HearingPrecedentRetrievalReceipt,
    HearingRoleOutput,
    HearingCallTrace,
]:
    session = _session()
    opened = begin_hearing(session)
    retrieval = _retrieval(session, opened)
    checkpoint = complete_precedent_retrieval(session, opened, retrieval)
    payload, _, _ = _payloads(evidence_ref=_ref(ArtifactKind.CROP, "cycle-1-visible-crop"))
    output, trace = _role_output(session, checkpoint, retrieval, payload)
    return session, checkpoint, retrieval, output, trace


@pytest.mark.parametrize("field", ("request", "response", "parse_receipt", "usage"))
def test_call_closure_rejects_untyped_members(field: str) -> None:
    _, _, _, _, trace = _prosecutor_authority()
    call = trace.successful_call
    values: dict[str, object] = {
        "request": call.request,
        "response": call.response,
        "parse_receipt": call.parse_receipt,
        "usage": call.usage,
    }
    values[field] = object()

    with pytest.raises(TypeError, match=f"call closure {field.replace('_', ' ')}"):
        HearingCallClosure(**values)  # type: ignore[arg-type]


def test_call_closure_rejects_scope_binding_and_budget_drift() -> None:
    _, _, _, _, trace = _prosecutor_authority()
    call = trace.successful_call

    with pytest.raises(ValueError, match="one exact scope"):
        HearingCallClosure(
            request=call.request,
            response=call.response.model_copy(update={"case_id": "other-case"}),
            parse_receipt=call.parse_receipt,
            usage=call.usage,
        )
    with pytest.raises(ValueError, match="conflicts with its exact request"):
        HearingCallClosure(
            request=call.request,
            response=_unchecked_model_copy(
                call.response,
                request_id=_sha("other-request"),
            ),
            parse_receipt=call.parse_receipt,
            usage=call.usage,
        )  # type: ignore[arg-type]

    oversized_response = call.response.model_copy(update={"input_tokens": 101})
    oversized_usage = call.usage.model_copy(
        update={
            "input_tokens": 101,
            "estimated_cost": call.request.budget.estimate_cost(
                input_tokens=101,
                output_tokens=oversized_response.output_tokens,
            ),
        }
    )
    with pytest.raises(ValueError, match="exceeds its request-bound budget"):
        HearingCallClosure(
            request=call.request,
            response=oversized_response,
            parse_receipt=call.parse_receipt,
            usage=oversized_usage,
        )


def test_repair_closure_rejects_media_even_after_contract_bypass() -> None:
    _, _, _, output, primary_trace = _prosecutor_authority()
    repaired_trace = _repair_trace(primary_trace.successful_call, output.payload)
    repair = repaired_trace.successful_call
    forged_request = _unchecked_model_copy(
        repair.request,
        media=primary_trace.successful_call.request.media,
    )
    forged_response = _unchecked_model_copy(
        repair.response,
        request_id=forged_request.request_id,
        request_sha256=forged_request.request_sha256,
        cache_key=forged_request.cache_key,
    )
    forged_parse = _unchecked_model_copy(
        repair.parse_receipt,
        request_id=forged_request.request_id,
        request_sha256=forged_request.request_sha256,
        response_id=forged_response.response_id,
    )
    forged_usage = _unchecked_model_copy(
        repair.usage,
        request_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=forged_request.request_id,
        ),
        response_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=forged_response.response_id,
        ),
        input_images=1,
        input_pixels=100,
    )

    with pytest.raises(ValueError, match="repair must disclose zero media"):
        HearingCallClosure(
            request=forged_request,
            response=forged_response,
            parse_receipt=forged_parse,
            usage=forged_usage,
        )  # type: ignore[arg-type]


def test_call_trace_rejects_shape_sequence_terminal_and_repair_authority_drift() -> None:
    _, _, _, output, primary_trace = _prosecutor_authority()
    primary = primary_trace.successful_call
    repaired_trace = _repair_trace(primary, output.payload)
    failed_primary, repair = repaired_trace.calls

    with pytest.raises(ValueError, match="one primary"):
        HearingCallTrace(calls=())
    with pytest.raises(ValueError, match="primary then optional repair"):
        HearingCallTrace(calls=(primary, primary))
    with pytest.raises(ValueError, match="must end in a strict parsed result"):
        HearingCallTrace(calls=(failed_primary,))

    changed_scope = _unchecked_call(
        repair,
        request=repair.request.model_copy(update={"provider": "different-provider"}),
    )
    with pytest.raises(ValueError, match="changed primary call authority"):
        HearingCallTrace(calls=(failed_primary, changed_scope))

    wrong_repair_binding = _unchecked_call(
        failed_primary,
        parse_receipt=failed_primary.parse_receipt.model_copy(
            update={"repair_request_id": _sha("wrong-repair")}
        ),
    )
    with pytest.raises(ValueError, match="lacks exact primary failure authority"):
        HearingCallTrace(calls=(wrong_repair_binding, repair))


def test_transition_pair_and_session_guards_reject_forged_typed_objects() -> None:
    session = _session()
    opened = begin_hearing(session)
    human = transfer_to_human_review(
        session,
        opened,
        HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
    )
    assert human.human_review_receipt is not None

    with pytest.raises(ValueError, match="must be returned together"):
        hearing_fsm.HearingTransition(checkpoint=human.checkpoint)
    with pytest.raises(ValueError, match="conflicts with its returned receipt"):
        hearing_fsm.HearingTransition(
            checkpoint=human.checkpoint.model_copy(
                update={"human_review_receipt_id": _sha("forged-receipt")}
            ),
            human_review_receipt=human.human_review_receipt,
        )

    with pytest.raises(TypeError, match="session must be"):
        hearing_fsm._validate_session(object(), opened)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="checkpoint must be"):
        hearing_fsm._validate_session(session, object())  # type: ignore[arg-type]
    with pytest.raises(HearingTransitionError, match="outside the supplied"):
        hearing_fsm._validate_session(
            session,
            opened.model_copy(update={"case_id": "other-case"}),
        )
    with pytest.raises(HearingTransitionError, match="immutable session budget"):
        hearing_fsm._validate_session(
            session,
            _unchecked_model_copy(
                opened,
                judge_cycle=session.max_total_judge_cycles + 1,
            ),
        )  # type: ignore[arg-type]
    with pytest.raises(HearingTransitionError, match="counters exceed"):
        hearing_fsm._validate_session(
            session,
            _unchecked_model_copy(
                opened,
                prior_acquisition_rounds=session.acquisition_round_limit + 1,
            ),
        )  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="session must be"):
        begin_hearing(object())  # type: ignore[arg-type]


def test_precedent_retrieval_rejects_untyped_and_cross_cycle_authority() -> None:
    session = _session()
    opened = begin_hearing(session)

    with pytest.raises(TypeError, match="receipt must be"):
        complete_precedent_retrieval(
            session,
            opened,
            object(),  # type: ignore[arg-type]
        )
    with pytest.raises(HearingTransitionError, match="exact hearing cycle"):
        complete_precedent_retrieval(
            session,
            opened,
            _retrieval(session, opened).model_copy(update={"case_id": "other-case"}),
        )


def test_role_scope_guards_reject_role_model_retrieval_request_and_usage_drift() -> None:
    session, checkpoint, _, output, trace = _prosecutor_authority()

    with pytest.raises(TypeError, match="trace must be"):
        hearing_fsm._validate_trace_scope(
            session,
            checkpoint,
            object(),  # type: ignore[arg-type]
            VlmRole.PROSECUTOR,
            output,
        )
    with pytest.raises(TypeError, match="output must be"):
        hearing_fsm._validate_trace_scope(
            session,
            checkpoint,
            trace,
            VlmRole.PROSECUTOR,
            object(),  # type: ignore[arg-type]
        )
    with pytest.raises(HearingTransitionError, match="transition role"):
        hearing_fsm._validate_trace_scope(
            session,
            checkpoint,
            trace,
            VlmRole.DEFENDER,
            output,
        )
    with pytest.raises(HearingTransitionError, match="session model or prompt"):
        hearing_fsm._validate_trace_scope(
            session,
            checkpoint,
            trace,
            VlmRole.PROSECUTOR,
            output.model_copy(update={"model_manifest_id": _sha("wrong-model")}),
        )
    with pytest.raises(HearingTransitionError, match="precedent retrieval authority"):
        hearing_fsm._validate_trace_scope(
            session,
            checkpoint,
            trace,
            VlmRole.PROSECUTOR,
            output.model_copy(update={"precedent_retrieval_receipt_id": _sha("wrong-retrieval")}),
        )

    call = trace.successful_call
    request_drift = _unchecked_call(
        call,
        request=_unchecked_model_copy(call.request, run_id="other-run"),
    )
    with pytest.raises(HearingTransitionError, match="checkpoint authority"):
        hearing_fsm._validate_trace_scope(
            session,
            checkpoint,
            _unchecked_trace(request_drift),
            VlmRole.PROSECUTOR,
            output,
        )

    usage_drift = _unchecked_call(
        call,
        usage=_unchecked_model_copy(call.usage, run_id="other-run"),
    )
    with pytest.raises(HearingTransitionError, match="usage is outside"):
        hearing_fsm._validate_trace_scope(
            session,
            checkpoint,
            _unchecked_trace(usage_drift),
            VlmRole.PROSECUTOR,
            output,
        )


def test_role_commit_rejects_duplicate_artifact_and_usage_authority() -> None:
    session, checkpoint, _, output, trace = _prosecutor_authority()

    with pytest.raises(HearingTransitionError, match="existing artifact ref"):
        complete_prosecutor(
            session,
            _unchecked_model_copy(
                checkpoint,
                model_request_refs=trace.model_request_refs,
            ),
            output,
            trace,
        )  # type: ignore[arg-type]
    with pytest.raises(HearingTransitionError, match="existing usage authority"):
        complete_prosecutor(
            session,
            _unchecked_model_copy(
                checkpoint,
                usage_receipts=trace.usage_receipts,
            ),
            output,
            trace,
        )  # type: ignore[arg-type]


def _judge_pending_authority(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    *,
    acquire: bool = False,
) -> tuple[
    HearingCheckpoint,
    HearingRoleOutput,
    HearingCallTrace,
    AcquisitionRequestPayload | None,
]:
    retrieval = _retrieval(session, checkpoint)
    prosecutor_pending = complete_precedent_retrieval(session, checkpoint, retrieval)
    acquisition_payload = _acquisition_payload(prosecutor_pending.judge_cycle) if acquire else None
    prosecutor_payload, defender_payload, judge_payload = _payloads(
        evidence_ref=_ref(
            ArtifactKind.CROP,
            f"cycle-{prosecutor_pending.judge_cycle}-visible-crop",
        ),
        acquisition_payload=acquisition_payload,
    )
    prosecutor, prosecutor_trace = _role_output(
        session,
        prosecutor_pending,
        retrieval,
        prosecutor_payload,
    )
    defender_pending = complete_prosecutor(
        session,
        prosecutor_pending,
        prosecutor,
        prosecutor_trace,
    )
    defender, defender_trace = _role_output(
        session,
        defender_pending,
        retrieval,
        defender_payload,
        prosecutor_output_id=prosecutor.output_id,
    )
    judge_pending = complete_defender(
        session,
        defender_pending,
        defender,
        defender_trace,
    )
    judge, judge_trace = _role_output(
        session,
        judge_pending,
        retrieval,
        judge_payload,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    return judge_pending, judge, judge_trace, acquisition_payload


def _acquisition_pending_authority() -> tuple[
    HearingSession,
    HearingCheckpoint,
    AcquisitionRequest,
]:
    session = _session()
    judge_pending, judge, judge_trace, payload = _judge_pending_authority(
        session,
        begin_hearing(session),
        acquire=True,
    )
    assert payload is not None
    request = _acquisition_request(judge_pending, judge, payload)
    transition = complete_judge(
        session,
        judge_pending,
        judge,
        judge_trace,
        acquisition_request=request,
    )
    return session, transition.checkpoint, request


def test_defender_and_judge_reject_cross_role_output_substitution() -> None:
    session = _session()
    opened = begin_hearing(session)
    retrieval = _retrieval(session, opened)
    prosecutor_pending = complete_precedent_retrieval(session, opened, retrieval)
    prosecutor_payload, defender_payload, judge_payload = _payloads(
        evidence_ref=_ref(ArtifactKind.CROP, "cycle-1-visible-crop")
    )
    prosecutor, prosecutor_trace = _role_output(
        session,
        prosecutor_pending,
        retrieval,
        prosecutor_payload,
    )
    defender_pending = complete_prosecutor(
        session,
        prosecutor_pending,
        prosecutor,
        prosecutor_trace,
    )
    unrelated_prosecutor_id = _sha("unrelated-prosecutor-output")
    defender, defender_trace = _role_output(
        session,
        defender_pending,
        retrieval,
        defender_payload,
        prosecutor_output_id=unrelated_prosecutor_id,
    )
    with pytest.raises(HearingTransitionError, match="persisted prosecution"):
        complete_defender(
            session,
            defender_pending,
            defender,
            defender_trace,
        )

    defender, defender_trace = _role_output(
        session,
        defender_pending,
        retrieval,
        defender_payload,
        prosecutor_output_id=prosecutor.output_id,
    )
    judge_pending = complete_defender(
        session,
        defender_pending,
        defender,
        defender_trace,
    )
    judge, judge_trace = _role_output(
        session,
        judge_pending,
        retrieval,
        judge_payload,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=_sha("unrelated-defender-output"),
    )
    with pytest.raises(HearingTransitionError, match="both persisted advocates"):
        complete_judge(session, judge_pending, judge, judge_trace)


def test_judge_rejects_non_judge_payload_after_contract_bypass() -> None:
    session = _session()
    judge_pending, judge, judge_trace, _ = _judge_pending_authority(
        session,
        begin_hearing(session),
    )

    class JudgeShapedNonJudgePayload:
        role = VlmRole.JUDGE
        payload_sha256 = _sha("judge-shaped-non-judge-payload")

    payload = JudgeShapedNonJudgePayload()
    successful = judge_trace.successful_call
    forged_parse = _unchecked_model_copy(
        successful.parse_receipt,
        parsed_payload_sha256=payload.payload_sha256,
    )
    forged_output = _unchecked_model_copy(
        judge,
        payload=payload,
        parse_receipt_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_PARSE_RECEIPT,
            artifact_id=forged_parse.parse_receipt_id,
        ),
    )
    forged_call = _unchecked_call(
        successful,
        parse_receipt=forged_parse,
    )

    with pytest.raises(HearingTransitionError, match="requires a Judge payload"):
        complete_judge(
            session,
            judge_pending,
            forged_output,  # type: ignore[arg-type]
            _unchecked_trace(forged_call),
        )


def test_judge_acquisition_authority_is_required_and_exact() -> None:
    session = _session()
    judge_pending, judge, judge_trace, payload = _judge_pending_authority(
        session,
        begin_hearing(session),
        acquire=True,
    )
    assert payload is not None
    request = _acquisition_request(judge_pending, judge, payload)

    with pytest.raises(HearingTransitionError, match="requires its scoped request"):
        complete_judge(session, judge_pending, judge, judge_trace)
    with pytest.raises(HearingTransitionError, match="conflicts with the Judge proposal"):
        complete_judge(
            session,
            judge_pending,
            judge,
            judge_trace,
            acquisition_request=request.model_copy(update={"case_id": "other-case"}),
        )

    checkpoint = begin_hearing(session)
    for _ in range(session.acquisition_round_limit):
        acquired, hearing_round = _complete_role_cycle(session, checkpoint, acquire=True)
        assert hearing_round is not None
        checkpoint = start_cycle_after_acquisition(session, acquired).checkpoint
    exhausted_pending, exhausted_judge, exhausted_trace, exhausted_payload = (
        _judge_pending_authority(session, checkpoint, acquire=True)
    )
    assert exhausted_payload is not None
    with pytest.raises(
        HearingTransitionError,
        match="cannot create executable acquisition authority",
    ):
        complete_judge(
            session,
            exhausted_pending,
            exhausted_judge,
            exhausted_trace,
            acquisition_request=request,
        )


def test_acquisition_completion_rejects_untyped_or_wrong_receipt() -> None:
    session, checkpoint, request = _acquisition_pending_authority()

    with pytest.raises(TypeError, match="ToolExecutionReceipt"):
        complete_acquisition(
            session,
            checkpoint,
            object(),  # type: ignore[arg-type]
        )
    other_request = request.model_copy(update={"case_id": "other-case"})
    wrong_receipt = _unchecked_model_copy(
        _tool_receipt(request),
        request=other_request,
    )
    with pytest.raises(HearingTransitionError, match="does not close"):
        complete_acquisition(
            session,
            checkpoint,
            wrong_receipt,  # type: ignore[arg-type]
        )


def test_cycle_restart_rejects_non_acquisition_and_forged_budget_states() -> None:
    session = _session()
    terminal, terminal_round = _complete_role_cycle(session, begin_hearing(session))
    assert terminal_round is not None
    with pytest.raises(HearingTransitionError, match="did not complete an acquisition"):
        start_cycle_after_acquisition(session, terminal)

    _, acquired, _ = _acquisition_pending_authority()
    assert acquired.acquisition_request is not None
    completed = complete_acquisition(
        session,
        acquired,
        _tool_receipt(acquired.acquisition_request),
    )
    forged_cycle_six = _unchecked_model_copy(completed, judge_cycle=5)
    with pytest.raises(
        HearingTransitionError,
        match="cannot authorize another Judge cycle",
    ):
        start_cycle_after_acquisition(
            session,
            forged_cycle_six,  # type: ignore[arg-type]
        )

    over_limit = _unchecked_model_copy(
        completed,
        prior_acquisition_rounds=session.acquisition_round_limit,
    )
    with pytest.raises(ValueError, match="cycle conflicts with prior-round counters"):
        start_cycle_after_acquisition(
            session,
            over_limit,  # type: ignore[arg-type]
        )
    without_judge = _unchecked_model_copy(over_limit, judge_output=None)
    with pytest.raises(HearingTransitionError, match="lacks its Judge output"):
        start_cycle_after_acquisition(
            session,
            without_judge,  # type: ignore[arg-type]
        )


def test_procedural_review_rejects_missing_or_nonterminal_judge_authority() -> None:
    session = _session()
    terminal, hearing_round = _complete_role_cycle(session, begin_hearing(session))
    assert hearing_round is not None
    closure = _review_closure(
        session,
        (hearing_round,),
        (terminal,),
        "review-authority",
    )

    without_judge = _unchecked_model_copy(terminal, judge_output=None)
    with pytest.raises(HearingTransitionError, match="requires a terminal Judge output"):
        record_procedural_review(
            session,
            without_judge,  # type: ignore[arg-type]
            closure,
        )

    acquired, acquisition_round = _complete_role_cycle(
        session,
        begin_hearing(session),
        acquire=True,
    )
    assert acquisition_round is not None
    with pytest.raises(HearingTransitionError, match="cannot enter procedural review"):
        record_procedural_review(session, acquired, closure)


def test_procedural_review_must_close_exact_checkpoint_and_call_authority() -> None:
    session = _session()
    terminal, hearing_round = _complete_role_cycle(session, begin_hearing(session))
    assert hearing_round is not None
    closure = _review_closure(
        session,
        (hearing_round,),
        (terminal,),
        "exact-review-authority",
    )

    wrong_pack = _unchecked_model_copy(
        terminal,
        current_evidence_pack_id=_sha("unrelated-current-pack"),
    )
    with pytest.raises(HearingTransitionError, match="checkpoint authority"):
        record_procedural_review(
            session,
            wrong_pack,  # type: ignore[arg-type]
            closure,
        )

    omitted_request = _ref(ArtifactKind.MODEL_REQUEST, "unrecorded-checkpoint-request")
    checkpoint_with_unrecorded_call = _unchecked_model_copy(
        terminal,
        model_request_refs=tuple(
            sorted(
                (*terminal.model_request_refs, omitted_request),
                key=lambda ref: ref.sort_key,
            )
        ),
    )
    with pytest.raises(HearingTransitionError, match="omits current checkpoint request"):
        record_procedural_review(
            session,
            checkpoint_with_unrecorded_call,  # type: ignore[arg-type]
            closure,
        )


def test_rework_requires_exact_failed_review_authority() -> None:
    session = _session()
    terminal, hearing_round = _complete_role_cycle(session, begin_hearing(session))
    assert hearing_round is not None
    closure = _review_closure(
        session,
        (hearing_round,),
        (terminal,),
        "failed-review-authority",
    )
    rework_ready = record_procedural_review(session, terminal, closure)

    without_review = _unchecked_model_copy(rework_ready, procedural_review_ref=None)
    with pytest.raises(HearingTransitionError, match="lacks its failed review"):
        start_rework_cycle(
            session,
            without_review,  # type: ignore[arg-type]
            closure,
        )

    different_review = _review_closure(
        session,
        (hearing_round,),
        (terminal,),
        "different-failed-review-authority",
    )
    with pytest.raises(HearingTransitionError, match="exact failed review"):
        start_rework_cycle(session, rework_ready, different_review)


def test_rework_rejects_forged_sixth_judge_cycle() -> None:
    session = _session()
    checkpoint = begin_hearing(session)
    rounds: list[HearingRound] = []
    completed_checkpoints: list[HearingCheckpoint] = []

    for _ in range(session.acquisition_round_limit):
        checkpoint, hearing_round = _complete_role_cycle(
            session,
            checkpoint,
            acquire=True,
        )
        assert hearing_round is not None
        rounds.append(hearing_round)
        completed_checkpoints.append(checkpoint)
        checkpoint = start_cycle_after_acquisition(session, checkpoint).checkpoint

    for review_index in range(session.rework_round_limit):
        checkpoint, hearing_round = _complete_role_cycle(session, checkpoint)
        assert hearing_round is not None
        rounds.append(hearing_round)
        completed_checkpoints.append(checkpoint)
        closure = _review_closure(
            session,
            tuple(rounds),
            tuple(completed_checkpoints),
            f"cycle-five-setup-{review_index}",
        )
        checkpoint = record_procedural_review(session, checkpoint, closure)
        checkpoint = start_rework_cycle(session, checkpoint, closure).checkpoint

    terminal, hearing_round = _complete_role_cycle(session, checkpoint)
    assert hearing_round is not None
    rounds.append(hearing_round)
    completed_checkpoints.append(terminal)
    closure = _review_closure(
        session,
        tuple(rounds),
        tuple(completed_checkpoints),
        "cycle-five-failed-review",
    )
    rework_ready = record_procedural_review(session, terminal, closure)
    forged_unused_rework = _unchecked_model_copy(
        rework_ready,
        prior_rework_rounds=session.rework_round_limit - 1,
    )

    with pytest.raises(
        HearingTransitionError,
        match="cannot authorize another Judge cycle",
    ):
        start_rework_cycle(
            session,
            forged_unused_rework,  # type: ignore[arg-type]
            closure,
        )


def test_human_transfer_rejects_untyped_owned_or_misplaced_authority() -> None:
    session = _session()
    opened = begin_hearing(session)

    with pytest.raises(TypeError, match="HearingHumanReviewReason"):
        transfer_to_human_review(
            session,
            opened,
            "EVIDENCE_UNAVAILABLE",  # type: ignore[arg-type]
        )
    with pytest.raises(HearingTransitionError, match="exact failed-review transition"):
        transfer_to_human_review(
            session,
            opened,
            HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED,
        )
    with pytest.raises(HearingTransitionError, match="wrong procedural authority"):
        transfer_to_human_review(
            session,
            opened,
            HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
            procedural_review_ref=_ref(
                ArtifactKind.PROCEDURAL_REVIEW,
                "misplaced-review-authority",
            ),
        )


def test_unrecoverable_acquisition_transfer_requires_exact_request_authority() -> None:
    session, checkpoint, _ = _acquisition_pending_authority()
    assert checkpoint.acquisition_request is not None
    expected_ref = checkpoint.acquisition_request.source_model_request_ref

    without_request = _unchecked_model_copy(checkpoint, acquisition_request=None)
    with pytest.raises(HearingTransitionError, match="lacks its exact request"):
        transfer_to_human_review(
            session,
            without_request,  # type: ignore[arg-type]
            HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE,
        )
    with pytest.raises(HearingTransitionError, match="wrong acquisition authority"):
        transfer_to_human_review(
            session,
            checkpoint,
            HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE,
            acquisition_request_ref=_ref(
                ArtifactKind.MODEL_REQUEST,
                "wrong-acquisition-authority",
            ),
        )

    transition = transfer_to_human_review(
        session,
        checkpoint,
        HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE,
        acquisition_request_ref=expected_ref,
    )
    assert transition.human_review_receipt is not None
    assert transition.human_review_receipt.acquisition_request_ref == expected_ref


def test_backlog_transfer_requires_exact_exhausted_pending_role() -> None:
    session = _session()
    opened = begin_hearing(session)
    prosecutor_pending = complete_precedent_retrieval(
        session,
        opened,
        _retrieval(session, opened),
    )
    backlog = BacklogItem(
        run_id=RUN_ID,
        case_id=CASE_ID,
        stage=BacklogStage.HEARING,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=INITIAL_PACK_ID,
        ),
        stage_input_sha256=_sha("initial-pack-document"),
        attempt_count=1,
        max_attempts=1,
        status=BacklogStatus.EXHAUSTED,
        manifest_id=MANIFEST_ID,
    )

    with pytest.raises(HearingTransitionError, match="typed exhausted item"):
        transfer_to_human_review(
            session,
            prosecutor_pending,
            HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED,
        )
    with pytest.raises(HearingTransitionError, match="exact pending role"):
        transfer_to_human_review(
            session,
            prosecutor_pending,
            HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED,
            backlog_item=backlog.model_copy(update={"case_id": "other-case"}),
        )
    with pytest.raises(HearingTransitionError, match="only backlog exhaustion"):
        transfer_to_human_review(
            session,
            opened,
            HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
            backlog_item=backlog,
        )
