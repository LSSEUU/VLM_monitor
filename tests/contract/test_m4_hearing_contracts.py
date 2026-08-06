import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.backlog import BacklogLeaseIdentity, BacklogRetryContext
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionClaimState,
    AcquisitionExecutionMode,
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    ModelParseStatus,
    ObjectiveFactKind,
    PrivacyPolicy,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    UnknownReferenceNamespace,
    VerdictDecision,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import (
    OtherCameraSameTimeParameters,
    RecropParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    ToolResult,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing import (
    AcquisitionExecutionClaimAuthority,
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    AcquisitionRequestPayload,
    DefenderModelPayload,
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryFailure,
    HearingBacklogRetrySuccess,
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingCycleScope,
    HearingHumanReviewReason,
    HearingHumanReviewReceipt,
    HearingInitialStrictParseFailureProof,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingModelResponseRecoveryReport,
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalResult,
    HearingPrecedentRetrievalStatus,
    HearingRecord,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingSessionEntryStatus,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    HearingUnknownReferenceAttempt,
    HearingUnknownReferenceSource,
    HearingUsageReceipt,
    HearingVerdictBinding,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
    ToolExecutionManifest,
    ToolExecutionReceipt,
    derive_hearing_model_response_id,
    derive_m4_tool_result_id,
    validate_hearing_cycle_scope_binding,
)
from labcourt.contracts.m3_models import (
    PromptManifest,
    VlmCallBudget,
)
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.model_call_failures import (
    ModelCallFailureClosureKind,
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument, JudgeResponse, ProceduralDefect
from labcourt.schema_export import expected_schema_files
from labcourt.schema_registry import SCHEMA_MODELS

RUN_ID = "run-01"
CASE_ID = "case-01"
MANIFEST = "f" * 64
PROMPT_BUNDLE = "e" * 64
PACK_ID = "d" * 64
SCREENING_ID = "c" * 64


def _sha(value: int) -> str:
    return f"{value:064x}"


def _ref(kind: ArtifactKind, value: int) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=_sha(value))


def _prompt(role: VlmRole) -> PromptManifest:
    return PromptManifest(
        prompt_id=f"hearing-{role.value.lower()}-v1",
        role=role,
        template_sha256=_sha(100 + list(VlmRole).index(role)),
        output_schema_sha256=_sha(200 + list(VlmRole).index(role)),
        prompt_bundle_sha256=PROMPT_BUNDLE,
        renderer_version="jinja-3-1",
    )


def _budget(*, repair: bool = False) -> VlmCallBudget:
    return VlmCallBudget(
        max_images=0 if repair else 4,
        max_input_pixels=0 if repair else 100_000,
        max_output_tokens=1_024,
        pricing_currency="USD",
        input_cost_per_million_tokens=0.25,
        output_cost_per_million_tokens=1.0,
        max_estimated_cost=2.0,
        max_response_bytes=65_536,
        max_json_depth=8,
        max_json_fields=256,
        max_string_chars=16_384,
        timeout_seconds=15.0,
    )


def _session(
    *,
    rework_entry: bool = False,
    acquisition_round_limit: int = 2,
) -> HearingSession:
    return HearingSession(
        run_id=RUN_ID,
        case_id=CASE_ID,
        screening_id=SCREENING_ID,
        entry_status=(
            HearingSessionEntryStatus.REWORK_REQUIRED
            if rework_entry
            else HearingSessionEntryStatus.ESCALATED
        ),
        initial_evidence_pack_id=PACK_ID,
        initial_evidence_pack_version=1,
        initial_trigger_review_ref=(
            _ref(ArtifactKind.PROCEDURAL_REVIEW, 400) if rework_entry else None
        ),
        initial_defect_codes=(
            (ProceduralDefectCode.UNANSWERED_DEFENSE_POINT,) if rework_entry else ()
        ),
        acquisition_round_limit=acquisition_round_limit,
        max_total_images=20,
        max_total_output_tokens=6_000,
        hearing_prompt_bundle_sha256=PROMPT_BUNDLE,
        prosecutor_model_manifest_id=_sha(301),
        defender_model_manifest_id=_sha(302),
        judge_model_manifest_id=_sha(303),
        manifest_id=MANIFEST,
    )


def _retrieval(
    session: HearingSession,
    *,
    degraded: bool = False,
    round_index: int = 1,
    prior_acquisition_rounds: int = 0,
    prior_rework_rounds: int = 0,
) -> HearingPrecedentRetrievalReceipt:
    return HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=round_index,
        prior_acquisition_rounds=prior_acquisition_rounds,
        prior_rework_rounds=prior_rework_rounds,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version="laboratory-v1",
        top_k=4,
        query_sha256=_sha(410),
        initial_trigger_review_ref=(
            session.initial_trigger_review_ref if round_index == 1 else None
        ),
        initial_defect_codes=session.initial_defect_codes if round_index == 1 else (),
        status=(
            HearingPrecedentRetrievalStatus.DEGRADED
            if degraded
            else HearingPrecedentRetrievalStatus.SUCCESS
        ),
        degraded_reason=(
            HearingPrecedentDegradedReason.EMBEDDING_PROVIDER_UNAVAILABLE if degraded else None
        ),
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_sha(411),
        embedding_model_manifest_id=None if degraded else _sha(412),
        candidate_snapshot_sha256=_sha(413),
        visible_snapshot_sha256=_sha(414),
        manifest_id=MANIFEST,
    )


def _cycle_scope(
    session: HearingSession,
    retrieval: HearingPrecedentRetrievalReceipt,
) -> HearingCycleScope:
    return HearingCycleScope(
        run_id=retrieval.run_id,
        case_id=retrieval.case_id,
        hearing_session_id=session.session_id,
        cycle_index=retrieval.round_index,
        prior_acquisition_rounds=retrieval.prior_acquisition_rounds,
        prior_rework_rounds=retrieval.prior_rework_rounds,
        cycle_evidence_pack_id=retrieval.current_evidence_pack_id,
        cycle_evidence_pack_version=retrieval.current_evidence_pack_version,
        initial_trigger_review_ref=retrieval.initial_trigger_review_ref,
        initial_defect_codes=retrieval.initial_defect_codes,
        rework_review_ref=retrieval.rework_review_ref,
        rework_defect_codes=retrieval.rework_defect_codes,
        manifest_id=retrieval.manifest_id,
    )


def _prosecution_argument() -> Argument:
    return Argument(
        stance=ArgumentStance.PROSECUTION,
        claim="The cited crop supports the alleged laboratory rule violation.",
        evidence_refs=(_ref(ArtifactKind.CROP, 1),),
        uncertainty=0.1,
    )


def _defense_argument() -> Argument:
    return Argument(
        stance=ArgumentStance.DEFENSE,
        claim="Reflection and occlusion remain plausible counter-explanations.",
        evidence_refs=(_ref(ArtifactKind.CROP, 2),),
        uncertainty=0.4,
    )


def _role_output(
    session: HearingSession,
    retrieval: HearingPrecedentRetrievalReceipt,
    role: VlmRole,
    payload: ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
    ordinal: int,
    *,
    prosecutor_output_id: str | None = None,
    defender_output_id: str | None = None,
) -> HearingRoleOutput:
    model_id = {
        VlmRole.PROSECUTOR: session.prosecutor_model_manifest_id,
        VlmRole.DEFENDER: session.defender_model_manifest_id,
        VlmRole.JUDGE: session.judge_model_manifest_id,
    }[role]
    return HearingRoleOutput(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=retrieval.round_index,
        prior_acquisition_rounds=retrieval.prior_acquisition_rounds,
        prior_rework_rounds=retrieval.prior_rework_rounds,
        current_evidence_pack_id=retrieval.current_evidence_pack_id,
        current_evidence_pack_version=retrieval.current_evidence_pack_version,
        prompt_manifest=_prompt(role),
        model_manifest_id=model_id,
        request_ref=_ref(ArtifactKind.MODEL_REQUEST, 10 + ordinal),
        response_ref=_ref(ArtifactKind.MODEL_RESPONSE, 20 + ordinal),
        parse_receipt_ref=_ref(ArtifactKind.MODEL_PARSE_RECEIPT, 30 + ordinal),
        prosecutor_output_id=prosecutor_output_id,
        defender_output_id=defender_output_id,
        precedent_retrieval_degraded=(retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED),
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        initial_trigger_review_ref=retrieval.initial_trigger_review_ref,
        initial_defect_codes=retrieval.initial_defect_codes,
        rework_review_ref=retrieval.rework_review_ref,
        rework_defect_codes=retrieval.rework_defect_codes,
        payload=payload,
        manifest_id=MANIFEST,
    )


def _final_round(
    *,
    degraded: bool = False,
    rework_entry: bool = False,
) -> tuple[HearingSession, HearingRound]:
    session = _session(rework_entry=rework_entry)
    retrieval = _retrieval(session, degraded=degraded)
    prosecutor = _role_output(
        session,
        retrieval,
        VlmRole.PROSECUTOR,
        ProsecutorModelPayload(
            arguments=(_prosecution_argument(),),
            case_summary="The prosecution relies only on typed evidence references.",
        ),
        1,
    )
    defender = _role_output(
        session,
        retrieval,
        VlmRole.DEFENDER,
        DefenderModelPayload(
            arguments=(_defense_argument(),),
            case_summary="The defense preserves uncertainty and possible counter-evidence.",
        ),
        2,
        prosecutor_output_id=prosecutor.output_id,
    )
    response = JudgeResponse(
        defense_argument_id=_defense_argument().argument_id,
        disposition="PARTIALLY_ACCEPTED",
        response_summary="The concern lowers confidence but does not erase cited observations.",
        evidence_refs=(_ref(ArtifactKind.CROP, 2),),
    )
    judge = _role_output(
        session,
        retrieval,
        VlmRole.JUDGE,
        JudgeModelPayload(
            judge_responses=(response,),
            outcome=JudgeFinalDecisionPayload(
                decision=VerdictDecision.ESTABLISHED,
                confidence=0.82,
                recommended_alert_level=AlertLevel.CONFIRMED,
                rationale_summary="The structured record supports a reviewable final proposal.",
            ),
        ),
        3,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    return session, HearingRound(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        precedent_retrieval_degraded=degraded,
        precedent_retrieval_receipt=retrieval,
        initial_trigger_review_ref=session.initial_trigger_review_ref,
        initial_defect_codes=session.initial_defect_codes,
        prosecutor_output=prosecutor,
        defender_output=defender,
        judge_output=judge,
        manifest_id=MANIFEST,
    )


def _usage(output: HearingRoleOutput) -> HearingUsageReceipt:
    return HearingUsageReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=output.hearing_session_id,
        round_index=output.round_index,
        role=output.role,
        request_ref=output.request_ref,
        response_ref=output.response_ref,
        input_images=1,
        input_pixels=10_000,
        input_tokens=100,
        output_tokens=50,
        latency_ms=20,
        retry_count=0,
        estimated_cost=0.001,
        manifest_id=MANIFEST,
    )


def _checkpoint_trace(*outputs: HearingRoleOutput) -> dict[str, object]:
    return {
        "model_request_refs": tuple(
            sorted((item.request_ref for item in outputs), key=lambda item: item.sort_key)
        ),
        "model_response_refs": tuple(
            sorted((item.response_ref for item in outputs), key=lambda item: item.sort_key)
        ),
        "parse_receipt_refs": tuple(
            sorted((item.parse_receipt_ref for item in outputs), key=lambda item: item.sort_key)
        ),
        "usage_receipts": tuple(
            sorted(
                (_usage(item) for item in outputs),
                key=lambda item: (
                    item.round_index,
                    item.role.value,
                    item.request_ref.artifact_id,
                ),
            )
        ),
    }


def _record() -> HearingRecord:
    session, hearing_round = _final_round()
    outputs = (
        hearing_round.prosecutor_output,
        hearing_round.defender_output,
        hearing_round.judge_output,
    )
    return HearingRecord(
        run_id=RUN_ID,
        case_id=CASE_ID,
        version=1,
        session=session,
        screening_id=SCREENING_ID,
        initial_evidence_pack_id=PACK_ID,
        initial_evidence_pack_version=1,
        rounds=(hearing_round,),
        model_request_refs=tuple(
            sorted((item.request_ref for item in outputs), key=lambda x: x.sort_key)
        ),
        model_response_refs=tuple(
            sorted((item.response_ref for item in outputs), key=lambda x: x.sort_key)
        ),
        parse_receipt_refs=tuple(
            sorted((item.parse_receipt_ref for item in outputs), key=lambda x: x.sort_key)
        ),
        usage_receipts=tuple(
            sorted(
                (_usage(item) for item in outputs),
                key=lambda x: (
                    x.round_index,
                    x.role.value,
                    x.request_ref.artifact_id,
                ),
            )
        ),
        manifest_id=MANIFEST,
    )


def _media() -> VLMMediaRef:
    return VLMMediaRef(
        crop_id=_sha(1),
        media_sha256=_sha(500),
        local_path=f"{RUN_ID}/frames/{_sha(500)}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=100,
        height=100,
    )


def _model_request(
    role: VlmRole = VlmRole.PROSECUTOR,
    *,
    repair: bool = False,
    session: HearingSession | None = None,
    retrieval: HearingPrecedentRetrievalReceipt | None = None,
    prosecutor_output_id: str | None = None,
    defender_output_id: str | None = None,
) -> HearingModelRequest:
    bound_session = session or _session()
    bound_retrieval = retrieval or _retrieval(bound_session)
    media = () if repair else (_media(),)
    prosecutor_output_ref = (
        None
        if role == VlmRole.PROSECUTOR
        else ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=prosecutor_output_id or _sha(601),
        )
    )
    defender_output_ref = (
        ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=defender_output_id or _sha(602),
        )
        if role == VlmRole.JUDGE
        else None
    )
    return HearingModelRequest(
        attempt_index=1 if repair else 0,
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=bound_session.session_id,
        round_index=bound_retrieval.round_index,
        prior_acquisition_rounds=bound_retrieval.prior_acquisition_rounds,
        prior_rework_rounds=bound_retrieval.prior_rework_rounds,
        current_evidence_pack_id=bound_retrieval.current_evidence_pack_id,
        current_evidence_pack_version=bound_retrieval.current_evidence_pack_version,
        screening_ref=_ref(ArtifactKind.SCREENING_RESULT, 603),
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        role=role,
        provider_profile=f"fake-{role.value.lower()}",
        provider="fixture",
        model="fixture-vlm",
        revision="1.0.0",
        model_manifest_id={
            VlmRole.PROSECUTOR: bound_session.prosecutor_model_manifest_id,
            VlmRole.DEFENDER: bound_session.defender_model_manifest_id,
            VlmRole.JUDGE: bound_session.judge_model_manifest_id,
        }[role],
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=_prompt(role),
        hearing_prompt_bundle_sha256=PROMPT_BUNDLE,
        rendered_prompt_sha256=_sha(604),
        hearing_context_sha256=_sha(605),
        media=media,
        allowed_evidence_refs=(_ref(ArtifactKind.CROP, 1),),
        prosecutor_output_ref=prosecutor_output_ref,
        defender_output_ref=defender_output_ref,
        precedent_retrieval_degraded=(
            bound_retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED
        ),
        precedent_retrieval_receipt_id=bound_retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=bound_retrieval.receipt_sha256,
        initial_trigger_review_ref=bound_retrieval.initial_trigger_review_ref,
        initial_defect_codes=bound_retrieval.initial_defect_codes,
        rework_review_ref=bound_retrieval.rework_review_ref,
        rework_defect_codes=bound_retrieval.rework_defect_codes,
        original_request_id=_sha(606) if repair else None,
        original_response_id=_sha(607) if repair else None,
        original_response_content_sha256=_sha(608) if repair else None,
        repair_context_sha256=_sha(609) if repair else None,
        temperature=0.0,
        seed=7,
        budget=_budget(repair=repair),
        manifest_id=MANIFEST,
    )


def _response_for_request(request: HearingModelRequest, ordinal: int) -> HearingModelResponse:
    content_sha256 = _sha(ordinal)
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
    return HearingModelResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        role=request.role,
        attempt_index=request.attempt_index,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=512,
        input_tokens=100,
        output_tokens=50,
        latency_ms=20,
        model_manifest_id=request.model_manifest_id,
        manifest_id=MANIFEST,
    )


def _parser_defect(response_id: str) -> ProceduralDefect:
    return ProceduralDefect(
        code=ProceduralDefectCode.MALFORMED_STRUCTURE,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.MALFORMED_JSON,
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response_id,
        ),
        field=ProceduralField.JSON_ROOT,
    )


def _strict_retry_fixture() -> tuple[
    BacklogLeaseIdentity,
    HearingModelRequest,
    HearingStrictParseFailureProof,
]:
    lease = BacklogLeaseIdentity(
        run_id=RUN_ID,
        item_id=_sha(610),
        lease_id=_sha(611),
        attempt_count=1,
        retry_generation=1,
    )
    context = BacklogRetryContext(
        backlog_item_id=lease.item_id,
        retry_generation=lease.retry_generation,
    )
    primary = _model_request().model_copy(update={"backlog_retry_context": context})
    primary_response = _response_for_request(primary, 612)
    repair = _model_request(repair=True).model_copy(
        update={
            "backlog_retry_context": context,
            "original_request_id": primary.request_id,
            "original_response_id": primary_response.response_id,
            "original_response_content_sha256": primary_response.content_sha256,
        }
    )
    repair_response = _response_for_request(repair, 613)
    primary_parse = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=primary.hearing_session_id,
        round_index=1,
        role=primary.role,
        attempt_index=0,
        request_id=primary.request_id,
        request_sha256=primary.request_sha256,
        response_id=primary_response.response_id,
        response_content_sha256=primary_response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=primary.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(_parser_defect(primary_response.response_id),),
        repair_request_id=repair.request_id,
        manifest_id=MANIFEST,
    )
    repair_parse = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=repair.hearing_session_id,
        round_index=1,
        role=repair.role,
        attempt_index=1,
        request_id=repair.request_id,
        request_sha256=repair.request_sha256,
        response_id=repair_response.response_id,
        response_content_sha256=repair_response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=repair.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.INVALID_FINAL,
        defects=(_parser_defect(repair_response.response_id),),
        manifest_id=MANIFEST,
    )
    proof = HearingStrictParseFailureProof(
        lease=lease,
        source_checkpoint_id=_sha(614),
        source_checkpoint_sha256=_sha(615),
        source_checkpoint_version=2,
        role=VlmRole.PROSECUTOR,
        attempts=(
            HearingStrictParseFailureAttempt(
                request=primary,
                response=primary_response,
                parse_receipt=primary_parse,
            ),
            HearingStrictParseFailureAttempt(
                request=repair,
                response=repair_response,
                parse_receipt=repair_parse,
            ),
        ),
    )
    return lease, primary, proof


def _initial_strict_failure_fixture() -> HearingInitialStrictParseFailureProof:
    primary = _model_request()
    primary_response = _response_for_request(primary, 980)
    repair = _model_request(repair=True).model_copy(
        update={
            "original_request_id": primary.request_id,
            "original_response_id": primary_response.response_id,
            "original_response_content_sha256": primary_response.content_sha256,
        }
    )
    repair_response = _response_for_request(repair, 981)
    primary_parse = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=primary.hearing_session_id,
        round_index=primary.round_index,
        role=primary.role,
        attempt_index=0,
        request_id=primary.request_id,
        request_sha256=primary.request_sha256,
        response_id=primary_response.response_id,
        response_content_sha256=primary_response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=primary.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(_parser_defect(primary_response.response_id),),
        repair_request_id=repair.request_id,
        manifest_id=MANIFEST,
    )
    repair_parse = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=repair.hearing_session_id,
        round_index=repair.round_index,
        role=repair.role,
        attempt_index=1,
        request_id=repair.request_id,
        request_sha256=repair.request_sha256,
        response_id=repair_response.response_id,
        response_content_sha256=repair_response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=repair.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.INVALID_FINAL,
        defects=(_parser_defect(repair_response.response_id),),
        manifest_id=MANIFEST,
    )
    return HearingInitialStrictParseFailureProof(
        backlog_item_id=_sha(982),
        source_checkpoint_id=_sha(983),
        source_checkpoint_sha256=_sha(984),
        source_checkpoint_version=2,
        role=VlmRole.PROSECUTOR,
        attempts=(
            HearingStrictParseFailureAttempt(
                request=primary,
                response=primary_response,
                parse_receipt=primary_parse,
            ),
            HearingStrictParseFailureAttempt(
                request=repair,
                response=repair_response,
                parse_receipt=repair_parse,
            ),
        ),
    )


def _prosecutor_retry_success_fixture() -> HearingBacklogRetrySuccess:
    session, hearing_round = _final_round()
    retrieval = hearing_round.precedent_retrieval_receipt
    opened = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=1,
        phase=HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        manifest_id=MANIFEST,
    )
    source = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=2,
        phase=HearingCheckpointPhase.PROSECUTOR_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        previous_checkpoint_id=opened.checkpoint_id,
        previous_checkpoint_sha256=opened.checkpoint_sha256,
        previous_phase=opened.phase,
        precedent_retrieval_receipt=retrieval,
        manifest_id=MANIFEST,
    )
    lease = BacklogLeaseIdentity(
        run_id=RUN_ID,
        item_id=_sha(623),
        lease_id=_sha(624),
        attempt_count=1,
        retry_generation=0,
    )
    request = _model_request(session=session, retrieval=retrieval)
    response = _response_for_request(request, 625)
    output = hearing_round.prosecutor_output.model_copy(
        update={
            "prompt_manifest": request.prompt_manifest,
            "model_manifest_id": request.model_manifest_id,
            "request_ref": ArtifactRef(
                kind=ArtifactKind.MODEL_REQUEST,
                artifact_id=request.request_id,
            ),
            "response_ref": ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
        }
    )
    parse_receipt = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        role=request.role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=output.payload.payload_sha256,
        manifest_id=MANIFEST,
    )
    output = output.model_copy(
        update={
            "parse_receipt_ref": ArtifactRef(
                kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                artifact_id=parse_receipt.parse_receipt_id,
            )
        }
    )
    next_checkpoint = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=3,
        phase=HearingCheckpointPhase.DEFENDER_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        previous_checkpoint_id=source.checkpoint_id,
        previous_checkpoint_sha256=source.checkpoint_sha256,
        previous_phase=source.phase,
        precedent_retrieval_receipt=retrieval,
        prosecutor_output=output,
        manifest_id=MANIFEST,
        **_checkpoint_trace(output),
    )
    return HearingBacklogRetrySuccess(
        lease=lease,
        session=session,
        source_checkpoint_id=source.checkpoint_id,
        source_checkpoint_sha256=source.checkpoint_sha256,
        source_checkpoint_version=source.version,
        request=request,
        response=response,
        parse_receipt=parse_receipt,
        parsed_role_output=output,
        next_checkpoint=next_checkpoint,
        manifest_id=MANIFEST,
    )


def _judge_acquisition_retry_success(
    *,
    acquisition_round_limit: int,
    prior_acquisition_rounds: int,
) -> HearingBacklogRetrySuccess:
    session = _session(acquisition_round_limit=acquisition_round_limit)
    round_index = prior_acquisition_rounds + 1
    retrieval = _retrieval(
        session,
        round_index=round_index,
        prior_acquisition_rounds=prior_acquisition_rounds,
    )
    prosecutor = _role_output(
        session,
        retrieval,
        VlmRole.PROSECUTOR,
        ProsecutorModelPayload(
            arguments=(_prosecution_argument(),),
            case_summary="The prosecution cites typed evidence.",
        ),
        41,
    )
    defender = _role_output(
        session,
        retrieval,
        VlmRole.DEFENDER,
        DefenderModelPayload(
            arguments=(_defense_argument(),),
            case_summary="The defense preserves uncertainty.",
        ),
        42,
        prosecutor_output_id=prosecutor.output_id,
    )
    acquisition_payload = AcquisitionRequestPayload(
        action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
        validated_parameters=TrackConfidenceCurveParameters(
            action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
            track_ref="cam-01:epoch-01:track-01",
            start_frame=1,
            end_frame_exclusive=3,
        ),
        reason_summary="One bounded confidence curve can resolve the ambiguity.",
    )
    request = _model_request(
        VlmRole.JUDGE,
        session=session,
        retrieval=retrieval,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    response = _response_for_request(request, 626 + prior_acquisition_rounds)
    judge = _role_output(
        session,
        retrieval,
        VlmRole.JUDGE,
        JudgeModelPayload(outcome=JudgeAcquisitionDecisionPayload(request=acquisition_payload)),
        43,
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    ).model_copy(
        update={
            "prompt_manifest": request.prompt_manifest,
            "model_manifest_id": request.model_manifest_id,
            "request_ref": ArtifactRef(
                kind=ArtifactKind.MODEL_REQUEST,
                artifact_id=request.request_id,
            ),
            "response_ref": ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
        }
    )
    parse_receipt = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=round_index,
        role=VlmRole.JUDGE,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=judge.payload.payload_sha256,
        manifest_id=MANIFEST,
    )
    judge = judge.model_copy(
        update={
            "parse_receipt_ref": ArtifactRef(
                kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                artifact_id=parse_receipt.parse_receipt_id,
            )
        }
    )
    source = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=4,
        phase=HearingCheckpointPhase.JUDGE_PENDING,
        judge_cycle=round_index,
        prior_acquisition_rounds=prior_acquisition_rounds,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        previous_checkpoint_id=_sha(627),
        previous_checkpoint_sha256=_sha(628),
        previous_phase=HearingCheckpointPhase.DEFENDER_PENDING,
        precedent_retrieval_receipt=retrieval,
        prosecutor_output=prosecutor,
        defender_output=defender,
        manifest_id=MANIFEST,
        **_checkpoint_trace(prosecutor, defender),
    )
    exhausted = prior_acquisition_rounds >= acquisition_round_limit
    human: HearingHumanReviewReceipt | None = None
    acquisition: AcquisitionRequest | None = None
    human_fields: dict[str, object] = {}
    if exhausted:
        human = HearingHumanReviewReceipt(
            run_id=RUN_ID,
            case_id=CASE_ID,
            hearing_session_id=session.session_id,
            current_evidence_pack_id=PACK_ID,
            current_evidence_pack_version=1,
            judge_cycle=round_index,
            reason=HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED,
            source_checkpoint_id=source.checkpoint_id,
            source_checkpoint_sha256=source.checkpoint_sha256,
            source_checkpoint_version=source.version,
            acquisition_request_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_REQUEST,
                artifact_id=request.request_id,
            ),
            manifest_id=MANIFEST,
        )
        human_fields = {
            "human_review_receipt_id": human.receipt_id,
            "human_review_receipt_sha256": human.receipt_sha256,
            "human_review_reason": human.reason,
        }
    else:
        acquisition = AcquisitionRequest(
            run_id=RUN_ID,
            case_id=CASE_ID,
            hearing_session_id=session.session_id,
            round_index=round_index,
            prior_acquisition_rounds=prior_acquisition_rounds,
            prior_rework_rounds=0,
            current_evidence_pack_id=PACK_ID,
            current_evidence_pack_version=1,
            source_judge_output_id=judge.output_id,
            source_model_request_ref=judge.request_ref,
            source_model_response_ref=judge.response_ref,
            request_payload=acquisition_payload,
            manifest_id=MANIFEST,
        )
    next_checkpoint = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=5,
        phase=(
            HearingCheckpointPhase.HUMAN_REVIEW
            if exhausted
            else HearingCheckpointPhase.ACQUISITION_PENDING
        ),
        judge_cycle=round_index,
        prior_acquisition_rounds=prior_acquisition_rounds,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        previous_checkpoint_id=source.checkpoint_id,
        previous_checkpoint_sha256=source.checkpoint_sha256,
        previous_phase=source.phase,
        precedent_retrieval_receipt=retrieval,
        prosecutor_output=prosecutor,
        defender_output=defender,
        judge_output=judge,
        acquisition_request=acquisition,
        manifest_id=MANIFEST,
        **human_fields,
        **_checkpoint_trace(prosecutor, defender, judge),
    )
    lease = BacklogLeaseIdentity(
        run_id=RUN_ID,
        item_id=_sha(629 + prior_acquisition_rounds),
        lease_id=_sha(633 + prior_acquisition_rounds),
        attempt_count=1,
        retry_generation=0,
    )
    return HearingBacklogRetrySuccess(
        lease=lease,
        session=session,
        source_checkpoint_id=source.checkpoint_id,
        source_checkpoint_sha256=source.checkpoint_sha256,
        source_checkpoint_version=source.version,
        request=request,
        response=response,
        parse_receipt=parse_receipt,
        parsed_role_output=judge,
        next_checkpoint=next_checkpoint,
        human_review_receipt=human,
        manifest_id=MANIFEST,
    )


def test_hearing_backlog_generation_advances_only_after_two_strict_failures() -> None:
    lease, primary, proof = _strict_retry_fixture()
    response_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=attempt.response.response_id,
                )
                for attempt in proof.attempts
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    failure = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=proof.source_checkpoint_id,
        source_checkpoint_sha256=proof.source_checkpoint_sha256,
        source_checkpoint_version=proof.source_checkpoint_version,
        request=primary,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.PENDING,
        response_refs=response_refs,
        strict_parse_failure=proof,
        manifest_id=MANIFEST,
    )
    assert failure.next_retry_generation == 2
    completion = HearingBacklogCompletionReceipt(
        outcome=failure,
        backlog_status=BacklogStatus.PENDING,
        source_checkpoint_id=proof.source_checkpoint_id,
        source_checkpoint_sha256=proof.source_checkpoint_sha256,
        source_checkpoint_version=proof.source_checkpoint_version,
        resulting_checkpoint_id=proof.source_checkpoint_id,
        resulting_checkpoint_sha256=proof.source_checkpoint_sha256,
        resulting_checkpoint_version=proof.source_checkpoint_version,
        completion_case_status=CaseStatus.BACKLOGGED,
        completion_case_revision=3,
        completion_audit_sequence=7,
        completion_audit_entry_hash=_sha(616),
        manifest_id=MANIFEST,
    )
    assert (
        HearingBacklogCompletionReceipt.model_validate(completion.model_dump(mode="json"))
        == completion
    )
    with pytest.raises(ValidationError, match="same-role repair"):
        proof.model_copy(update={"attempts": tuple(reversed(proof.attempts))})


def test_hearing_lease_expiry_closes_against_stage_input_without_inventing_a_call() -> None:
    stage_request = _model_request()
    lease = BacklogLeaseIdentity(
        run_id=RUN_ID,
        item_id=_sha(614),
        lease_id=_sha(615),
        attempt_count=2,
        retry_generation=1,
    )
    failure = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=_sha(616),
        source_checkpoint_sha256=_sha(617),
        source_checkpoint_version=2,
        request=stage_request,
        request_binding="BACKLOG_STAGE_INPUT",
        lease_expiry_resume_request_ref=None,
        role=stage_request.role,
        reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED,
        next_status=BacklogStatus.PENDING,
        manifest_id=MANIFEST,
    )

    assert failure.request.backlog_retry_context is None
    assert failure.next_retry_generation == lease.retry_generation
    assert HearingBacklogRetryFailure.model_validate(failure.model_dump(mode="json")) == failure


def test_hearing_lease_expiry_requires_explicit_stage_input_binding() -> None:
    stage_request = _model_request()
    lease = BacklogLeaseIdentity(
        run_id=RUN_ID,
        item_id=_sha(618),
        lease_id=_sha(619),
        attempt_count=2,
        retry_generation=1,
    )
    with pytest.raises(ValidationError, match="immutable backlog stage input"):
        HearingBacklogRetryFailure(
            lease=lease,
            source_checkpoint_id=_sha(620),
            source_checkpoint_sha256=_sha(621),
            source_checkpoint_version=2,
            request=stage_request,
            role=stage_request.role,
            reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED,
            next_status=BacklogStatus.PENDING,
            manifest_id=MANIFEST,
        )


def test_hearing_backlog_success_binds_exact_call_output_usage_and_next_checkpoint() -> None:
    success = _prosecutor_retry_success_fixture()
    receipt = HearingBacklogCompletionReceipt(
        outcome=success,
        backlog_status=BacklogStatus.COMPLETED,
        source_checkpoint_id=success.source_checkpoint_id,
        source_checkpoint_sha256=success.source_checkpoint_sha256,
        source_checkpoint_version=success.source_checkpoint_version,
        resulting_checkpoint_id=success.next_checkpoint.checkpoint_id,
        resulting_checkpoint_sha256=success.next_checkpoint.checkpoint_sha256,
        resulting_checkpoint_version=success.next_checkpoint.version,
        completion_case_status=CaseStatus.DELIBERATING,
        completion_case_revision=3,
        completion_audit_sequence=8,
        completion_audit_entry_hash=_sha(635),
        manifest_id=MANIFEST,
    )
    assert receipt.backlog_status == BacklogStatus.COMPLETED
    with pytest.raises(ValidationError, match="exact parsed call"):
        success.model_copy(
            update={
                "parsed_role_output": success.parsed_role_output.model_copy(
                    update={"precedent_retrieval_receipt_sha256": _sha(636)}
                )
            }
        )


@pytest.mark.parametrize(
    ("acquisition_round_limit", "prior_acquisition_rounds", "exhausted"),
    [
        (0, 0, True),
        (1, 0, False),
        (1, 1, True),
        (2, 0, False),
        (2, 2, True),
    ],
)
def test_judge_backlog_success_respects_configured_acquisition_limit(
    acquisition_round_limit: int,
    prior_acquisition_rounds: int,
    exhausted: bool,
) -> None:
    success = _judge_acquisition_retry_success(
        acquisition_round_limit=acquisition_round_limit,
        prior_acquisition_rounds=prior_acquisition_rounds,
    )
    expected_phase = (
        HearingCheckpointPhase.HUMAN_REVIEW
        if exhausted
        else HearingCheckpointPhase.ACQUISITION_PENDING
    )
    expected_case_status = CaseStatus.HUMAN_REVIEW if exhausted else CaseStatus.DELIBERATING
    assert success.next_checkpoint.phase == expected_phase
    assert (success.human_review_receipt is not None) == exhausted
    completion = HearingBacklogCompletionReceipt(
        outcome=success,
        backlog_status=BacklogStatus.COMPLETED,
        source_checkpoint_id=success.source_checkpoint_id,
        source_checkpoint_sha256=success.source_checkpoint_sha256,
        source_checkpoint_version=success.source_checkpoint_version,
        resulting_checkpoint_id=success.next_checkpoint.checkpoint_id,
        resulting_checkpoint_sha256=success.next_checkpoint.checkpoint_sha256,
        resulting_checkpoint_version=success.next_checkpoint.version,
        completion_case_status=expected_case_status,
        completion_case_revision=3,
        completion_audit_sequence=9,
        completion_audit_entry_hash=_sha(637),
        manifest_id=MANIFEST,
    )
    assert completion.completion_case_status == expected_case_status


def test_failure_authority_distinguishes_reservation_from_disclosure_and_unknown() -> None:
    request = _model_request()
    generation_zero_lease = BacklogLeaseIdentity(
        run_id=RUN_ID,
        item_id=_sha(620),
        lease_id=_sha(622),
        attempt_count=1,
        retry_generation=0,
    )
    provider_retry = HearingBacklogRetryFailure(
        lease=generation_zero_lease,
        source_checkpoint_id=_sha(617),
        source_checkpoint_sha256=_sha(618),
        source_checkpoint_version=2,
        request=request,
        role=request.role,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=MANIFEST,
    )
    assert provider_retry.request.request_id == request.request_id
    assert provider_retry.request.backlog_retry_context is None
    authority = HearingModelCallFailureAuthority(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=request.hearing_session_id,
        role=request.role,
        request=request,
        source_checkpoint_id=_sha(617),
        source_checkpoint_sha256=_sha(618),
        source_checkpoint_version=2,
        claim_owner_sha256=_sha(619),
        claim_lease_expires_at=datetime(2026, 7, 28, 12, tzinfo=UTC),
        claim_takeover_count=0,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        reserved_images=1,
        reserved_pixels=10_000,
        disclosed_images=0,
        disclosed_pixels=0,
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        estimated_cost=0.0,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        backlog_item_id=generation_zero_lease.item_id,
        backlog_version=1,
        backlog_status=BacklogStatus.PENDING,
        backlog_attempt_count=0,
        retry_generation=0,
        closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
        completion_receipt_id=None,
        closure_case_revision=3,
        closure_audit_sequence=7,
        closure_audit_entry_hash=_sha(621),
        manifest_id=MANIFEST,
        recorded_at=datetime(2026, 7, 28, 11, tzinfo=UTC),
    )
    assert authority.reserved_images == 1 and authority.disclosed_images == 0
    record = _record().model_copy(update={"failure_authorities": (authority,)})
    assert record.total_reserved_images == 4
    assert record.total_input_images == 3
    payload = authority.model_dump(mode="json", exclude_computed_fields=True)
    payload["delivery_certainty"] = VLMDeliveryCertainty.UNKNOWN.value
    with pytest.raises(ValidationError):
        HearingModelCallFailureAuthority.model_validate(payload)


def test_role_payloads_are_strict_role_bound_and_preserve_unknown_refs() -> None:
    unknown = _ref(ArtifactKind.CROP, 999)
    argument = _prosecution_argument().model_copy(update={"evidence_refs": (unknown,)})
    payload = ProsecutorModelPayload(
        arguments=(argument,),
        case_summary="Unknown but syntactically valid references remain for the later gate.",
    )
    assert payload.arguments[0].evidence_refs == (unknown,)
    with pytest.raises(ValidationError):
        ProsecutorModelPayload.model_validate(
            {**payload.model_dump(mode="json", exclude_computed_fields=True), "role": "DEFENDER"}
        )
    session = _session()
    retrieval = _retrieval(session)
    with pytest.raises(ValidationError, match="prompt manifest"):
        _role_output(
            session,
            retrieval,
            VlmRole.PROSECUTOR,
            payload,
            1,
        ).model_copy(update={"prompt_manifest": _prompt(VlmRole.DEFENDER)})
    with pytest.raises(ValidationError, match="must cite typed evidence"):
        ProsecutorModelPayload(
            arguments=(_prosecution_argument().model_copy(update={"evidence_refs": ()}),),
            case_summary="A prosecution claim cannot omit its typed evidence.",
        )


def test_judge_outcome_is_exactly_final_or_one_typed_acquisition() -> None:
    final = JudgeModelPayload(
        outcome=JudgeFinalDecisionPayload(
            decision=VerdictDecision.NOT_ESTABLISHED,
            confidence=0.7,
            recommended_alert_level=AlertLevel.ADVISORY,
            rationale_summary="The evidence does not establish the allegation.",
        )
    )
    tampered = final.model_dump(mode="json", exclude_computed_fields=True)
    assert isinstance(tampered["outcome"], dict)
    tampered["outcome"]["request"] = {
        "action": "RECROP",
        "validated_parameters": {
            "action": "RECROP",
            "frame_id": "cam-01:stream-01:1",
            "bbox": {"x1": 0, "y1": 0, "x2": 10, "y2": 10},
        },
        "reason_summary": "Need another crop.",
        "supporting_evidence_refs": [],
    }
    with pytest.raises(ValidationError):
        JudgeModelPayload.model_validate(tampered)

    acquisition = JudgeModelPayload(
        outcome=JudgeAcquisitionDecisionPayload(
            request=AcquisitionRequestPayload(
                action=AcquisitionAction.RECROP,
                validated_parameters=RecropParameters(
                    action=AcquisitionAction.RECROP,
                    frame_id="cam-01:stream-01:1",
                    bbox=BBoxXYXY(x1=0, y1=0, x2=10, y2=10),
                ),
                reason_summary="A bounded recrop can resolve the visible ambiguity.",
            )
        )
    )
    assert acquisition.outcome.request.action == AcquisitionAction.RECROP


def test_hearing_model_call_cache_parse_and_repair_identity_are_scoped() -> None:
    request = _model_request()
    response_id = derive_hearing_model_response_id(RUN_ID, request.request_id, _sha(700))
    response = HearingModelResponse(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=request.hearing_session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        role=request.role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=_sha(700),
        size_bytes=512,
        input_tokens=100,
        output_tokens=50,
        latency_ms=20,
        model_manifest_id=request.model_manifest_id,
        manifest_id=MANIFEST,
    )
    unknown = HearingUnknownReferenceAttempt(
        namespace=UnknownReferenceNamespace.EVIDENCE,
        source=HearingUnknownReferenceSource.ARGUMENT_EVIDENCE_REF,
        value_sha256=_sha(701),
    )
    receipt = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=request.hearing_session_id,
        round_index=1,
        role=request.role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        unknown_reference_attempts=(unknown,),
        parsed_payload_sha256=_sha(702),
        manifest_id=MANIFEST,
    )
    cache = HearingModelCacheEntry(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=request.hearing_session_id,
        round_index=1,
        role=request.role,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        cache_key=request.cache_key,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        model_manifest_id=request.model_manifest_id,
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=MANIFEST,
    )
    assert receipt.unknown_reference_attempts == (unknown,)
    assert cache.cache_entry_id != cache.model_copy(update={"case_id": "case-02"}).cache_entry_id
    repair = _model_request(repair=True)
    assert repair.media == () and repair.repair_context_sha256 is not None
    with pytest.raises(ValidationError, match="redisclose media"):
        repair.model_copy(update={"media": (_media(),)})
    frame_disclosure = request.model_dump(mode="json", exclude_computed_fields=True)
    frame_disclosure["allowed_evidence_refs"] = [
        ArtifactRef(
            kind=ArtifactKind.FRAME,
            artifact_id="cam-01:stream-01:1",
        ).model_dump(mode="json")
    ]
    with pytest.raises(ValidationError, match="unauthorized artifact kind"):
        HearingModelRequest.model_validate(frame_disclosure)


def test_cycle_scope_is_the_early_authority_for_every_cycle_bound_artifact() -> None:
    session, hearing_round = _final_round()
    retrieval = hearing_round.precedent_retrieval_receipt
    scope = _cycle_scope(session, retrieval)
    request = _model_request(session=session, retrieval=retrieval)
    checkpoint = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=1,
        phase=HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        manifest_id=MANIFEST,
    )

    for artifact in (retrieval, request, checkpoint, hearing_round):
        validate_hearing_cycle_scope_binding(scope, artifact)
        assert artifact.cycle_scope_id == scope.cycle_id
        assert artifact.cycle_scope_sha256 == scope.cycle_sha256

    with pytest.raises(ValueError, match="stored cycle scope"):
        validate_hearing_cycle_scope_binding(
            scope,
            request.model_copy(update={"current_evidence_pack_id": _sha(999)}),
        )
    serialized = scope.model_dump(mode="json")
    serialized["cycle_id"] = _sha(998)
    with pytest.raises(ValidationError, match="cycle_id"):
        HearingCycleScope.model_validate(serialized)


def test_hearing_unknown_reference_diagnostics_have_closed_m4_path_semantics() -> None:
    expected_sources = {
        "ARGUMENT_EVIDENCE_REF",
        "JUDGE_RESPONSE_EVIDENCE_REF",
        "JUDGE_CITATION_REF",
        "OBJECTIVE_CLAIM_EVIDENCE_REF",
        "OBSERVATION_CROP_ID",
        "PRECEDENT_APPLICATION_ID",
        "PRECEDENT_FACT_DIFFERENCE_REF",
        "ACQUISITION_SUPPORTING_EVIDENCE_REF",
        "ACQUISITION_PARAMETER_FRAME_ID",
        "ACQUISITION_PARAMETER_CROP_ID",
    }
    assert {source.value for source in HearingUnknownReferenceSource} == expected_sources
    for source in HearingUnknownReferenceSource:
        expected_namespace = (
            UnknownReferenceNamespace.PRECEDENT
            if source == HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID
            else UnknownReferenceNamespace.EVIDENCE
        )
        attempt = HearingUnknownReferenceAttempt(
            namespace=expected_namespace,
            source=source,
            value_sha256=_sha(710 + list(HearingUnknownReferenceSource).index(source)),
        )
        assert attempt.source == source
        with pytest.raises(ValidationError, match="namespace"):
            HearingUnknownReferenceAttempt(
                namespace=(
                    UnknownReferenceNamespace.EVIDENCE
                    if expected_namespace == UnknownReferenceNamespace.PRECEDENT
                    else UnknownReferenceNamespace.PRECEDENT
                ),
                source=source,
                value_sha256=attempt.value_sha256,
            )

    request = _model_request()
    response = _response_for_request(request, 721)
    attempts = tuple(
        sorted(
            (
                HearingUnknownReferenceAttempt(
                    namespace=UnknownReferenceNamespace.EVIDENCE,
                    source=HearingUnknownReferenceSource.OBSERVATION_CROP_ID,
                    value_sha256=_sha(722),
                ),
                HearingUnknownReferenceAttempt(
                    namespace=UnknownReferenceNamespace.EVIDENCE,
                    source=HearingUnknownReferenceSource.JUDGE_CITATION_REF,
                    value_sha256=_sha(723),
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    with pytest.raises(ValidationError, match="stable order"):
        HearingModelParseReceipt(
            run_id=RUN_ID,
            case_id=CASE_ID,
            hearing_session_id=request.hearing_session_id,
            round_index=1,
            role=request.role,
            attempt_index=0,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            response_id=response.response_id,
            response_content_sha256=response.content_sha256,
            parser_version="strict-json-v1",
            output_schema_sha256=request.prompt_manifest.output_schema_sha256,
            status=ModelParseStatus.PARSED,
            unknown_reference_attempts=tuple(reversed(attempts)),
            parsed_payload_sha256=_sha(724),
            manifest_id=MANIFEST,
        )


@pytest.mark.parametrize(
    ("parameters", "inputs", "outputs", "needs_model"),
    [
        (
            RequestMoreFramesParameters(
                action=AcquisitionAction.REQUEST_MORE_FRAMES,
                camera_id="cam-01",
                stream_id="stream-01",
                start_frame=1,
                end_frame_exclusive=3,
            ),
            (),
            (
                ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-01:stream-01:1"),
                ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-01:stream-01:2"),
            ),
            False,
        ),
        (
            RecropParameters(
                action=AcquisitionAction.RECROP,
                frame_id="cam-01:stream-01:1",
                bbox=BBoxXYXY(x1=0, y1=0, x2=10, y2=10),
            ),
            (ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-01:stream-01:1"),),
            (_ref(ArtifactKind.CROP, 801),),
            False,
        ),
        (
            OtherCameraSameTimeParameters(
                action=AcquisitionAction.OTHER_CAMERA_SAME_TIME,
                source_frame_id="cam-01:stream-01:1",
                target_camera_id="cam-02",
            ),
            (ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-01:stream-01:1"),),
            (ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-02:stream-02:1"),),
            False,
        ),
        (
            TrackConfidenceCurveParameters(
                action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
                track_ref="cam-01:epoch-01:track-01",
                start_frame=1,
                end_frame_exclusive=3,
            ),
            (),
            (ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id="fact-curve-01"),),
            False,
        ),
        (
            RedetectHighResolutionParameters(
                action=AcquisitionAction.REDETECT_HIGH_RES,
                crop_id=_sha(1),
                prompts=("goggles", "protective eyewear"),
            ),
            (_ref(ArtifactKind.CROP, 1),),
            (ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id="detection-01"),),
            True,
        ),
    ],
)
def test_all_five_acquisition_actions_form_an_exact_execution_closure(
    parameters: object,
    inputs: tuple[ArtifactRef, ...],
    outputs: tuple[ArtifactRef, ...],
    needs_model: bool,
) -> None:
    session = _session()
    payload = AcquisitionRequestPayload(
        action=parameters.action,  # type: ignore[attr-defined]
        validated_parameters=parameters,  # type: ignore[arg-type]
        reason_summary="The Judge requested one bounded evidence operation.",
    )
    request = AcquisitionRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        source_judge_output_id=_sha(810),
        source_model_request_ref=_ref(ArtifactKind.MODEL_REQUEST, 811),
        source_model_response_ref=_ref(ArtifactKind.MODEL_RESPONSE, 812),
        request_payload=payload,
        manifest_id=MANIFEST,
    )
    execution = ToolExecutionManifest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        acquisition_request_id=request.request_id,
        action=request.action,
        tool_id=f"tool-{request.action.value.lower()}",
        tool_revision="tool-v1",
        parameters_schema_sha256=_sha(813),
        component_manifest_id=_sha(814),
        model_manifest_id=_sha(815) if needs_model else None,
        manifest_id=MANIFEST,
    )
    current_pack = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=PACK_ID)
    all_inputs = tuple(sorted((current_pack, *inputs), key=lambda item: item.sort_key))
    tool_result_id = derive_m4_tool_result_id(
        request.action,
        all_inputs,
        tuple(sorted(outputs, key=lambda item: item.sort_key)),
        request.validated_parameters,
        execution.execution_manifest_id,
    )
    result = ToolResult(
        tool_result_id=tool_result_id,
        action=request.action,
        input_refs=all_inputs,
        output_refs=tuple(sorted(outputs, key=lambda item: item.sort_key)),
        validated_parameters=request.validated_parameters,
        execution_manifest_id=execution.execution_manifest_id,
    )
    receipt = ToolExecutionReceipt(
        request=request,
        execution_manifest=execution,
        tool_result=result,
        resulting_evidence_pack_id=_sha(816),
        resulting_evidence_pack_version=2,
    )
    assert receipt.resulting_evidence_pack_version == 2
    invalid = payload.model_dump(mode="json", exclude_computed_fields=True)
    invalid["validated_parameters"]["path"] = "C:/unsafe"
    with pytest.raises(ValidationError):
        AcquisitionRequestPayload.model_validate(invalid)


def test_acquisition_execution_publication_fences_one_idempotent_result() -> None:
    session = _session()
    parameters = TrackConfidenceCurveParameters(
        action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
        track_ref="cam-01:epoch-01:track-01",
        start_frame=1,
        end_frame_exclusive=3,
    )
    request = AcquisitionRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        source_judge_output_id=_sha(820),
        source_model_request_ref=_ref(ArtifactKind.MODEL_REQUEST, 821),
        source_model_response_ref=_ref(ArtifactKind.MODEL_RESPONSE, 822),
        request_payload=AcquisitionRequestPayload(
            action=parameters.action,
            validated_parameters=parameters,
            reason_summary="The Judge requested a confidence curve.",
        ),
        manifest_id=MANIFEST,
    )
    manifest = ToolExecutionManifest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        acquisition_request_id=request.request_id,
        action=request.action,
        tool_id="track-confidence-tool",
        tool_revision="tool-v1",
        parameters_schema_sha256=_sha(823),
        component_manifest_id=_sha(824),
        manifest_id=MANIFEST,
    )
    input_refs = (ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=PACK_ID),)
    output_refs = (ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id="fact-curve-01"),)
    result = ToolResult(
        tool_result_id=derive_m4_tool_result_id(
            request.action,
            input_refs,
            output_refs,
            request.validated_parameters,
            manifest.execution_manifest_id,
        ),
        action=request.action,
        input_refs=input_refs,
        output_refs=output_refs,
        validated_parameters=request.validated_parameters,
        execution_manifest_id=manifest.execution_manifest_id,
    )
    fact = ObjectiveFact(
        fact_id="fact-curve-01",
        kind=ObjectiveFactKind.DETECTION_SCORE,
        value=0.75,
        source_ref=ArtifactRef(
            kind=ArtifactKind.TOOL_RESULT,
            artifact_id=result.tool_result_id,
        ),
        source_manifest_id=manifest.execution_manifest_id,
    )
    publication = AcquisitionExecutionPublication(
        request=request,
        execution_manifest=manifest,
        tool_result=result,
        objective_facts=(fact,),
        execution_mode=AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
        idempotency_key=request.request_id,
        claim_owner_sha256=_sha(825),
        claim_fence=1,
    )
    claim = AcquisitionExecutionClaimAuthority(
        request=request,
        execution_mode=AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
        idempotency_key=request.request_id,
        status=AcquisitionExecutionClaimState.ACTIVE,
        owner_token_sha256=_sha(825),
        owner_fence=1,
        lease_expires_at="2026-07-28T12:02:00.000000Z",
        created_at="2026-07-28T12:00:00.000000Z",
        updated_at="2026-07-28T12:00:00.000000Z",
    )

    assert AcquisitionExecutionClaimAuthority.model_validate(claim.model_dump(mode="json")) == claim
    assert (
        AcquisitionExecutionPublication.model_validate(publication.model_dump(mode="json"))
        == publication
    )
    incomplete_completion = claim.model_dump(mode="json")
    incomplete_completion.update(
        status=AcquisitionExecutionClaimState.COMPLETED,
        lease_expires_at=None,
    )
    with pytest.raises(ValidationError, match="completed acquisition claim"):
        AcquisitionExecutionClaimAuthority.model_validate(incomplete_completion)
    tampered = publication.model_dump(mode="json", exclude={"publication_id"})
    tampered["idempotency_key"] = _sha(826)
    with pytest.raises(ValidationError, match="idempotency key"):
        AcquisitionExecutionPublication.model_validate(tampered)


def test_empty_successful_precedent_retrieval_is_distinct_from_degraded() -> None:
    session = _session()
    empty = _retrieval(session)
    degraded = _retrieval(session, degraded=True)
    assert empty.scored_precedents == degraded.scored_precedents == ()
    assert empty.status == HearingPrecedentRetrievalStatus.SUCCESS
    assert degraded.status == HearingPrecedentRetrievalStatus.DEGRADED
    assert empty.receipt_id != degraded.receipt_id


def test_session_record_usage_and_computed_identities_fail_closed() -> None:
    record = _record()
    assert record.complete is True
    assert record.total_output_tokens == 150
    assert record.model_validate(record.model_dump(mode="json")) == record
    tampered = record.model_dump(mode="json")
    tampered["record_id"] = _sha(999)
    with pytest.raises(ValidationError, match="record_id"):
        HearingRecord.model_validate(tampered)
    duplicate = record.usage_receipts[0]
    with pytest.raises(ValidationError, match="charge"):
        record.model_copy(
            update={
                "usage_receipts": (
                    duplicate,
                    duplicate.model_copy(update={"role": VlmRole.JUDGE}),
                    record.usage_receipts[2],
                )
            }
        )


def test_checkpoint_represents_partial_progress_and_rejects_jump_or_cross_pack() -> None:
    session, hearing_round = _final_round()
    opened = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=1,
        phase=HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        manifest_id=MANIFEST,
    )
    prosecutor_pending = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=2,
        phase=HearingCheckpointPhase.PROSECUTOR_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        previous_checkpoint_id=opened.checkpoint_id,
        previous_checkpoint_sha256=opened.checkpoint_sha256,
        previous_phase=opened.phase,
        precedent_retrieval_receipt=hearing_round.precedent_retrieval_receipt,
        manifest_id=MANIFEST,
    )
    assert prosecutor_pending.phase == HearingCheckpointPhase.PROSECUTOR_PENDING
    with pytest.raises(ValidationError, match="first checkpoint"):
        opened.model_copy(update={"phase": HearingCheckpointPhase.JUDGE_PENDING})
    with pytest.raises(ValidationError, match="pack scope"):
        HearingCheckpoint(
            **prosecutor_pending.model_dump(
                mode="python",
                exclude={
                    "checkpoint_id",
                    "checkpoint_sha256",
                    "phase",
                    "previous_checkpoint_id",
                    "previous_checkpoint_sha256",
                    "previous_phase",
                    "prosecutor_output",
                    "version",
                    "model_request_refs",
                    "model_response_refs",
                    "parse_receipt_refs",
                    "usage_receipts",
                },
            ),
            version=3,
            phase=HearingCheckpointPhase.DEFENDER_PENDING,
            previous_checkpoint_id=prosecutor_pending.checkpoint_id,
            previous_checkpoint_sha256=prosecutor_pending.checkpoint_sha256,
            previous_phase=prosecutor_pending.phase,
            prosecutor_output=hearing_round.prosecutor_output.model_copy(
                update={"current_evidence_pack_id": _sha(998)}
            ),
            **_checkpoint_trace(hearing_round.prosecutor_output),
        )


def test_checkpoint_role_output_requires_its_complete_provider_trace() -> None:
    session, hearing_round = _final_round()
    with pytest.raises(ValidationError, match="complete provider traces"):
        HearingCheckpoint(
            run_id=RUN_ID,
            case_id=CASE_ID,
            hearing_session_id=session.session_id,
            hearing_session_sha256=session.session_sha256,
            version=2,
            phase=HearingCheckpointPhase.DEFENDER_PENDING,
            judge_cycle=1,
            prior_acquisition_rounds=0,
            prior_rework_rounds=0,
            cycle_evidence_pack_id=PACK_ID,
            cycle_evidence_pack_version=1,
            current_evidence_pack_id=PACK_ID,
            current_evidence_pack_version=1,
            previous_checkpoint_id=_sha(920),
            previous_checkpoint_sha256=_sha(921),
            previous_phase=HearingCheckpointPhase.PROSECUTOR_PENDING,
            precedent_retrieval_receipt=hearing_round.precedent_retrieval_receipt,
            prosecutor_output=hearing_round.prosecutor_output,
            manifest_id=MANIFEST,
        )


def test_round_complete_final_checkpoint_cannot_smuggle_an_acquisition_request() -> None:
    session, hearing_round = _final_round()
    judge = hearing_round.judge_output
    request = AcquisitionRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        source_judge_output_id=judge.output_id,
        source_model_request_ref=judge.request_ref,
        source_model_response_ref=judge.response_ref,
        request_payload=AcquisitionRequestPayload(
            action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
            validated_parameters=TrackConfidenceCurveParameters(
                action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
                track_ref="cam-01:epoch-01:track-01",
                start_frame=1,
                end_frame_exclusive=3,
            ),
            reason_summary="This request must not coexist with a final Judge proposal.",
        ),
        manifest_id=MANIFEST,
    )
    with pytest.raises(ValidationError, match="Judge proposal"):
        HearingCheckpoint(
            run_id=RUN_ID,
            case_id=CASE_ID,
            hearing_session_id=session.session_id,
            hearing_session_sha256=session.session_sha256,
            version=2,
            phase=HearingCheckpointPhase.ROUND_COMPLETE,
            judge_cycle=1,
            prior_acquisition_rounds=0,
            prior_rework_rounds=0,
            cycle_evidence_pack_id=PACK_ID,
            cycle_evidence_pack_version=1,
            current_evidence_pack_id=PACK_ID,
            current_evidence_pack_version=1,
            previous_checkpoint_id=_sha(922),
            previous_checkpoint_sha256=_sha(923),
            previous_phase=HearingCheckpointPhase.JUDGE_PENDING,
            precedent_retrieval_receipt=hearing_round.precedent_retrieval_receipt,
            prosecutor_output=hearing_round.prosecutor_output,
            defender_output=hearing_round.defender_output,
            judge_output=judge,
            acquisition_request=request,
            manifest_id=MANIFEST,
            **_checkpoint_trace(
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                judge,
            ),
        )


def test_checkpoint_review_authority_is_phase_and_reason_bound() -> None:
    session = _session()
    with pytest.raises(ValidationError, match="cannot claim a procedural review"):
        HearingCheckpoint(
            run_id=RUN_ID,
            case_id=CASE_ID,
            hearing_session_id=session.session_id,
            hearing_session_sha256=session.session_sha256,
            version=1,
            phase=HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
            judge_cycle=1,
            prior_acquisition_rounds=0,
            prior_rework_rounds=0,
            cycle_evidence_pack_id=PACK_ID,
            cycle_evidence_pack_version=1,
            current_evidence_pack_id=PACK_ID,
            current_evidence_pack_version=1,
            procedural_review_ref=_ref(ArtifactKind.PROCEDURAL_REVIEW, 924),
            manifest_id=MANIFEST,
        )


def test_human_review_receipt_binds_the_preterminal_checkpoint() -> None:
    session = _session()
    source = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=1,
        phase=HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        manifest_id=MANIFEST,
    )
    receipt = HearingHumanReviewReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        judge_cycle=1,
        reason=HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
        source_checkpoint_id=source.checkpoint_id,
        source_checkpoint_sha256=source.checkpoint_sha256,
        source_checkpoint_version=source.version,
        manifest_id=MANIFEST,
    )
    terminal = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=2,
        phase=HearingCheckpointPhase.HUMAN_REVIEW,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        previous_checkpoint_id=source.checkpoint_id,
        previous_checkpoint_sha256=source.checkpoint_sha256,
        previous_phase=source.phase,
        human_review_receipt_id=receipt.receipt_id,
        human_review_receipt_sha256=receipt.receipt_sha256,
        human_review_reason=receipt.reason,
        manifest_id=MANIFEST,
    )
    assert terminal.human_review_receipt_id == receipt.receipt_id
    assert HearingHumanReviewReceipt.model_validate(receipt.model_dump(mode="json")) == receipt
    with pytest.raises(ValidationError, match="receipt_sha256"):
        HearingHumanReviewReceipt.model_validate(
            {**receipt.model_dump(mode="json"), "receipt_sha256": _sha(900)}
        )


@pytest.mark.parametrize(
    ("reason", "authority_fields"),
    [
        (
            HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED,
            {"acquisition_request_ref": _ref(ArtifactKind.MODEL_REQUEST, 930)},
        ),
        (
            HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED,
            {"procedural_review_ref": _ref(ArtifactKind.PROCEDURAL_REVIEW, 931)},
        ),
        (HearingHumanReviewReason.HEARING_BUDGET_EXHAUSTED, {}),
        (HearingHumanReviewReason.EVIDENCE_UNAVAILABLE, {}),
        (
            HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE,
            {"acquisition_request_ref": _ref(ArtifactKind.MODEL_REQUEST, 932)},
        ),
        (
            HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED,
            {"backlog_item_ref": _ref(ArtifactKind.BACKLOG_ITEM, 933)},
        ),
    ],
)
def test_human_review_reason_requires_exact_authority_set(
    reason: HearingHumanReviewReason,
    authority_fields: dict[str, ArtifactRef],
) -> None:
    receipt = HearingHumanReviewReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=_session().session_id,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        judge_cycle=1,
        reason=reason,
        source_checkpoint_id=_sha(934),
        source_checkpoint_sha256=_sha(935),
        source_checkpoint_version=2,
        manifest_id=MANIFEST,
        **authority_fields,
    )
    contamination = (
        {"procedural_review_ref": _ref(ArtifactKind.PROCEDURAL_REVIEW, 936)}
        if receipt.procedural_review_ref is None
        else {"backlog_item_ref": _ref(ArtifactKind.BACKLOG_ITEM, 937)}
    )
    with pytest.raises(ValidationError, match="exact authority"):
        receipt.model_copy(update=contamination)


@pytest.mark.parametrize(
    ("reason", "allowed_phase", "wrong_phase"),
    [
        (
            HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED,
            HearingCheckpointPhase.JUDGE_PENDING,
            HearingCheckpointPhase.PROSECUTOR_PENDING,
        ),
        (
            HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED,
            HearingCheckpointPhase.REWORK_READY,
            HearingCheckpointPhase.ROUND_COMPLETE,
        ),
        (
            HearingHumanReviewReason.HEARING_BUDGET_EXHAUSTED,
            HearingCheckpointPhase.DEFENDER_PENDING,
            HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        ),
        (
            HearingHumanReviewReason.EVIDENCE_UNAVAILABLE,
            HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
            HearingCheckpointPhase.ACQUISITION_PENDING,
        ),
        (
            HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE,
            HearingCheckpointPhase.ACQUISITION_PENDING,
            HearingCheckpointPhase.JUDGE_PENDING,
        ),
        (
            HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED,
            HearingCheckpointPhase.PROSECUTOR_PENDING,
            HearingCheckpointPhase.ACQUISITION_PENDING,
        ),
    ],
)
def test_human_review_reason_is_bound_to_source_phase(
    reason: HearingHumanReviewReason,
    allowed_phase: HearingCheckpointPhase,
    wrong_phase: HearingCheckpointPhase,
) -> None:
    session = _session()
    fields: dict[str, object] = {}
    if reason == HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED:
        fields["procedural_review_ref"] = _ref(ArtifactKind.PROCEDURAL_REVIEW, 938)
    checkpoint = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=2,
        phase=HearingCheckpointPhase.HUMAN_REVIEW,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        previous_checkpoint_id=_sha(939),
        previous_checkpoint_sha256=_sha(940),
        previous_phase=allowed_phase,
        human_review_receipt_id=_sha(941),
        human_review_receipt_sha256=_sha(942),
        human_review_reason=reason,
        manifest_id=MANIFEST,
        **fields,
    )
    assert checkpoint.previous_phase == allowed_phase
    with pytest.raises(ValidationError, match="source phase"):
        checkpoint.model_copy(update={"previous_phase": wrong_phase})


def test_every_terminal_judge_proposal_can_bind_a_verdict_before_l5_passes() -> None:
    record = _record()
    hearing_round = record.rounds[-1]
    binding = HearingVerdictBinding(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=record.hearing_session_id,
        hearing_record_id=record.record_id,
        hearing_record_version=record.version,
        hearing_record_sha256=record.record_sha256,
        judge_round_id=hearing_round.round_id,
        judge_round_index=1,
        evidence_pack_id=PACK_ID,
        evidence_pack_version=1,
        prosecutor_output_id=hearing_round.prosecutor_output.output_id,
        defender_output_id=hearing_round.defender_output.output_id,
        judge_output_id=hearing_round.judge_output.output_id,
        verdict_id=_sha(901),
        verdict_version=1,
        verdict_input_sha256=_sha(902),
        verdict_sha256=_sha(903),
        model_request_refs=record.model_request_refs,
        model_response_refs=record.model_response_refs,
        parse_receipt_refs=record.parse_receipt_refs,
        manifest_id=MANIFEST,
    )
    assert binding.binding_id
    assert "procedural_review" not in HearingVerdictBinding.model_fields


def test_m4_prompt_templates_keep_data_and_repair_context_explicit() -> None:
    prompt_root = Path(__file__).parents[2] / "prompts"
    for role in ("prosecutor", "defender", "judge"):
        text = (prompt_root / f"hearing_{role}_v1.jinja").read_text(encoding="utf-8")
        assert "HEARING_CONTEXT_JSON={{ hearing_context_json }}" in text
        assert "REPAIR_CONTEXT_JSON={{ repair_context_json }}" in text
        assert "PRIOR_RESPONSE_JSON={{ prior_response_json }}" in text
        assert "OUTPUT_SCHEMA_JSON={{ output_schema_json }}" in text
        assert "chain of thought" in text


def _representative_roots() -> dict[str, object]:
    request = _model_request()
    response_id = derive_hearing_model_response_id(RUN_ID, request.request_id, _sha(950))
    response = HearingModelResponse(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=request.hearing_session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        role=request.role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{RUN_ID}/model_responses/{response_id}.json",
        content_sha256=_sha(950),
        size_bytes=1,
        model_manifest_id=request.model_manifest_id,
        manifest_id=MANIFEST,
    )
    record = _record()
    session = record.session
    hearing_round = record.rounds[0]
    cycle_scope = _cycle_scope(session, hearing_round.precedent_retrieval_receipt)
    opened = HearingCheckpoint(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=1,
        phase=HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=PACK_ID,
        cycle_evidence_pack_version=1,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        manifest_id=MANIFEST,
    )
    unknown_attempt = HearingUnknownReferenceAttempt(
        namespace=UnknownReferenceNamespace.EVIDENCE,
        source=HearingUnknownReferenceSource.OBSERVATION_CROP_ID,
        value_sha256=_sha(970),
    )
    parsed = HearingModelParseReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        role=request.role,
        attempt_index=0,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        unknown_reference_attempts=(unknown_attempt,),
        parsed_payload_sha256=hearing_round.prosecutor_output.payload.payload_sha256,
        manifest_id=MANIFEST,
    )
    cache = HearingModelCacheEntry(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        role=request.role,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        cache_key=request.cache_key,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        model_manifest_id=request.model_manifest_id,
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=MANIFEST,
    )
    human = HearingHumanReviewReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        judge_cycle=1,
        reason=HearingHumanReviewReason.HEARING_BUDGET_EXHAUSTED,
        source_checkpoint_id=opened.checkpoint_id,
        source_checkpoint_sha256=opened.checkpoint_sha256,
        source_checkpoint_version=1,
        manifest_id=MANIFEST,
    )
    lease, retry_primary, strict_proof = _strict_retry_fixture()
    strict_response_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=attempt.response.response_id,
                )
                for attempt in strict_proof.attempts
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    retry_failure = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=strict_proof.source_checkpoint_id,
        source_checkpoint_sha256=strict_proof.source_checkpoint_sha256,
        source_checkpoint_version=strict_proof.source_checkpoint_version,
        request=retry_primary,
        role=retry_primary.role,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.PENDING,
        response_refs=strict_response_refs,
        strict_parse_failure=strict_proof,
        manifest_id=MANIFEST,
    )
    retry_success = _prosecutor_retry_success_fixture()
    completion = HearingBacklogCompletionReceipt(
        outcome=retry_success,
        backlog_status=BacklogStatus.COMPLETED,
        source_checkpoint_id=retry_success.source_checkpoint_id,
        source_checkpoint_sha256=retry_success.source_checkpoint_sha256,
        source_checkpoint_version=retry_success.source_checkpoint_version,
        resulting_checkpoint_id=retry_success.next_checkpoint.checkpoint_id,
        resulting_checkpoint_sha256=retry_success.next_checkpoint.checkpoint_sha256,
        resulting_checkpoint_version=retry_success.next_checkpoint.version,
        completion_case_status=CaseStatus.DELIBERATING,
        completion_case_revision=3,
        completion_audit_sequence=8,
        completion_audit_entry_hash=_sha(960),
        manifest_id=MANIFEST,
    )
    initial_failure_authority = HearingModelCallFailureAuthority(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=request.hearing_session_id,
        role=request.role,
        request=request,
        source_checkpoint_id=opened.checkpoint_id,
        source_checkpoint_sha256=opened.checkpoint_sha256,
        source_checkpoint_version=opened.version,
        claim_owner_sha256=_sha(961),
        claim_lease_expires_at=datetime(2026, 7, 28, 12, tzinfo=UTC),
        claim_takeover_count=0,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        reserved_images=1,
        reserved_pixels=10_000,
        disclosed_images=0,
        disclosed_pixels=0,
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        estimated_cost=0.0,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        backlog_item_id=_sha(962),
        backlog_version=1,
        backlog_status=BacklogStatus.PENDING,
        backlog_attempt_count=0,
        retry_generation=0,
        closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
        closure_case_revision=3,
        closure_audit_sequence=8,
        closure_audit_entry_hash=_sha(963),
        manifest_id=MANIFEST,
        recorded_at=datetime(2026, 7, 28, 11, tzinfo=UTC),
    )
    acquisition_payload = AcquisitionRequestPayload(
        action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
        validated_parameters=TrackConfidenceCurveParameters(
            action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
            track_ref="cam-01:epoch-01:track-01",
            start_frame=1,
            end_frame_exclusive=3,
        ),
        reason_summary="The confidence curve can resolve association ambiguity.",
    )
    acquisition_request = AcquisitionRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        source_judge_output_id=hearing_round.judge_output.output_id,
        source_model_request_ref=hearing_round.judge_output.request_ref,
        source_model_response_ref=hearing_round.judge_output.response_ref,
        request_payload=acquisition_payload,
        manifest_id=MANIFEST,
    )
    tool_manifest = ToolExecutionManifest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        acquisition_request_id=acquisition_request.request_id,
        action=acquisition_request.action,
        tool_id="tool-track-confidence-curve",
        tool_revision="tool-v1",
        parameters_schema_sha256=_sha(964),
        component_manifest_id=_sha(965),
        manifest_id=MANIFEST,
    )
    tool_inputs = (ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=PACK_ID),)
    tool_outputs = (ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id="fact-curve-01"),)
    tool_result = ToolResult(
        tool_result_id=derive_m4_tool_result_id(
            acquisition_request.action,
            tool_inputs,
            tool_outputs,
            acquisition_request.validated_parameters,
            tool_manifest.execution_manifest_id,
        ),
        action=acquisition_request.action,
        input_refs=tool_inputs,
        output_refs=tool_outputs,
        validated_parameters=acquisition_request.validated_parameters,
        execution_manifest_id=tool_manifest.execution_manifest_id,
    )
    tool_receipt = ToolExecutionReceipt(
        request=acquisition_request,
        execution_manifest=tool_manifest,
        tool_result=tool_result,
        resulting_evidence_pack_id=_sha(966),
        resulting_evidence_pack_version=2,
    )
    embedding_manifest = ModelManifest(
        component="text_embedding",
        provider="fake",
        model="deterministic-text-embedding",
        revision="1.0.0",
        license_id="synthetic-fixture",
    )
    retrieval_query = HearingPrecedentRetrievalQuery(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        cycle_scope_id=cycle_scope.cycle_id,
        cycle_scope_sha256=cycle_scope.cycle_sha256,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        current_evidence_pack_sha256=_sha(971),
        evidence_class=hearing_round.precedent_retrieval_receipt.evidence_class,
        violation_type=hearing_round.precedent_retrieval_receipt.violation_type,
        rule_version=hearing_round.precedent_retrieval_receipt.rule_version,
        situation_text="A reagent container remained open during controlled work.",
        top_k=hearing_round.precedent_retrieval_receipt.top_k,
        config_sha256=_sha(972),
        retriever_version=hearing_round.precedent_retrieval_receipt.retriever_version,
        retriever_manifest_id=(hearing_round.precedent_retrieval_receipt.retriever_manifest_id),
        embedding_model_manifest=embedding_manifest,
        manifest_id=MANIFEST,
    )
    retrieval_result = HearingPrecedentRetrievalResult(query=retrieval_query)
    outcome_receipt = hearing_round.precedent_retrieval_receipt.model_copy(
        update={
            "query_sha256": retrieval_query.query_sha256,
            "candidate_snapshot_sha256": retrieval_result.candidate_snapshot_sha256,
            "visible_snapshot_sha256": retrieval_result.visible_snapshot_sha256,
            "embedding_model_manifest_id": embedding_manifest.model_manifest_id,
        }
    )
    retrieval_outcome = HearingPrecedentRetrievalOutcome(
        query=retrieval_query,
        result=retrieval_result,
        receipt=outcome_receipt,
    )
    verdict_binding = HearingVerdictBinding(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=record.hearing_session_id,
        hearing_record_id=record.record_id,
        hearing_record_version=record.version,
        hearing_record_sha256=record.record_sha256,
        judge_round_id=hearing_round.round_id,
        judge_round_index=1,
        evidence_pack_id=PACK_ID,
        evidence_pack_version=1,
        prosecutor_output_id=hearing_round.prosecutor_output.output_id,
        defender_output_id=hearing_round.defender_output.output_id,
        judge_output_id=hearing_round.judge_output.output_id,
        verdict_id=_sha(967),
        verdict_version=1,
        verdict_input_sha256=_sha(968),
        verdict_sha256=_sha(969),
        model_request_refs=record.model_request_refs,
        model_response_refs=record.model_response_refs,
        parse_receipt_refs=record.parse_receipt_refs,
        manifest_id=MANIFEST,
    )
    initial_strict_proof = _initial_strict_failure_fixture()
    recovery_report = HearingModelResponseRecoveryReport(
        run_id=RUN_ID,
        started_at=datetime(2026, 7, 28, 12, tzinfo=UTC),
        claim_limit=10,
        claims_scanned=0,
        scan_complete=True,
    )
    rework_receipt = HearingReworkReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        failed_review_id=_sha(985),
        prior_round_id=hearing_round.round_id,
        next_cycle_scope_id=_sha(986),
        next_cycle_scope_sha256=_sha(987),
        rework_index=1,
        defect_codes=(ProceduralDefectCode.UNANSWERED_DEFENSE_POINT,),
        prompt_defect_summary_sha256=_sha(988),
        manifest_id=MANIFEST,
    )
    return {
        "acquisition-request": acquisition_request,
        "acquisition-request-payload": acquisition_payload,
        "defender-model-payload": hearing_round.defender_output.payload,
        "hearing-backlog-completion-receipt": completion,
        "hearing-backlog-retry-failure": retry_failure,
        "hearing-backlog-retry-success": retry_success,
        "hearing-checkpoint": opened,
        "hearing-cycle-scope": cycle_scope,
        "hearing-human-review-receipt": human,
        "hearing-initial-strict-parse-failure-proof": initial_strict_proof,
        "hearing-model-cache-entry": cache,
        "hearing-model-call-failure-authority": initial_failure_authority,
        "hearing-model-parse-receipt": parsed,
        "hearing-model-request": request,
        "hearing-model-response": response,
        "hearing-model-response-recovery-report": recovery_report,
        "hearing-precedent-retrieval-outcome": retrieval_outcome,
        "hearing-precedent-retrieval-query": retrieval_query,
        "hearing-precedent-retrieval-receipt": hearing_round.precedent_retrieval_receipt,
        "hearing-precedent-retrieval-result": retrieval_result,
        "hearing-record": record,
        "hearing-rework-receipt": rework_receipt,
        "hearing-role-output": hearing_round.prosecutor_output,
        "hearing-round": hearing_round,
        "hearing-session": session,
        "hearing-strict-parse-failure-attempt": strict_proof.attempts[0],
        "hearing-strict-parse-failure-proof": strict_proof,
        "hearing-usage-receipt": record.usage_receipts[0],
        "hearing-unknown-reference-attempt": unknown_attempt,
        "hearing-verdict-binding": verdict_binding,
        "judge-model-payload": hearing_round.judge_output.payload,
        "prosecutor-model-payload": hearing_round.prosecutor_output.payload,
        "tool-execution-manifest": tool_manifest,
        "tool-execution-receipt": tool_receipt,
        "tool-result": tool_result,
    }


def test_m4_root_schemas_validate_round_trip_and_identity_vector_is_golden() -> None:
    schemas = expected_schema_files()
    roots = _representative_roots()
    expected_root_names = {name for name in SCHEMA_MODELS if name.startswith("hearing-")} | {
        "acquisition-request",
        "acquisition-request-payload",
        "defender-model-payload",
        "judge-model-payload",
        "prosecutor-model-payload",
        "tool-execution-manifest",
        "tool-execution-receipt",
        "tool-result",
    }
    assert set(roots) == expected_root_names
    validation_roots = {
        "acquisition-request-payload",
        "defender-model-payload",
        "judge-model-payload",
        "prosecutor-model-payload",
    }
    for name, root in roots.items():
        payload = root.model_dump(
            mode="json",
            exclude_computed_fields=name in validation_roots,
        )
        Draft202012Validator(json.loads(schemas[f"{name}.schema.json"])).validate(payload)
        assert type(root).model_validate(root.model_dump(mode="json")) == root
    expected = {
        "session_id": "19f6616b230d431e828a81844411d951edcbbfd9c66bfa9bbfe83b4018539308",
        "cycle_id": "58de55e40960d0b281c72a4c7a62fd84b45bca39b779b5bf836ce7f330c61ba3",
        "retrieval_id": "03c2bf2073b6b6b2051261d48886757a48b86939bb95c75104ac07829bb98c87",
        "retrieval_query_id": "6401378d5561275e6c6562758add340106e85f406830d9bea9b152b4f3f53c3d",
        "retrieval_result_id": "24b032fcc641d57d89f4f746e9b91c88d41b37aa2e6d077033d58419e7cbbae4",
        "retrieval_outcome_receipt_id": (
            "59b12498ab23dbddc9efade2af82c000e212ca0cabf171e3d9ec46c282e7ac3d"
        ),
        "round_id": "d54621b8b6dd783ec7d2792ce8505f2435a4a694a4e46ec981a43c07e1eb92f9",
        "record_id": "3bfad98790525766fd4ff06f0a4f3eede635dc07db2213373e593f7d843b13e9",
        "checkpoint_id": "63ac5ac9f6718682588bb38a5a5d22c384421fbd11c921f1b77f5c45ccd1ea73",
        "request_id": "88271620700176a143bf463fc36e680cb8d231115fd396720314da282062de13",
    }
    actual = {
        "session_id": roots["hearing-session"].session_id,
        "cycle_id": roots["hearing-cycle-scope"].cycle_id,
        "retrieval_id": roots["hearing-precedent-retrieval-receipt"].receipt_id,
        "retrieval_query_id": roots["hearing-precedent-retrieval-query"].query_id,
        "retrieval_result_id": roots["hearing-precedent-retrieval-result"].result_id,
        "retrieval_outcome_receipt_id": roots[
            "hearing-precedent-retrieval-outcome"
        ].receipt.receipt_id,
        "round_id": roots["hearing-round"].round_id,
        "record_id": roots["hearing-record"].record_id,
        "checkpoint_id": roots["hearing-checkpoint"].checkpoint_id,
        "request_id": roots["hearing-model-request"].request_id,
    }
    assert actual == expected
