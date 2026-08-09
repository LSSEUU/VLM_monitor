import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from labcourt.contracts.backlog import BacklogItem, BacklogRetryContext
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AcquisitionAction,
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ModelParseStatus,
    ObjectiveFactKind,
    ObservationSource,
    PpeType,
    PrecedentLookupStatus,
    PrecedentSource,
    PrecedentStatus,
    PrivacyPolicy,
    PrivacyReasonCode,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    ScreeningConflictCode,
    ScreeningDecision,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
    VerdictDecision,
    ViolationType,
    VlmRole,
    WearStatus,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    ObservabilityComponents,
    ObservabilityScore,
    ObservationSufficiencyInput,
    PrivacyReceipt,
    RequestMoreFramesParameters,
    ToolResult,
    TrackSummary,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing import derive_m4_tool_result_id
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    PrecedentLookupQuery,
    PrecedentResolution,
    PromptManifest,
    UnknownReferenceAttempt,
    VlmCallBudget,
)
from labcourt.contracts.model_call_failures import (
    ModelCallFailureAuthority,
    ModelCallFailureClosureKind,
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.precedents import Precedent
from labcourt.contracts.screening import (
    FrameObservation,
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningModelPayload,
    ScreeningResult,
    StructureRepairRequest,
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import (
    DEFECT_ORDER,
    ObjectiveClaim,
    ProceduralDefect,
    ProceduralReview,
    Verdict,
)
from labcourt.schema_export import expected_schema_files

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
RUN_ID = "run-01"
SHA_0 = "0" * 64
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64
SHA_8 = "8" * 64
SHA_9 = "9" * 64
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _prompt(role: VlmRole = VlmRole.SCREENING) -> PromptManifest:
    return PromptManifest(
        prompt_id=f"{role.value.lower()}-v1",
        role=role,
        template_sha256=SHA_1,
        output_schema_sha256=SHA_2,
        prompt_bundle_sha256=SHA_3,
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
        max_json_fields=128,
        max_string_chars=8_192,
        timeout_seconds=15.0,
        claim_completion_grace_seconds=5.0,
    )


def _media(crop_id: str = SHA_4, *, run_id: str = RUN_ID) -> VLMMediaRef:
    return VLMMediaRef(
        crop_id=crop_id,
        media_sha256=SHA_5,
        local_path=f"{run_id}/frames/{SHA_5}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=100,
        height=100,
    )


def _request(
    *,
    run_id: str = RUN_ID,
    case_id: str = "case-01",
    evidence_pack_id: str = SHA_6,
    evidence_pack_version: int = 1,
    violation_type: ViolationType = ViolationType.REAGENT_CONTAINER_OPEN,
    evidence_class: EvidenceClass = EvidenceClass.PRESENCE,
    allowed_evidence_refs: tuple[ArtifactRef, ...] | None = None,
) -> VLMRequest:
    media = (_media(run_id=run_id),)
    return VLMRequest(
        run_id=run_id,
        case_id=case_id,
        evidence_pack_id=evidence_pack_id,
        evidence_pack_version=evidence_pack_version,
        provider_profile="fake-screening",
        provider="fixture",
        model="fixture-vlm",
        revision="1.0.0",
        model_manifest_id=SHA_7,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=_prompt(),
        rendered_prompt_sha256=SHA_8,
        violation_type=violation_type,
        evidence_class=evidence_class,
        rule_summary="Apply the configured laboratory rule.",
        media=media,
        allowed_evidence_refs=allowed_evidence_refs
        or (ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media[0].crop_id),),
        objective_summary={"duration_frames": 91},
        temperature=0.0,
        seed=7,
        budget=_budget(),
        manifest_id=SHA_9,
    )


def _response(request: VLMRequest, *, content_sha256: str = EMPTY_SHA256) -> VLMResponse:
    response_id = derive_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
    return VLMResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        purpose=request.purpose,
        attempt_index=0,
        raw_response_ref=(f"{request.run_id}/model_responses/{response_id}.json"),
        content_sha256=content_sha256,
        size_bytes=0,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _failure_authority(request: VLMRequest | None = None) -> ModelCallFailureAuthority:
    request = request or _request()
    return ModelCallFailureAuthority(
        run_id=RUN_ID,
        request=request,
        claim_owner_sha256=SHA_A,
        claim_lease_expires_at=datetime(2026, 7, 28, 8, 30, tzinfo=UTC),
        claim_takeover_count=0,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        backlog_item_id=SHA_B,
        backlog_version=1,
        backlog_status=BacklogStatus.PENDING,
        backlog_attempt_count=0,
        retry_generation=0,
        closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
        closure_case_revision=2,
        closure_audit_sequence=3,
        closure_audit_entry_hash=SHA_C,
        manifest_id=request.manifest_id,
        recorded_at=datetime(2026, 7, 28, 8, 10, tzinfo=UTC),
    )


def _parsed(
    *,
    run_id: str = RUN_ID,
    case_id: str = "case-01",
    evidence_pack_id: str = SHA_6,
    evidence_pack_version: int = 1,
    violation_type: ViolationType = ViolationType.REAGENT_CONTAINER_OPEN,
    evidence_class: EvidenceClass = EvidenceClass.PRESENCE,
    probability: float = 0.95,
    observations: tuple[FrameObservation, ...] = (),
    objective_claims: tuple[ObjectiveClaim, ...] = (),
    manifest_id: str = SHA_9,
) -> ParsedScreeningOutput:
    return ParsedScreeningOutput(
        run_id=run_id,
        case_id=case_id,
        evidence_pack_id=evidence_pack_id,
        evidence_pack_version=evidence_pack_version,
        request_id=SHA_A,
        response_id=SHA_B,
        response_content_sha256=SHA_C,
        output_schema_sha256=SHA_2,
        payload=ScreeningModelPayload(
            violation_type=violation_type,
            evidence_class=evidence_class,
            violation_probability=probability,
            frame_observations=observations,
            objective_claims=objective_claims,
            prosecution_summary="The structured observations support routing.",
            rationale_summary="Only typed fields are used by deterministic code.",
        ),
        manifest_id=manifest_id,
    )


def _screening(
    parsed: ParsedScreeningOutput,
    *,
    version: int = 1,
    authoritative_evidence_class: EvidenceClass | None = None,
    l1_score: float = 0.2,
    strong_threshold: float = 0.8,
    alleged_crop_ids: tuple[str, ...] = (),
    clear_crop_ids: tuple[str, ...] = (),
    correction_frame_ids: tuple[str, ...] = (),
    required_clear_count: int | None = None,
) -> ScreeningResult:
    return ScreeningResult(
        run_id=parsed.run_id,
        case_id=parsed.case_id,
        version=version,
        evidence_pack_id=parsed.evidence_pack_id,
        evidence_pack_version=parsed.evidence_pack_version,
        parsed_output=parsed,
        low_probability=0.15,
        high_probability=0.88,
        authoritative_evidence_class=(authoritative_evidence_class or parsed.evidence_class),
        authoritative_l1_score=l1_score,
        strong_signal_threshold=strong_threshold,
        conflict_policy_version="strong-signal-v1",
        alleged_interval_crop_ids=alleged_crop_ids,
        authoritative_clear_crop_ids=clear_crop_ids,
        correction_frame_ids=correction_frame_ids,
        required_clear_count=required_clear_count,
        router_version="screening-router-v1",
        manifest_id=parsed.manifest_id,
    )


def _parser_defect(
    response_id: str,
    code: ProceduralDefectCode = ProceduralDefectCode.MALFORMED_STRUCTURE,
) -> ProceduralDefect:
    if code == ProceduralDefectCode.INVALID_ENUM:
        return ProceduralDefect(
            code=code,
            origin=ProceduralDefectOrigin.PARSER,
            reason_code=ProceduralReasonCode.UNKNOWN_ENUM_VALUE,
            artifact_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response_id,
            ),
            field=ProceduralField.ENUM_VALUE,
            value_sha256=SHA_D,
        )
    return ProceduralDefect(
        code=code,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.MALFORMED_JSON,
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response_id,
        ),
        field=ProceduralField.JSON_ROOT,
    )


def _repair(request: VLMRequest, response: VLMResponse) -> StructureRepairRequest:
    return StructureRepairRequest(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        provider_profile=request.provider_profile,
        provider=request.provider,
        model=request.model,
        revision=request.revision,
        model_manifest_id=request.model_manifest_id,
        execution_location=request.execution_location,
        prompt_manifest=_prompt(VlmRole.STRUCTURE_REPAIR),
        rendered_prompt_sha256=SHA_D,
        original_request_id=request.request_id,
        original_request_sha256=request.request_sha256,
        original_backlog_retry_context_id=(
            request.backlog_retry_context.context_id
            if request.backlog_retry_context is not None
            else None
        ),
        original_response_id=response.response_id,
        original_response_sha256=response.content_sha256,
        parse_defect_codes=(
            ProceduralDefectCode.MALFORMED_STRUCTURE,
            ProceduralDefectCode.INVALID_ENUM,
        ),
        temperature=0.0,
        seed=7,
        budget=_budget(repair=True),
        backlog_retry_context=request.backlog_retry_context,
        manifest_id=request.manifest_id,
    )


def _verdict(
    screening: ScreeningResult,
    *,
    violation_type: ViolationType | None = None,
) -> Verdict:
    return Verdict(
        run_id=screening.run_id,
        case_id=screening.case_id,
        version=1,
        screening_id=screening.screening_id,
        violation_type=violation_type or screening.parsed_output.violation_type,
        evidence_pack_id=screening.evidence_pack_id,
        evidence_pack_version=screening.evidence_pack_version,
        decision=VerdictDecision.ESTABLISHED,
        confidence=0.95,
        recommended_alert_level="CONFIRMED",
        rationale_summary="The fast verdict preserves only auditable structured inputs.",
        model_response_refs=(ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=SHA_B),),
        manifest_id=screening.manifest_id,
    )


def _review(
    verdict: Verdict,
    *,
    defects: tuple[ProceduralDefect, ...] = (),
) -> ProceduralReview:
    return ProceduralReview(
        run_id=verdict.run_id,
        case_id=verdict.case_id,
        version=1,
        evidence_pack_id=verdict.evidence_pack_id,
        evidence_pack_version=verdict.evidence_pack_version,
        reviewed_verdict_id=verdict.verdict_id,
        reviewed_verdict_version=verdict.version,
        reviewed_verdict_sha256=verdict.verdict_sha256,
        gate_version="procedural-gate-v1",
        defects=defects,
        manifest_id=verdict.manifest_id,
    )


def _presence_pack() -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )
    frame_ref = ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id="cam-01:demo-ntsc:90",
    )
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = (detection_ref, frame_ref)
    crop = Crop(
        frame_id=frame_ref.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=500, y1=300, x2=620, y2=650),
        source_refs=source_refs,
        local_path="frames/bottle.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=SHA_A,
        pixel_sha256=SHA_B,
        media_sha256=SHA_C,
        output_width=120,
        output_height=350,
        size_bytes=4_096,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )
    draft = EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        event=event,
        key_frame_ids=(frame_ref.artifact_id,),
        focus_crops=(crop,),
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=0,
            end_frame_exclusive=91,
            observed_frame_count=91,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )
    return _close_pack(draft)


def _absence_crop(event: CandidateEvent, frame_index: int) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
    bbox = BBoxXYXY(x1=0, y1=0, x2=100, y2=100)
    preserved = BBoxXYXY(x1=10, y1=10, x2=90, y2=55)
    return Crop(
        frame_id=frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=bbox,
        source_refs=(frame_ref,),
        local_path=f"frames/absence-{frame_index}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=sha256_hex(["source", frame_id]),
        pixel_sha256=sha256_hex(["pixel", frame_id]),
        media_sha256=sha256_hex(["media", frame_id]),
        output_width=100,
        output_height=100,
        size_bytes=1_024,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
            transform_version="ppe-preserve-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.PPE_REGION_PRESERVED,
            input_refs=(frame_ref,),
            ppe_type=PpeType.GOGGLES,
            anchor_type=AnchorType.HEAD,
            preserved_regions=(preserved,),
            keypoints=(Keypoint(name="nose", x=50.0, y=40.0, score=0.9),),
            anchor_bbox=preserved,
            association_method=AssociationMethod.KEYPOINT,
            fill_rgb=(0, 0, 0),
        ),
        observability=ObservabilityScore(
            total=0.9,
            components=ObservabilityComponents(
                person_confidence=0.9,
                keypoint_visibility=0.9,
                frontality=0.9,
                sharpness=0.9,
                exposure=0.9,
                non_occlusion=0.9,
            ),
            source=ObservationSource.PRECOMPUTED_FIXTURE,
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )


def _absence_pack() -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    temporal = tuple(_absence_crop(event, index) for index in (0, 75, 149))
    clear_ids = tuple(sorted(crop.crop_id for crop in temporal))
    draft = EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        event=event,
        key_frame_ids=tuple(
            f"{event.camera_id}:{event.stream_id}:{index}" for index in (0, 75, 149, 150)
        ),
        temporal_crops=temporal,
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=0,
            end_frame_exclusive=152,
            observed_frame_count=151,
        ),
        confirmation_record=event.confirmation,
        observation_sufficiency_input=ObservationSufficiencyInput(
            clear_crop_ids=clear_ids,
            clear_threshold=0.5,
            required_clear_count=2,
            selected_by_observability=True,
        ),
        manifest_id=event.manifest_id,
    )
    return _close_pack(draft)


def _close_pack(draft: EvidencePackDraft) -> EvidencePack:
    report = ClosureReport(
        run_id=draft.run_id,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    payload = draft.model_dump(mode="json", exclude={"pack_id"})
    payload["closure_report"] = report.model_dump(mode="json")
    return EvidencePack.model_validate(payload)


def _m4_request_more_frames_successor(
    previous: EvidencePack,
    *,
    include_tool_result: bool = True,
    tamper_existing_crop: bool = False,
) -> EvidencePack:
    payload = previous.model_dump(
        mode="json",
        exclude={"pack_id", "closure_report"},
    )
    payload["version"] = previous.version + 1
    if tamper_existing_crop:
        payload["focus_crops"][0]["tags"] = {"zone_id": "rewritten-zone"}
    if include_tool_result:
        start_frame = previous.event.end_frame_exclusive + previous.version
        parameters = RequestMoreFramesParameters(
            action=AcquisitionAction.REQUEST_MORE_FRAMES,
            camera_id=previous.event.camera_id,
            stream_id=previous.event.stream_id,
            start_frame=start_frame,
            end_frame_exclusive=start_frame + 1,
        )
        input_refs = (ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=previous.pack_id),)
        output_refs = (
            ArtifactRef(
                kind=ArtifactKind.FRAME,
                artifact_id=(
                    f"{previous.event.camera_id}:{previous.event.stream_id}:{start_frame}"
                ),
            ),
        )
        execution_manifest_id = hashlib.sha256(f"execution-{previous.version}".encode()).hexdigest()
        result = ToolResult(
            tool_result_id=derive_m4_tool_result_id(
                parameters.action,
                input_refs,
                output_refs,
                parameters,
                execution_manifest_id,
            ),
            action=parameters.action,
            input_refs=input_refs,
            output_refs=output_refs,
            validated_parameters=parameters,
            execution_manifest_id=execution_manifest_id,
        )
        results = (*previous.tool_results, result)
        payload["tool_results"] = [
            item.model_dump(mode="json")
            for item in sorted(results, key=lambda item: item.tool_result_id)
        ]
    return _close_pack(EvidencePackDraft.model_validate(payload))


def test_request_cache_and_response_identities_are_run_and_pack_scoped() -> None:
    request = _request()
    assert VLMRequest.model_validate(request.model_dump(mode="json")) == request
    assert _request(case_id="case-02").cache_key != request.cache_key
    assert _request(evidence_pack_id=SHA_7).cache_key != request.cache_key
    assert _request(evidence_pack_version=2).cache_key != request.cache_key
    assert _request(run_id="run-02").cache_key != request.cache_key

    larger_prompt_budget = request.budget.model_copy(
        update={"max_prompt_bytes": request.budget.max_prompt_bytes + 1}
    )
    larger_input_token_budget = request.budget.model_copy(
        update={"max_input_tokens": request.budget.max_input_tokens + 1}
    )
    changed_pricing = request.budget.model_copy(update={"input_cost_per_million_tokens": 0.5})
    changed_cost_cap = request.budget.model_copy(update={"max_estimated_cost": 1.5})
    changed_claim_grace = request.budget.model_copy(update={"claim_completion_grace_seconds": 6.0})
    assert request.model_copy(update={"budget": larger_prompt_budget}).request_id != (
        request.request_id
    )
    assert request.model_copy(update={"budget": larger_input_token_budget}).cache_key != (
        request.cache_key
    )
    assert request.model_copy(update={"budget": changed_pricing}).request_id != (request.request_id)
    assert request.model_copy(update={"budget": changed_cost_cap}).cache_key != request.cache_key
    assert request.model_copy(update={"budget": changed_claim_grace}).request_id != (
        request.request_id
    )
    assert request.budget.claim_lease_seconds == 20.0

    response = _response(request)
    assert response.size_bytes == 0
    assert VLMResponse.model_validate(response.model_dump(mode="json")) == response
    other_run_id = derive_model_response_id(
        "run-02",
        request.request_id,
        response.content_sha256,
    )
    assert other_run_id != response.response_id

    wrong_path = response.model_dump(mode="json")
    wrong_path.pop("response_id")
    wrong_path["raw_response_ref"] = f"other/model_responses/{response.response_id}.json"
    with pytest.raises(ValidationError, match="canonical run location"):
        VLMResponse.model_validate(wrong_path)


def test_backlog_generation_zero_preserves_request_identity_without_binding_a_lease() -> None:
    ordinary = _request()
    generation_zero = ordinary.model_copy(
        update={
            "backlog_retry_context": BacklogRetryContext(
                backlog_item_id=SHA_1,
                retry_generation=0,
            )
        }
    )
    generation_one = ordinary.model_copy(
        update={
            "backlog_retry_context": BacklogRetryContext(
                backlog_item_id=SHA_1,
                retry_generation=1,
            )
        }
    )
    assert generation_zero.request_id == ordinary.request_id
    assert generation_zero.request_sha256 == ordinary.request_sha256
    assert generation_zero.cache_key == ordinary.cache_key
    assert generation_one.request_id != ordinary.request_id
    assert generation_one.request_sha256 != ordinary.request_sha256
    assert generation_one.cache_key != ordinary.cache_key
    assert "lease" not in generation_zero.request_projection()

    repair = _repair(generation_zero, _response(generation_zero))
    assert repair.backlog_retry_context == generation_zero.backlog_retry_context
    assert (
        repair.original_backlog_retry_context_id == generation_zero.backlog_retry_context.context_id
    )
    with pytest.raises(ValidationError, match="must match its original request context"):
        repair.model_copy(update={"original_backlog_retry_context_id": SHA_2})


def test_model_call_failure_authority_json_round_trip_and_computed_field_guards() -> None:
    authority = _failure_authority()
    serialized = json.loads(json.dumps(authority.model_dump(mode="json")))

    assert ModelCallFailureAuthority.model_validate(serialized) == authority
    assert serialized["authority_id"] == authority.authority_id
    assert serialized["request_document_sha256"] == authority.request_document_sha256

    forged = dict(serialized)
    forged["authority_id"] = SHA_0
    with pytest.raises(ValidationError, match="authority_id conflicts"):
        ModelCallFailureAuthority.model_validate(forged)

    forged_request = dict(serialized)
    forged_request["request_document_sha256"] = SHA_0
    with pytest.raises(ValidationError, match="request_document_sha256 conflicts"):
        ModelCallFailureAuthority.model_validate(forged_request)

    unknown = dict(serialized)
    unknown["delivery_certainty"] = VLMDeliveryCertainty.UNKNOWN.value
    unknown.pop("request_document_sha256")
    unknown.pop("authority_id")
    with pytest.raises(ValidationError):
        ModelCallFailureAuthority.model_validate(unknown)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_prompt_bytes", 0),
        ("max_prompt_bytes", 1_048_577),
        ("max_input_tokens", 0),
        ("max_input_tokens", 262_145),
        ("claim_completion_grace_seconds", 0),
        ("claim_completion_grace_seconds", 301.0),
    ],
)
def test_vlm_prompt_and_input_token_budgets_are_strict_and_bounded(
    field: str,
    value: object,
) -> None:
    payload = _budget().model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        VlmCallBudget.model_validate(payload)


def test_vlm_cost_budget_prices_exact_usage_and_is_fail_closed_at_the_boundary() -> None:
    budget = _budget()

    assert budget.pricing_currency == "USD"
    assert budget.estimate_cost(input_tokens=2_000_000, output_tokens=500_000) == 1.0
    assert budget.allows_cost(input_tokens=2_000_000, output_tokens=500_000)
    assert not budget.allows_cost(input_tokens=4_000_001, output_tokens=1_000_000)

    with pytest.raises(ValueError, match="non-negative integer"):
        budget.estimate_cost(input_tokens=True, output_tokens=0)  # type: ignore[arg-type]


def test_vlm_cost_budget_preserves_cny_as_request_bound_cost_authority() -> None:
    payload = _budget().model_dump(mode="json")
    payload.update(
        {
            "pricing_currency": "CNY",
            "input_cost_per_million_tokens": 1.0,
            "output_cost_per_million_tokens": 10.0,
        }
    )

    budget = VlmCallBudget.model_validate(payload)

    assert budget.pricing_currency == "CNY"
    assert budget.estimate_cost(input_tokens=1_000_000, output_tokens=100_000) == 2.0


def test_request_whitelists_every_citable_namespace_and_exact_media_crops() -> None:
    allowed = (
        ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_4),
        ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-01:stream-01:7"),
        ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id="fact-01"),
        ArtifactRef(kind=ArtifactKind.TOOL_RESULT, artifact_id="tool-01"),
    )
    request = _request(allowed_evidence_refs=allowed)
    assert request.allowed_evidence_refs == allowed

    with pytest.raises(ValidationError, match="exactly match request media"):
        _request(allowed_evidence_refs=allowed[1:])
    with pytest.raises(ValidationError, match="non-citable"):
        _request(
            allowed_evidence_refs=(
                ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_4),
                ArtifactRef(kind=ArtifactKind.VERDICT, artifact_id=SHA_5),
            )
        )


def test_repair_is_media_free_once_only_and_uses_taxonomy_order() -> None:
    request = _request()
    response = _response(request)
    repair = _repair(request, response)
    assert "media" not in repair.model_dump(mode="json")
    assert StructureRepairRequest.model_validate(repair.model_dump(mode="json")) == repair

    with pytest.raises(ValidationError, match="stable order"):
        StructureRepairRequest.model_validate(
            {
                **repair.model_dump(
                    mode="json",
                    exclude={"request_sha256", "request_id", "cache_key"},
                ),
                "parse_defect_codes": [
                    ProceduralDefectCode.INVALID_ENUM,
                    ProceduralDefectCode.MALFORMED_STRUCTURE,
                ],
            }
        )
    with pytest.raises(ValidationError):
        StructureRepairRequest.model_validate(
            {
                **repair.model_dump(
                    mode="json",
                    exclude={"request_sha256", "request_id", "cache_key"},
                ),
                "media": [],
            }
        )


def test_parse_receipt_cannot_skip_or_repeat_structure_repair() -> None:
    request = _request()
    response = _response(request)
    repair = _repair(request, response)
    defect = _parser_defect(response.response_id)
    unknown_attempt = UnknownReferenceAttempt(
        namespace=UnknownReferenceNamespace.EVIDENCE,
        source=UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID,
        value_sha256=SHA_1,
    )
    assert "unknown_reference_attempts" not in response.model_dump(mode="json")
    first = ModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        attempt_index=0,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(defect,),
        unknown_reference_attempts=(unknown_attempt,),
        repair_request_id=repair.request_id,
        manifest_id=request.manifest_id,
    )
    assert first.status == ModelParseStatus.REPAIR_REQUIRED

    payload = first.model_dump(mode="json", exclude={"parse_receipt_id"})
    payload.update(
        {
            "status": ModelParseStatus.INVALID_FINAL,
            "repair_request_id": None,
        }
    )
    with pytest.raises(ValidationError, match="requires the repair attempt"):
        ModelParseReceipt.model_validate(payload)
    payload["attempt_index"] = 1
    final = ModelParseReceipt.model_validate(payload)
    assert final.status == ModelParseStatus.INVALID_FINAL


def test_parsed_output_uses_typed_objective_claims_and_has_no_visibility_authority() -> None:
    claim = ObjectiveClaim(
        kind=ObjectiveFactKind.PERSON_COUNT,
        value=2,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id="fact-person-count",
        ),
    )
    parsed = _parsed(objective_claims=(claim,))
    assert parsed.objective_claims == (claim,)
    assert set(parsed.payload.model_dump(mode="json")) == {
        "violation_type",
        "evidence_class",
        "violation_probability",
        "frame_observations",
        "evidence_citations",
        "objective_claims",
        "prosecution_summary",
        "rationale_summary",
    }
    with pytest.raises(ValidationError):
        ScreeningModelPayload.model_validate(
            {**parsed.payload.model_dump(mode="json"), "run_id": RUN_ID}
        )

    with pytest.raises(ValidationError):
        FrameObservation.model_validate(
            {
                "crop_id": SHA_1,
                "wear_status": WearStatus.UNCLEAR,
                "reason_summary": "The crop is partially occluded.",
                "visibility": 0.99,
            }
        )


def test_absence_establishment_requires_every_authoritative_clear_label() -> None:
    observations = tuple(
        FrameObservation(
            crop_id=crop_id,
            wear_status=WearStatus.NOT_WORN,
            reason_summary="No goggles are visible in this clear crop.",
        )
        for crop_id in (SHA_1, SHA_2, SHA_3)
    )
    parsed = _parsed(
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        observations=observations,
    )
    established = _screening(
        parsed,
        alleged_crop_ids=(SHA_1, SHA_2, SHA_3),
        clear_crop_ids=(SHA_1, SHA_2, SHA_3),
        correction_frame_ids=("cam-01:stream-01:151",),
        required_clear_count=2,
    )
    assert established.decision == ScreeningDecision.ESTABLISHED

    with_non_clear = _screening(
        parsed.model_copy(
            update={
                "payload": parsed.payload.model_copy(
                    update={
                        "frame_observations": (
                            *observations,
                            FrameObservation(
                                crop_id=SHA_4,
                                wear_status=WearStatus.UNCLEAR,
                                reason_summary="This non-clear crop remains only context.",
                            ),
                        )
                    }
                )
            }
        ),
        alleged_crop_ids=(SHA_1, SHA_2, SHA_3, SHA_4),
        clear_crop_ids=(SHA_1, SHA_2, SHA_3),
        correction_frame_ids=("cam-01:stream-01:151",),
        required_clear_count=2,
    )
    assert with_non_clear.decision == ScreeningDecision.ESTABLISHED

    missing = _screening(
        parsed.model_copy(
            update={
                "payload": parsed.payload.model_copy(
                    update={"frame_observations": observations[:2]}
                )
            }
        ),
        alleged_crop_ids=(SHA_1, SHA_2, SHA_3),
        clear_crop_ids=(SHA_1, SHA_2, SHA_3),
        correction_frame_ids=("cam-01:stream-01:151",),
        required_clear_count=2,
    )
    assert missing.decision == ScreeningDecision.ESCALATE

    worn = _screening(
        parsed.model_copy(
            update={
                "payload": parsed.payload.model_copy(
                    update={
                        "frame_observations": (
                            observations[0].model_copy(update={"wear_status": WearStatus.WORN}),
                            *observations[1:],
                        )
                    }
                )
            }
        ),
        alleged_crop_ids=(SHA_1, SHA_2, SHA_3),
        clear_crop_ids=(SHA_1, SHA_2, SHA_3),
        correction_frame_ids=("cam-01:stream-01:151",),
        required_clear_count=2,
    )
    assert worn.decision == ScreeningDecision.NOT_ESTABLISHED
    strong_absence = worn.model_copy(
        update={"authoritative_l1_score": 0.95, "strong_signal_threshold": 0.8}
    )
    assert strong_absence.conflict_codes == ()
    assert strong_absence.decision == ScreeningDecision.NOT_ESTABLISHED


def test_strong_signal_conflicts_are_computed_and_serialized_claims_are_verified() -> None:
    parsed = _parsed(probability=0.05)
    conflict = _screening(parsed, l1_score=0.9, strong_threshold=0.8)
    assert conflict.conflict_codes == (ScreeningConflictCode.STRONG_SIGNAL_CONFLICT,)
    assert conflict.decision == ScreeningDecision.ESCALATE

    tampered = conflict.model_dump(mode="json")
    tampered["conflict_codes"] = []
    with pytest.raises(ValidationError, match="serialized screening conflicts"):
        ScreeningResult.model_validate(tampered)

    wrong_class = _screening(
        _parsed(evidence_class=EvidenceClass.ABSENCE, probability=0.95),
        authoritative_evidence_class=EvidenceClass.PRESENCE,
    )
    assert wrong_class.conflict_codes == (ScreeningConflictCode.MODEL_EVIDENCE_CLASS_MISMATCH,)
    assert wrong_class.decision == ScreeningDecision.ESCALATE


def test_unknown_reference_and_citation_contracts_never_store_raw_attempts() -> None:
    attempt = UnknownReferenceAttempt(
        namespace=UnknownReferenceNamespace.EVIDENCE,
        source=UnknownReferenceSource.EVIDENCE_CITATION_REF,
        value_sha256=SHA_1,
    )
    assert set(attempt.model_dump(mode="json")) == {
        "namespace",
        "source",
        "value_sha256",
    }
    with pytest.raises(ValidationError):
        UnknownReferenceAttempt.model_validate(
            {**attempt.model_dump(mode="json"), "value": "secret-host-path"}
        )

    citation = EvidenceCitation(
        evidence_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_2),
        bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
        coordinate_space="CITED_ARTIFACT_PIXELS",
    )
    assert EvidenceCitation.model_validate(citation.model_dump(mode="json")) == citation
    with pytest.raises(ValidationError, match="coordinates require"):
        EvidenceCitation(
            evidence_ref=ArtifactRef(
                kind=ArtifactKind.OBJECTIVE_FACT,
                artifact_id="fact-01",
            ),
            bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
            coordinate_space="CITED_ARTIFACT_PIXELS",
        )
    frame_citation = EvidenceCitation(
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.FRAME,
            artifact_id="cam-01:stream-01:7",
        ),
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=100),
        coordinate_space="CITED_ARTIFACT_PIXELS",
    )
    assert frame_citation.coordinate_space == "CITED_ARTIFACT_PIXELS"
    with pytest.raises(ValidationError, match="required together"):
        EvidenceCitation(
            evidence_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_2),
            bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
        )
    tampered = citation.model_dump(mode="json")
    tampered["citation_id"] = SHA_0
    with pytest.raises(ValidationError, match="citation_id"):
        EvidenceCitation.model_validate(tampered)
    invalid_schema_pair = citation.model_dump(mode="json")
    invalid_schema_pair["coordinate_space"] = None
    citation_schema = json.loads(expected_schema_files()["evidence-citation.schema.json"])
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(citation_schema).validate(invalid_schema_pair)


def test_precedent_resolution_distinguishes_missing_from_invisible() -> None:
    query = PrecedentLookupQuery(
        run_id=RUN_ID,
        case_id="case-01",
        precedent_id="precedent-01",
        rule_version="laboratory-v1",
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        manifest_id=SHA_1,
    )
    snapshot = Precedent(
        precedent_id=query.precedent_id,
        situation_text="A reagent container remained open during active work.",
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        status=PrecedentStatus.ACTIVE,
        evidence_class=query.evidence_class,
        violation_type=query.violation_type,
        rule_version=query.rule_version,
    )
    found = PrecedentResolution(
        query=query,
        status=PrecedentLookupStatus.FOUND,
        snapshot=snapshot,
        authoritative_similarity=0.91,
        lookup_version="precedent-lookup-v1",
    )
    assert PrecedentResolution.model_validate(found.model_dump(mode="json")) == found

    for status in (
        PrecedentLookupStatus.NOT_FOUND,
        PrecedentLookupStatus.NOT_VISIBLE,
    ):
        unresolved = PrecedentResolution(
            query=query,
            status=status,
            lookup_version="precedent-lookup-v1",
        )
        assert unresolved.snapshot is None
        assert unresolved.authoritative_similarity is None
        assert unresolved.receipt_id != found.receipt_id

    with pytest.raises(ValidationError, match="requires a scored snapshot"):
        PrecedentResolution(
            query=query,
            status=PrecedentLookupStatus.FOUND,
            lookup_version="precedent-lookup-v1",
        )


def test_defect_taxonomy_order_context_and_review_passed_are_not_forgeable() -> None:
    assert tuple(ProceduralDefectCode) == DEFECT_ORDER
    malformed = _parser_defect(SHA_A)
    invalid_enum = _parser_defect(SHA_A, ProceduralDefectCode.INVALID_ENUM)
    assert malformed.sort_key < invalid_enum.sort_key

    with pytest.raises(ValidationError):
        ProceduralDefect.model_validate(
            {**malformed.model_dump(mode="json"), "detail": "provider traceback"}
        )

    screening = _screening(_parsed())
    verdict = _verdict(screening)
    review = _review(verdict)
    assert review.passed is True
    assert "procedural_review" not in Verdict.model_fields
    assert Verdict.model_validate(verdict.model_dump(mode="json")) == verdict

    tampered = review.model_dump(mode="json")
    tampered["passed"] = False
    with pytest.raises(ValidationError, match="passed conflicts"):
        ProceduralReview.model_validate(tampered)


def test_case_revalidates_absence_authority_against_the_current_pack() -> None:
    pack = _absence_pack()
    clear_ids = tuple(sorted(pack.observation_sufficiency_input.clear_crop_ids))
    alleged_ids = tuple(sorted(crop.crop_id for crop in pack.temporal_crops))
    observations = tuple(
        FrameObservation(
            crop_id=crop_id,
            wear_status=WearStatus.NOT_WORN,
            reason_summary="No goggles are visible in this clear crop.",
        )
        for crop_id in clear_ids
    )
    parsed = _parsed(
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        observations=observations,
        manifest_id=pack.manifest_id,
    )
    screening = _screening(
        parsed,
        l1_score=pack.event.l1_score,
        alleged_crop_ids=alleged_ids,
        clear_crop_ids=clear_ids,
        correction_frame_ids=(pack.confirmation_record.post_threshold_recovery_frame_id,),
        required_clear_count=pack.observation_sufficiency_input.required_clear_count,
    )
    case = Case(
        run_id=RUN_ID,
        status=CaseStatus.SCREENED,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        manifest_id=pack.manifest_id,
    )
    assert case.screening_results == (screening,)

    for update in (
        {"authoritative_clear_crop_ids": clear_ids[:-1]},
        {"authoritative_l1_score": 0.0},
        {"correction_frame_ids": ("cam-01:demo-absence:152",)},
    ):
        changed = screening.model_copy(update=update)
        with pytest.raises(ValidationError, match="screening"):
            Case.model_validate(
                {
                    **case.model_dump(mode="json", exclude={"case_id"}),
                    "screening_results": [changed.model_dump(mode="json")],
                }
            )


def test_case_preserves_rejected_mismatch_verdict_and_gates_ready_status() -> None:
    pack = _presence_pack()
    parsed = _parsed(
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        violation_type=ViolationType.FOOD_OR_DRINK_IN_LAB,
        evidence_class=pack.event.evidence_class,
        probability=0.95,
        manifest_id=pack.manifest_id,
    )
    screening = _screening(parsed, l1_score=pack.event.l1_score)
    mismatched = _verdict(screening)
    assert mismatched.violation_type != pack.event.violation_type
    defect = ProceduralDefect(
        code=ProceduralDefectCode.VIOLATION_TYPE_MISMATCH,
        origin=ProceduralDefectOrigin.PROCEDURAL_GATE,
        reason_code=ProceduralReasonCode.CASE_VIOLATION_CONFLICT,
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.VERDICT,
            artifact_id=mismatched.verdict_id,
        ),
        field=ProceduralField.VIOLATION_TYPE,
        related_refs=(ArtifactRef(kind=ArtifactKind.CASE, artifact_id=pack.case_id),),
    )
    failed = _review(mismatched, defects=(defect,))
    history = Case(
        run_id=RUN_ID,
        status=CaseStatus.REWORK_REQUIRED,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        verdicts=(mismatched,),
        procedural_reviews=(failed,),
        manifest_id=pack.manifest_id,
    )
    assert history.procedural_reviews[-1].passed is False

    with pytest.raises(ValidationError, match="latest verdict to pass review"):
        history.model_copy(update={"status": CaseStatus.READY_FOR_ALERT_POLICY}).model_validate(
            {
                **history.model_dump(mode="json", exclude={"case_id"}),
                "status": CaseStatus.READY_FOR_ALERT_POLICY,
            }
        )

    matching = _verdict(screening)
    passed = _review(matching)
    ready = Case(
        run_id=RUN_ID,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        verdicts=(matching,),
        procedural_reviews=(passed,),
        manifest_id=pack.manifest_id,
    )
    assert ready.status == CaseStatus.READY_FOR_ALERT_POLICY


def test_case_accepts_only_proven_m4_acquisition_successors_for_verdict_scope() -> None:
    initial_pack = _presence_pack()
    parsed = _parsed(
        case_id=initial_pack.case_id,
        evidence_pack_id=initial_pack.pack_id,
        violation_type=initial_pack.event.violation_type,
        evidence_class=initial_pack.event.evidence_class,
        probability=0.95,
        manifest_id=initial_pack.manifest_id,
    )
    screening = _screening(parsed, l1_score=initial_pack.event.l1_score)
    acquired_pack = _m4_request_more_frames_successor(initial_pack)
    acquired_verdict = _verdict(screening).model_copy(
        update={
            "evidence_pack_id": acquired_pack.pack_id,
            "evidence_pack_version": acquired_pack.version,
        }
    )
    acquired_review = _review(acquired_verdict)

    ready = Case(
        run_id=RUN_ID,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=initial_pack.event,
        evidence_packs=(initial_pack, acquired_pack),
        screening_results=(screening,),
        verdicts=(acquired_verdict,),
        procedural_reviews=(acquired_review,),
        manifest_id=initial_pack.manifest_id,
    )
    assert ready.verdicts[-1].evidence_pack_id == acquired_pack.pack_id

    no_tool_pack = _m4_request_more_frames_successor(
        initial_pack,
        include_tool_result=False,
    )
    no_tool_verdict = acquired_verdict.model_copy(update={"evidence_pack_id": no_tool_pack.pack_id})
    with pytest.raises(ValidationError, match="exactly one tool result"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.PROCEDURAL_REVIEW,
            event=initial_pack.event,
            evidence_packs=(initial_pack, no_tool_pack),
            screening_results=(screening,),
            verdicts=(no_tool_verdict,),
            manifest_id=initial_pack.manifest_id,
        )

    rewritten_pack = _m4_request_more_frames_successor(
        initial_pack,
        tamper_existing_crop=True,
    )
    rewritten_verdict = acquired_verdict.model_copy(
        update={"evidence_pack_id": rewritten_pack.pack_id}
    )
    with pytest.raises(ValidationError, match="rewrote immutable pack field focus_crops"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.PROCEDURAL_REVIEW,
            event=initial_pack.event,
            evidence_packs=(initial_pack, rewritten_pack),
            screening_results=(screening,),
            verdicts=(rewritten_verdict,),
            manifest_id=initial_pack.manifest_id,
        )

    wrong_screening_verdict = acquired_verdict.model_copy(update={"screening_id": SHA_D})
    with pytest.raises(ValidationError, match="unknown screening"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.PROCEDURAL_REVIEW,
            event=initial_pack.event,
            evidence_packs=(initial_pack, acquired_pack),
            screening_results=(screening,),
            verdicts=(wrong_screening_verdict,),
            manifest_id=initial_pack.manifest_id,
        )


def test_case_statuses_require_their_authoritative_current_binding() -> None:
    pack = _presence_pack()
    parsed = _parsed(
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        probability=0.05,
        manifest_id=pack.manifest_id,
    )
    escalated_screening = _screening(
        parsed,
        l1_score=pack.event.l1_score,
        strong_threshold=0.5,
    )
    assert escalated_screening.decision == ScreeningDecision.ESCALATE
    escalated = Case(
        run_id=RUN_ID,
        status=CaseStatus.ESCALATED,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(escalated_screening,),
        manifest_id=pack.manifest_id,
    )
    assert escalated.status == CaseStatus.ESCALATED

    established = _screening(
        parsed.model_copy(
            update={"payload": parsed.payload.model_copy(update={"violation_probability": 0.95})}
        ),
        l1_score=pack.event.l1_score,
        strong_threshold=0.5,
    )
    with pytest.raises(ValidationError, match="latest screening to escalate"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.ESCALATED,
            event=pack.event,
            evidence_packs=(pack,),
            screening_results=(established,),
            manifest_id=pack.manifest_id,
        )
    with pytest.raises(ValidationError, match="SCREENED requires"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.SCREENED,
            event=pack.event,
            evidence_packs=(pack,),
            manifest_id=pack.manifest_id,
        )
    with pytest.raises(ValidationError, match="does not escalate"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.SCREENED,
            event=pack.event,
            evidence_packs=(pack,),
            screening_results=(escalated_screening,),
            manifest_id=pack.manifest_id,
        )

    backlogged = Case(
        run_id=RUN_ID,
        status=CaseStatus.BACKLOGGED,
        event=pack.event,
        evidence_packs=(pack,),
        current_backlog_item_id=SHA_1,
        manifest_id=pack.manifest_id,
    )
    assert backlogged.current_backlog_item_id == SHA_1
    with pytest.raises(ValidationError, match="requires a current backlog"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.BACKLOGGED,
            event=pack.event,
            evidence_packs=(pack,),
            manifest_id=pack.manifest_id,
        )
    with pytest.raises(ValidationError, match="only BACKLOGGED"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.EVIDENCE_READY,
            event=pack.event,
            evidence_packs=(pack,),
            current_backlog_item_id=SHA_1,
            manifest_id=pack.manifest_id,
        )
    with pytest.raises(ValidationError, match="typed evidence or exhausted-backlog"):
        Case(
            run_id=RUN_ID,
            status=CaseStatus.HUMAN_REVIEW,
            event=pack.event,
            evidence_packs=(pack,),
            manifest_id=pack.manifest_id,
        )


def test_case_accepts_only_an_exact_typed_hearing_human_review_transition() -> None:
    pack = _presence_pack()
    transition = TimelineEntry(
        sequence=0,
        action="CASE_STATE_CHANGED",
        stage="HEARING",
        object_ref=SHA_1,
        details={
            "reason": "HEARING_BUDGET_EXHAUSTED",
            "hearing_session_id": SHA_2,
            "judge_cycle": 1,
        },
    )
    case = Case(
        run_id=RUN_ID,
        status=CaseStatus.HUMAN_REVIEW,
        event=pack.event,
        evidence_packs=(pack,),
        manifest_id=pack.manifest_id,
        timeline=(transition,),
    )

    assert case.timeline[-1] == transition
    for invalid_details in (
        {**transition.details, "unexpected": "field"},
        {**transition.details, "reason": "UNCONTROLLED_REASON"},
        {**transition.details, "hearing_session_id": "not-a-sha"},
        {**transition.details, "judge_cycle": True},
        {**transition.details, "judge_cycle": 6},
    ):
        with pytest.raises(ValidationError, match="typed evidence or exhausted-backlog"):
            Case.model_validate(
                {
                    **case.model_dump(mode="json", exclude={"case_id", "timeline"}),
                    "timeline": [
                        {
                            **transition.model_dump(mode="json"),
                            "details": invalid_details,
                        }
                    ],
                }
            )


def test_backlog_lease_cas_and_exhaustion_state_are_explicit() -> None:
    base = BacklogItem(
        run_id=RUN_ID,
        case_id="case-01",
        stage=BacklogStage.SCREENING,
        role=VlmRole.SCREENING,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=SHA_1,
        ),
        stage_input_sha256=SHA_2,
        max_attempts=2,
        manifest_id=SHA_3,
    )
    leased = BacklogItem(
        **base.model_dump(
            mode="python",
            exclude={
                "item_id",
                "completed",
                "status",
                "attempt_count",
                "lease_id",
                "lease_owner_sha256",
                "lease_expires_at",
            },
        ),
        attempt_count=1,
        status=BacklogStatus.LEASED,
        lease_id=SHA_4,
        lease_owner_sha256=SHA_5,
        lease_expires_at=datetime(2026, 7, 27, 12, tzinfo=UTC),
    )
    assert leased.item_id == base.item_id

    with pytest.raises(ValidationError, match="complete lease ownership"):
        BacklogItem.model_validate(
            {
                **leased.model_dump(
                    mode="json",
                    exclude={"item_id", "completed", "lease_id"},
                ),
                "lease_id": None,
            }
        )
    with pytest.raises(ValidationError, match="EXHAUSTED"):
        BacklogItem(
            **base.model_dump(
                mode="python",
                exclude={"item_id", "completed", "attempt_count"},
            ),
            attempt_count=2,
        )
    exhausted = BacklogItem(
        **base.model_dump(
            mode="python",
            exclude={
                "item_id",
                "completed",
                "status",
                "attempt_count",
                "lease_id",
                "lease_owner_sha256",
                "lease_expires_at",
            },
        ),
        attempt_count=2,
        status=BacklogStatus.EXHAUSTED,
    )
    assert exhausted.item_id == base.item_id

    with pytest.raises(ValidationError, match="must use UTC"):
        BacklogItem(
            **base.model_dump(
                mode="python",
                exclude={
                    "item_id",
                    "completed",
                    "status",
                    "attempt_count",
                    "lease_id",
                    "lease_owner_sha256",
                    "lease_expires_at",
                },
            ),
            attempt_count=1,
            status=BacklogStatus.LEASED,
            lease_id=SHA_4,
            lease_owner_sha256=SHA_5,
            lease_expires_at=datetime(
                2026,
                7,
                27,
                12,
                tzinfo=timezone(timedelta(hours=8)),
            ),
        )


def test_hearing_backlog_can_resume_one_exact_role_request() -> None:
    request = BacklogItem(
        run_id=RUN_ID,
        case_id="case-01",
        stage=BacklogStage.HEARING,
        role=VlmRole.JUDGE,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=SHA_1,
        ),
        stage_input_sha256=SHA_2,
        max_attempts=2,
        manifest_id=SHA_3,
    )

    assert request.stage_input_ref.kind == ArtifactKind.MODEL_REQUEST
    with pytest.raises(ValidationError, match="stage input kind"):
        BacklogItem.model_validate(
            {
                **request.model_dump(
                    mode="json",
                    exclude={"item_id", "completed", "stage_input_ref"},
                ),
                "stage_input_ref": {
                    "kind": ArtifactKind.MODEL_RESPONSE,
                    "artifact_id": SHA_1,
                },
            }
        )


@pytest.mark.parametrize(
    "kind",
    [
        ArtifactKind.MODEL_REQUEST,
        ArtifactKind.MODEL_RESPONSE,
        ArtifactKind.PROMPT_MANIFEST,
        ArtifactKind.MODEL_PARSE_RECEIPT,
        ArtifactKind.PARSED_MODEL_OUTPUT,
        ArtifactKind.PROCEDURAL_REVIEW,
        ArtifactKind.MODEL_CACHE_ENTRY,
        ArtifactKind.SCREENING_RESULT,
        ArtifactKind.VERDICT,
        ArtifactKind.BACKLOG_ITEM,
    ],
)
def test_m3_content_addressed_artifact_references_require_sha256(
    kind: ArtifactKind,
) -> None:
    assert ArtifactRef(kind=kind, artifact_id=SHA_1).artifact_id == SHA_1
    with pytest.raises(ValidationError):
        ArtifactRef(kind=kind, artifact_id="unguarded-token")


def test_model_cache_entry_identity_includes_run_case_and_pack_scope() -> None:
    request = _request()
    response = _response(request, content_sha256=SHA_A)
    entry = ModelCacheEntry(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        cache_key=request.cache_key,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        model_manifest_id=request.model_manifest_id,
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=request.manifest_id,
    )
    other_case = entry.model_copy(update={"case_id": "case-02"})
    other_pack = entry.model_copy(update={"evidence_pack_id": SHA_B})
    assert entry.cache_entry_id != other_case.cache_entry_id
    assert entry.cache_entry_id != other_pack.cache_entry_id


def _representative_m3_instances() -> dict[str, object]:
    request = _request()
    response = _response(request, content_sha256=SHA_A)
    claim = ObjectiveClaim(
        kind=ObjectiveFactKind.PERSON_COUNT,
        value=2,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id="fact-person-count",
        ),
    )
    parsed = _parsed(objective_claims=(claim,))
    screening = _screening(parsed)
    verdict = _verdict(screening)
    review = _review(verdict)
    defect = _parser_defect(response.response_id)
    parse_receipt = ModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        attempt_index=0,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(defect,),
        repair_request_id=_repair(request, response).request_id,
        manifest_id=request.manifest_id,
    )
    cache_entry = ModelCacheEntry(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        cache_key=request.cache_key,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        model_manifest_id=request.model_manifest_id,
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=request.manifest_id,
    )
    backlog = BacklogItem(
        run_id=RUN_ID,
        case_id="case-01",
        stage=BacklogStage.SCREENING,
        role=VlmRole.SCREENING,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=SHA_1,
        ),
        stage_input_sha256=SHA_2,
        max_attempts=2,
        manifest_id=SHA_3,
    )
    lookup_query = PrecedentLookupQuery(
        run_id=RUN_ID,
        case_id="case-01",
        precedent_id="precedent-01",
        rule_version="laboratory-v1",
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        manifest_id=SHA_1,
    )
    resolution = PrecedentResolution(
        query=lookup_query,
        status=PrecedentLookupStatus.NOT_FOUND,
        lookup_version="precedent-lookup-v1",
    )
    return {
        "backlog-item": backlog,
        "evidence-citation": EvidenceCitation(
            evidence_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_4),
            bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
            coordinate_space="CITED_ARTIFACT_PIXELS",
        ),
        "model-cache-entry": cache_entry,
        "model-call-failure-authority": _failure_authority(request),
        "model-parse-receipt": parse_receipt,
        "parsed-screening-output": parsed,
        "precedent-lookup-query": lookup_query,
        "precedent-resolution": resolution,
        "procedural-defect": defect,
        "procedural-review": review,
        "prompt-manifest": request.prompt_manifest,
        "screening-result": screening,
        "screening-model-payload": parsed.payload,
        "structure-repair-request": _repair(request, response),
        "verdict": verdict,
        "vlm-request": request,
        "vlm-response": response,
    }


def _m3_identity_vector() -> dict[str, object]:
    instances = _representative_m3_instances()
    request = instances["vlm-request"]
    response = instances["vlm-response"]
    parsed = instances["parsed-screening-output"]
    screening = instances["screening-result"]
    verdict = instances["verdict"]
    review = instances["procedural-review"]
    repair = instances["structure-repair-request"]
    receipt = instances["model-parse-receipt"]
    cache = instances["model-cache-entry"]
    backlog = instances["backlog-item"]
    lookup_query = instances["precedent-lookup-query"]
    resolution = instances["precedent-resolution"]
    assert isinstance(request, VLMRequest)
    assert isinstance(response, VLMResponse)
    assert isinstance(parsed, ParsedScreeningOutput)
    assert isinstance(screening, ScreeningResult)
    assert isinstance(verdict, Verdict)
    assert isinstance(review, ProceduralReview)
    assert isinstance(repair, StructureRepairRequest)
    assert isinstance(receipt, ModelParseReceipt)
    assert isinstance(cache, ModelCacheEntry)
    assert isinstance(backlog, BacklogItem)
    assert isinstance(lookup_query, PrecedentLookupQuery)
    assert isinstance(resolution, PrecedentResolution)
    return {
        "prompt_manifest_id": request.prompt_manifest.prompt_manifest_id,
        "request_sha256": request.request_sha256,
        "request_id": request.request_id,
        "cache_key": request.cache_key,
        "response_id": response.response_id,
        "parsed_output_sha256": parsed.parsed_output_sha256,
        "parsed_output_id": parsed.parsed_output_id,
        "model_payload_sha256": parsed.model_payload_sha256,
        "screening_model_schema_sha256": hashlib.sha256(
            expected_schema_files()["screening-model-payload.schema.json"].encode("utf-8")
        ).hexdigest(),
        "screening_id": screening.screening_id,
        "screening_decision": screening.decision.value,
        "repair_request_sha256": repair.request_sha256,
        "repair_request_id": repair.request_id,
        "repair_cache_key": repair.cache_key,
        "parse_receipt_id": receipt.parse_receipt_id,
        "cache_entry_id": cache.cache_entry_id,
        "verdict_input_sha256": verdict.verdict_input_sha256,
        "verdict_id": verdict.verdict_id,
        "verdict_sha256": verdict.verdict_sha256,
        "review_id": review.review_id,
        "review_passed": review.passed,
        "backlog_item_id": backlog.item_id,
        "precedent_query_id": lookup_query.query_id,
        "precedent_receipt_id": resolution.receipt_id,
    }


def test_m3_identity_golden_vector_is_exact() -> None:
    expected = json.loads(
        (FIXTURES.parent / "m3" / "canonical-id-vectors.json").read_text(encoding="utf-8")
    )
    assert _m3_identity_vector() == expected


def test_every_m3_root_instance_validates_against_its_exported_schema() -> None:
    schemas = expected_schema_files()
    for name, instance in _representative_m3_instances().items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        validator = Draft202012Validator(schema)
        validator.validate(
            instance.model_dump(
                mode="json",
                exclude_computed_fields=name == "screening-model-payload",
            )
        )
