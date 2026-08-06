from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AcquisitionAction,
    ArtifactKind,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ObjectiveFactKind,
    PrivacyPolicy,
    PrivacyReasonCode,
)
from labcourt.contracts.events import CandidateEvent, ObjectiveFact, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    EvidencePack,
    EvidencePackDraft,
    OtherCameraSameTimeParameters,
    PrivacyReceipt,
    RecropParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    ToolResult,
    TrackConfidenceCurveParameters,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing import (
    MAX_ACQUISITION_RETURNED_FRAMES,
    AcquisitionRequest,
    AcquisitionRequestPayload,
    ToolExecutionManifest,
    ToolExecutionReceipt,
    derive_m4_tool_result_id,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.domain.evidence_authority import (
    AcquisitionAuthorityError,
    AcquisitionExecution,
    EvidenceAuthorityError,
    EvidenceDisclosureError,
    EvidencePackSuccessorError,
    LoadedEvidenceObjects,
    RecropAuthorityUnrecoverable,
    derive_citable_refs,
    derive_evidence_authority,
    derive_evidence_pack_successor,
    derive_recrop_source_refs,
    derive_role_disclosure,
    extend_hearing_evidence_grant,
    finalize_evidence_pack_successor,
    validate_evidence_pack_successor,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
RUN_ID = "run-m4-authority"
SESSION_ID = sha256_hex(["m4-authority-session"])


def _sha(token: str) -> str:
    return sha256_hex(["m4-authority-test", token])


def _ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _close(draft: EvidencePackDraft) -> EvidencePack:
    report = _closure(draft)
    payload = draft.model_dump(mode="python", exclude={"pack_id"})
    payload["closure_report"] = report
    return EvidencePack.model_validate(payload)


def _closure(draft: EvidencePackDraft) -> ClosureReport:
    return ClosureReport(
        run_id=draft.run_id,
        root_ref=_ref(ArtifactKind.CASE, draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )


def _event() -> CandidateEvent:
    return CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )


def _focus_crop(event: CandidateEvent, token: str, x1: int) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}"
    frame_ref = _ref(ArtifactKind.FRAME, frame_id)
    detection_ref = _ref(ArtifactKind.DETECTION, f"det-{token}")
    source_refs = tuple(sorted((detection_ref, frame_ref), key=lambda ref: ref.sort_key))
    bbox = BBoxXYXY(x1=x1, y1=20, x2=x1 + 100, y2=220)
    media_sha = _sha(f"media-{token}")
    return Crop(
        frame_id=frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=bbox,
        source_refs=source_refs,
        local_path=f"{RUN_ID}/frames/{media_sha}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=_sha(f"source-{token}"),
        pixel_sha256=_sha(f"pixel-{token}"),
        media_sha256=media_sha,
        output_width=bbox.width,
        output_height=bbox.height,
        size_bytes=1_024,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="privacy-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )


def _pack(*, crop_count: int = 2) -> EvidencePack:
    event = _event()
    crops = tuple(
        sorted(
            (_focus_crop(event, f"focus-{index}", 10 + index * 120) for index in range(crop_count)),
            key=lambda crop: (crop.frame_id, crop.crop_id),
        )
    )
    return _close(
        EvidencePackDraft(
            run_id=RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=(f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}",),
            focus_crops=crops,
            objective_facts=event.objective_facts,
            track_summary=TrackSummary(
                primary_track_ref=event.primary_track_ref,
                start_frame=event.start_frame,
                end_frame_exclusive=event.end_frame_exclusive,
                observed_frame_count=event.end_frame_exclusive - event.start_frame,
            ),
            confirmation_record=event.confirmation,
            manifest_id=event.manifest_id,
        )
    )


def _parameters(pack: EvidencePack, action: AcquisitionAction) -> object:
    if action == AcquisitionAction.REQUEST_MORE_FRAMES:
        return RequestMoreFramesParameters(
            action=action,
            camera_id=pack.event.camera_id,
            stream_id=pack.event.stream_id,
            start_frame=91,
            end_frame_exclusive=92,
        )
    if action == AcquisitionAction.RECROP:
        return RecropParameters(
            action=action,
            frame_id=pack.key_frame_ids[0],
            bbox=BBoxXYXY(x1=5, y1=10, x2=85, y2=170),
        )
    if action == AcquisitionAction.OTHER_CAMERA_SAME_TIME:
        return OtherCameraSameTimeParameters(
            action=action,
            source_frame_id=pack.key_frame_ids[0],
            target_camera_id="cam-02",
        )
    if action == AcquisitionAction.TRACK_CONFIDENCE_CURVE:
        assert pack.event.primary_track_ref is not None
        return TrackConfidenceCurveParameters(
            action=action,
            track_ref=pack.event.primary_track_ref,
            start_frame=pack.event.start_frame,
            end_frame_exclusive=pack.event.end_frame_exclusive,
        )
    return RedetectHighResolutionParameters(
        action=action,
        crop_id=pack.crops[0].crop_id,
        prompts=("open reagent container",),
    )


def _request(
    pack: EvidencePack,
    parameters: object,
    *,
    prior_acquisitions: int = 0,
    current_version: int | None = None,
) -> AcquisitionRequest:
    payload = AcquisitionRequestPayload(
        action=parameters.action,
        validated_parameters=parameters,
        reason_summary="A bounded typed acquisition can resolve the remaining ambiguity.",
    )
    return AcquisitionRequest(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=SESSION_ID,
        round_index=prior_acquisitions + 1,
        prior_acquisition_rounds=prior_acquisitions,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=(
            pack.version if current_version is None else current_version
        ),
        source_judge_output_id=_sha(f"judge-{prior_acquisitions}"),
        source_model_request_ref=_ref(
            ArtifactKind.MODEL_REQUEST,
            _sha(f"model-request-{prior_acquisitions}"),
        ),
        source_model_response_ref=_ref(
            ArtifactKind.MODEL_RESPONSE,
            _sha(f"model-response-{prior_acquisitions}"),
        ),
        request_payload=payload,
        manifest_id=pack.manifest_id,
    )


def _frame(frame_id: str, token: str) -> FrameRef:
    camera_id, stream_id, index_text = frame_id.split(":")
    return FrameRef(
        camera_id=camera_id,
        stream_id=stream_id,
        frame_index=int(index_text),
        fps_num=30_000,
        fps_den=1_001,
        width=1_920,
        height=1_080,
        content_sha256=_sha(f"frame-{token}"),
    )


def _recrop_objects(
    pack: EvidencePack,
    authority: object,
    parameters: RecropParameters,
) -> tuple[CropRequest, Crop]:
    source_refs = derive_recrop_source_refs(authority, parameters)
    crop_request = CropRequest(
        frame_id=parameters.frame_id,
        source=CropSource.RECROP,
        bbox=parameters.bbox,
        output_width=parameters.bbox.width,
        output_height=parameters.bbox.height,
        source_refs=source_refs,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        encoding_version="png-v1",
        primary_track_ref=pack.event.primary_track_ref,
        tags={"zone_id": pack.event.zone_id},
    )
    media_sha = _sha(f"recrop-media-{parameters.frame_id}-{parameters.bbox.x1}")
    crop = Crop(
        frame_id=parameters.frame_id,
        source=CropSource.RECROP,
        bbox=parameters.bbox,
        source_refs=source_refs,
        local_path=f"{pack.run_id}/frames/{media_sha}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=_sha(f"recrop-source-{parameters.frame_id}"),
        pixel_sha256=_sha(f"recrop-pixel-{parameters.frame_id}-{parameters.bbox.x1}"),
        media_sha256=media_sha,
        output_width=parameters.bbox.width,
        output_height=parameters.bbox.height,
        size_bytes=2_048,
        media_type=MediaType.IMAGE_PNG,
        encoding_version=crop_request.encoding_version,
        privacy_receipt=PrivacyReceipt(
            policy=crop_request.privacy_policy,
            transform_version=crop_request.privacy_transform_version,
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=crop_request.primary_track_ref,
        tags={"zone_id": pack.event.zone_id},
    )
    return crop_request, crop


def _execution(
    pack: EvidencePack,
    action: AcquisitionAction,
    *,
    receipts: tuple[ToolExecutionReceipt, ...] = (),
    loaded: LoadedEvidenceObjects | None = None,
    parameters: object | None = None,
    prior_acquisitions: int = 0,
    current_version: int | None = None,
) -> AcquisitionExecution:
    parameters = parameters or _parameters(pack, action)
    if loaded is None and isinstance(parameters, OtherCameraSameTimeParameters):
        loaded = LoadedEvidenceObjects(
            frames=(_frame(parameters.source_frame_id, "other-camera-source"),)
        )
    loaded = loaded or LoadedEvidenceObjects()
    authority = derive_evidence_authority(pack, receipts, loaded)
    request = _request(
        pack,
        parameters,
        prior_acquisitions=prior_acquisitions,
        current_version=current_version,
    )
    manifest = ToolExecutionManifest(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=request.hearing_session_id,
        acquisition_request_id=request.request_id,
        action=action,
        tool_id=f"tool-{action.value.lower().replace('_', '-')}",
        tool_revision="tool-v1",
        parameters_schema_sha256=_sha(f"schema-{action.value}"),
        component_manifest_id=_sha(f"component-{action.value}"),
        model_manifest_id=(
            _sha(f"model-{action.value}") if action == AcquisitionAction.REDETECT_HIGH_RES else None
        ),
        manifest_id=pack.manifest_id,
    )
    current_pack_ref = _ref(ArtifactKind.EVIDENCE_PACK, pack.pack_id)
    crop_request: CropRequest | None = None
    if isinstance(parameters, RequestMoreFramesParameters):
        frames = tuple(
            sorted(
                (
                    _frame(
                        f"{parameters.camera_id}:{parameters.stream_id}:{frame_index}",
                        f"requested-{frame_index}",
                    )
                    for frame_index in range(
                        parameters.start_frame,
                        parameters.end_frame_exclusive,
                        parameters.step,
                    )
                ),
                key=lambda frame: frame.frame_id,
            )
        )
        outputs = LoadedEvidenceObjects(frames=frames)
        input_refs = (current_pack_ref,)
        output_refs = tuple(
            sorted(
                (_ref(ArtifactKind.FRAME, frame.frame_id) for frame in frames),
                key=lambda ref: ref.sort_key,
            )
        )
    elif isinstance(parameters, OtherCameraSameTimeParameters):
        output = _frame(
            f"{parameters.target_camera_id}:other-stream:90",
            "other-camera",
        )
        outputs = LoadedEvidenceObjects(frames=(output,))
        input_refs = tuple(
            sorted(
                (
                    current_pack_ref,
                    _ref(ArtifactKind.FRAME, parameters.source_frame_id),
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        output_refs = (_ref(ArtifactKind.FRAME, output.frame_id),)
    elif isinstance(parameters, RecropParameters):
        crop_request, crop = _recrop_objects(pack, authority, parameters)
        outputs = LoadedEvidenceObjects(crops=(crop,))
        input_refs = tuple(
            sorted((current_pack_ref, *crop_request.source_refs), key=lambda ref: ref.sort_key)
        )
        output_refs = (_ref(ArtifactKind.CROP, crop.crop_id),)
    elif isinstance(parameters, TrackConfidenceCurveParameters):
        output_refs = (_ref(ArtifactKind.OBJECTIVE_FACT, "fact-track-confidence-01"),)
        input_refs = (current_pack_ref,)
        result_id = derive_m4_tool_result_id(
            action,
            input_refs,
            output_refs,
            parameters,
            manifest.execution_manifest_id,
        )
        fact = ObjectiveFact(
            fact_id=output_refs[0].artifact_id,
            kind=ObjectiveFactKind.DETECTION_SCORE,
            value=0.75,
            source_ref=_ref(ArtifactKind.TOOL_RESULT, result_id),
            source_manifest_id=manifest.execution_manifest_id,
        )
        outputs = LoadedEvidenceObjects(objective_facts=(fact,))
    else:
        assert isinstance(parameters, RedetectHighResolutionParameters)
        source_crop = next(crop for crop in authority.crops if crop.crop_id == parameters.crop_id)
        assert manifest.model_manifest_id is not None
        detection = Detection(
            detection_id="redetect-result-01",
            frame_id=source_crop.frame_id,
            label="open reagent container",
            bbox=BBoxXYXY(
                x1=source_crop.bbox.x1 + 1,
                y1=source_crop.bbox.y1 + 1,
                x2=source_crop.bbox.x1 + 20,
                y2=source_crop.bbox.y1 + 20,
            ),
            score=0.88,
            track_ref=pack.event.primary_track_ref,
            model_manifest_id=manifest.model_manifest_id,
        )
        outputs = LoadedEvidenceObjects(detections=(detection,))
        input_refs = tuple(
            sorted(
                (current_pack_ref, _ref(ArtifactKind.CROP, parameters.crop_id)),
                key=lambda ref: ref.sort_key,
            )
        )
        output_refs = (_ref(ArtifactKind.DETECTION, detection.detection_id),)
    result_id = derive_m4_tool_result_id(
        action,
        input_refs,
        output_refs,
        parameters,
        manifest.execution_manifest_id,
    )
    result = ToolResult(
        tool_result_id=result_id,
        action=action,
        input_refs=input_refs,
        output_refs=output_refs,
        validated_parameters=parameters,
        execution_manifest_id=manifest.execution_manifest_id,
    )
    return AcquisitionExecution(
        request=request,
        execution_manifest=manifest,
        tool_result=result,
        output_objects=outputs,
        crop_request=crop_request,
    )


def _finalize(
    pack: EvidencePack,
    execution: AcquisitionExecution,
    *,
    receipts: tuple[ToolExecutionReceipt, ...] = (),
    loaded: LoadedEvidenceObjects | None = None,
):
    parameters = execution.request.validated_parameters
    if loaded is None and isinstance(parameters, OtherCameraSameTimeParameters):
        loaded = LoadedEvidenceObjects(
            frames=(_frame(parameters.source_frame_id, "other-camera-source"),)
        )
    draft = derive_evidence_pack_successor(
        pack,
        execution,
        current_receipts=receipts,
        current_loaded_objects=loaded,
    )
    return finalize_evidence_pack_successor(
        pack,
        execution,
        _closure(draft),
        current_receipts=receipts,
        current_loaded_objects=loaded,
    )


def _reload_with_output_refs(
    update,
    output_refs: tuple[ArtifactRef, ...],
    *,
    loaded_objects: LoadedEvidenceObjects | None = None,
):
    """Build an adversarial persisted graph that bypasses contract construction."""

    original = update.receipt.tool_result
    result_id = derive_m4_tool_result_id(
        original.action,
        original.input_refs,
        output_refs,
        original.validated_parameters,
        original.execution_manifest_id,
    )
    result = ToolResult.model_construct(
        tool_result_id=result_id,
        action=original.action,
        input_refs=original.input_refs,
        output_refs=output_refs,
        validated_parameters=original.validated_parameters,
        execution_manifest_id=original.execution_manifest_id,
    )
    object.__setattr__(update.pack, "tool_results", (result,))
    receipt = ToolExecutionReceipt.model_construct(
        request=update.receipt.request,
        execution_manifest=update.receipt.execution_manifest,
        tool_result=result,
        resulting_evidence_pack_id=update.pack.pack_id,
        resulting_evidence_pack_version=update.pack.version,
    )
    return derive_evidence_authority(
        update.pack,
        (receipt,),
        loaded_objects or LoadedEvidenceObjects(),
    )


@pytest.mark.parametrize("action", tuple(AcquisitionAction))
def test_five_actions_form_exact_semantic_supersets_and_safe_authority(
    action: AcquisitionAction,
) -> None:
    current = _pack()
    execution = _execution(current, action)
    update = _finalize(current, execution)

    assert update.pack.version == current.version + 1
    for field_name in (
        "run_id",
        "case_id",
        "complete",
        "event",
        "key_frame_ids",
        "panorama_crops",
        "subject_crops",
        "focus_crops",
        "temporal_crops",
        "track_summary",
        "confirmation_record",
        "observation_sufficiency_input",
        "manifest_id",
    ):
        assert getattr(update.pack, field_name) == getattr(current, field_name)
    assert all(fact in update.pack.objective_facts for fact in current.objective_facts)
    assert update.receipt.tool_result == execution.tool_result
    assert update.receipt.resulting_evidence_pack_id == update.pack.pack_id

    citable = derive_citable_refs(update.authority)
    assert _ref(ArtifactKind.FRAME, current.key_frame_ids[0]) not in citable
    assert all(ref.kind != ArtifactKind.FRAME for ref in citable)
    assert all(ref.kind != ArtifactKind.DETECTION for ref in citable)
    assert _ref(ArtifactKind.TOOL_RESULT, execution.tool_result.tool_result_id) in citable

    selected_id = min(crop.crop_id for crop in current.crops)
    disclosure = derive_role_disclosure(update.authority, (selected_id,))
    assert {item.crop_id for item in disclosure.media} == {selected_id}
    assert {
        ref.artifact_id for ref in disclosure.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
    } == {selected_id}
    assert all(
        ref.kind not in {ArtifactKind.FRAME, ArtifactKind.DETECTION}
        for ref in disclosure.allowed_evidence_refs
    )
    assert all(
        bounds.artifact_ref.kind == ArtifactKind.CROP for bounds in disclosure.artifact_bounds
    )

    if action == AcquisitionAction.RECROP:
        crop = execution.output_objects.crops[0]
        assert _ref(ArtifactKind.CROP, crop.crop_id) in citable
    elif action == AcquisitionAction.TRACK_CONFIDENCE_CURVE:
        fact = execution.output_objects.objective_facts[0]
        assert fact in update.pack.objective_facts
        assert _ref(ArtifactKind.OBJECTIVE_FACT, fact.fact_id) in citable
    elif action == AcquisitionAction.REDETECT_HIGH_RES:
        detection = execution.output_objects.detections[0]
        assert _ref(ArtifactKind.DETECTION, detection.detection_id) not in citable
    else:
        frame = execution.output_objects.frames[0]
        assert _ref(ArtifactKind.FRAME, frame.frame_id) not in citable


def test_other_camera_pixels_never_enter_role_media_whitelist_or_bounds() -> None:
    current = _pack()
    update = _finalize(
        current,
        _execution(current, AcquisitionAction.OTHER_CAMERA_SAME_TIME),
    )
    other_frame = next(
        frame for frame in update.loaded_objects.frames if frame.camera_id == "cam-02"
    )
    other_ref = _ref(ArtifactKind.FRAME, other_frame.frame_id)
    disclosure = derive_role_disclosure(update.authority, (current.crops[0].crop_id,))

    assert other_ref in update.authority.acquisition_input_refs
    assert other_ref not in update.authority.candidate_citable_refs
    assert other_ref not in disclosure.allowed_evidence_refs
    assert all(item.crop_id != other_frame.frame_id for item in disclosure.media)
    assert all(bounds.artifact_ref != other_ref for bounds in disclosure.artifact_bounds)


def test_recrop_is_citable_media_but_unselected_crops_are_not_disclosed() -> None:
    current = _pack()
    execution = _execution(current, AcquisitionAction.RECROP)
    update = _finalize(current, execution)
    recrop = execution.output_objects.crops[0]
    disclosure = derive_role_disclosure(update.authority, (recrop.crop_id,))

    assert disclosure.media[0].crop_id == recrop.crop_id
    assert disclosure.artifact_bounds[0].artifact_ref == _ref(
        ArtifactKind.CROP,
        recrop.crop_id,
    )
    assert {
        ref.artifact_id for ref in disclosure.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
    } == {recrop.crop_id}
    assert not {crop.crop_id for crop in current.crops} & {
        ref.artifact_id for ref in disclosure.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
    }


def test_missing_loaded_output_and_missing_successor_closure_fail_typed() -> None:
    current = _pack()
    execution = _execution(current, AcquisitionAction.REQUEST_MORE_FRAMES)
    draft = derive_evidence_pack_successor(current, execution)
    with pytest.raises(EvidencePackSuccessorError, match="exact passing closure"):
        finalize_evidence_pack_successor(current, execution, None)

    update = finalize_evidence_pack_successor(current, execution, _closure(draft))
    with pytest.raises(EvidenceAuthorityError, match="loaded content closure"):
        derive_evidence_authority(
            update.pack,
            update.receipts,
            LoadedEvidenceObjects(),
        )


def test_loaded_selection_and_receipt_order_are_fail_closed() -> None:
    frame_91 = _frame("cam-01:demo-ntsc:91", "91")
    frame_92 = _frame("cam-01:demo-ntsc:92", "92")
    with pytest.raises(EvidenceAuthorityError, match="stable artifact order"):
        LoadedEvidenceObjects(frames=(frame_92, frame_91))

    current = _pack()
    crop_ids = tuple(crop.crop_id for crop in current.crops)
    authority = derive_evidence_authority(current)
    with pytest.raises(EvidenceDisclosureError, match="unique and stable"):
        derive_role_disclosure(authority, tuple(reversed(crop_ids)))

    first = _finalize(
        current,
        _execution(current, AcquisitionAction.REQUEST_MORE_FRAMES),
    )
    recrop_parameters = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id=first.loaded_objects.frames[0].frame_id,
        bbox=BBoxXYXY(x1=10, y1=10, x2=90, y2=170),
    )
    second_execution = _execution(
        first.pack,
        AcquisitionAction.RECROP,
        receipts=first.receipts,
        loaded=first.loaded_objects,
        parameters=recrop_parameters,
        prior_acquisitions=1,
    )
    second = _finalize(
        first.pack,
        second_execution,
        receipts=first.receipts,
        loaded=first.loaded_objects,
    )
    with pytest.raises(EvidenceAuthorityError, match="version order"):
        derive_evidence_authority(
            second.pack,
            tuple(reversed(second.receipts)),
            second.loaded_objects,
        )


def test_wrong_request_version_and_failed_closure_leave_current_pack_unchanged() -> None:
    current = _pack()
    before = current.model_dump(mode="json")
    wrong = _execution(
        current,
        AcquisitionAction.REQUEST_MORE_FRAMES,
        current_version=current.version + 1,
    )
    with pytest.raises(AcquisitionAuthorityError, match="outside the current pack scope"):
        derive_evidence_pack_successor(current, wrong)

    execution = _execution(current, AcquisitionAction.REQUEST_MORE_FRAMES)
    draft = derive_evidence_pack_successor(current, execution)
    bad_closure = ClosureReport(
        run_id=draft.run_id,
        root_ref=_ref(ArtifactKind.CASE, draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=_sha("wrong-closure-input"),
        checked_refs=draft.expected_closure_refs(),
    )
    with pytest.raises(EvidencePackSuccessorError, match="closure or receipt"):
        finalize_evidence_pack_successor(current, execution, bad_closure)
    assert current.model_dump(mode="json") == before


def test_successor_validation_rejects_rewritten_old_object_even_if_identity_is_unchanged() -> None:
    current = _pack()
    execution = _execution(current, AcquisitionAction.REQUEST_MORE_FRAMES)
    update = _finalize(current, execution)
    payload = update.pack.model_dump(
        mode="python",
        exclude={"pack_id", "closure_report"},
    )
    payload["focus_crops"][0]["tags"] = {"zone_id": "rewritten-zone"}
    rewritten = _close(EvidencePackDraft.model_validate(payload))
    assert rewritten.pack_id == update.pack.pack_id

    with pytest.raises(EvidencePackSuccessorError, match="rewrote immutable field focus_crops"):
        validate_evidence_pack_successor(
            current,
            rewritten,
            update.receipt,
            loaded_objects=update.loaded_objects,
        )


def test_recrop_source_is_stable_prior_crop_or_prior_tool_result_without_cycle() -> None:
    current = _pack()
    parameters = _parameters(current, AcquisitionAction.RECROP)
    assert isinstance(parameters, RecropParameters)
    authority = derive_evidence_authority(current)
    expected_crop_ref = min(
        (_ref(ArtifactKind.CROP, crop.crop_id) for crop in current.crops),
        key=lambda ref: ref.sort_key,
    )
    assert expected_crop_ref in derive_recrop_source_refs(authority, parameters)

    first_execution = _execution(current, AcquisitionAction.REQUEST_MORE_FRAMES)
    first = _finalize(current, first_execution)
    acquired_frame = first.loaded_objects.frames[0]
    followup_parameters = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id=acquired_frame.frame_id,
        bbox=BBoxXYXY(x1=10, y1=10, x2=90, y2=170),
    )
    second_execution = _execution(
        first.pack,
        AcquisitionAction.RECROP,
        receipts=first.receipts,
        loaded=first.loaded_objects,
        parameters=followup_parameters,
        prior_acquisitions=1,
    )
    prior_result_ref = _ref(
        ArtifactKind.TOOL_RESULT,
        first_execution.tool_result.tool_result_id,
    )
    current_result_ref = _ref(
        ArtifactKind.TOOL_RESULT,
        second_execution.tool_result.tool_result_id,
    )
    assert prior_result_ref in second_execution.crop_request.source_refs
    assert current_result_ref not in second_execution.crop_request.source_refs
    second = _finalize(
        first.pack,
        second_execution,
        receipts=first.receipts,
        loaded=first.loaded_objects,
    )
    assert second.authority.pack == second.pack


def test_recrop_rejects_other_camera_unclosed_frame_and_missing_prior_source() -> None:
    current = _pack()
    other = _finalize(
        current,
        _execution(current, AcquisitionAction.OTHER_CAMERA_SAME_TIME),
    )
    other_frame = next(
        frame for frame in other.loaded_objects.frames if frame.camera_id == "cam-02"
    )
    other_parameters = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id=other_frame.frame_id,
        bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
    )
    with pytest.raises(AcquisitionAuthorityError, match="current event stream"):
        derive_recrop_source_refs(other.authority, other_parameters)

    unclosed = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id="cam-01:demo-ntsc:89",
        bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
    )
    with pytest.raises(AcquisitionAuthorityError, match="absent from current pack closure"):
        derive_recrop_source_refs(derive_evidence_authority(current), unclosed)

    crop_free = _pack(crop_count=0)
    no_source = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id=crop_free.key_frame_ids[0],
        bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
    )
    with pytest.raises(RecropAuthorityUnrecoverable, match="neither an existing crop"):
        derive_recrop_source_refs(derive_evidence_authority(crop_free), no_source)


def test_l5_grant_is_union_of_actual_role_disclosures_across_pack_history() -> None:
    current = _pack()
    selected_initial = min(crop.crop_id for crop in current.crops)
    initial_disclosure = derive_role_disclosure(
        derive_evidence_authority(current),
        (selected_initial,),
    )
    grant = extend_hearing_evidence_grant(None, initial_disclosure)

    first_execution = _execution(current, AcquisitionAction.REQUEST_MORE_FRAMES)
    first = _finalize(current, first_execution)
    first_disclosure = derive_role_disclosure(first.authority, (selected_initial,))
    grant = extend_hearing_evidence_grant(grant, first_disclosure)

    recrop_parameters = RecropParameters(
        action=AcquisitionAction.RECROP,
        frame_id=first.loaded_objects.frames[0].frame_id,
        bbox=BBoxXYXY(x1=10, y1=10, x2=90, y2=170),
    )
    second_execution = _execution(
        first.pack,
        AcquisitionAction.RECROP,
        receipts=first.receipts,
        loaded=first.loaded_objects,
        parameters=recrop_parameters,
        prior_acquisitions=1,
    )
    second = _finalize(
        first.pack,
        second_execution,
        receipts=first.receipts,
        loaded=first.loaded_objects,
    )
    recrop_id = second_execution.output_objects.crops[0].crop_id
    second_disclosure = derive_role_disclosure(second.authority, (recrop_id,))
    grant = extend_hearing_evidence_grant(grant, second_disclosure)

    granted_crops = {
        ref.artifact_id for ref in grant.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
    }
    assert granted_crops == {selected_initial, recrop_id}
    assert all(
        ref.kind not in {ArtifactKind.FRAME, ArtifactKind.DETECTION}
        for ref in grant.allowed_evidence_refs
    )
    assert {bounds.artifact_ref.artifact_id for bounds in grant.artifact_bounds} == granted_crops
    assert grant.latest_evidence_pack_id == second.pack.pack_id
    assert grant.latest_evidence_pack_version == second.pack.version


def test_requested_frames_reload_as_exact_range_with_content_hashes() -> None:
    current = _pack()
    parameters = RequestMoreFramesParameters(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        camera_id=current.event.camera_id,
        stream_id=current.event.stream_id,
        start_frame=91,
        end_frame_exclusive=97,
        step=2,
    )
    execution = _execution(
        current,
        AcquisitionAction.REQUEST_MORE_FRAMES,
        parameters=parameters,
    )
    update = _finalize(current, execution)
    expected_ids = tuple(
        f"{parameters.camera_id}:{parameters.stream_id}:{index}" for index in range(91, 97, 2)
    )

    assert tuple(frame.frame_id for frame in update.loaded_objects.frames) == expected_ids
    assert all(frame.content_sha256 is not None for frame in update.loaded_objects.frames)
    assert (
        derive_evidence_authority(
            update.pack,
            update.receipts,
            update.loaded_objects,
        )
        == update.authority
    )

    missing_refs = execution.tool_result.output_refs[:-1]
    missing_loaded = LoadedEvidenceObjects(frames=update.loaded_objects.frames[:-1])
    with pytest.raises(AcquisitionAuthorityError, match="exactly match range"):
        _reload_with_output_refs(
            update,
            missing_refs,
            loaded_objects=missing_loaded,
        )

    current = _pack()
    update = _finalize(
        current,
        _execution(
            current,
            AcquisitionAction.REQUEST_MORE_FRAMES,
            parameters=parameters,
        ),
    )
    no_hash = update.loaded_objects.frames[0].model_copy(update={"content_sha256": None})
    loaded = LoadedEvidenceObjects(
        frames=tuple(
            sorted(
                (no_hash, *update.loaded_objects.frames[1:]),
                key=lambda frame: frame.frame_id,
            )
        )
    )
    with pytest.raises(EvidenceAuthorityError, match="loaded content closure"):
        derive_evidence_authority(update.pack, update.receipts, loaded)


def test_other_camera_reload_requires_loaded_same_time_hashed_frames() -> None:
    current = _pack()
    update = _finalize(
        current,
        _execution(current, AcquisitionAction.OTHER_CAMERA_SAME_TIME),
    )
    parameters = update.receipt.request.validated_parameters
    assert isinstance(parameters, OtherCameraSameTimeParameters)
    source = next(
        frame
        for frame in update.loaded_objects.frames
        if frame.frame_id == parameters.source_frame_id
    )
    outputs = tuple(
        frame
        for frame in update.loaded_objects.frames
        if frame.frame_id != parameters.source_frame_id
    )

    assert source.content_sha256 is not None
    assert outputs
    assert all(frame.camera_id == parameters.target_camera_id for frame in outputs)
    assert all(frame.content_sha256 is not None for frame in outputs)
    assert all(frame.timestamp_ms == source.timestamp_ms for frame in outputs)
    # This deliberately unregistered stream proves target-stream authorization
    # remains the executor's RunManifest responsibility.
    assert {frame.stream_id for frame in outputs} == {"other-stream"}

    with pytest.raises(EvidenceAuthorityError, match="lacks frame closure"):
        derive_evidence_authority(
            update.pack,
            update.receipts,
            LoadedEvidenceObjects(frames=outputs),
        )

    wrong_time = outputs[0].model_copy(update={"fps_num": 25, "fps_den": 1})
    wrong_loaded = LoadedEvidenceObjects(
        frames=tuple(sorted((source, wrong_time), key=lambda frame: frame.frame_id))
    )
    with pytest.raises(AcquisitionAuthorityError, match="source timestamp"):
        derive_evidence_authority(update.pack, update.receipts, wrong_loaded)


def test_redetection_reload_binds_prompt_label_frame_and_frame_space_crop_bbox() -> None:
    current = _pack()
    update = _finalize(
        current,
        _execution(current, AcquisitionAction.REDETECT_HIGH_RES),
    )
    parameters = update.receipt.request.validated_parameters
    assert isinstance(parameters, RedetectHighResolutionParameters)
    source = next(crop for crop in current.crops if crop.crop_id == parameters.crop_id)
    detection = update.loaded_objects.detections[0]

    assert detection.label in parameters.prompts
    assert detection.frame_id == source.frame_id
    assert source.bbox.x1 <= detection.bbox.x1 < detection.bbox.x2 <= source.bbox.x2
    assert source.bbox.y1 <= detection.bbox.y1 < detection.bbox.y2 <= source.bbox.y2
    assert (
        derive_evidence_authority(
            update.pack,
            update.receipts,
            update.loaded_objects,
        )
        == update.authority
    )

    wrong_label = detection.model_copy(update={"label": "not-a-requested-label"})
    with pytest.raises(AcquisitionAuthorityError, match="prompt"):
        derive_evidence_authority(
            update.pack,
            update.receipts,
            LoadedEvidenceObjects(detections=(wrong_label,)),
        )
    outside = detection.model_copy(
        update={
            "bbox": BBoxXYXY(
                x1=0,
                y1=0,
                x2=source.bbox.x1 + 1,
                y2=source.bbox.y1 + 1,
            )
        }
    )
    with pytest.raises(AcquisitionAuthorityError, match="crop, prompt, or model"):
        derive_evidence_authority(
            update.pack,
            update.receipts,
            LoadedEvidenceObjects(detections=(outside,)),
        )


def _invalid_output_refs(
    action: AcquisitionAction,
    count: int,
) -> tuple[ArtifactRef, ...]:
    kind = {
        AcquisitionAction.REQUEST_MORE_FRAMES: ArtifactKind.FRAME,
        AcquisitionAction.RECROP: ArtifactKind.CROP,
        AcquisitionAction.OTHER_CAMERA_SAME_TIME: ArtifactKind.FRAME,
        AcquisitionAction.TRACK_CONFIDENCE_CURVE: ArtifactKind.OBJECTIVE_FACT,
        AcquisitionAction.REDETECT_HIGH_RES: ArtifactKind.DETECTION,
    }[action]
    refs = []
    for index in range(count):
        artifact_id = (
            f"cam-99:stream-{index:04d}:10000"
            if kind == ArtifactKind.FRAME
            else _sha(f"invalid-{action.value}-{index}")
        )
        refs.append(_ref(kind, artifact_id))
    return tuple(sorted(refs, key=lambda ref: ref.sort_key))


@pytest.mark.parametrize("action", tuple(AcquisitionAction))
@pytest.mark.parametrize("boundary", ("empty", "over_max"))
def test_all_five_action_cardinality_bounds_reject_adversarial_reload(
    action: AcquisitionAction,
    boundary: str,
) -> None:
    current = _pack()
    update = _finalize(current, _execution(current, action))
    count = (
        0
        if boundary == "empty"
        else 2
        if action == AcquisitionAction.RECROP
        else MAX_ACQUISITION_RETURNED_FRAMES + 1
    )
    with pytest.raises(AcquisitionAuthorityError, match=r"cardinality|exactly one"):
        _reload_with_output_refs(
            update,
            _invalid_output_refs(action, count),
        )


def test_recrop_reload_adds_output_crop_to_citable_and_disclosable_authority() -> None:
    current = _pack()
    execution = _execution(current, AcquisitionAction.RECROP)
    update = _finalize(current, execution)
    reloaded = derive_evidence_authority(
        update.pack,
        update.receipts,
        update.loaded_objects,
    )
    recrop = execution.output_objects.crops[0]
    disclosure = derive_role_disclosure(reloaded, (recrop.crop_id,))

    assert recrop in reloaded.crops
    assert _ref(ArtifactKind.CROP, recrop.crop_id) in reloaded.candidate_citable_refs
    assert disclosure.media[0].crop_id == recrop.crop_id
