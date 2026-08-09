from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import ConfirmationPolicy, PrivacyPolicy, ViolationType
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.pilot import (
    PilotA2Report,
    PilotEvidencePackSummary,
    PilotPerceptionArtifactReceipt,
    PilotPerceptionArtifactRole,
    PilotPerceptionCompletionManifest,
    PilotPerceptionExecutionManifest,
    PilotPerceptionReport,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotRunRequest,
    PilotTrackerThresholds,
    PilotWorkerBox,
    PilotWorkerDetection,
)
from labcourt.schema_export import expected_schema_files


def _request() -> PilotRunRequest:
    return PilotRunRequest(
        run_id="pilot-001",
        config_sha256="1" * 64,
        video_relative_path="inputs/pilot-demo.mp4",
        video_sha256="2" * 64,
        selected_rules=(ViolationType.PPE_GOGGLES_MISSING,),
        resume=True,
        max_cases=20,
    )


def _execution_manifest() -> PilotPerceptionExecutionManifest:
    return PilotPerceptionExecutionManifest(
        detector=ModelManifest(
            component="detector",
            provider="HuggingFace",
            model="IDEA-Research/grounding-dino-tiny",
            revision="a2bb814dd30d776dcf7e30523b00659f4f141c71",
            weights_sha256="1a2412ef99bd74bcd3c2a246fa1e48581f8889a1300c9051974741314fc042f3",
            license_id="Apache-2.0",
        ),
        tracker=ModelManifest(
            component="tracker",
            provider="Roboflow",
            model="trackers.ByteTrackTracker",
            revision="2.5.0.post0",
            weights_sha256=None,
            license_id="Apache-2.0",
        ),
        prompts={
            "person": ("person",),
            "goggles": ("safety goggles", "protective eyewear"),
        },
        device="cuda:0",
        score_threshold=0.35,
        high_confidence_threshold=0.5,
        bbox_policy="CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1",
        goggles_nms_iou_threshold=0.95,
        tracker_initialization_policy="ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1",
        tracker_thresholds=PilotTrackerThresholds(
            track_activation_threshold=0.25,
            lost_track_buffer=30,
            minimum_iou_threshold=0.1,
            minimum_consecutive_frames=1,
        ),
        software_versions={
            "torch": "2.13.0",
            "transformers": "5.14.1",
            "trackers": "2.5.0.post0",
        },
    )


def test_pilot_run_request_is_exported_and_round_trips() -> None:
    request = _request()
    assert PilotRunRequest.model_validate_json(request.model_dump_json()) == request
    assert "pilot-run-request.schema.json" in expected_schema_files()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "CON"),
        ("video_relative_path", "../outside.mp4"),
        ("video_relative_path", "inputs/not-video.txt"),
        ("max_cases", 0),
        ("max_cases", True),
    ],
)
def test_pilot_run_request_rejects_untrusted_boundaries(field: str, value: object) -> None:
    payload = _request().model_dump(mode="python")
    payload[field] = value
    with pytest.raises(ValidationError):
        PilotRunRequest.model_validate(payload)


def test_pilot_run_request_rejects_duplicate_rules() -> None:
    payload = _request().model_dump(mode="python")
    payload["selected_rules"] = [
        ViolationType.PPE_GOGGLES_MISSING,
        ViolationType.PPE_GOGGLES_MISSING,
    ]
    with pytest.raises(ValidationError, match="unique"):
        PilotRunRequest.model_validate(payload)


def test_perception_manifest_is_content_derived_and_exported() -> None:
    manifest = _execution_manifest()
    assert len(manifest.manifest_id) == 64
    assert (
        PilotPerceptionExecutionManifest.model_validate_json(manifest.model_dump_json()) == manifest
    )
    assert "pilot-perception-execution-manifest.schema.json" in expected_schema_files()

    payload = manifest.model_dump(mode="python")
    payload["manifest_id"] = "0" * 64
    with pytest.raises(ValidationError, match="does not match"):
        PilotPerceptionExecutionManifest.model_validate(payload)


def test_perception_manifest_requires_real_weight_identity_and_exact_initial_labels() -> None:
    payload = _execution_manifest().model_dump(mode="python", exclude_computed_fields=True)
    payload["detector"]["weights_sha256"] = None
    with pytest.raises(ValidationError, match="weight SHA-256"):
        PilotPerceptionExecutionManifest.model_validate(payload)

    payload = _execution_manifest().model_dump(mode="python", exclude_computed_fields=True)
    payload["prompts"]["gloves"] = ["gloves"]
    with pytest.raises(ValidationError, match="exactly person and goggles"):
        PilotPerceptionExecutionManifest.model_validate(payload)

    payload = _execution_manifest().model_dump(mode="python", exclude_computed_fields=True)
    payload["empty_detection_policy"] = "PERMISSIVE_EMPTY_LABELS"
    with pytest.raises(ValidationError):
        PilotPerceptionExecutionManifest.model_validate(payload)


def test_perception_manifest_binds_complete_fail_closed_pose_controls() -> None:
    base = _execution_manifest().model_dump(mode="python", exclude_computed_fields=True)
    base.update(
        {
            "pose": ModelManifest(
                component="pose",
                provider="HuggingFace",
                model="usyd-community/vitpose-plus-small",
                revision="0c30b6534bb621af0162b481176742577264e36e",
                weights_sha256=("f7bad8ed09eeeb2a7de6b38faaa8a88d07838e23e9c06a2a782099bca7467cb9"),
                license_id="Apache-2.0",
            ).model_dump(mode="python", exclude_computed_fields=True),
            "pose_dataset_index": 0,
            "pose_keypoint_score_threshold": 0.8,
            "pose_minimum_eye_span_ratio": 0.03,
            "pose_maximum_eye_span_ratio": 0.3,
            "pose_keypoint_policy": "DUAL_EYE_SCORE_AND_GEOMETRY_V1",
        }
    )
    manifest = PilotPerceptionExecutionManifest.model_validate(base)
    assert manifest.pose is not None
    assert manifest.pose.component == "pose"

    missing_control = dict(base)
    missing_control.pop("pose_keypoint_score_threshold")
    with pytest.raises(ValidationError, match="complete fail-closed controls"):
        PilotPerceptionExecutionManifest.model_validate(missing_control)

    reversed_span = dict(base)
    reversed_span["pose_minimum_eye_span_ratio"] = 0.4
    with pytest.raises(ValidationError, match="strictly ordered"):
        PilotPerceptionExecutionManifest.model_validate(reversed_span)

    payload = _execution_manifest().model_dump(mode="python", exclude_computed_fields=True)
    payload["goggles_nms_iou_threshold"] = 1.1
    with pytest.raises(ValidationError):
        PilotPerceptionExecutionManifest.model_validate(payload)


def test_worker_request_and_explicit_empty_success_round_trip() -> None:
    manifest = _execution_manifest()
    request = PilotPerceptionWorkerRequest(
        request_id="frame-000001",
        frame_id="cam-01:pilot-stream:1",
        frame_content_sha256="2" * 64,
        fps_num=25,
        fps_den=1,
        width=16,
        height=12,
        image_sha256="3" * 64,
        image_base64="cG5n",
        expected_manifest_id=manifest.manifest_id,
    )
    response = PilotPerceptionWorkerResponse(
        request_id=request.request_id,
        frame_id=request.frame_id,
        frame_content_sha256=request.frame_content_sha256,
        manifest_id=manifest.manifest_id,
        detections=(),
    )

    assert PilotPerceptionWorkerRequest.model_validate_json(request.model_dump_json()) == request
    assert PilotPerceptionWorkerResponse.model_validate_json(response.model_dump_json()) == response
    assert response.status == "SUCCEEDED"
    assert response.detections == ()


def test_worker_detection_requires_person_track_and_strict_supported_labels() -> None:
    valid = {
        "label": "person",
        "source_label": "person",
        "bbox": {"x1": 1.0, "y1": 2.0, "x2": 10.0, "y2": 11.0},
        "score": 0.75,
        "local_track_id": "42",
    }
    assert PilotWorkerDetection.model_validate(valid).local_track_id == "42"

    invalid = dict(valid)
    invalid["local_track_id"] = None
    with pytest.raises(ValidationError, match="requires a local anonymous track"):
        PilotWorkerDetection.model_validate(invalid)

    with pytest.raises(ValidationError):
        PilotWorkerDetection(
            label="gloves",
            source_label="gloves",
            bbox=PilotWorkerBox(x1=1.0, y1=2.0, x2=10.0, y2=11.0),
            score=0.75,
            local_track_id=None,
        )


def test_worker_pose_output_requires_typed_keypoints_and_manifest_identity() -> None:
    pose_manifest_id = "9" * 64
    detection = PilotWorkerDetection(
        label="person",
        source_label="person",
        bbox=PilotWorkerBox(x1=1.0, y1=2.0, x2=10.0, y2=11.0),
        score=0.75,
        local_track_id="42",
        keypoints=(
            Keypoint(name="left_eye", x=4.0, y=4.0, score=0.91),
            Keypoint(name="right_eye", x=7.0, y=4.0, score=0.92),
        ),
        pose_manifest_id=pose_manifest_id,
    )
    assert detection.pose_manifest_id == pose_manifest_id

    payload = detection.model_dump(mode="python")
    payload["pose_manifest_id"] = None
    with pytest.raises(ValidationError, match="require a pose manifest"):
        PilotWorkerDetection.model_validate(payload)

    payload = detection.model_dump(mode="python")
    payload["label"] = "goggles"
    payload["local_track_id"] = None
    with pytest.raises(ValidationError, match="only person detections"):
        PilotWorkerDetection.model_validate(payload)


def test_perception_report_counts_are_self_consistent() -> None:
    report = PilotPerceptionReport(
        run_id="pilot-001",
        frames_processed=3,
        detection_count=5,
        person_count=3,
        goggles_count=2,
        track_count=1,
        provider_failures=0,
        manifest_id=_execution_manifest().manifest_id,
        preview_path="runs/pilot-001/debug/perception-preview.mp4",
    )
    assert report.person_count + report.goggles_count == report.detection_count

    payload = report.model_dump(mode="python")
    payload["detection_count"] = 4
    with pytest.raises(ValidationError, match="label counts"):
        PilotPerceptionReport.model_validate(payload)


def _evidence_summary() -> PilotEvidencePackSummary:
    return PilotEvidencePackSummary(
        event_id="event-001",
        case_id="case-001",
        pack_id="pack-001",
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        confirmation_policy=ConfirmationPolicy.STRICT_CAUSAL,
        complete=True,
        closure_passed=True,
        panorama_crop_count=1,
        subject_crop_count=1,
        focus_crop_count=0,
        temporal_crop_count=3,
        cloud_allowed_crop_count=3,
        local_only_crop_count=2,
        privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
    )


def _a2_report(*, with_evidence: bool = True) -> PilotA2Report:
    packs = (_evidence_summary(),) if with_evidence else ()
    return PilotA2Report(
        run_id="pilot-001",
        state="EVIDENCE_READY" if with_evidence else "NO_CANDIDATE",
        config_sha256="1" * 64,
        video_sha256="2" * 64,
        perception_manifest_id="3" * 64,
        perception_completion_id="4" * 64,
        run_manifest_id="5" * 64,
        selected_rules=(ViolationType.PPE_GOGGLES_MISSING,),
        frames_processed=241,
        association_count=241,
        l0_reminder_count=1,
        suppression_count=0,
        candidate_event_count=len(packs),
        evidence_pack_count=len(packs),
        evidence_packs=packs,
    )


def test_a2_report_is_content_derived_exported_and_has_no_subject_fields() -> None:
    report = _a2_report()

    assert PilotA2Report.model_validate_json(report.model_dump_json()) == report
    assert "pilot-a2-report.schema.json" in expected_schema_files()
    assert "pilot-evidence-pack-summary.schema.json" in expected_schema_files()
    assert "track" not in report.model_dump_json()

    payload = report.model_dump(mode="python")
    payload["report_id"] = "0" * 64
    with pytest.raises(ValidationError, match="report_id"):
        PilotA2Report.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("state", "NO_CANDIDATE", "state"),
        ("candidate_event_count", 0, "one complete EvidencePack"),
        ("evidence_pack_count", 0, "summaries"),
        ("selected_rules", [], "at least 1 item"),
    ],
)
def test_a2_report_rejects_inconsistent_success(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _a2_report().model_dump(mode="python", exclude_computed_fields=True)
    payload[field] = value
    with pytest.raises(ValidationError, match=message):
        PilotA2Report.model_validate(payload)


def test_a2_report_accepts_a_true_no_candidate_result() -> None:
    report = _a2_report(with_evidence=False)

    assert report.state == "NO_CANDIDATE"
    assert report.evidence_packs == ()


def test_a2_evidence_summary_rejects_media_access_count_drift() -> None:
    payload = _evidence_summary().model_dump(mode="python")
    payload["local_only_crop_count"] = 1

    with pytest.raises(ValidationError, match="media-access counts"):
        PilotEvidencePackSummary.model_validate(payload)


def _artifact_receipt(
    role: PilotPerceptionArtifactRole,
    suffix: str,
    marker: str,
) -> PilotPerceptionArtifactReceipt:
    return PilotPerceptionArtifactReceipt(
        role=role,
        artifact_ref=f"runs/pilot-001/{suffix}",
        artifact_sha256=marker * 64,
        artifact_size_bytes=12,
    )


def _completion_manifest() -> PilotPerceptionCompletionManifest:
    return PilotPerceptionCompletionManifest(
        run_id="pilot-001",
        config_sha256="1" * 64,
        video_sha256="2" * 64,
        manifest_id=_execution_manifest().manifest_id,
        artifacts=(
            _artifact_receipt("VIDEO_MANIFEST", "input/video-manifest.json", "3"),
            _artifact_receipt(
                "EXECUTION_MANIFEST",
                "perception/execution-manifest.json",
                "4",
            ),
            _artifact_receipt(
                "FRAME_BUNDLES",
                "perception/frame-bundles.jsonl",
                "5",
            ),
            _artifact_receipt(
                "FRAME_RECEIPTS",
                "perception/frame-receipts.jsonl",
                "6",
            ),
            _artifact_receipt("REPORT", "perception/report.json", "7"),
            _artifact_receipt("PREVIEW", "debug/perception-preview.mp4", "8"),
        ),
    )


def test_perception_completion_is_content_derived_and_exported() -> None:
    completion = _completion_manifest()

    assert len(completion.completion_id) == 64
    assert (
        PilotPerceptionCompletionManifest.model_validate_json(completion.model_dump_json())
        == completion
    )
    schemas = expected_schema_files()
    assert "pilot-perception-artifact-receipt.schema.json" in schemas
    assert "pilot-perception-completion-manifest.schema.json" in schemas

    payload = completion.model_dump(mode="python")
    payload["completion_id"] = "0" * 64
    with pytest.raises(ValidationError, match="completion_id"):
        PilotPerceptionCompletionManifest.model_validate(payload)


def test_perception_completion_requires_exact_ordered_run_scoped_inventory() -> None:
    completion = _completion_manifest()
    payload = completion.model_dump(mode="python", exclude_computed_fields=True)
    payload["artifacts"] = list(reversed(payload["artifacts"]))
    with pytest.raises(ValidationError, match="exact ordered"):
        PilotPerceptionCompletionManifest.model_validate(payload)

    payload = completion.model_dump(mode="python", exclude_computed_fields=True)
    payload["artifacts"][0]["artifact_ref"] = "runs/another/input/video-manifest.json"
    with pytest.raises(ValidationError, match="run and role"):
        PilotPerceptionCompletionManifest.model_validate(payload)

    payload = completion.model_dump(mode="python")
    payload["artifacts"][0]["artifact_sha256"] = "9" * 64
    with pytest.raises(ValidationError, match="receipt_id"):
        PilotPerceptionCompletionManifest.model_validate(payload)


def test_perception_completion_accepts_exact_inventory_without_optional_preview() -> None:
    payload = _completion_manifest().model_dump(mode="python", exclude_computed_fields=True)
    payload["artifacts"] = payload["artifacts"][:-1]

    completion = PilotPerceptionCompletionManifest.model_validate(payload)

    assert tuple(artifact.role for artifact in completion.artifacts) == (
        "VIDEO_MANIFEST",
        "EXECUTION_MANIFEST",
        "FRAME_BUNDLES",
        "FRAME_RECEIPTS",
        "REPORT",
    )
