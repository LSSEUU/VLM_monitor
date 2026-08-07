from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import ViolationType
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.pilot import (
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
            label="gloves",  # type: ignore[arg-type]
            source_label="gloves",
            bbox=PilotWorkerBox(x1=1.0, y1=2.0, x2=10.0, y2=11.0),
            score=0.75,
            local_track_id=None,
        )


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
