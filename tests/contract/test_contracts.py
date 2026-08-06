import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.enums import EvidenceClass
from labcourt.contracts.events import CandidateEvent, SafetySignal
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import (
    RunManifest,
    SoftwareComponentManifest,
    StreamManifest,
)
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import parse_frame_id, require_portable_run_id
from labcourt.domain.canonical import canonical_json

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m0"
M2_FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"


@pytest.mark.parametrize(
    "run_id",
    ("run-01", "RUN_01", "portable.name", "compliance-run"),
)
def test_portable_run_filesystem_identity_accepts_unambiguous_ascii(run_id: str) -> None:
    assert require_portable_run_id(run_id, "run_id") == run_id


@pytest.mark.parametrize(
    "run_id",
    (
        "run-01.",
        "CON",
        "con.json",
        "NUL.audit",
        "COM1",
        "com9.data",
        "LPT1",
        "lpt9.txt",
    ),
)
def test_portable_run_filesystem_identity_rejects_windows_aliases(run_id: str) -> None:
    with pytest.raises(ValueError, match="portable run filesystem identity"):
        require_portable_run_id(run_id, "run_id")


@pytest.mark.parametrize(
    ("path", "model"),
    [
        (FIXTURES / "frame-ref-ntsc.json", FrameRef),
        (FIXTURES / "frame-bundle-presence.json", FrameBundle),
        (M2_FIXTURES / "candidate-event-presence.json", CandidateEvent),
        (M2_FIXTURES / "candidate-event-absence-strict.json", CandidateEvent),
        (FIXTURES / "safety-signal-certified.json", SafetySignal),
        (M2_FIXTURES / "run-manifest-fake.json", RunManifest),
    ],
)
def test_primary_fixtures_round_trip(path: Path, model: type[object]) -> None:
    raw = json.loads(path.read_text(encoding="utf-8"))
    parsed = model.model_validate(raw)  # type: ignore[attr-defined]
    reparsed = model.model_validate(parsed.model_dump(mode="json"))  # type: ignore[attr-defined]
    assert canonical_json(parsed.model_dump(mode="json")) == canonical_json(
        reparsed.model_dump(mode="json")
    )


def test_extra_fields_are_rejected() -> None:
    raw = json.loads((FIXTURES / "frame-ref-ntsc.json").read_text(encoding="utf-8"))
    raw["wall_clock"] = "forbidden"
    with pytest.raises(ValidationError, match="Extra inputs"):
        FrameRef.model_validate(raw)


@pytest.mark.parametrize(
    "values",
    [
        {"x1": 1, "y1": 1, "x2": 1, "y2": 2},
        {"x1": -1, "y1": 1, "x2": 2, "y2": 2},
        {"x1": 2, "y1": 2, "x2": 1, "y2": 1},
    ],
)
def test_invalid_bbox_is_rejected(values: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        BBoxXYXY.model_validate(values)


def test_frame_bundle_rejects_out_of_bounds_detection() -> None:
    raw = json.loads((FIXTURES / "frame-bundle-presence.json").read_text(encoding="utf-8"))
    raw["detections"][0]["bbox"]["x2"] = 5000
    with pytest.raises(ValidationError, match="exceeds frame bounds"):
        FrameBundle.model_validate(raw)


@pytest.mark.parametrize("detection_id", ["bad/id", "d" * 65])
def test_frame_bundle_rejects_detection_ids_that_are_not_reference_tokens(
    detection_id: str,
) -> None:
    raw = json.loads((FIXTURES / "frame-bundle-presence.json").read_text(encoding="utf-8"))
    raw["detections"][0]["detection_id"] = detection_id

    with pytest.raises(ValidationError):
        FrameBundle.model_validate(raw)


def test_frame_bundle_rejects_ambiguous_or_out_of_bounds_keypoints() -> None:
    raw = json.loads((FIXTURES / "frame-bundle-presence.json").read_text(encoding="utf-8"))
    raw["detections"][0]["keypoints"] = [
        {"name": "nose", "x": 200.0, "y": 100.0, "score": 0.9},
        {"name": "nose", "x": 201.0, "y": 101.0, "score": 0.8},
    ]
    with pytest.raises(ValidationError, match="duplicate keypoint"):
        FrameBundle.model_validate(raw)

    raw["detections"][0]["keypoints"] = [{"name": "nose", "x": 1280.0, "y": 100.0, "score": 0.9}]
    with pytest.raises(ValidationError, match="outside frame"):
        FrameBundle.model_validate(raw)


def test_violation_registry_rejects_wrong_evidence_class() -> None:
    raw = json.loads(
        (M2_FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    raw["evidence_class"] = EvidenceClass.PRESENCE.value
    with pytest.raises(ValidationError, match="requires evidence_class"):
        CandidateEvent.model_validate(raw)


def test_strict_causal_fixture_keeps_post_threshold_violation() -> None:
    event = CandidateEvent.model_validate_json(
        (M2_FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    assert event.confirmation.post_threshold_recovery_frame_id is not None
    assert event.confirmation.suppressed is False


def test_authoritative_frame_integers_are_strict() -> None:
    raw = json.loads((FIXTURES / "frame-ref-ntsc.json").read_text(encoding="utf-8"))
    raw["frame_index"] = True
    with pytest.raises(ValidationError, match="valid integer"):
        FrameRef.model_validate(raw)


def test_frame_id_tokens_are_unambiguous() -> None:
    raw = json.loads((FIXTURES / "frame-ref-ntsc.json").read_text(encoding="utf-8"))
    raw["camera_id"] = "cam:01"
    with pytest.raises(ValidationError, match="pattern"):
        FrameRef.model_validate(raw)


def test_serialized_derived_frame_fields_must_match() -> None:
    frame = FrameRef.model_validate_json(
        (FIXTURES / "frame-ref-ntsc.json").read_text(encoding="utf-8")
    )
    serialized = frame.model_dump(mode="json")
    serialized["timestamp_ms"] += 1
    with pytest.raises(ValidationError, match="does not match"):
        FrameRef.model_validate(serialized)


def test_serialized_manifest_id_must_match() -> None:
    manifest = RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    serialized = manifest.model_dump(mode="json")
    serialized["manifest_id"] = "0" * 64
    with pytest.raises(ValidationError, match="does not match"):
        RunManifest.model_validate(serialized)


def test_nested_contract_mappings_are_immutable_and_copy_is_revalidated() -> None:
    manifest = RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    with pytest.raises(TypeError, match="immutable"):
        manifest.models["detector"] = manifest.models["tracker"]

    event = CandidateEvent.model_validate_json(
        (M2_FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )
    with pytest.raises(ValidationError, match="event_id"):
        event.model_copy(update={"event_id": "wrong"})


def test_m2_manifest_rejects_legacy_wire_and_preserves_model_manifest_ids() -> None:
    legacy_payload = json.loads((FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8"))
    current = RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )

    with pytest.raises(ValidationError, match=r"2\.0\.0"):
        RunManifest.model_validate(legacy_payload)
    assert current.schema_version == "2.0.0"
    assert current.streams == ()
    assert current.software_components == {}
    assert current.pixel_format == "RGB8"
    assert current.pixel_hash_algorithm == "LCPIX1"
    assert current.image_encoding_version == "png-v1"
    assert {name: component.model_manifest_id for name, component in current.models.items()} == {
        name: component["model_manifest_id"] for name, component in legacy_payload["models"].items()
    }


def test_m2_candidate_event_rejects_legacy_untyped_objective_source() -> None:
    legacy_payload = json.loads(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )
    with pytest.raises(ValidationError, match="source_ref"):
        CandidateEvent.model_validate(legacy_payload)


def test_stream_manifest_requires_canonical_fps_and_run_stable_order() -> None:
    first = StreamManifest(
        camera_id="cam-01",
        stream_id="stream-01",
        input_file_sha256="a" * 64,
        fps_num=30_000,
        fps_den=1_001,
        timing_mode="CFR",
        timing_authority="TRUSTED_SIDECAR",
        timing_evidence_type="TRUSTED_SIDECAR_JSON",
        timing_evidence_sha256="b" * 64,
        width=1280,
        height=720,
        frame_count=100,
        decoder="opencv",
        decoder_version="4.12.0",
        backend="ffmpeg",
        software_component="opencv",
        library="opencv-python-headless",
        library_version="4.12.0",
        codec="h264",
        color_conversion="BGR_TO_RGB",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    second = first.model_copy(update={"stream_id": "stream-02"})
    manifest = RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    component = SoftwareComponentManifest(
        component="opencv",
        package="opencv-python-headless",
        version="4.12.0",
        license_id="Apache-2.0",
    )
    assert manifest.model_copy(
        update={
            "streams": (first, second),
            "software_components": {"opencv": component},
        }
    ).streams == (first, second)

    with pytest.raises(ValidationError, match="lowest terms"):
        first.model_copy(update={"fps_num": 60, "fps_den": 2})
    with pytest.raises(ValidationError, match="timing evidence type"):
        first.model_copy(update={"timing_evidence_type": "CALLER_DECLARATION"})
    with pytest.raises(ValidationError, match="stable order"):
        manifest.model_copy(
            update={
                "streams": (second, first),
                "software_components": {"opencv": component},
            }
        )
    with pytest.raises(ValidationError, match="unique"):
        manifest.model_copy(
            update={
                "streams": (first, first),
                "software_components": {"opencv": component},
            }
        )
    with pytest.raises(ValidationError, match="unknown software component"):
        manifest.model_copy(update={"streams": (first,)})
    mismatched_component = component.model_copy(update={"version": "4.11.0"})
    with pytest.raises(ValidationError, match="does not match"):
        manifest.model_copy(
            update={
                "streams": (first,),
                "software_components": {"opencv": mismatched_component},
            }
        )


def test_software_component_mapping_key_must_match_component() -> None:
    component = SoftwareComponentManifest(
        component="pillow",
        package="Pillow",
        version="12.0.0",
        license_id="HPND",
    )
    manifest = RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    updated = manifest.model_copy(update={"software_components": {"pillow": component}})
    assert updated.software_components["pillow"] == component
    with pytest.raises(ValidationError, match="mapping key"):
        manifest.model_copy(update={"software_components": {"opencv": component}})


@pytest.mark.parametrize(
    "path",
    [
        "../outside.png",
        "/absolute/outside.png",
        "C:/Windows/outside.png",
        "\\\\server\\share\\outside.png",
        "frames/bad:stream.png",
        "frames/COM¹.png",
        "frames/lpt².log",
        "frames/COM³",
    ],
)
def test_workspace_paths_reject_traversal_and_windows_absolute_forms(path: str) -> None:
    with pytest.raises(ValueError, match=r"workspace-relative|safe"):
        require_safe_relative_posix_path(path)


def test_workspace_path_accepts_portable_relative_form() -> None:
    assert require_safe_relative_posix_path("frames/crop-001.png") == "frames/crop-001.png"


def test_workspace_path_rejects_non_string_values() -> None:
    with pytest.raises(TypeError, match="string"):
        require_safe_relative_posix_path(None)  # type: ignore[arg-type]


def test_frame_id_parser_rejects_noncanonical_leading_zeroes() -> None:
    with pytest.raises(ValueError, match="frame_index"):
        parse_frame_id("cam-01:stream-01:0001")
