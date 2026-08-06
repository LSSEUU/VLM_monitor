import json
from pathlib import Path

from labcourt.config_loader import load_config
from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.events import CandidateEvent, SafetySignal
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.ids import make_event_id
from labcourt.schema_export import export_schemas

PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "m0"
M2_FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "m2"
EXPECTED_M0_FIXTURES = {
    "candidate-event-absence-strict.json",
    "candidate-event-presence.json",
    "canonical-id-vectors.json",
    "config-invalid-evidence-indent.yaml",
    "frame-bundle-presence.json",
    "frame-ref-ntsc.json",
    "run-manifest-fake.json",
    "safety-signal-certified.json",
}


def test_m0_offline_contract_toolchain(tmp_path: Path) -> None:
    assert {path.name for path in FIXTURES.iterdir()} == EXPECTED_M0_FIXTURES
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    assert len(config.zones) == 1

    fixture_models = {
        "frame-ref-ntsc.json": FrameRef,
        "frame-bundle-presence.json": FrameBundle,
        "candidate-event-presence.json": CandidateEvent,
        "candidate-event-absence-strict.json": CandidateEvent,
        "safety-signal-certified.json": SafetySignal,
    }
    parsed_fixtures: dict[str, object] = {}
    for filename, model in fixture_models.items():
        root = M2_FIXTURES if filename.startswith("candidate-event-") else FIXTURES
        payload = json.loads((root / filename).read_text(encoding="utf-8"))
        parsed_fixtures[filename] = model.model_validate(payload)

    legacy_manifest = json.loads((FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8"))
    manifest = RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    assert manifest.config_sha256 == config.config_sha256
    assert manifest.rule_version == config.rule_version
    assert manifest.reproducibility_mode == config.run.reproducibility_mode
    assert manifest.random_seed == config.run.random_seed
    assert manifest.privacy_transform_version == config.evidence.privacy_transform_version
    assert manifest.storage_boundary == config.run.storage_boundary

    frame_ref = parsed_fixtures["frame-ref-ntsc.json"]
    frame_bundle = parsed_fixtures["frame-bundle-presence.json"]
    presence_event = parsed_fixtures["candidate-event-presence.json"]
    absence_event = parsed_fixtures["candidate-event-absence-strict.json"]
    safety_signal = parsed_fixtures["safety-signal-certified.json"]
    assert isinstance(frame_ref, FrameRef)
    assert isinstance(frame_bundle, FrameBundle)
    assert isinstance(presence_event, CandidateEvent)
    assert isinstance(absence_event, CandidateEvent)
    assert isinstance(safety_signal, SafetySignal)

    for event_name in (
        "candidate-event-presence.json",
        "candidate-event-absence-strict.json",
    ):
        event = parsed_fixtures[event_name]
        assert isinstance(event, CandidateEvent)
        assert event.manifest_id == manifest.manifest_id
        assert event.rule_version == manifest.rule_version
        assert event.event_id == make_event_id(
            camera_id=event.camera_id,
            stream_id=event.stream_id,
            violation_type=event.violation_type,
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            rule_version=event.rule_version,
        )

    detector_manifest_id = manifest.models["detector"].model_manifest_id
    known_manifest_ids = {
        manifest.manifest_id,
        *(model.model_manifest_id for model in manifest.models.values()),
    }
    assert all(
        detection.model_manifest_id == detector_manifest_id for detection in frame_bundle.detections
    )
    assert all(
        fact.source_manifest_id in known_manifest_ids
        for event in (presence_event, absence_event)
        for fact in event.objective_facts
    )

    assert frame_bundle.frame.camera_id == presence_event.camera_id
    assert frame_bundle.frame.stream_id == presence_event.stream_id
    assert frame_bundle.frame.frame_index == presence_event.trigger_frame
    assert presence_event.primary_track_ref in {
        detection.track_ref for detection in frame_bundle.detections if detection.track_ref
    }

    zones = {zone.zone_id: zone for zone in config.zones}
    for event in (presence_event, absence_event):
        assert event.zone_id in zones
        assert zones[event.zone_id].camera_id == event.camera_id
    assert frame_ref.camera_id in {zone.camera_id for zone in config.zones}
    assert safety_signal.zone_id in zones
    assert safety_signal.signal_type in config.safety.allowed_signal_types
    assert safety_signal.certification_id in config.safety.certification_ids
    assert safety_signal.source_class.value in {
        source.value for source in config.safety.allowed_direct_sources
    }

    vectors = json.loads((FIXTURES / "canonical-id-vectors.json").read_text(encoding="utf-8"))
    golden_event = vectors["event"]
    assert presence_event.event_id == golden_event["expected_event_id"]
    crop_vector = vectors["crop"]
    bottle = next(
        detection for detection in frame_bundle.detections if detection.label == "reagent_bottle"
    )
    assert crop_vector["frame_id"] == frame_bundle.frame.frame_id
    assert crop_vector["source_media_sha256"] == frame_bundle.frame.content_sha256
    assert crop_vector["bbox"] == [
        bottle.bbox.x1,
        bottle.bbox.y1,
        bottle.bbox.x2,
        bottle.bbox.y2,
    ]
    assert vectors["manifest"]["expected_manifest_id"] == legacy_manifest["manifest_id"]

    schema_dir = tmp_path / "schemas"
    assert export_schemas(schema_dir, check=False) == []
    assert export_schemas(schema_dir, check=True) == []
