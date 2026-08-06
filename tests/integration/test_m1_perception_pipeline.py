from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.precomputed import PrecomputedFrameSource
from labcourt.application.perception import PerceptionPipeline
from labcourt.config_loader import load_config
from labcourt.contracts.config import AppConfig, ZoneConfig
from labcourt.contracts.detections import Detection, FrameBundle
from labcourt.contracts.enums import ConfirmationPolicy, PpeType, RiskLevel, ViolationType
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.registry import VIOLATION_REGISTRY
from labcourt.exceptions import ContractViolation, ManifestMismatch

DETECTOR_MANIFEST_ID = "ea8e4e6b9a8708aa12432ba691de04e4bd3f3de511717b6a6d212bd1e1536783"
TRACK_REF = "cam-01:epoch-01:person-01"


def _config() -> AppConfig:
    base = load_config(Path(__file__).parents[2] / "configs" / "default.yaml")
    zone = ZoneConfig(
        zone_id="zone-01",
        camera_id="cam-01",
        polygon=((0, 0), (639, 0), (639, 479), (0, 479)),
        risk_level=RiskLevel.HIGH,
        required_ppe=(PpeType.GOGGLES,),
        reminder_channel="display-01",
    )
    return base.model_copy(
        update={
            "zones": (zone,),
            "l0": base.l0.model_copy(update={"reminder_cooldown_seconds": 2.0}),
            "absence": base.absence.model_copy(
                update={
                    "dwell_seconds_by_risk": {
                        RiskLevel.LOW: 2.0,
                        RiskLevel.MEDIUM: 2.0,
                        RiskLevel.HIGH: 2.0,
                    },
                    "context_lookahead_seconds": 1.0,
                    "track_grace_seconds": 1.0,
                }
            ),
            "perception": base.perception.model_copy(
                update={
                    "detector": base.perception.detector.model_copy(
                        update={"model_id": "precomputed-demo-v1"}
                    ),
                    "observability": base.perception.observability.model_copy(
                        update={"clear_frame_threshold": 1.0}
                    ),
                }
            ),
        }
    )


def _bundle(
    frame_index: int,
    *,
    goggles: bool = False,
    detector_manifest_id: str = DETECTOR_MANIFEST_ID,
    stream_id: str = "stream-01",
    fps_num: int = 1,
    fps_den: int = 1,
) -> FrameBundle:
    from labcourt.contracts.frames import FrameRef

    frame = FrameRef(
        camera_id="cam-01",
        stream_id=stream_id,
        frame_index=frame_index,
        fps_num=fps_num,
        fps_den=fps_den,
        width=640,
        height=480,
    )
    detections = [
        Detection(
            detection_id=f"person-{frame_index}",
            frame_id=frame.frame_id,
            label="person",
            bbox=BBoxXYXY(x1=100, y1=40, x2=300, y2=400),
            score=0.9,
            track_ref=TRACK_REF,
            model_manifest_id=detector_manifest_id,
        )
    ]
    if goggles:
        detections.append(
            Detection(
                detection_id=f"goggles-{frame_index}",
                frame_id=frame.frame_id,
                label="goggles",
                bbox=BBoxXYXY(x1=150, y1=70, x2=250, y2=150),
                score=0.9,
                model_manifest_id=detector_manifest_id,
            )
        )
    return FrameBundle(frame=frame, detections=tuple(reversed(detections)))


def _pipeline(config: AppConfig | None = None) -> PerceptionPipeline:
    resolved = config or _config()
    fixture = Path(__file__).parents[2] / "tests" / "fixtures" / "m2" / "run-manifest-fake.json"
    manifest = RunManifest.model_validate_json(fixture.read_text(encoding="utf-8")).model_copy(
        update={
            "schema_version": resolved.schema_version,
            "config_sha256": resolved.config_sha256,
            "rule_version": resolved.rule_version,
            "privacy_transform_version": resolved.evidence.privacy_transform_version,
            "reproducibility_mode": resolved.run.reproducibility_mode,
            "random_seed": resolved.run.random_seed,
            "storage_boundary": resolved.run.storage_boundary,
        }
    )
    return PerceptionPipeline(
        config=resolved,
        run_manifest=manifest,
    )


def test_precomputed_missing_ppe_emits_anonymous_reminder_and_strict_event_in_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    source = PrecomputedFrameSource(tuple(_bundle(index) for index in (2, 0, 1)))
    pipeline = _pipeline()

    first = pipeline.run(source)
    replay = pipeline.run(source)

    assert first == replay
    assert first.frames_processed == 3
    assert len(first.associations) == 3
    assert all(not association.result.present for association in first.associations)
    # At 1 fps, the exact two-second cooldown permits a second reminder on frame 2.
    assert len(first.reminders) == 2
    reminder = first.reminders[0]
    assert reminder.zone_id == "zone-01"
    assert reminder.ppe_type == PpeType.GOGGLES
    assert TRACK_REF not in reminder.model_dump_json()
    assert len(first.events) == 1
    event = first.events[0]
    assert event.violation_type == ViolationType.PPE_GOGGLES_MISSING
    assert event.confirmation.policy == ConfirmationPolicy.STRICT_CAUSAL
    assert (event.start_frame, event.end_frame_exclusive) == (0, 2)
    assert event.event_id == replay.events[0].event_id
    # A maximum clear-frame threshold cannot gate L1; the pipeline has no
    # observability input and still emits the candidate.
    assert first.suppressions == ()
    assert list(tmp_path.rglob("*")) == []


def test_positive_ppe_association_resets_the_absence_window() -> None:
    source = PrecomputedFrameSource(
        (
            _bundle(0),
            _bundle(1, goggles=True),
            _bundle(2),
            _bundle(3),
            _bundle(4),
        )
    )

    result = _pipeline().run(source)

    assert [item.result.present for item in result.associations] == [
        False,
        True,
        False,
        False,
        False,
    ]
    assert len(result.events) == 1
    assert (result.events[0].start_frame, result.events[0].end_frame_exclusive) == (2, 4)


def test_reminder_cooldowns_are_exact_and_independent_per_stream_timebase() -> None:
    one_fps = tuple(_bundle(index, stream_id="stream-1fps") for index in range(3))
    two_fps = tuple(_bundle(index, stream_id="stream-2fps", fps_num=2) for index in range(5))

    result = _pipeline().run(PrecomputedFrameSource((*two_fps, *one_fps)))

    assert len(result.reminders) == 4


def test_pipeline_rejects_any_detection_from_an_unpinned_manifest() -> None:
    source = PrecomputedFrameSource(
        (
            _bundle(0),
            _bundle(1, detector_manifest_id="c" * 64),
        )
    )

    with pytest.raises(ManifestMismatch, match="pinned detector manifest"):
        _pipeline().run(source)


def test_pipeline_fails_closed_if_ppe_registry_cooldowns_diverge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    violation_type = ViolationType.PPE_GLOVES_MISSING
    changed = VIOLATION_REGISTRY[violation_type].model_copy(
        update={"default_cooldown_seconds": 31.0}
    )
    monkeypatch.setitem(VIOLATION_REGISTRY, violation_type, changed)

    with pytest.raises(ContractViolation, match="cooldowns must agree"):
        _pipeline()


def test_pipeline_rejects_manifest_that_is_not_bound_to_config() -> None:
    config = _config()
    fixture = Path(__file__).parents[2] / "tests" / "fixtures" / "m2" / "run-manifest-fake.json"
    mismatched = RunManifest.model_validate_json(fixture.read_text(encoding="utf-8"))

    with pytest.raises(ManifestMismatch, match="config_sha256"):
        PerceptionPipeline(config=config, run_manifest=mismatched)


def test_pipeline_rejects_detector_semantics_not_pinned_by_config() -> None:
    config = _config()
    fixture = Path(__file__).parents[2] / "tests" / "fixtures" / "m2" / "run-manifest-fake.json"
    base = RunManifest.model_validate_json(fixture.read_text(encoding="utf-8"))
    detector = base.models["detector"].model_copy(update={"model": "unexpected-detector"})
    models = dict(base.models)
    models["detector"] = detector
    mismatched = base.model_copy(
        update={
            "config_sha256": config.config_sha256,
            "models": models,
        }
    )

    with pytest.raises(ManifestMismatch, match=r"detector\.model"):
        PerceptionPipeline(config=config, run_manifest=mismatched)


def test_pipeline_rejects_image_encoding_not_pinned_by_config() -> None:
    config = _config()
    fixture = Path(__file__).parents[2] / "tests" / "fixtures" / "m2" / "run-manifest-fake.json"
    base = RunManifest.model_validate_json(fixture.read_text(encoding="utf-8"))
    mismatched = base.model_copy(
        update={
            "schema_version": config.schema_version,
            "config_sha256": config.config_sha256,
            "rule_version": config.rule_version,
            "privacy_transform_version": config.evidence.privacy_transform_version,
            "reproducibility_mode": config.run.reproducibility_mode,
            "random_seed": config.run.random_seed,
            "storage_boundary": config.run.storage_boundary,
            "image_encoding_version": "png-other",
        }
    )

    with pytest.raises(ManifestMismatch, match="image_encoding_version"):
        PerceptionPipeline(config=config, run_manifest=mismatched)


def test_pipeline_rejects_causal_reordering_and_frame_gaps() -> None:
    class SourceInGivenOrder:
        def __init__(self, bundles: tuple[FrameBundle, ...]) -> None:
            self.bundles = bundles

        def iter_frames(self):  # type: ignore[no-untyped-def]
            return iter(self.bundles)

    with pytest.raises(ContractViolation, match="causal order"):
        _pipeline().run(SourceInGivenOrder((_bundle(2), _bundle(0), _bundle(1))))

    with pytest.raises(ContractViolation, match="contiguous"):
        _pipeline().run(SourceInGivenOrder((_bundle(0), _bundle(2))))


def test_end_of_source_finalizes_strict_history_without_full_lookahead() -> None:
    result = _pipeline().run(PrecomputedFrameSource((_bundle(0), _bundle(1))))

    assert len(result.events) == 1
    assert (result.events[0].start_frame, result.events[0].end_frame_exclusive) == (0, 2)
