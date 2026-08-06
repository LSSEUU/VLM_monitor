import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.adapters.precomputed import PrecomputedFrameSource, SyntheticFrameSource
from labcourt.contracts.detections import Detection, FrameBundle
from labcourt.contracts.enums import (
    DirectSafetySourceClass,
    PpeType,
    SafetySignalType,
    SafetySourceClass,
)
from labcourt.contracts.events import SafetySignal
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.reminders import SoftReminder
from labcourt.domain.reminders import InMemorySoftReminderService
from labcourt.domain.safety import (
    candidate_event_from_video_signal,
    emergency_incident_from_signal,
)
from labcourt.exceptions import ContractViolation, EvidenceMissing
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256


def _frame(
    frame_index: int,
    *,
    stream_id: str = "stream-01",
    width: int = 640,
    height: int = 480,
    content_sha256: str | None = None,
) -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id=stream_id,
        frame_index=frame_index,
        fps_num=30,
        fps_den=1,
        width=width,
        height=height,
        content_sha256=content_sha256,
    )


def _bundle(frame_index: int, *, label: str = "person") -> FrameBundle:
    frame = _frame(frame_index)
    return FrameBundle(
        frame=frame,
        detections=(
            Detection(
                detection_id=f"det-{frame_index}",
                frame_id=frame.frame_id,
                label=label,
                bbox=BBoxXYXY(x1=10, y1=20, x2=100, y2=200),
                score=0.9,
                model_manifest_id="a" * 64,
            ),
        ),
    )


def _signal(
    *,
    signal_type: SafetySignalType = SafetySignalType.OPEN_FLAME,
    source_class: SafetySourceClass = SafetySourceClass.PHYSICAL_SENSOR,
    certification_id: str = "cert-lab-01",
) -> SafetySignal:
    return SafetySignal(
        signal_id="signal-001",
        signal_type=signal_type,
        zone_id="hood-01",
        start_frame=20,
        end_frame_exclusive=22,
        value=True,
        unit=None,
        source_class=source_class,
        certification_id=certification_id,
        quality=1.0,
    )


def _route(signal: SafetySignal, *, enabled: bool = True):
    return emergency_incident_from_signal(
        signal,
        hard_alerts_enabled=enabled,
        allowed_signal_types=(SafetySignalType.OPEN_FLAME,),
        certification_ids=("cert-lab-01",),
        allowed_direct_sources=(DirectSafetySourceClass.PHYSICAL_SENSOR,),
    )


def test_synthetic_and_precomputed_sources_have_stable_frame_order() -> None:
    synthetic = SyntheticFrameSource((_frame(2), _frame(0), _frame(1)))
    precomputed = PrecomputedFrameSource((_bundle(2), _bundle(0), _bundle(1)))

    expected = ["cam-01:stream-01:0", "cam-01:stream-01:1", "cam-01:stream-01:2"]
    assert [bundle.frame.frame_id for bundle in synthetic.iter_frames()] == expected
    assert [bundle.frame.frame_id for bundle in precomputed.iter_frames()] == expected
    assert [
        frame.frame.frame_index for frame in precomputed.get_range("cam-01", "stream-01", 0, 3, 2)
    ] == [0, 2]
    assert precomputed.get_frame(expected[1]).ephemeral is True
    assert precomputed.get_frame(expected[1]).media_ref.startswith("memory/precomputed/")
    assert not hasattr(synthetic, "read_rgb8")
    assert not hasattr(precomputed, "read_rgb8")

    with pytest.raises(EvidenceMissing, match="unknown frame_id"):
        precomputed.get_frame("cam-01:stream-01:99")


def test_frame_source_range_is_scoped_to_camera_and_stream() -> None:
    source = SyntheticFrameSource(
        (
            _frame(1, stream_id="stream-02"),
            _frame(0, stream_id="stream-01"),
            _frame(0, stream_id="stream-02"),
            _frame(1, stream_id="stream-01"),
        )
    )

    selected = source.get_range("cam-01", "stream-02", 0, 2)
    assert [item.frame.frame_id for item in selected] == [
        "cam-01:stream-02:0",
        "cam-01:stream-02:1",
    ]
    assert not hasattr(source, "read_rgb8")


def test_rgb8_frame_accepts_exact_bytes_and_matching_content_hash() -> None:
    pixels = bytes((1, 2, 3, 4, 5, 6))
    frame = _frame(
        0,
        width=2,
        height=1,
        content_sha256="cc6e99d412643ddc652153d20f0085d636d520675266c1d25149730f23bfa896",
    )

    rgb8 = RGB8Frame(frame=frame, pixels=pixels)

    assert rgb8.frame is frame
    assert rgb8.pixels is pixels
    assert rgb8_pixel_sha256(2, 1, pixels) == frame.content_sha256
    assert not hasattr(rgb8, "__dict__")
    assert not hasattr(RGB8Frame, "model_fields")
    with pytest.raises(AttributeError):
        rgb8.pixels = b""  # type: ignore[misc]


def test_rgb8_frame_rejects_missing_content_hash() -> None:
    pixels = bytes(6)
    with pytest.raises(ValueError, match="content_sha256 is required"):
        RGB8Frame(frame=_frame(0, width=2, height=1), pixels=pixels)


def test_rgb8_frame_rejects_wrong_byte_length() -> None:
    pixels = bytes(5)
    frame = _frame(
        0,
        width=2,
        height=1,
        content_sha256=rgb8_pixel_sha256(2, 1, bytes(6)),
    )
    with pytest.raises(ValueError, match=r"width \* height \* 3"):
        RGB8Frame(frame=frame, pixels=pixels)


def test_rgb8_frame_rejects_content_hash_mismatch() -> None:
    pixels = bytes(6)
    frame = _frame(
        0,
        width=2,
        height=1,
        content_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="does not match RGB8 bytes"):
        RGB8Frame(frame=frame, pixels=pixels)


def test_frame_sources_reject_duplicate_frame_ids() -> None:
    with pytest.raises(ContractViolation, match="duplicate frame_id"):
        SyntheticFrameSource((_frame(0), _frame(0)))
    with pytest.raises(ContractViolation, match="duplicate frame_id"):
        PrecomputedFrameSource((_bundle(0), _bundle(0)))


def test_precomputed_sources_read_strict_utf8_json_and_jsonl(tmp_path: Path) -> None:
    bundles = (_bundle(1, label="护目镜"), _bundle(0))
    payloads = [bundle.model_dump(mode="json") for bundle in bundles]
    json_path = tmp_path / "frames.json"
    jsonl_path = tmp_path / "frames.jsonl"
    json_path.write_text(json.dumps(payloads, ensure_ascii=False), encoding="utf-8")
    jsonl_path.write_text(
        "\n".join(json.dumps(payload, ensure_ascii=False) for payload in payloads),
        encoding="utf-8",
    )

    from_json = PrecomputedFrameSource.from_json_file(json_path)
    from_jsonl = PrecomputedFrameSource.from_jsonl_file(jsonl_path)
    assert [bundle.frame.frame_index for bundle in from_json.iter_frames()] == [0, 1]
    assert [bundle.frame.frame_index for bundle in from_jsonl.iter_frames()] == [0, 1]
    assert tuple(from_json.iter_frames())[1].detections[0].label == "护目镜"

    valid_line = json.dumps(payloads[0], ensure_ascii=False)
    jsonl_path.write_text(f"{valid_line}\n\n{valid_line}", encoding="utf-8")
    with pytest.raises(ContractViolation, match="empty line"):
        PrecomputedFrameSource.from_jsonl_file(jsonl_path)

    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    with pytest.raises(ContractViolation, match="as UTF-8"):
        PrecomputedFrameSource.from_json_file(invalid_utf8)


@pytest.mark.parametrize(
    "path",
    [Path("//server/share/frames.json"), Path("https://example.invalid/frames.json")],
)
def test_precomputed_source_rejects_network_paths(path: Path) -> None:
    with pytest.raises(ContractViolation, match="local filesystem"):
        PrecomputedFrameSource.from_json_file(path)


def test_soft_reminder_is_identity_free_and_cooldown_is_memory_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    service = InMemorySoftReminderService(cooldown_frames=30)
    track_ref = "cam-01:epoch-01:track-01"

    first = service.maybe_remind(
        frame_index=10,
        track_ref=track_ref,
        zone_id="hood-01",
        ppe_type=PpeType.GOGGLES,
        channel="display-01",
    )
    suppressed = service.maybe_remind(
        frame_index=39,
        track_ref=track_ref,
        zone_id="hood-01",
        ppe_type=PpeType.GOGGLES,
        channel="display-01",
    )
    after_cooldown = service.maybe_remind(
        frame_index=40,
        track_ref=track_ref,
        zone_id="hood-01",
        ppe_type=PpeType.GOGGLES,
        channel="display-01",
    )

    assert first is not None
    assert suppressed is None
    assert after_cooldown is not None
    assert set(SoftReminder.model_fields) == {"zone_id", "ppe_type", "message", "channel"}
    assert track_ref not in first.model_dump_json()
    assert not any("track" in name for name in type(first).model_fields)
    assert track_ref not in repr(service._last_observed)
    assert track_ref not in repr(service._last_reminded)
    assert list(tmp_path.rglob("*")) == []

    restarted = InMemorySoftReminderService(cooldown_frames=30)
    assert (
        restarted.maybe_remind(
            frame_index=11,
            track_ref=track_ref,
            zone_id="hood-01",
            ppe_type=PpeType.GOGGLES,
            channel="display-01",
        )
        is not None
    )


def test_soft_reminder_rejects_free_form_identity_bearing_message() -> None:
    with pytest.raises(ValidationError):
        SoftReminder(
            zone_id="hood-01",
            ppe_type=PpeType.GOGGLES,
            message="Alice: 请佩戴护目镜。",
            channel="display-01",
        )


def test_soft_reminder_service_prunes_expired_ephemeral_keys() -> None:
    service = InMemorySoftReminderService(cooldown_frames=3)
    service.maybe_remind(
        frame_index=1,
        track_ref="cam-01:epoch-01:track-01",
        zone_id="hood-01",
        ppe_type=PpeType.GOGGLES,
        channel="display-01",
    )

    assert service.prune(current_frame=3) == 0
    assert service.prune(current_frame=4) == 1
    assert service._last_observed == {}
    assert service._last_reminded == {}


def test_certified_safety_signal_routes_to_deterministic_incident() -> None:
    signal = _signal()
    first = _route(signal)
    replay = _route(signal)

    assert first is not None
    assert first == replay
    assert first.adjudicated is False
    assert first.signal_id == signal.signal_id
    assert first.certification_id == signal.certification_id
    assert first.incident_id != first.delivery_idempotency_key

    changed = signal.model_copy(update={"end_frame_exclusive": 23})
    changed_incident = _route(changed)
    assert changed_incident is not None
    assert changed_incident.incident_id != first.incident_id
    assert changed_incident.delivery_idempotency_key != first.delivery_idempotency_key


@pytest.mark.parametrize(
    ("signal", "enabled"),
    [
        (_signal(source_class=SafetySourceClass.VIDEO_HEURISTIC), True),
        (_signal(source_class=SafetySourceClass.VALIDATED_DETERMINISTIC), True),
        (_signal(signal_type=SafetySignalType.SMOKE), True),
        (_signal(certification_id="cert-unapproved"), True),
        (_signal(), False),
    ],
)
def test_unapproved_safety_signals_never_route_directly(
    signal: SafetySignal,
    enabled: bool,
) -> None:
    assert _route(signal, enabled=enabled) is None


def test_video_heuristic_is_downgraded_to_non_hard_candidate() -> None:
    signal = _signal(
        source_class=SafetySourceClass.VIDEO_HEURISTIC,
        certification_id="video-model-revision",
    )

    candidate = candidate_event_from_video_signal(
        signal,
        camera_id="cam-01",
        stream_id="stream-01",
        rule_version="laboratory-v1",
        manifest_id="b" * 64,
        source_manifest_id="a" * 64,
    )

    assert candidate is not None
    assert candidate.hard_rule is False
    assert candidate.violation_type.value == "OPEN_FLAME"
    assert candidate.start_frame == signal.start_frame
    assert candidate.end_frame_exclusive == signal.end_frame_exclusive
    assert candidate.objective_facts[0].source_ref.kind.value == "SAFETY_SIGNAL"
    assert candidate.objective_facts[0].source_ref.artifact_id == signal.signal_id
    assert _route(signal) is None


def test_unmapped_video_signal_fails_closed_instead_of_guessing_rule() -> None:
    signal = _signal(
        signal_type=SafetySignalType.HEAT_ACTIVITY,
        source_class=SafetySourceClass.VIDEO_HEURISTIC,
        certification_id="video-model-revision",
    )

    assert (
        candidate_event_from_video_signal(
            signal,
            camera_id="cam-01",
            stream_id="stream-01",
            rule_version="laboratory-v1",
            manifest_id="b" * 64,
            source_manifest_id="a" * 64,
        )
        is None
    )
