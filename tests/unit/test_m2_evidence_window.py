from dataclasses import FrozenInstanceError

import pytest

from labcourt.contracts.enums import (
    ConfirmationPolicy,
    EvidenceClass,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent, ConfirmationRecord
from labcourt.contracts.frames import FrameRef
from labcourt.domain.evidence_window import (
    ObservabilityCandidate,
    build_evidence_window,
    select_key_frames,
)

SHA = "a" * 64


def _event(
    *,
    evidence_class: EvidenceClass = EvidenceClass.ABSENCE,
    start_frame: int = 100,
    end_frame_exclusive: int = 106,
    trigger_frame: int = 105,
    recovery_frame: int | None = None,
) -> CandidateEvent:
    if evidence_class == EvidenceClass.ABSENCE:
        violation_type = ViolationType.PPE_GOGGLES_MISSING
        confirmation = ConfirmationRecord(
            policy=ConfirmationPolicy.STRICT_CAUSAL,
            examined_frame_ids=(f"cam-01:stream-01:{trigger_frame}",),
            post_threshold_recovery_frame_id=(
                f"cam-01:stream-01:{recovery_frame}" if recovery_frame is not None else None
            ),
            resolved_frame=recovery_frame,
        )
        primary_track_ref = "cam-01:epoch-01:person-01"
    else:
        violation_type = ViolationType.REAGENT_CONTAINER_OPEN
        confirmation = ConfirmationRecord(policy=ConfirmationPolicy.NONE)
        primary_track_ref = "cam-01:epoch-01:bottle-01"
    return CandidateEvent(
        camera_id="cam-01",
        stream_id="stream-01",
        rule_version="rule-v1",
        violation_type=violation_type,
        evidence_class=evidence_class,
        zone_id="zone-01",
        start_frame=start_frame,
        end_frame_exclusive=end_frame_exclusive,
        trigger_frame=trigger_frame,
        primary_track_ref=primary_track_ref,
        l1_score=0.8,
        confirmation=confirmation,
        manifest_id=SHA,
    )


def _frame(
    frame_index: int,
    *,
    camera_id: str = "cam-01",
    stream_id: str = "stream-01",
    fps_num: int = 30_000,
    fps_den: int = 1_001,
) -> FrameRef:
    return FrameRef(
        camera_id=camera_id,
        stream_id=stream_id,
        frame_index=frame_index,
        fps_num=fps_num,
        fps_den=fps_den,
        width=1_920,
        height=1_080,
        content_sha256=SHA,
    )


def test_ntsc_window_uses_outward_exact_rational_rounding() -> None:
    event = _event(start_frame=97, end_frame_exclusive=101, trigger_frame=100)

    window = build_evidence_window(
        event,
        fps_num=30_000,
        fps_den=1_001,
        pre_seconds="0.1",
        post_seconds="0.1",
        stream_start_frame=0,
        stream_end_frame_exclusive=1_000,
    )

    # 0.1 seconds at 30000/1001 FPS is 2.997... frames, rounded outward to 3.
    assert (window.start_frame, window.end_frame_exclusive) == (97, 104)
    assert window.frame_count == 7


def test_window_clips_to_authoritative_stream_bounds_and_zero_contains_trigger() -> None:
    start_event = _event(start_frame=0, end_frame_exclusive=1, trigger_frame=0)
    clipped = build_evidence_window(
        start_event,
        fps_num=30_000,
        fps_den=1_001,
        pre_seconds=10,
        post_seconds=10,
        stream_start_frame=0,
        stream_end_frame_exclusive=2,
    )
    zero = build_evidence_window(
        start_event,
        fps_num=30_000,
        fps_den=1_001,
        pre_seconds=0,
        post_seconds=0,
        stream_start_frame=0,
        stream_end_frame_exclusive=2,
    )

    assert (clipped.start_frame, clipped.end_frame_exclusive) == (0, 2)
    assert (zero.start_frame, zero.end_frame_exclusive) == (0, 1)
    with pytest.raises(FrozenInstanceError):
        zero.start_frame = 1  # type: ignore[misc]


def test_window_rejects_an_event_outside_authoritative_stream_bounds() -> None:
    event = _event(start_frame=100, end_frame_exclusive=106, trigger_frame=105)
    with pytest.raises(ValueError, match="event interval"):
        build_evidence_window(
            event,
            fps_num=30_000,
            fps_den=1_001,
            pre_seconds=1,
            post_seconds=1,
            stream_start_frame=101,
            stream_end_frame_exclusive=200,
        )


def test_key_frames_preserve_priority_but_emit_chronological_order() -> None:
    event = _event(recovery_frame=108)
    window = build_evidence_window(
        event,
        fps_num=30_000,
        fps_den=1_001,
        pre_seconds=1,
        post_seconds=1,
        stream_start_frame=0,
        stream_end_frame_exclusive=1_000,
    )
    available = tuple(
        _frame(index) for index in range(window.start_frame, window.end_frame_exclusive)
    )

    selection = select_key_frames(
        event,
        window,
        available,
        state_transition_frame_ids=(
            "cam-01:stream-01:105",
            "cam-01:stream-01:103",
            "cam-01:stream-01:103",
        ),
        observability_candidates=(
            ObservabilityCandidate("cam-01:stream-01:102", 0.8),
            ObservabilityCandidate("cam-01:stream-01:101", 0.9),
            ObservabilityCandidate("cam-01:stream-01:100", 0.9),
        ),
        top_m=2,
    )

    assert selection.temporal_top_m_frame_ids == (
        "cam-01:stream-01:100",
        "cam-01:stream-01:101",
    )
    assert selection.selection_priority_frame_ids == (
        "cam-01:stream-01:105",  # trigger; duplicate transition/last is removed
        "cam-01:stream-01:103",
        "cam-01:stream-01:100",  # event first; also top-M
        "cam-01:stream-01:108",  # recorded recovery
        "cam-01:stream-01:101",
    )
    assert selection.frame_ids == (
        "cam-01:stream-01:100",
        "cam-01:stream-01:101",
        "cam-01:stream-01:103",
        "cam-01:stream-01:105",
        "cam-01:stream-01:108",
    )


def test_presence_does_not_add_observability_top_m() -> None:
    event = _event(
        evidence_class=EvidenceClass.PRESENCE,
        start_frame=10,
        end_frame_exclusive=13,
        trigger_frame=12,
    )
    window = build_evidence_window(
        event,
        fps_num=30,
        fps_den=1,
        pre_seconds=1,
        post_seconds=1,
        stream_start_frame=0,
        stream_end_frame_exclusive=100,
    )
    available = tuple(_frame(index, fps_num=30, fps_den=1) for index in range(0, 43))

    selection = select_key_frames(
        event,
        window,
        available,
        observability_candidates=(ObservabilityCandidate("cam-01:stream-01:11", 1.0),),
        top_m=3,
    )

    assert selection.temporal_top_m_frame_ids == ()
    assert selection.frame_ids == (
        "cam-01:stream-01:10",
        "cam-01:stream-01:12",
    )


def test_selection_rejects_cross_stream_or_missing_required_frames() -> None:
    event = _event()
    window = build_evidence_window(
        event,
        fps_num=30_000,
        fps_den=1_001,
        pre_seconds=1,
        post_seconds=1,
        stream_start_frame=0,
        stream_end_frame_exclusive=1_000,
    )

    with pytest.raises(ValueError, match="another camera or stream"):
        select_key_frames(
            event,
            window,
            (_frame(105, stream_id="other-stream"),),
            top_m=1,
        )

    with pytest.raises(ValueError, match="event first frame is not available"):
        select_key_frames(event, window, (_frame(105),), top_m=1)


def test_selection_rejects_observability_outside_alleged_interval() -> None:
    event = _event()
    window = build_evidence_window(
        event,
        fps_num=30_000,
        fps_den=1_001,
        pre_seconds=1,
        post_seconds=1,
        stream_start_frame=0,
        stream_end_frame_exclusive=1_000,
    )
    available = tuple(
        _frame(index) for index in range(window.start_frame, window.end_frame_exclusive)
    )

    with pytest.raises(ValueError, match="alleged event interval"):
        select_key_frames(
            event,
            window,
            available,
            observability_candidates=(ObservabilityCandidate("cam-01:stream-01:99", 1.0),),
            top_m=1,
        )
