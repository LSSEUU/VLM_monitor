"""Deterministic evidence windows and key-frame selection."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from math import isfinite
from typing import TypeAlias

from labcourt.contracts.enums import EvidenceClass
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.domain.timebase import seconds_to_frames

Seconds: TypeAlias = Decimal | Fraction | str | int | float


def _require_int(value: int, name: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


@dataclass(frozen=True, slots=True)
class EvidenceWindow:
    """A half-open, stream-clipped window around one event trigger."""

    camera_id: str
    stream_id: str
    stream_start_frame: int
    stream_end_frame_exclusive: int
    start_frame: int
    end_frame_exclusive: int
    trigger_frame: int
    fps_num: int
    fps_den: int

    def __post_init__(self) -> None:
        require_reference_token(self.camera_id, "camera_id")
        require_reference_token(self.stream_id, "stream_id")
        stream_start = _require_int(self.stream_start_frame, "stream_start_frame")
        stream_end = _require_int(
            self.stream_end_frame_exclusive,
            "stream_end_frame_exclusive",
            minimum=1,
        )
        start = _require_int(self.start_frame, "start_frame")
        end = _require_int(self.end_frame_exclusive, "end_frame_exclusive", minimum=1)
        trigger = _require_int(self.trigger_frame, "trigger_frame")
        fps_num = _require_int(self.fps_num, "fps_num", minimum=1)
        fps_den = _require_int(self.fps_den, "fps_den", minimum=1)
        if stream_start >= stream_end:
            raise ValueError("stream frame interval must be non-empty")
        if not stream_start <= start <= trigger < end <= stream_end:
            raise ValueError("evidence window must contain its trigger inside stream bounds")
        if fps_num <= 0 or fps_den <= 0:  # Kept explicit for the dataclass invariant.
            raise ValueError("FPS numerator and denominator must be positive")

    @property
    def frame_count(self) -> int:
        return self.end_frame_exclusive - self.start_frame

    def contains(self, frame_index: int) -> bool:
        _require_int(frame_index, "frame_index")
        return self.start_frame <= frame_index < self.end_frame_exclusive


@dataclass(frozen=True, slots=True)
class ObservabilityCandidate:
    """A frame and its already-computed observability used only for ranking."""

    frame_id: str
    score: float

    def __post_init__(self) -> None:
        parse_frame_id(self.frame_id)
        if (
            not isinstance(self.score, int | float)
            or isinstance(self.score, bool)
            or not isfinite(self.score)
        ):
            raise TypeError("observability score must be a finite number")
        if not 0 <= self.score <= 1:
            raise ValueError("observability score must be within [0, 1]")


@dataclass(frozen=True, slots=True)
class KeyFrameSelection:
    """Key frames in both selection-priority and chronological output order."""

    selection_priority_frame_ids: tuple[str, ...]
    frame_ids: tuple[str, ...]
    temporal_top_m_frame_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        priority = self.selection_priority_frame_ids
        ordered = self.frame_ids
        temporal = self.temporal_top_m_frame_ids
        if len(priority) != len(set(priority)) or len(ordered) != len(set(ordered)):
            raise ValueError("selected frame IDs must be unique")
        if set(priority) != set(ordered):
            raise ValueError("selection and output orders must contain the same frame IDs")
        if len(temporal) != len(set(temporal)):
            raise ValueError("temporal top-M frame IDs must be unique")
        if not set(temporal).issubset(ordered):
            raise ValueError("temporal top-M frames must be selected key frames")
        ordered_keys = tuple(_frame_sort_key(frame_id) for frame_id in ordered)
        if ordered_keys != tuple(sorted(ordered_keys)):
            raise ValueError("frame_ids must use chronological stable order")


def build_evidence_window(
    event: CandidateEvent,
    *,
    fps_num: int,
    fps_den: int,
    pre_seconds: Seconds,
    post_seconds: Seconds,
    stream_start_frame: int,
    stream_end_frame_exclusive: int,
) -> EvidenceWindow:
    """Build ``trigger +/- seconds`` with exact rational-FPS outward rounding.

    The post side is half-open and includes the trigger itself. For example, a zero-second
    pre/post window contains exactly the trigger frame. Stream bounds are authoritative and
    must be supplied explicitly; current frame availability is never mistaken for end-of-stream.
    """

    if not isinstance(event, CandidateEvent):
        raise TypeError("event must be a CandidateEvent")
    stream_start = _require_int(stream_start_frame, "stream_start_frame")
    stream_end = _require_int(
        stream_end_frame_exclusive,
        "stream_end_frame_exclusive",
        minimum=1,
    )
    if stream_start >= stream_end:
        raise ValueError("stream frame interval must be non-empty")
    if event.start_frame < stream_start or event.end_frame_exclusive > stream_end:
        raise ValueError("event interval must lie inside authoritative stream bounds")

    pre_frames = seconds_to_frames(pre_seconds, fps_num, fps_den)
    post_frames = seconds_to_frames(post_seconds, fps_num, fps_den)
    start = max(stream_start, event.trigger_frame - pre_frames)
    end = min(stream_end, event.trigger_frame + post_frames + 1)
    return EvidenceWindow(
        camera_id=event.camera_id,
        stream_id=event.stream_id,
        stream_start_frame=stream_start,
        stream_end_frame_exclusive=stream_end,
        start_frame=start,
        end_frame_exclusive=end,
        trigger_frame=event.trigger_frame,
        fps_num=fps_num,
        fps_den=fps_den,
    )


def _frame_sort_key(frame_id: str) -> tuple[int, str]:
    _, _, frame_index = parse_frame_id(frame_id)
    return frame_index, frame_id


def _frame_id(event: CandidateEvent, frame_index: int) -> str:
    return f"{event.camera_id}:{event.stream_id}:{frame_index}"


def _index_available_frames(
    event: CandidateEvent,
    window: EvidenceWindow,
    available_frames: Sequence[FrameRef],
) -> dict[str, FrameRef]:
    by_id: dict[str, FrameRef] = {}
    for frame in available_frames:
        if not isinstance(frame, FrameRef):
            raise TypeError("available_frames must contain FrameRef values")
        if (frame.camera_id, frame.stream_id) != (event.camera_id, event.stream_id):
            raise ValueError("available frame belongs to another camera or stream")
        if (frame.fps_num, frame.fps_den) != (window.fps_num, window.fps_den):
            raise ValueError("available frame FPS differs from the evidence window")
        if not (window.stream_start_frame <= frame.frame_index < window.stream_end_frame_exclusive):
            raise ValueError("available frame lies outside authoritative stream bounds")
        if frame.frame_id in by_id:
            raise ValueError(f"duplicate available frame: {frame.frame_id}")
        by_id[frame.frame_id] = frame
    return by_id


def _require_selected_frame(
    frame_id: str,
    *,
    event: CandidateEvent,
    window: EvidenceWindow,
    available_by_id: dict[str, FrameRef],
    role: str,
) -> str:
    camera_id, stream_id, frame_index = parse_frame_id(frame_id)
    if (camera_id, stream_id) != (event.camera_id, event.stream_id):
        raise ValueError(f"{role} frame belongs to another camera or stream")
    if not window.contains(frame_index):
        raise ValueError(f"{role} frame lies outside the evidence window")
    if frame_id not in available_by_id:
        raise ValueError(f"{role} frame is not available: {frame_id}")
    return frame_id


def select_key_frames(
    event: CandidateEvent,
    window: EvidenceWindow,
    available_frames: Sequence[FrameRef],
    *,
    observability_candidates: Sequence[ObservabilityCandidate] = (),
    state_transition_frame_ids: Sequence[str] = (),
    recovery_frame_id: str | None = None,
    top_m: int = 0,
) -> KeyFrameSelection:
    """Select required frames with fixed priority and stable chronological output.

    Priority is trigger, state transitions, event first/last, recovery, then absence
    observability top-M. Each explicit input must resolve to an available frame in the
    window; the function never substitutes a neighboring frame.
    """

    if not isinstance(event, CandidateEvent):
        raise TypeError("event must be a CandidateEvent")
    if not isinstance(window, EvidenceWindow):
        raise TypeError("window must be an EvidenceWindow")
    if (window.camera_id, window.stream_id, window.trigger_frame) != (
        event.camera_id,
        event.stream_id,
        event.trigger_frame,
    ):
        raise ValueError("evidence window does not belong to the event")
    _require_int(top_m, "top_m")
    if event.evidence_class == EvidenceClass.ABSENCE and top_m == 0:
        raise ValueError("absence key-frame selection requires top_m > 0")

    available_by_id = _index_available_frames(event, window, available_frames)
    priority: list[str] = []
    selected: set[str] = set()

    def add(frame_id: str, role: str) -> None:
        checked = _require_selected_frame(
            frame_id,
            event=event,
            window=window,
            available_by_id=available_by_id,
            role=role,
        )
        if checked not in selected:
            selected.add(checked)
            priority.append(checked)

    add(_frame_id(event, event.trigger_frame), "trigger")

    transitions = sorted(set(state_transition_frame_ids), key=_frame_sort_key)
    for frame_id in transitions:
        add(frame_id, "state transition")

    add(_frame_id(event, event.start_frame), "event first")
    add(_frame_id(event, event.end_frame_exclusive - 1), "event last")

    recorded_recovery = event.confirmation.post_threshold_recovery_frame_id
    if (
        recovery_frame_id is not None
        and recorded_recovery is not None
        and recovery_frame_id != recorded_recovery
    ):
        raise ValueError("recovery frame conflicts with the CandidateEvent confirmation")
    recovery = recovery_frame_id if recovery_frame_id is not None else recorded_recovery
    if recovery is not None:
        _, _, recovery_index = parse_frame_id(recovery)
        if recovery_index < event.end_frame_exclusive:
            raise ValueError("recovery frame must follow the alleged event interval")
        add(recovery, "recovery")

    candidate_by_id: dict[str, ObservabilityCandidate] = {}
    for candidate in observability_candidates:
        if not isinstance(candidate, ObservabilityCandidate):
            raise TypeError("observability_candidates must contain ObservabilityCandidate values")
        camera_id, stream_id, frame_index = parse_frame_id(candidate.frame_id)
        if (camera_id, stream_id) != (event.camera_id, event.stream_id):
            raise ValueError("observability candidate belongs to another camera or stream")
        if not event.start_frame <= frame_index < event.end_frame_exclusive:
            raise ValueError("observability candidate lies outside the alleged event interval")
        _require_selected_frame(
            candidate.frame_id,
            event=event,
            window=window,
            available_by_id=available_by_id,
            role="observability candidate",
        )
        if candidate.frame_id in candidate_by_id:
            raise ValueError(f"duplicate observability candidate: {candidate.frame_id}")
        candidate_by_id[candidate.frame_id] = candidate

    temporal_top_m: tuple[str, ...] = ()
    if event.evidence_class == EvidenceClass.ABSENCE:
        ranked = sorted(
            candidate_by_id.values(),
            key=lambda candidate: (-candidate.score, *_frame_sort_key(candidate.frame_id)),
        )
        temporal_top_m = tuple(candidate.frame_id for candidate in ranked[:top_m])
        for frame_id in temporal_top_m:
            add(frame_id, "absence top-M")

    ordered = tuple(sorted(priority, key=_frame_sort_key))
    return KeyFrameSelection(
        selection_priority_frame_ids=tuple(priority),
        frame_ids=ordered,
        temporal_top_m_frame_ids=temporal_top_m,
    )


__all__ = [
    "EvidenceWindow",
    "KeyFrameSelection",
    "ObservabilityCandidate",
    "Seconds",
    "build_evidence_window",
    "select_key_frames",
]
