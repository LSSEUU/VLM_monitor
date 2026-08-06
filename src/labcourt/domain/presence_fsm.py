"""Deterministic frame-time state machine for presence-type violations."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from labcourt.contracts.enums import (
    ArtifactKind,
    ConfirmationPolicy,
    EvidenceClass,
    ObjectiveFactKind,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent, ConfirmationRecord, ObjectiveFact
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.references import TrackRef, require_track_ref_camera
from labcourt.contracts.registry import VIOLATION_REGISTRY
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.timebase import seconds_to_frames


class PresenceState(StrEnum):
    IDLE = "IDLE"
    ACCUMULATING = "ACCUMULATING"
    COOLDOWN = "COOLDOWN"


@dataclass(frozen=True, slots=True)
class PresenceResult:
    state: PresenceState
    emitted_event: CandidateEvent | None = None
    updated_event: CandidateEvent | None = None


@dataclass(slots=True)
class _PresenceRecord:
    state: PresenceState = PresenceState.IDLE
    start_frame: int | None = None
    last_frame: int | None = None
    fps_num: int | None = None
    fps_den: int | None = None
    maximum_score: float = 0.0
    cooldown_until: int | None = None
    current_event: CandidateEvent | None = None


PresenceKey = tuple[str, str, str, str]


class PresenceFSM:
    """Maintain independent state per camera/stream/zone/anonymous object reference."""

    def __init__(
        self,
        *,
        violation_type: ViolationType,
        dwell_seconds: float,
        cooldown_seconds: float,
        rule_version: str,
        manifest_id: str,
        source_manifest_id: str,
    ) -> None:
        definition = VIOLATION_REGISTRY[violation_type]
        if definition.evidence_class != EvidenceClass.PRESENCE:
            raise ValueError("PresenceFSM requires a presence-type violation")
        if dwell_seconds < 0 or cooldown_seconds < 0:
            raise ValueError("presence dwell and cooldown must be non-negative")
        self.violation_type = violation_type
        self.dwell_seconds = Decimal(str(dwell_seconds))
        self.cooldown_seconds = Decimal(str(cooldown_seconds))
        self.rule_version = rule_version
        self.manifest_id = manifest_id
        self.source_manifest_id = source_manifest_id
        self._records: dict[PresenceKey, _PresenceRecord] = {}

    def observe(
        self,
        *,
        frame: FrameRef,
        zone_id: str,
        primary_track_ref: TrackRef,
        condition_met: bool,
        l1_score: float,
        related_track_refs: tuple[TrackRef, ...] = (),
    ) -> PresenceResult:
        require_track_ref_camera(primary_track_ref, frame.camera_id)
        if not isinstance(condition_met, bool):
            raise TypeError("condition_met must be bool")
        if (
            not isinstance(l1_score, int | float)
            or isinstance(l1_score, bool)
            or not 0 <= l1_score <= 1
        ):
            raise ValueError("l1_score must be numeric in [0, 1]")

        key = (
            frame.camera_id,
            frame.stream_id,
            zone_id,
            primary_track_ref,
        )
        record = self._records.setdefault(key, _PresenceRecord())
        self._validate_timebase(record, frame)
        contiguous = record.last_frame is None or frame.frame_index == record.last_frame + 1
        if record.last_frame is not None and frame.frame_index <= record.last_frame:
            raise ValueError("presence observations must be strictly increasing per key")
        record.last_frame = frame.frame_index

        if not condition_met:
            if record.state == PresenceState.COOLDOWN:
                # A known negative closes the continuous event interval. The cooldown
                # remains as a tombstone, but a later positive may not stretch the old
                # event across this negative frame.
                record.current_event = None
            if record.state == PresenceState.ACCUMULATING or (
                record.state == PresenceState.COOLDOWN
                and record.cooldown_until is not None
                and frame.frame_index >= record.cooldown_until
            ):
                self._reset_to_idle(record)
            return PresenceResult(state=record.state)

        if record.state == PresenceState.COOLDOWN:
            if record.cooldown_until is not None and frame.frame_index < record.cooldown_until:
                if not contiguous or record.current_event is None:
                    record.current_event = None
                    return PresenceResult(state=PresenceState.COOLDOWN)
                record.maximum_score = max(record.maximum_score, float(l1_score))
                updated = self._extend_event(record, frame)
                cooldown_frames = seconds_to_frames(
                    self.cooldown_seconds,
                    frame.fps_num,
                    frame.fps_den,
                )
                record.cooldown_until = frame.frame_index + max(1, cooldown_frames)
                return PresenceResult(
                    state=PresenceState.COOLDOWN,
                    updated_event=updated,
                )
            self._begin_accumulation(record, frame, float(l1_score))
        elif record.state == PresenceState.IDLE or not contiguous:
            self._begin_accumulation(record, frame, float(l1_score))
        else:
            record.maximum_score = max(record.maximum_score, float(l1_score))

        dwell_frames = max(
            1,
            seconds_to_frames(
                self.dwell_seconds,
                frame.fps_num,
                frame.fps_den,
            ),
        )
        assert record.start_frame is not None
        observed_frames = frame.frame_index - record.start_frame + 1
        if observed_frames < dwell_frames:
            return PresenceResult(state=PresenceState.ACCUMULATING)

        event = self._build_event(
            record=record,
            frame=frame,
            zone_id=zone_id,
            primary_track_ref=primary_track_ref,
            related_track_refs=related_track_refs,
        )
        cooldown_frames = seconds_to_frames(
            self.cooldown_seconds,
            frame.fps_num,
            frame.fps_den,
        )
        record.state = PresenceState.COOLDOWN
        record.cooldown_until = frame.frame_index + max(1, cooldown_frames)
        record.current_event = event
        return PresenceResult(state=record.state, emitted_event=event)

    def state_for(
        self,
        *,
        camera_id: str,
        stream_id: str,
        zone_id: str,
        primary_track_ref: str,
    ) -> PresenceState:
        record = self._records.get((camera_id, stream_id, zone_id, primary_track_ref))
        return record.state if record is not None else PresenceState.IDLE

    def prune_stale(
        self,
        *,
        camera_id: str,
        stream_id: str,
        current_frame: int,
        grace_frames: int,
    ) -> int:
        if current_frame < 0 or grace_frames < 0:
            raise ValueError("frame and grace values must be non-negative")
        stale = [
            key
            for key, record in self._records.items()
            if key[:2] == (camera_id, stream_id)
            and record.last_frame is not None
            and current_frame - record.last_frame > grace_frames
            and not (
                record.state == PresenceState.COOLDOWN
                and record.cooldown_until is not None
                and current_frame < record.cooldown_until
            )
        ]
        for key in stale:
            del self._records[key]
        return len(stale)

    @staticmethod
    def _validate_timebase(record: _PresenceRecord, frame: FrameRef) -> None:
        if record.fps_num is None:
            record.fps_num = frame.fps_num
            record.fps_den = frame.fps_den
        else:
            assert record.fps_den is not None
            if record.fps_num * frame.fps_den != frame.fps_num * record.fps_den:
                raise ValueError("a presence state key cannot change timebase")

    @staticmethod
    def _reset_to_idle(record: _PresenceRecord) -> None:
        record.state = PresenceState.IDLE
        record.start_frame = None
        record.maximum_score = 0.0
        record.cooldown_until = None
        record.current_event = None

    @staticmethod
    def _begin_accumulation(
        record: _PresenceRecord,
        frame: FrameRef,
        score: float,
    ) -> None:
        record.state = PresenceState.ACCUMULATING
        record.start_frame = frame.frame_index
        record.maximum_score = score
        record.cooldown_until = None
        record.current_event = None

    def _duration_fact(
        self,
        *,
        start_frame: int,
        end_frame_exclusive: int,
        source_ref: str,
    ) -> ObjectiveFact:
        return ObjectiveFact(
            fact_id=(f"duration-{self.violation_type.value.lower()}-{start_frame}"),
            kind=ObjectiveFactKind.DURATION_FRAMES,
            value=end_frame_exclusive - start_frame,
            source_ref=ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=source_ref),
            source_manifest_id=self.source_manifest_id,
            unit="frames",
        )

    def _build_event(
        self,
        *,
        record: _PresenceRecord,
        frame: FrameRef,
        zone_id: str,
        primary_track_ref: TrackRef,
        related_track_refs: tuple[TrackRef, ...],
    ) -> CandidateEvent:
        assert record.start_frame is not None
        end_frame_exclusive = frame.frame_index + 1
        return CandidateEvent(
            camera_id=frame.camera_id,
            stream_id=frame.stream_id,
            rule_version=self.rule_version,
            violation_type=self.violation_type,
            evidence_class=EvidenceClass.PRESENCE,
            zone_id=zone_id,
            start_frame=record.start_frame,
            end_frame_exclusive=end_frame_exclusive,
            trigger_frame=frame.frame_index,
            primary_track_ref=primary_track_ref,
            related_track_refs=tuple(sorted(related_track_refs)),
            hard_rule=False,
            l1_score=record.maximum_score,
            confirmation=ConfirmationRecord(policy=ConfirmationPolicy.NONE),
            objective_facts=(
                self._duration_fact(
                    start_frame=record.start_frame,
                    end_frame_exclusive=end_frame_exclusive,
                    source_ref=frame.frame_id,
                ),
            ),
            manifest_id=self.manifest_id,
        )

    def _extend_event(
        self,
        record: _PresenceRecord,
        frame: FrameRef,
    ) -> CandidateEvent:
        assert record.current_event is not None
        end_frame_exclusive = frame.frame_index + 1
        event = record.current_event
        updated = event.model_copy(
            update={
                "end_frame_exclusive": end_frame_exclusive,
                "l1_score": record.maximum_score,
                "objective_facts": (
                    self._duration_fact(
                        start_frame=event.start_frame,
                        end_frame_exclusive=end_frame_exclusive,
                        source_ref=frame.frame_id,
                    ),
                ),
            }
        )
        record.current_event = updated
        return updated
