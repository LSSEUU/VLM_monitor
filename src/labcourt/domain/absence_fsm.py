"""Causal frame-time state machine for absence-type PPE violations."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from math import isfinite

from labcourt.contracts.config import AbsenceConfig
from labcourt.contracts.detections import AssociationResult
from labcourt.contracts.enums import (
    ArtifactKind,
    ConfirmationPolicy,
    EvidenceClass,
    ObjectiveFactKind,
    PpeType,
    RiskLevel,
    RunMode,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent, ConfirmationRecord, ObjectiveFact
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import (
    FrameId,
    TrackRef,
    parse_frame_id,
    require_reference_token,
    require_track_ref_camera,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.timebase import seconds_to_frames

_PPE_VIOLATION = {
    PpeType.GOGGLES: ViolationType.PPE_GOGGLES_MISSING,
    PpeType.GLOVES: ViolationType.PPE_GLOVES_MISSING,
    PpeType.LAB_COAT: ViolationType.PPE_LAB_COAT_MISSING,
}

_PPE_LABEL = {
    PpeType.GOGGLES: "goggles",
    PpeType.GLOVES: "gloves",
    PpeType.LAB_COAT: "lab_coat",
}


class AbsenceState(StrEnum):
    PRESENT = "PRESENT"
    ACCUMULATING = "ACCUMULATING"
    PENDING_CONFIRMATION = "PENDING_CONFIRMATION"
    COOLDOWN = "COOLDOWN"
    CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True)
class AbsenceObservation:
    track_ref: TrackRef
    ppe_type: PpeType
    zone_id: str
    risk_level: RiskLevel
    ppe_present: bool
    l1_score: float


@dataclass(frozen=True, slots=True)
class LatePositiveEvidence:
    """Typed evidence that one associated PPE detection belongs to an alleged frame."""

    detection_id: str
    evidence_ref: str
    frame_id: FrameId
    ppe_label: str
    score: float
    track_ref: TrackRef
    ppe_type: PpeType
    zone_id: str
    model_manifest_id: str
    association: AssociationResult


@dataclass(frozen=True, slots=True)
class AbsenceSuppression:
    camera_id: str
    stream_id: str
    track_ref: TrackRef
    ppe_type: PpeType
    zone_id: str
    start_frame: int
    end_frame_exclusive: int
    confirmation: ConfirmationRecord
    detection_ids: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AbsenceResult:
    state: AbsenceState
    emitted_event: CandidateEvent | None = None
    suppression: AbsenceSuppression | None = None


AbsenceKey = tuple[str, str, str, PpeType, str]
PendingKey = tuple[AbsenceKey, int]
StreamKey = tuple[str, str]
ResultSortKey = tuple[str, str, str, str, str, int, int]
ResultEntry = tuple[ResultSortKey, AbsenceResult]


@dataclass(slots=True)
class _AbsenceRecord:
    state: AbsenceState = AbsenceState.PRESENT
    start_frame: int | None = None
    last_seen_frame: int | None = None
    maximum_score: float = 0.0
    examined_frame_ids: list[str] = field(default_factory=list)
    cooldown_until: int | None = None


@dataclass(slots=True)
class _PendingAllegation:
    key: AbsenceKey
    start_frame: int
    threshold_frame_exclusive: int
    confirmation_deadline_exclusive: int
    maximum_score: float
    examined_frame_ids: tuple[str, ...]
    trigger_source_ref: str
    post_threshold_recovery_frame_id: str | None = None
    resolved_frame: int | None = None


@dataclass(slots=True)
class _StreamCursor:
    fps_num: int
    fps_den: int
    last_frame: int


def _key_sort(key: AbsenceKey) -> tuple[str, str, str, str, str]:
    camera_id, stream_id, track_ref, ppe_type, zone_id = key
    return camera_id, stream_id, track_ref, ppe_type.value, zone_id


def _pending_sort(pending: _PendingAllegation) -> tuple[str, str, str, str, str, int]:
    return (*_key_sort(pending.key), pending.start_frame)


class AbsenceFSM:
    """Track live absence state separately from immutable alleged intervals."""

    def __init__(
        self,
        *,
        config: AbsenceConfig,
        run_mode: RunMode,
        cooldown_seconds: float,
        rule_version: str,
        manifest_id: str,
        source_manifest_id: str,
    ) -> None:
        if not isinstance(run_mode, RunMode):
            raise TypeError("run_mode must be a RunMode")
        if config.confirmation_policy == ConfirmationPolicy.NONE:
            raise ValueError("absence state machine requires a confirmation policy")
        if (
            config.confirmation_policy == ConfirmationPolicy.SOURCE_COMPAT
            and run_mode != RunMode.OFFLINE_EXPERIMENT
        ):
            raise ValueError("SOURCE_COMPAT is limited to OFFLINE_EXPERIMENT")
        if (
            config.confirmation_policy == ConfirmationPolicy.SOURCE_COMPAT
            and not config.source_compat_enabled_for_offline_experiments
        ):
            raise ValueError("SOURCE_COMPAT requires the explicit experimental opt-in")
        if cooldown_seconds < 0:
            raise ValueError("absence cooldown must be non-negative")
        self.config = config
        self.run_mode = run_mode
        self.cooldown_seconds = Decimal(str(cooldown_seconds))
        self.rule_version = rule_version
        self.manifest_id = manifest_id
        self.source_manifest_id = source_manifest_id
        self._records: dict[AbsenceKey, _AbsenceRecord] = {}
        self._pending: dict[PendingKey, _PendingAllegation] = {}
        self._streams: dict[StreamKey, _StreamCursor] = {}

    def process_frame(
        self,
        frame: FrameRef,
        observations: tuple[AbsenceObservation, ...],
    ) -> tuple[AbsenceResult, ...]:
        """Process one strictly increasing stream frame and advance pending windows."""

        keyed_observations = [
            (
                (
                    frame.camera_id,
                    frame.stream_id,
                    item.track_ref,
                    item.ppe_type,
                    item.zone_id,
                ),
                item,
            )
            for item in observations
        ]
        keys = [key for key, _ in keyed_observations]
        if len(keys) != len(set(keys)):
            raise ValueError("absence observations must be unique per frame and key")

        ordered_observations = sorted(
            keyed_observations,
            key=lambda item: _key_sort(item[0]),
        )
        for _, observation in ordered_observations:
            self._validate_observation(frame, observation)

        stream_key = (frame.camera_id, frame.stream_id)
        self._advance_stream_cursor(frame)
        entries = self._finalize_due(stream_key, cutoff_exclusive=frame.frame_index)

        observed_keys = set(keys)
        for key, observation in ordered_observations:
            record = self._records.setdefault(key, _AbsenceRecord())
            entries.extend(self._observe_key(frame, observation, key, record))

        self._close_stale_records(frame, observed_keys)
        entries.extend(self._finalize_due(stream_key, cutoff_exclusive=frame.frame_index + 1))
        entries.sort(key=lambda item: item[0])
        return tuple(result for _, result in entries)

    def finalize(self) -> tuple[AbsenceResult, ...]:
        """Deterministically finalize every pending allegation at offline end-of-stream."""

        for record in self._records.values():
            self._close_record(record)
        entries: list[ResultEntry] = []
        for pending_id, pending in sorted(
            tuple(self._pending.items()),
            key=lambda item: _pending_sort(item[1]),
        ):
            event = self._build_event(pending)
            entries.append(
                self._pending_entry(
                    pending,
                    AbsenceResult(state=AbsenceState.CLOSED, emitted_event=event),
                    priority=0,
                )
            )
            del self._pending[pending_id]
        return tuple(result for _, result in entries)

    def register_late_positives(
        self,
        evidence: tuple[LatePositiveEvidence, ...],
        *,
        score_threshold: float,
    ) -> tuple[AbsenceSuppression, ...]:
        """Atomically validate and apply a stable batch of alleged-interval positives."""

        self._validate_unit_interval(score_threshold, "score_threshold")
        unique: dict[tuple[str, str, str, str, str, str, str], LatePositiveEvidence] = {}
        for item in evidence:
            self._validate_late_evidence_shape(item)
            identity = (
                item.frame_id,
                item.detection_id,
                item.evidence_ref,
                item.track_ref,
                item.ppe_type.value,
                item.zone_id,
                item.model_manifest_id,
            )
            previous = unique.get(identity)
            if previous is not None and previous != item:
                raise ValueError("conflicting duplicate late-positive evidence")
            unique[identity] = item

        grouped: dict[PendingKey, list[LatePositiveEvidence]] = {}
        ordered = sorted(unique.values(), key=self._late_evidence_sort_key)
        for item in ordered:
            pending_id = self._validate_late_positive(item, score_threshold)
            grouped.setdefault(pending_id, []).append(item)

        suppressions: list[AbsenceSuppression] = []
        for pending_id in sorted(grouped, key=lambda item: _pending_sort(self._pending[item])):
            pending = self._pending[pending_id]
            items = grouped[pending_id]
            counterevidence_frame_ids = tuple(
                sorted(
                    {item.frame_id for item in items},
                    key=lambda frame_id: parse_frame_id(frame_id)[2],
                )
            )
            confirmation = self._suppressed_confirmation(
                pending,
                counterevidence_frame_ids=counterevidence_frame_ids,
                reason="validated late PPE detections contradicted the alleged interval",
            )
            suppressions.append(
                self._suppression_from_pending(
                    pending,
                    confirmation,
                    detection_ids=tuple(sorted({item.detection_id for item in items})),
                    evidence_refs=tuple(sorted({item.evidence_ref for item in items})),
                )
            )
            del self._pending[pending_id]
        return tuple(suppressions)

    def state_for(
        self,
        *,
        camera_id: str,
        stream_id: str,
        track_ref: str,
        ppe_type: PpeType,
        zone_id: str,
    ) -> AbsenceState:
        record = self._records.get((camera_id, stream_id, track_ref, ppe_type, zone_id))
        return record.state if record is not None else AbsenceState.PRESENT

    def pending_count(self) -> int:
        """Return pending allegation count for diagnostics and deterministic tests."""

        return len(self._pending)

    def _advance_stream_cursor(self, frame: FrameRef) -> None:
        key = (frame.camera_id, frame.stream_id)
        cursor = self._streams.get(key)
        if cursor is None:
            self._streams[key] = _StreamCursor(
                fps_num=frame.fps_num,
                fps_den=frame.fps_den,
                last_frame=frame.frame_index,
            )
            return
        if cursor.fps_num * frame.fps_den != frame.fps_num * cursor.fps_den:
            raise ValueError("an absence stream cannot change timebase")
        if frame.frame_index <= cursor.last_frame:
            raise ValueError("absence stream frames must be strictly increasing")
        cursor.last_frame = frame.frame_index

    def _observe_key(
        self,
        frame: FrameRef,
        observation: AbsenceObservation,
        key: AbsenceKey,
        record: _AbsenceRecord,
    ) -> list[ResultEntry]:
        contiguous = (
            record.last_seen_frame is None or frame.frame_index == record.last_seen_frame + 1
        )
        record.last_seen_frame = frame.frame_index

        if observation.ppe_present:
            suppressions = self._record_recovery(frame, key)
            self._reset_to_present(record)
            record.last_seen_frame = frame.frame_index
            if suppressions:
                return [
                    self._pending_entry(
                        pending,
                        AbsenceResult(state=AbsenceState.PRESENT, suppression=suppression),
                        priority=1,
                    )
                    for pending, suppression in suppressions
                ]
            return [self._observation_entry(key, frame.frame_index, AbsenceState.PRESENT)]

        if record.state in {AbsenceState.COOLDOWN, AbsenceState.CLOSED}:
            if record.cooldown_until is not None and frame.frame_index < record.cooldown_until:
                record.state = AbsenceState.COOLDOWN
                return [self._observation_entry(key, frame.frame_index, AbsenceState.COOLDOWN)]
            self._begin_accumulation(record, frame, float(observation.l1_score))
        elif record.state == AbsenceState.PRESENT or not contiguous:
            self._begin_accumulation(record, frame, float(observation.l1_score))
        else:
            record.maximum_score = max(record.maximum_score, float(observation.l1_score))
            self._append_unique(record.examined_frame_ids, frame.frame_id)

        dwell_frames = max(
            1,
            seconds_to_frames(
                Decimal(str(self.config.dwell_seconds_by_risk[observation.risk_level])),
                frame.fps_num,
                frame.fps_den,
            ),
        )
        assert record.start_frame is not None
        if frame.frame_index - record.start_frame + 1 < dwell_frames:
            return [self._observation_entry(key, frame.frame_index, AbsenceState.ACCUMULATING)]

        pending = self._create_pending(frame, key, record)
        cooldown_frames = seconds_to_frames(
            self.cooldown_seconds,
            frame.fps_num,
            frame.fps_den,
        )
        record.state = AbsenceState.COOLDOWN
        record.start_frame = None
        record.maximum_score = 0.0
        record.examined_frame_ids = []
        record.cooldown_until = frame.frame_index + max(1, cooldown_frames)
        return [
            self._pending_entry(
                pending,
                AbsenceResult(state=AbsenceState.COOLDOWN),
                priority=2,
            )
        ]

    def _create_pending(
        self,
        frame: FrameRef,
        key: AbsenceKey,
        record: _AbsenceRecord,
    ) -> _PendingAllegation:
        assert record.start_frame is not None
        threshold_frame_exclusive = frame.frame_index + 1
        lookahead_frames = seconds_to_frames(
            Decimal(str(self.config.context_lookahead_seconds)),
            frame.fps_num,
            frame.fps_den,
        )
        pending = _PendingAllegation(
            key=key,
            start_frame=record.start_frame,
            threshold_frame_exclusive=threshold_frame_exclusive,
            confirmation_deadline_exclusive=threshold_frame_exclusive + lookahead_frames,
            maximum_score=record.maximum_score,
            examined_frame_ids=tuple(record.examined_frame_ids),
            trigger_source_ref=frame.frame_id,
        )
        pending_id = (key, pending.start_frame)
        if pending_id in self._pending:
            raise RuntimeError("duplicate pending allegation identity")
        self._pending[pending_id] = pending
        return pending

    def _record_recovery(
        self,
        frame: FrameRef,
        key: AbsenceKey,
    ) -> list[tuple[_PendingAllegation, AbsenceSuppression]]:
        suppressions: list[tuple[_PendingAllegation, AbsenceSuppression]] = []
        active = sorted(
            (
                pending
                for pending in self._pending.values()
                if pending.key == key
                and pending.threshold_frame_exclusive <= frame.frame_index
                and frame.frame_index < pending.confirmation_deadline_exclusive
            ),
            key=_pending_sort,
        )
        for pending in active:
            if pending.post_threshold_recovery_frame_id is None:
                pending.post_threshold_recovery_frame_id = frame.frame_id
                pending.resolved_frame = frame.frame_index
            if self.config.confirmation_policy == ConfirmationPolicy.SOURCE_COMPAT:
                confirmation = self._suppressed_confirmation(
                    pending,
                    counterevidence_frame_ids=(frame.frame_id,),
                    reason="SOURCE_COMPAT future recovery suppressed the candidate",
                    include_counterevidence_in_examined=True,
                )
                suppression = self._suppression_from_pending(pending, confirmation)
                suppressions.append((pending, suppression))
                del self._pending[(pending.key, pending.start_frame)]
        return suppressions

    def _finalize_due(
        self,
        stream_key: StreamKey,
        *,
        cutoff_exclusive: int,
    ) -> list[ResultEntry]:
        due = sorted(
            (
                (pending_id, pending)
                for pending_id, pending in self._pending.items()
                if pending.key[:2] == stream_key
                and pending.confirmation_deadline_exclusive <= cutoff_exclusive
            ),
            key=lambda item: _pending_sort(item[1]),
        )
        entries: list[ResultEntry] = []
        for pending_id, pending in due:
            event = self._build_event(pending)
            entries.append(
                self._pending_entry(
                    pending,
                    AbsenceResult(
                        state=self._state_for_key(pending.key),
                        emitted_event=event,
                    ),
                    priority=0,
                )
            )
            del self._pending[pending_id]
        return entries

    def _close_stale_records(
        self,
        frame: FrameRef,
        observed_keys: set[AbsenceKey],
    ) -> None:
        grace_frames = seconds_to_frames(
            Decimal(str(self.config.track_grace_seconds)),
            frame.fps_num,
            frame.fps_den,
        )
        for key, record in self._records.items():
            if key[:2] != (frame.camera_id, frame.stream_id) or key in observed_keys:
                continue
            if (
                record.last_seen_frame is not None
                and frame.frame_index - record.last_seen_frame > grace_frames
            ):
                self._close_record(record)

    @staticmethod
    def _close_record(record: _AbsenceRecord) -> None:
        record.state = AbsenceState.CLOSED
        record.start_frame = None
        record.maximum_score = 0.0
        record.examined_frame_ids = []

    def _build_event(self, pending: _PendingAllegation) -> CandidateEvent:
        confirmation = ConfirmationRecord(
            policy=self.config.confirmation_policy,
            examined_frame_ids=pending.examined_frame_ids,
            counterevidence_frame_ids=(),
            post_threshold_recovery_frame_id=pending.post_threshold_recovery_frame_id,
            resolved_frame=pending.resolved_frame,
            causal_risk=(self.config.confirmation_policy == ConfirmationPolicy.SOURCE_COMPAT),
        )
        camera_id, stream_id, track_ref, ppe_type, zone_id = pending.key
        violation_type = _PPE_VIOLATION[ppe_type]
        duration = pending.threshold_frame_exclusive - pending.start_frame
        return CandidateEvent(
            camera_id=camera_id,
            stream_id=stream_id,
            rule_version=self.rule_version,
            violation_type=violation_type,
            evidence_class=EvidenceClass.ABSENCE,
            zone_id=zone_id,
            start_frame=pending.start_frame,
            end_frame_exclusive=pending.threshold_frame_exclusive,
            trigger_frame=pending.threshold_frame_exclusive - 1,
            primary_track_ref=track_ref,
            hard_rule=False,
            l1_score=pending.maximum_score,
            confirmation=confirmation,
            objective_facts=(
                ObjectiveFact(
                    fact_id=f"duration-{violation_type.value.lower()}-{pending.start_frame}",
                    kind=ObjectiveFactKind.DURATION_FRAMES,
                    value=duration,
                    source_ref=ArtifactRef(
                        kind=ArtifactKind.FRAME,
                        artifact_id=pending.trigger_source_ref,
                    ),
                    source_manifest_id=self.source_manifest_id,
                    unit="frames",
                ),
            ),
            manifest_id=self.manifest_id,
        )

    def _suppressed_confirmation(
        self,
        pending: _PendingAllegation,
        *,
        counterevidence_frame_ids: tuple[str, ...],
        reason: str,
        include_counterevidence_in_examined: bool = False,
    ) -> ConfirmationRecord:
        examined = pending.examined_frame_ids
        if include_counterevidence_in_examined:
            examined = tuple(dict.fromkeys((*examined, *counterevidence_frame_ids)))
        return ConfirmationRecord(
            policy=self.config.confirmation_policy,
            examined_frame_ids=examined,
            counterevidence_frame_ids=counterevidence_frame_ids,
            post_threshold_recovery_frame_id=pending.post_threshold_recovery_frame_id,
            suppressed=True,
            suppression_reason=reason,
            resolved_frame=pending.resolved_frame,
            causal_risk=(self.config.confirmation_policy == ConfirmationPolicy.SOURCE_COMPAT),
        )

    @staticmethod
    def _suppression_from_pending(
        pending: _PendingAllegation,
        confirmation: ConfirmationRecord,
        *,
        detection_ids: tuple[str, ...] = (),
        evidence_refs: tuple[str, ...] = (),
    ) -> AbsenceSuppression:
        camera_id, stream_id, track_ref, ppe_type, zone_id = pending.key
        return AbsenceSuppression(
            camera_id=camera_id,
            stream_id=stream_id,
            track_ref=track_ref,
            ppe_type=ppe_type,
            zone_id=zone_id,
            start_frame=pending.start_frame,
            end_frame_exclusive=pending.threshold_frame_exclusive,
            confirmation=confirmation,
            detection_ids=detection_ids,
            evidence_refs=evidence_refs,
        )

    def _validate_late_positive(
        self,
        evidence: LatePositiveEvidence,
        score_threshold: float,
    ) -> PendingKey:
        if not evidence.detection_id.strip() or not evidence.evidence_ref.strip():
            raise ValueError("late-positive detection_id and evidence_ref must be non-empty")
        self._validate_unit_interval(evidence.score, "late-positive score")
        if evidence.score < score_threshold:
            raise ValueError("late-positive score is below the validated threshold")
        if evidence.ppe_label != _PPE_LABEL[evidence.ppe_type]:
            raise ValueError("late-positive label does not match ppe_type")
        if evidence.model_manifest_id != self.source_manifest_id:
            raise ValueError("late-positive evidence uses an unknown model manifest")
        if not evidence.association.present or (
            evidence.detection_id not in evidence.association.matched_detection_ids
        ):
            raise ValueError("late-positive detection is not present in its association result")

        camera_id, stream_id, frame_index = parse_frame_id(evidence.frame_id)
        require_track_ref_camera(evidence.track_ref, camera_id)
        key = (
            camera_id,
            stream_id,
            evidence.track_ref,
            evidence.ppe_type,
            evidence.zone_id,
        )
        matches = [
            pending_id
            for pending_id, pending in self._pending.items()
            if pending.key == key
            and pending.start_frame <= frame_index < pending.threshold_frame_exclusive
        ]
        if len(matches) != 1:
            raise ValueError("late-positive evidence must match exactly one pending allegation")
        pending = self._pending[matches[0]]
        if evidence.frame_id not in pending.examined_frame_ids:
            raise ValueError("late-positive frame was not examined in the alleged interval")
        return matches[0]

    @staticmethod
    def _validate_late_evidence_shape(evidence: LatePositiveEvidence) -> None:
        if not isinstance(evidence, LatePositiveEvidence):
            raise TypeError("late-positive evidence must use LatePositiveEvidence")
        if not isinstance(evidence.ppe_type, PpeType):
            raise TypeError("late-positive ppe_type must be a PpeType")
        if not isinstance(evidence.association, AssociationResult):
            raise TypeError("late-positive association must be an AssociationResult")
        if not isinstance(evidence.detection_id, str) or not evidence.detection_id.strip():
            raise ValueError("late-positive detection_id must be non-empty")
        if not isinstance(evidence.evidence_ref, str):
            raise TypeError("late-positive evidence_ref must be a string")
        require_safe_relative_posix_path(evidence.evidence_ref)
        if not isinstance(evidence.ppe_label, str):
            raise TypeError("late-positive ppe_label must be a string")
        if not isinstance(evidence.model_manifest_id, str):
            raise TypeError("late-positive model_manifest_id must be a string")
        require_reference_token(evidence.zone_id, "late-positive zone_id")

    @staticmethod
    def _late_evidence_sort_key(
        evidence: LatePositiveEvidence,
    ) -> tuple[str, str, str, str, str, int, str, str]:
        camera_id, stream_id, frame_index = parse_frame_id(evidence.frame_id)
        return (
            camera_id,
            stream_id,
            evidence.track_ref,
            evidence.ppe_type.value,
            evidence.zone_id,
            frame_index,
            evidence.detection_id,
            evidence.evidence_ref,
        )

    @staticmethod
    def _validate_observation(frame: FrameRef, observation: AbsenceObservation) -> None:
        require_track_ref_camera(observation.track_ref, frame.camera_id)
        if not isinstance(observation.ppe_present, bool):
            raise TypeError("ppe_present must be bool")
        AbsenceFSM._validate_unit_interval(observation.l1_score, "l1_score")

    @staticmethod
    def _validate_unit_interval(value: float, name: str) -> None:
        if (
            not isinstance(value, int | float)
            or isinstance(value, bool)
            or not isfinite(value)
            or not 0 <= value <= 1
        ):
            raise ValueError(f"{name} must be numeric in [0, 1]")

    @staticmethod
    def _append_unique(target: list[str], value: str) -> None:
        if value not in target:
            target.append(value)

    @staticmethod
    def _begin_accumulation(
        record: _AbsenceRecord,
        frame: FrameRef,
        score: float,
    ) -> None:
        record.state = AbsenceState.ACCUMULATING
        record.start_frame = frame.frame_index
        record.maximum_score = score
        record.examined_frame_ids = [frame.frame_id]
        record.cooldown_until = None

    @staticmethod
    def _reset_to_present(record: _AbsenceRecord) -> None:
        record.state = AbsenceState.PRESENT
        record.start_frame = None
        record.maximum_score = 0.0
        record.examined_frame_ids = []
        record.cooldown_until = None

    def _state_for_key(self, key: AbsenceKey) -> AbsenceState:
        record = self._records.get(key)
        return record.state if record is not None else AbsenceState.PRESENT

    @staticmethod
    def _observation_entry(
        key: AbsenceKey,
        frame_index: int,
        state: AbsenceState,
    ) -> ResultEntry:
        return (*_key_sort(key), frame_index, 2), AbsenceResult(state=state)

    @staticmethod
    def _pending_entry(
        pending: _PendingAllegation,
        result: AbsenceResult,
        *,
        priority: int,
    ) -> ResultEntry:
        return (*_key_sort(pending.key), pending.start_frame, priority), result
