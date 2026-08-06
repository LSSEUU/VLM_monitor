from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

import pytest
from pydantic import ValidationError

from labcourt.contracts.config import AbsenceConfig
from labcourt.contracts.detections import AssociationResult
from labcourt.contracts.enums import (
    AssociationMethod,
    ConfirmationPolicy,
    PpeType,
    RiskLevel,
    RunMode,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.domain.absence_fsm import (
    AbsenceFSM,
    AbsenceObservation,
    AbsenceResult,
    AbsenceState,
    AbsenceSuppression,
    LatePositiveEvidence,
)
from labcourt.domain.canonical import canonical_json
from labcourt.domain.presence_fsm import PresenceFSM, PresenceResult, PresenceState
from labcourt.domain.timebase import duration_ms

MANIFEST_ID = "a" * 64
MODEL_MANIFEST_ID = "b" * 64
TRACK_1 = "cam-01:epoch-01:person-01"
TRACK_2 = "cam-01:epoch-01:person-02"


def _frame(
    index: int,
    *,
    stream_id: str = "stream-01",
    fps_num: int = 1,
    fps_den: int = 1,
) -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id=stream_id,
        frame_index=index,
        fps_num=fps_num,
        fps_den=fps_den,
        width=640,
        height=480,
    )


def _presence(
    *,
    dwell_seconds: float = 2.0,
    cooldown_seconds: float = 2.0,
) -> PresenceFSM:
    return PresenceFSM(
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        dwell_seconds=dwell_seconds,
        cooldown_seconds=cooldown_seconds,
        rule_version="laboratory-v1",
        manifest_id=MANIFEST_ID,
        source_manifest_id=MODEL_MANIFEST_ID,
    )


def _absence_config(
    *,
    dwell_seconds: float = 2.0,
    lookahead_seconds: float = 2.0,
    grace_seconds: float = 1.0,
    policy: ConfirmationPolicy = ConfirmationPolicy.STRICT_CAUSAL,
) -> AbsenceConfig:
    return AbsenceConfig(
        dwell_seconds_by_risk={
            RiskLevel.LOW: dwell_seconds,
            RiskLevel.MEDIUM: dwell_seconds,
            RiskLevel.HIGH: dwell_seconds,
        },
        confirmation_policy=policy,
        context_lookahead_seconds=lookahead_seconds,
        track_grace_seconds=grace_seconds,
        temporal_crop_count=3,
        minimum_consistent_clear_frames=2,
        source_compat_enabled_for_offline_experiments=(policy == ConfirmationPolicy.SOURCE_COMPAT),
    )


def _absence(
    *,
    config: AbsenceConfig | None = None,
    run_mode: RunMode = RunMode.STANDARD,
    cooldown_seconds: float = 2.0,
) -> AbsenceFSM:
    return AbsenceFSM(
        config=config or _absence_config(),
        run_mode=run_mode,
        cooldown_seconds=cooldown_seconds,
        rule_version="laboratory-v1",
        manifest_id=MANIFEST_ID,
        source_manifest_id=MODEL_MANIFEST_ID,
    )


def _observation(
    *,
    track_ref: str = TRACK_1,
    present: bool,
    score: float = 0.8,
) -> AbsenceObservation:
    return AbsenceObservation(
        track_ref=track_ref,
        ppe_type=PpeType.GOGGLES,
        zone_id="zone-01",
        risk_level=RiskLevel.HIGH,
        ppe_present=present,
        l1_score=score,
    )


def _events(results: Iterable[AbsenceResult | PresenceResult]) -> tuple[CandidateEvent, ...]:
    return tuple(result.emitted_event for result in results if result.emitted_event is not None)


def _suppressions(results: Iterable[AbsenceResult]) -> tuple[AbsenceSuppression, ...]:
    return tuple(result.suppression for result in results if result.suppression is not None)


def _late_positive(
    *,
    frame_index: int,
    detection_id: str,
    evidence_ref: str,
    score: float = 0.9,
    track_ref: str = TRACK_1,
    model_manifest_id: str = MODEL_MANIFEST_ID,
    ppe_label: str = "goggles",
    matched: bool = True,
) -> LatePositiveEvidence:
    matched_ids = (detection_id,) if matched else ("different-detection",)
    return LatePositiveEvidence(
        detection_id=detection_id,
        evidence_ref=evidence_ref,
        frame_id=f"cam-01:stream-01:{frame_index}",
        ppe_label=ppe_label,
        score=score,
        track_ref=track_ref,
        ppe_type=PpeType.GOGGLES,
        zone_id="zone-01",
        model_manifest_id=model_manifest_id,
        association=AssociationResult(
            present=True,
            anchor_bbox=BBoxXYXY(x1=10, y1=10, x2=30, y2=30),
            matched_detection_ids=matched_ids,
            method=AssociationMethod.KEYPOINT,
        ),
    )


def test_presence_requires_continuity_then_extends_one_deterministic_event() -> None:
    engine = _presence(dwell_seconds=1.0, cooldown_seconds=1.0)
    engine.observe(
        frame=_frame(0, fps_num=2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.7,
    )
    engine.observe(
        frame=_frame(1, fps_num=2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=False,
        l1_score=0.0,
    )
    engine.observe(
        frame=_frame(2, fps_num=2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.8,
    )
    triggered = engine.observe(
        frame=_frame(3, fps_num=2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.9,
        related_track_refs=(TRACK_2,),
    )
    event = triggered.emitted_event
    assert event is not None
    assert (event.start_frame, event.end_frame_exclusive, event.trigger_frame) == (2, 4, 3)
    assert event.objective_facts[0].value == 2

    extended = engine.observe(
        frame=_frame(4, fps_num=2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.95,
    ).updated_event
    assert extended is not None
    assert extended.event_id == event.event_id
    assert extended.end_frame_exclusive == 5
    assert extended.objective_facts[0].value == 3


def test_presence_negative_or_noncontiguous_gap_never_extends_old_event() -> None:
    negative = _presence(dwell_seconds=1.0, cooldown_seconds=10.0)
    original = negative.observe(
        frame=_frame(0),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.8,
    ).emitted_event
    assert original is not None
    negative.observe(
        frame=_frame(1),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=False,
        l1_score=0.0,
    )
    after_negative = negative.observe(
        frame=_frame(2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.9,
    )
    assert after_negative.state == PresenceState.COOLDOWN
    assert after_negative.updated_event is None
    assert original.end_frame_exclusive == 1
    assert original.objective_facts[0].value == 1

    gap = _presence(dwell_seconds=1.0, cooldown_seconds=10.0)
    assert (
        gap.observe(
            frame=_frame(0),
            zone_id="zone-01",
            primary_track_ref=TRACK_1,
            condition_met=True,
            l1_score=0.8,
        ).emitted_event
        is not None
    )
    after_gap = gap.observe(
        frame=_frame(2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.9,
    )
    assert after_gap.state == PresenceState.COOLDOWN
    assert after_gap.updated_event is None


def test_presence_prune_preserves_unexpired_cooldown_tombstone() -> None:
    engine = _presence(dwell_seconds=1.0, cooldown_seconds=10.0)
    first = engine.observe(
        frame=_frame(0),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.8,
    )
    assert first.emitted_event is not None

    assert (
        engine.prune_stale(
            camera_id="cam-01",
            stream_id="stream-01",
            current_frame=2,
            grace_frames=1,
        )
        == 0
    )
    premature = engine.observe(
        frame=_frame(2),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.8,
    )
    assert premature.state == PresenceState.COOLDOWN
    assert premature.emitted_event is None
    assert premature.updated_event is None

    assert (
        engine.prune_stale(
            camera_id="cam-01",
            stream_id="stream-01",
            current_frame=10,
            grace_frames=1,
        )
        == 1
    )
    restarted = engine.observe(
        frame=_frame(10),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.8,
    )
    assert restarted.emitted_event is not None
    assert restarted.emitted_event.event_id != first.emitted_event.event_id


def test_presence_uses_exact_fractional_fps_and_never_joins_track_switches() -> None:
    ntsc = _presence(dwell_seconds=0.1)
    event = None
    for index in range(3):
        event = ntsc.observe(
            frame=_frame(index, fps_num=30_000, fps_den=1_001),
            zone_id="zone-01",
            primary_track_ref=TRACK_1,
            condition_met=True,
            l1_score=0.8,
        ).emitted_event
    assert event is not None
    assert duration_ms(event.start_frame, event.end_frame_exclusive, 30_000, 1_001) == 100

    switched = _presence(dwell_seconds=2.0)
    switched.observe(
        frame=_frame(0),
        zone_id="zone-01",
        primary_track_ref=TRACK_1,
        condition_met=True,
        l1_score=0.8,
    )
    switched.observe(
        frame=_frame(1),
        zone_id="zone-01",
        primary_track_ref=TRACK_2,
        condition_met=True,
        l1_score=0.8,
    )
    second = switched.observe(
        frame=_frame(2),
        zone_id="zone-01",
        primary_track_ref=TRACK_2,
        condition_met=True,
        l1_score=0.8,
    ).emitted_event
    assert second is not None
    assert second.start_frame == 1
    assert (
        switched.state_for(
            camera_id="cam-01",
            stream_id="stream-01",
            zone_id="zone-01",
            primary_track_ref=TRACK_1,
        )
        == PresenceState.ACCUMULATING
    )


def test_strict_recovery_and_track_loss_cannot_erase_pending_history() -> None:
    engine = _absence(config=_absence_config(lookahead_seconds=4.0, grace_seconds=1.0))
    engine.process_frame(_frame(0), (_observation(present=False),))
    threshold = engine.process_frame(_frame(1), (_observation(present=False),))
    assert threshold[0].state == AbsenceState.COOLDOWN
    assert engine.pending_count() == 1

    recovered = engine.process_frame(_frame(2), (_observation(present=True),))
    assert recovered[0].state == AbsenceState.PRESENT
    engine.process_frame(_frame(3), ())
    engine.process_frame(_frame(4), ())
    assert (
        engine.state_for(
            camera_id="cam-01",
            stream_id="stream-01",
            track_ref=TRACK_1,
            ppe_type=PpeType.GOGGLES,
            zone_id="zone-01",
        )
        == AbsenceState.CLOSED
    )

    due_on_empty_frame = engine.process_frame(_frame(5), ())
    event = _events(due_on_empty_frame)[0]
    assert (event.start_frame, event.end_frame_exclusive) == (0, 2)
    assert event.confirmation.post_threshold_recovery_frame_id == "cam-01:stream-01:2"
    assert event.confirmation.resolved_frame == 2
    assert not event.confirmation.suppressed
    assert engine.pending_count() == 0


def test_recovery_resets_live_state_and_reabsence_has_a_new_pending_identity() -> None:
    engine = _absence(config=_absence_config(lookahead_seconds=10.0))
    engine.process_frame(_frame(0), (_observation(present=False),))
    engine.process_frame(_frame(1), (_observation(present=False),))
    engine.process_frame(_frame(2), (_observation(present=True),))
    assert (
        engine.state_for(
            camera_id="cam-01",
            stream_id="stream-01",
            track_ref=TRACK_1,
            ppe_type=PpeType.GOGGLES,
            zone_id="zone-01",
        )
        == AbsenceState.PRESENT
    )

    engine.process_frame(_frame(3), (_observation(present=False),))
    engine.process_frame(_frame(4), (_observation(present=False),))
    assert engine.pending_count() == 2

    finalized = _events(engine.finalize())
    assert [(event.start_frame, event.end_frame_exclusive) for event in finalized] == [
        (0, 2),
        (3, 5),
    ]
    assert finalized[0].confirmation.resolved_frame == 2
    assert finalized[1].confirmation.resolved_frame is None
    assert engine.finalize() == ()


def test_continuous_missing_obeys_cooldown_and_pending_output_is_stable() -> None:
    engine = _absence(
        config=_absence_config(dwell_seconds=1.0, lookahead_seconds=10.0),
        cooldown_seconds=3.0,
    )
    engine.process_frame(_frame(0), (_observation(present=False),))
    assert engine.pending_count() == 1
    assert engine.process_frame(_frame(1), (_observation(present=False),))[0].state == (
        AbsenceState.COOLDOWN
    )
    assert engine.process_frame(_frame(2), (_observation(present=False),))[0].state == (
        AbsenceState.COOLDOWN
    )
    engine.process_frame(_frame(3), (_observation(present=False),))
    assert engine.pending_count() == 2

    events = _events(engine.finalize())
    assert [event.start_frame for event in events] == [0, 3]


def test_lost_track_keeps_absence_cooldown_tombstone() -> None:
    engine = _absence(
        config=_absence_config(
            dwell_seconds=1.0,
            lookahead_seconds=0.0,
            grace_seconds=1.0,
        ),
        cooldown_seconds=10.0,
    )
    first = _events(engine.process_frame(_frame(0), (_observation(present=False),)))[0]
    engine.process_frame(_frame(1), ())
    engine.process_frame(_frame(2), ())
    assert (
        engine.state_for(
            camera_id="cam-01",
            stream_id="stream-01",
            track_ref=TRACK_1,
            ppe_type=PpeType.GOGGLES,
            zone_id="zone-01",
        )
        == AbsenceState.CLOSED
    )

    premature = engine.process_frame(_frame(3), (_observation(present=False),))
    assert _events(premature) == ()
    assert premature[0].state == AbsenceState.COOLDOWN
    for index in range(4, 10):
        engine.process_frame(_frame(index), ())
    restarted = engine.process_frame(_frame(10), (_observation(present=False),))
    second = _events(restarted)[0]
    assert second.event_id != first.event_id
    assert second.start_frame == 10


def test_late_positive_batch_is_typed_atomic_stable_and_auditable() -> None:
    def pending_engine() -> AbsenceFSM:
        engine = _absence(config=_absence_config(lookahead_seconds=10.0))
        engine.process_frame(_frame(0), (_observation(present=False),))
        engine.process_frame(_frame(1), (_observation(present=False),))
        return engine

    frame_zero = _late_positive(
        frame_index=0,
        detection_id="det-a",
        evidence_ref="evidence/a",
    )
    frame_one = _late_positive(
        frame_index=1,
        detection_id="det-z",
        evidence_ref="evidence/z",
    )

    first_engine = pending_engine()
    first = first_engine.register_late_positives(
        (frame_one, frame_zero, frame_one),
        score_threshold=0.35,
    )
    second = pending_engine().register_late_positives(
        (frame_zero, frame_one),
        score_threshold=0.35,
    )
    assert first == second
    assert len(first) == 1
    suppression = first[0]
    assert suppression.confirmation.counterevidence_frame_ids == (
        "cam-01:stream-01:0",
        "cam-01:stream-01:1",
    )
    assert suppression.detection_ids == ("det-a", "det-z")
    assert suppression.evidence_refs == ("evidence/a", "evidence/z")
    assert first_engine.pending_count() == 0
    assert not hasattr(first_engine, "register_late_positive")

    atomic = pending_engine()
    invalid = replace(frame_one, score=0.1)
    with pytest.raises(ValueError, match="below the validated threshold"):
        atomic.register_late_positives((frame_zero, invalid), score_threshold=0.35)
    assert atomic.pending_count() == 1

    unsafe_ref = replace(frame_zero, evidence_ref="../outside")
    with pytest.raises(ValueError, match="workspace-relative POSIX path"):
        atomic.register_late_positives((unsafe_ref,), score_threshold=0.35)
    assert atomic.pending_count() == 1


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"ppe_label": "gloves"}, "label"),
        ({"model_manifest_id": "c" * 64}, "manifest"),
        ({"matched": False}, "association"),
        ({"frame_index": 2}, "exactly one pending"),
    ],
)
def test_late_positive_rejects_unbound_or_out_of_interval_evidence(
    change: dict[str, object],
    message: str,
) -> None:
    engine = _absence(config=_absence_config(lookahead_seconds=10.0))
    engine.process_frame(_frame(0), (_observation(present=False),))
    engine.process_frame(_frame(1), (_observation(present=False),))
    arguments: dict[str, object] = {
        "frame_index": 0,
        "detection_id": "det-01",
        "evidence_ref": "evidence/01",
    }
    arguments.update(change)
    evidence = _late_positive(**arguments)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=message):
        engine.register_late_positives((evidence,), score_threshold=0.35)
    assert engine.pending_count() == 1


def test_source_compat_is_opted_in_offline_and_future_recovery_is_risky() -> None:
    config = _absence_config(policy=ConfirmationPolicy.SOURCE_COMPAT)
    with pytest.raises(ValueError, match="OFFLINE_EXPERIMENT"):
        _absence(config=config)

    disabled = config.model_copy(update={"source_compat_enabled_for_offline_experiments": False})
    with pytest.raises(ValueError, match="explicit experimental opt-in"):
        _absence(config=disabled, run_mode=RunMode.OFFLINE_EXPERIMENT)

    engine = _absence(config=config, run_mode=RunMode.OFFLINE_EXPERIMENT)
    engine.process_frame(_frame(0), (_observation(present=False),))
    engine.process_frame(_frame(1), (_observation(present=False),))
    result = engine.process_frame(_frame(2), (_observation(present=True),))
    suppression = _suppressions(result)[0]
    assert suppression.confirmation.causal_risk
    assert suppression.confirmation.suppressed
    assert engine.pending_count() == 0
    assert engine.finalize() == ()


def test_absence_ntsc_dwell_and_lookahead_use_exact_ceil_frame_counts() -> None:
    engine = _absence(
        config=_absence_config(
            dwell_seconds=0.1,
            lookahead_seconds=0.1,
            grace_seconds=1.0,
        )
    )
    results: list[AbsenceResult] = []
    for index in range(3):
        results.extend(
            engine.process_frame(
                _frame(index, fps_num=30_000, fps_den=1_001),
                (_observation(present=False),),
            )
        )
    assert _events(results) == ()
    for index in range(3, 5):
        assert (
            _events(
                engine.process_frame(
                    _frame(index, fps_num=30_000, fps_den=1_001),
                    (),
                )
            )
            == ()
        )
    event = _events(
        engine.process_frame(
            _frame(5, fps_num=30_000, fps_den=1_001),
            (),
        )
    )[0]
    assert (event.start_frame, event.end_frame_exclusive) == (0, 3)
    assert duration_ms(event.start_frame, event.end_frame_exclusive, 30_000, 1_001) == 100


def test_absence_stream_cursor_validates_empty_frames_and_timebase() -> None:
    duplicate = _absence()
    duplicate.process_frame(_frame(0), ())
    with pytest.raises(ValueError, match="strictly increasing"):
        duplicate.process_frame(_frame(0), ())

    changed_timebase = _absence()
    changed_timebase.process_frame(_frame(0), ())
    with pytest.raises(ValueError, match="cannot change timebase"):
        changed_timebase.process_frame(_frame(1, fps_num=2), ())

    # Stream cursors are independent.
    changed_timebase.process_frame(_frame(0, stream_id="stream-02", fps_num=2), ())

    equivalent = _absence()
    equivalent.process_frame(_frame(0, fps_num=30, fps_den=1), ())
    equivalent.process_frame(_frame(1, fps_num=60, fps_den=2), ())


def test_invalid_absence_observation_does_not_consume_stream_frame() -> None:
    engine = _absence()
    engine.process_frame(_frame(0), ())

    invalid = replace(_observation(present=False), l1_score=float("nan"))
    with pytest.raises(ValueError, match=r"l1_score must be numeric in \[0, 1\]"):
        engine.process_frame(_frame(1), (invalid,))

    # Validation is atomic: corrected data for the same frame remains retryable.
    result = engine.process_frame(_frame(1), (_observation(present=False),))
    assert len(result) == 1
    assert result[0].state == AbsenceState.ACCUMULATING
    assert result[0].emitted_event is None


def test_full_candidate_replay_is_canonical_and_observation_order_independent() -> None:
    def replay(reverse: bool) -> str:
        engine = _absence(config=_absence_config(lookahead_seconds=1.0))
        output: list[AbsenceResult] = []
        for index in range(3):
            observations = (
                _observation(track_ref=TRACK_1, present=False, score=0.7),
                _observation(track_ref=TRACK_2, present=False, score=0.9),
            )
            if reverse:
                observations = tuple(reversed(observations))
            output.extend(engine.process_frame(_frame(index), observations))
        output.extend(engine.finalize())
        payload = [event.model_dump(mode="json") for event in _events(output)]
        return canonical_json(payload)

    assert replay(False) == replay(True)


def test_confirmation_contract_rejects_cross_stream_and_false_recovery_index() -> None:
    engine = _absence()
    emitted: list[AbsenceResult] = []
    for index in range(4):
        emitted.extend(engine.process_frame(_frame(index), (_observation(present=False),)))
    event = _events(emitted)[0]
    payload = event.model_dump(mode="json")
    payload["confirmation"]["examined_frame_ids"][0] = "cam-02:stream-01:0"
    with pytest.raises(ValidationError, match="another stream"):
        CandidateEvent.model_validate(payload)

    payload = event.model_dump(mode="json")
    payload["confirmation"]["post_threshold_recovery_frame_id"] = "cam-01:stream-01:4"
    payload["confirmation"]["resolved_frame"] = 99
    with pytest.raises(ValidationError, match="resolved_frame"):
        CandidateEvent.model_validate(payload)
