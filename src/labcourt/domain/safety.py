"""Fail-closed routing from certified safety signals to emergency incidents."""

from __future__ import annotations

from collections.abc import Collection

from labcourt.contracts.alerts import EmergencySafetyIncident
from labcourt.contracts.enums import (
    ArtifactKind,
    ConfirmationPolicy,
    DirectSafetySourceClass,
    EvidenceClass,
    ObjectiveFactKind,
    SafetySignalType,
    SafetySourceClass,
    ViolationType,
)
from labcourt.contracts.events import (
    CandidateEvent,
    ConfirmationRecord,
    ObjectiveFact,
    SafetySignal,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.canonical import sha256_hex

_VIDEO_CANDIDATE_VIOLATIONS = {
    SafetySignalType.OPEN_FLAME: ViolationType.OPEN_FLAME,
    SafetySignalType.SMOKE: ViolationType.SMOKE_ABNORMAL,
}


def _incident_id(signal: SafetySignal) -> str:
    return sha256_hex(
        [
            "emergency-safety-incident",
            1,
            {
                "signal_id": signal.signal_id,
                "signal_type": signal.signal_type,
                "zone_id": signal.zone_id,
                "start_frame": signal.start_frame,
                "end_frame_exclusive": signal.end_frame_exclusive,
                "value": signal.value,
                "unit": signal.unit,
                "source_class": signal.source_class,
                "certification_id": signal.certification_id,
                "quality": signal.quality,
            },
        ]
    )


def emergency_incident_from_signal(
    signal: SafetySignal,
    *,
    hard_alerts_enabled: bool,
    allowed_signal_types: Collection[SafetySignalType],
    certification_ids: Collection[str],
    allowed_direct_sources: Collection[DirectSafetySourceClass],
) -> EmergencySafetyIncident | None:
    """Route only a fully authorized direct signal; all other inputs fail closed."""

    if not isinstance(signal, SafetySignal):
        raise TypeError("signal must be a validated SafetySignal")
    if not isinstance(hard_alerts_enabled, bool):
        raise TypeError("hard_alerts_enabled must be a boolean")
    if not hard_alerts_enabled or signal.signal_type not in allowed_signal_types:
        return None
    if signal.certification_id is None or signal.certification_id not in certification_ids:
        return None

    try:
        direct_source = DirectSafetySourceClass(signal.source_class.value)
    except ValueError:
        return None
    if direct_source not in allowed_direct_sources:
        return None

    incident_id = _incident_id(signal)
    return EmergencySafetyIncident(
        incident_id=incident_id,
        signal_id=signal.signal_id,
        signal_type=signal.signal_type,
        zone_id=signal.zone_id,
        certification_id=signal.certification_id,
        delivery_idempotency_key=sha256_hex(["emergency-safety-delivery", 1, incident_id]),
    )


def candidate_event_from_video_signal(
    signal: SafetySignal,
    *,
    camera_id: str,
    stream_id: str,
    rule_version: str,
    manifest_id: str,
    source_manifest_id: str,
) -> CandidateEvent | None:
    """Downgrade an explicitly mapped video heuristic to a non-hard candidate.

    Compound signals such as heat plus occupancy need a separate deterministic rule
    and therefore fail closed here instead of being guessed from a single input.
    """

    if not isinstance(signal, SafetySignal):
        raise TypeError("signal must be a validated SafetySignal")
    if signal.source_class != SafetySourceClass.VIDEO_HEURISTIC:
        return None
    violation_type = _VIDEO_CANDIDATE_VIOLATIONS.get(signal.signal_type)
    if violation_type is None:
        return None
    return CandidateEvent(
        camera_id=camera_id,
        stream_id=stream_id,
        rule_version=rule_version,
        violation_type=violation_type,
        evidence_class=EvidenceClass.PRESENCE,
        zone_id=signal.zone_id,
        start_frame=signal.start_frame,
        end_frame_exclusive=signal.end_frame_exclusive,
        trigger_frame=signal.end_frame_exclusive - 1,
        primary_track_ref=None,
        hard_rule=False,
        l1_score=signal.quality,
        confirmation=ConfirmationRecord(policy=ConfirmationPolicy.NONE),
        objective_facts=(
            ObjectiveFact(
                fact_id=f"video-signal-{signal.signal_id}",
                kind=ObjectiveFactKind.DETECTION_SCORE,
                value=signal.quality,
                source_ref=ArtifactRef(
                    kind=ArtifactKind.SAFETY_SIGNAL,
                    artifact_id=signal.signal_id,
                ),
                source_manifest_id=source_manifest_id,
                unit=None,
            ),
        ),
        manifest_id=manifest_id,
    )


__all__ = ["candidate_event_from_video_signal", "emergency_incident_from_signal"]
