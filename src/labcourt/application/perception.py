"""Read-only M1 orchestration over the ``FrameSource`` contract.

The pipeline deliberately owns no repository, frame store, or audit-log port. Every
runtime object it creates is scoped to one ``run`` call and is discarded afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction

from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import AssociationResult, Detection, FrameBundle
from labcourt.contracts.enums import EvidenceClass, PpeType, ViolationType
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import FrameId, TrackRef, parse_frame_id
from labcourt.contracts.registry import VIOLATION_REGISTRY
from labcourt.contracts.reminders import SoftReminder
from labcourt.domain.absence_fsm import (
    AbsenceFSM,
    AbsenceObservation,
    AbsenceSuppression,
)
from labcourt.domain.association import associate_ppe
from labcourt.domain.reminders import InMemorySoftReminderService
from labcourt.domain.timebase import seconds_to_frames
from labcourt.domain.zones import locate_person_zone
from labcourt.exceptions import ContractViolation, ManifestMismatch
from labcourt.ports.frame_source import FrameSource

_PPE_VIOLATIONS = {
    PpeType.GOGGLES: ViolationType.PPE_GOGGLES_MISSING,
    PpeType.GLOVES: ViolationType.PPE_GLOVES_MISSING,
    PpeType.LAB_COAT: ViolationType.PPE_LAB_COAT_MISSING,
}
_StreamKey = tuple[str, str]


@dataclass(frozen=True, slots=True)
class AssociationRecord:
    """One deterministic person/PPE association decision."""

    frame_id: FrameId
    track_ref: TrackRef
    zone_id: str
    ppe_type: PpeType
    result: AssociationResult


@dataclass(frozen=True, slots=True)
class PerceptionRunResult:
    """Immutable in-memory output of one complete source replay."""

    frames_processed: int
    associations: tuple[AssociationRecord, ...]
    reminders: tuple[SoftReminder, ...]
    events: tuple[CandidateEvent, ...]
    suppressions: tuple[AbsenceSuppression, ...]


def _shared_absence_cooldown_seconds() -> float:
    """Read the one PPE cooldown policy and fail closed if registry entries diverge."""

    if set(_PPE_VIOLATIONS) != set(PpeType):
        raise ContractViolation("PPE violation registry mapping is incomplete")
    cooldowns: set[Decimal] = set()
    for ppe_type, violation_type in _PPE_VIOLATIONS.items():
        definition = VIOLATION_REGISTRY.get(violation_type)
        if (
            definition is None
            or definition.evidence_class != EvidenceClass.ABSENCE
            or definition.required_ppe != (ppe_type,)
        ):
            raise ContractViolation("PPE violation registry shape is invalid")
        cooldowns.add(Decimal(str(definition.default_cooldown_seconds)))
    if len(cooldowns) != 1:
        raise ContractViolation("PPE absence cooldowns must agree across the registry")
    return float(next(iter(cooldowns)))


def _validated_bundles(
    frame_source: FrameSource, detector_manifest_id: str
) -> tuple[FrameBundle, ...]:
    """Validate a bounded replay without rewriting its causal input order."""

    bundles = tuple(frame_source.iter_frames())
    if not bundles:
        raise ContractViolation("FrameSource yielded no frames")
    if any(not isinstance(bundle, FrameBundle) for bundle in bundles):
        raise ContractViolation("FrameSource.iter_frames() must yield FrameBundle values")

    frame_ids: set[str] = set()
    timebases: dict[_StreamKey, Fraction] = {}
    last_frame_indices: dict[_StreamKey, int] = {}
    for bundle in bundles:
        frame = bundle.frame
        if frame.frame_id in frame_ids:
            raise ContractViolation(f"FrameSource yielded duplicate frame_id: {frame.frame_id}")
        frame_ids.add(frame.frame_id)

        stream_key = (frame.camera_id, frame.stream_id)
        timebase = Fraction(frame.fps_num, frame.fps_den)
        previous_timebase = timebases.setdefault(stream_key, timebase)
        if previous_timebase != timebase:
            raise ContractViolation("a camera stream cannot change FPS within one replay")
        previous_frame = last_frame_indices.get(stream_key)
        if previous_frame is not None and frame.frame_index != previous_frame + 1:
            raise ContractViolation(
                "each camera stream must yield contiguous frames in causal order"
            )
        last_frame_indices[stream_key] = frame.frame_index

        for detection in bundle.detections:
            if detection.model_manifest_id != detector_manifest_id:
                raise ManifestMismatch(
                    f"detection {detection.detection_id} does not use the pinned detector manifest"
                )

    return bundles


def _validate_manifest(config: AppConfig, manifest: RunManifest) -> None:
    detector = manifest.models["detector"]
    checks = {
        "schema_version": manifest.schema_version == config.schema_version,
        "config_sha256": manifest.config_sha256 == config.config_sha256,
        "rule_version": manifest.rule_version == config.rule_version,
        "reproducibility_mode": (manifest.reproducibility_mode == config.run.reproducibility_mode),
        "random_seed": manifest.random_seed == config.run.random_seed,
        "privacy_transform_version": (
            manifest.privacy_transform_version == config.evidence.privacy_transform_version
        ),
        "image_encoding_version": (
            manifest.image_encoding_version == config.evidence.encoding_version
        ),
        "pixel_format": manifest.pixel_format == "RGB8",
        "pixel_hash_algorithm": manifest.pixel_hash_algorithm == "LCPIX1",
        "storage_boundary": manifest.storage_boundary == config.run.storage_boundary,
        "detector.provider": detector.provider == config.perception.provider,
        "detector.model": detector.model == config.perception.detector.model_id,
    }
    mismatches = sorted(name for name, matches in checks.items() if not matches)
    if mismatches:
        raise ManifestMismatch(
            f"run manifest does not match config fields: {', '.join(mismatches)}"
        )


def _tracked_people(bundle: FrameBundle) -> tuple[Detection, ...]:
    people = tuple(
        sorted(
            (
                detection
                for detection in bundle.detections
                if detection.label == "person" and detection.track_ref is not None
            ),
            key=lambda detection: (detection.track_ref or "", detection.detection_id),
        )
    )
    track_refs = tuple(person.track_ref for person in people)
    if len(track_refs) != len(set(track_refs)):
        raise ContractViolation("a frame cannot contain multiple person detections for one track")
    return people


class PerceptionPipeline:
    """Compose zones, PPE association, L0 reminders, and absence FSMs in memory."""

    __slots__ = (
        "_absence_cooldown_seconds",
        "_config",
        "_detector_manifest_id",
        "_run_manifest",
    )

    def __init__(
        self,
        *,
        config: AppConfig,
        run_manifest: RunManifest,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        if not isinstance(run_manifest, RunManifest):
            raise TypeError("run_manifest must be a RunManifest")
        _validate_manifest(config, run_manifest)
        self._config = config
        self._run_manifest = run_manifest
        self._detector_manifest_id = run_manifest.models["detector"].model_manifest_id
        self._absence_cooldown_seconds = _shared_absence_cooldown_seconds()

    def run(self, frame_source: FrameSource) -> PerceptionRunResult:
        """Process a replay using only ``iter_frames`` and return RAM-only artifacts."""

        bundles = _validated_bundles(frame_source, self._detector_manifest_id)
        absence = AbsenceFSM(
            config=self._config.absence,
            run_mode=self._config.run.mode,
            cooldown_seconds=self._absence_cooldown_seconds,
            rule_version=self._config.rule_version,
            manifest_id=self._run_manifest.manifest_id,
            source_manifest_id=self._detector_manifest_id,
        )
        reminder_services: dict[_StreamKey, InMemorySoftReminderService] = {}
        associations: list[AssociationRecord] = []
        reminders: list[SoftReminder] = []
        events: list[CandidateEvent] = []
        suppressions: list[AbsenceSuppression] = []

        for bundle in bundles:
            frame = bundle.frame
            stream_key = (frame.camera_id, frame.stream_id)
            existing_reminder_service = reminder_services.get(stream_key)
            if existing_reminder_service is not None:
                existing_reminder_service.prune(current_frame=frame.frame_index)
            observations: list[AbsenceObservation] = []
            for person in _tracked_people(bundle):
                track_ref = person.track_ref
                assert track_ref is not None
                try:
                    zone = locate_person_zone(frame, person, self._config.zones)
                except ValueError:
                    raise ContractViolation(
                        "person zone assignment violates configured policy boundaries"
                    ) from None
                if zone is None:
                    continue
                for ppe_type in sorted(zone.required_ppe, key=lambda item: item.value):
                    association = associate_ppe(
                        bundle,
                        track_ref,
                        ppe_type,
                        score_threshold=self._config.perception.detector.score_threshold,
                        config=self._config.perception.association,
                    )
                    associations.append(
                        AssociationRecord(
                            frame_id=frame.frame_id,
                            track_ref=track_ref,
                            zone_id=zone.zone_id,
                            ppe_type=ppe_type,
                            result=association,
                        )
                    )
                    observations.append(
                        AbsenceObservation(
                            track_ref=track_ref,
                            ppe_type=ppe_type,
                            zone_id=zone.zone_id,
                            risk_level=zone.risk_level,
                            ppe_present=association.present,
                            l1_score=float(person.score),
                        )
                    )
                    if self._config.l0.enabled and not association.present:
                        reminder_service = reminder_services.get(stream_key)
                        if reminder_service is None:
                            cooldown_frames = max(
                                1,
                                seconds_to_frames(
                                    Decimal(str(self._config.l0.reminder_cooldown_seconds)),
                                    frame.fps_num,
                                    frame.fps_den,
                                ),
                            )
                            reminder_service = InMemorySoftReminderService(cooldown_frames)
                            reminder_services[stream_key] = reminder_service
                        reminder = reminder_service.maybe_remind(
                            frame_index=frame.frame_index,
                            track_ref=track_ref,
                            zone_id=zone.zone_id,
                            ppe_type=ppe_type,
                            channel=zone.reminder_channel,
                        )
                        if reminder is not None:
                            reminders.append(reminder)

            frame_results = absence.process_frame(frame, tuple(observations))
            events.extend(
                result.emitted_event for result in frame_results if result.emitted_event is not None
            )
            suppressions.extend(
                result.suppression for result in frame_results if result.suppression is not None
            )

        final_results = absence.finalize()
        events.extend(
            result.emitted_event for result in final_results if result.emitted_event is not None
        )
        suppressions.extend(
            result.suppression for result in final_results if result.suppression is not None
        )

        return PerceptionRunResult(
            frames_processed=len(bundles),
            associations=tuple(
                sorted(
                    associations,
                    key=lambda item: (
                        *parse_frame_id(item.frame_id),
                        item.track_ref,
                        item.zone_id,
                        item.ppe_type.value,
                    ),
                )
            ),
            reminders=tuple(reminders),
            events=tuple(
                sorted(
                    events,
                    key=lambda item: (
                        item.camera_id,
                        item.stream_id,
                        item.start_frame,
                        item.violation_type.value,
                        item.primary_track_ref or "",
                        item.event_id,
                    ),
                )
            ),
            suppressions=tuple(
                sorted(
                    suppressions,
                    key=lambda item: (
                        item.camera_id,
                        item.stream_id,
                        item.start_frame,
                        item.track_ref,
                        item.ppe_type.value,
                        item.zone_id,
                    ),
                )
            ),
        )


__all__ = [
    "AssociationRecord",
    "PerceptionPipeline",
    "PerceptionRunResult",
]
