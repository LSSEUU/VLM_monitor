"""Deterministic M2 evidence construction and publication orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.application.integrity import evidence_failure_code_for_closure
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection, FrameBundle, Keypoint
from labcourt.contracts.enums import (
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    EvidenceClass,
    EvidenceFailureCode,
    PpeType,
    PrivacyPolicy,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    EvidencePackDraft,
    ObservabilityScore,
    ObservationSufficiencyInput,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.manifests import RunManifest, StreamManifest
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.contracts.registry import VIOLATION_REGISTRY
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.association import associate_ppe
from labcourt.domain.crop_geometry import (
    CropGeometryPlan,
    plan_absence_focus,
    plan_panorama,
    plan_presence_focus,
    plan_subject,
)
from labcourt.domain.evidence_window import (
    EvidenceWindow,
    KeyFrameSelection,
    ObservabilityCandidate,
    build_evidence_window,
    select_key_frames,
)
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ContractViolation,
    CreationClosureFailed,
    EvidenceMissing,
    ManifestMismatch,
    PathBoundaryViolation,
    PrivacyPolicyViolation,
)
from labcourt.ports.evidence_repository import (
    CaseSnapshot,
    EvidenceRepository,
    PublishResult,
)
from labcourt.ports.frame_store import FrameStore

MAX_EVIDENCE_BUILD_FRAMES = 10_000
MAX_DETECTIONS_PER_FRAME = 64
MAX_KEYPOINTS_PER_DETECTION = 256


@dataclass(frozen=True, slots=True)
class FrameCropContext:
    """Non-geometric selection context for one authoritative FrameBundle."""

    frame_id: str
    observability: ObservabilityScore | None = None
    presence_focus_detection_id: str | None = None

    def __post_init__(self) -> None:
        parse_frame_id(self.frame_id)
        if self.observability is not None and not isinstance(
            self.observability,
            ObservabilityScore,
        ):
            raise TypeError("observability must be an ObservabilityScore")
        if self.presence_focus_detection_id is not None:
            require_reference_token(
                self.presence_focus_detection_id,
                "presence focus detection ID",
            )


@dataclass(frozen=True, slots=True)
class EvidenceBuildRequest:
    """All bounded, already-validated inputs for one evidence-pack attempt."""

    run_id: str
    event: CandidateEvent
    bundles: tuple[FrameBundle, ...]
    crop_contexts: tuple[FrameCropContext, ...]
    available_end_frame_exclusive: int
    state_transition_frame_ids: tuple[str, ...] = ()
    complete: bool = True

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "evidence build run_id")
        if not isinstance(self.event, CandidateEvent):
            raise TypeError("event must be a CandidateEvent")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be a boolean")
        if (
            not isinstance(self.available_end_frame_exclusive, int)
            or isinstance(self.available_end_frame_exclusive, bool)
            or self.available_end_frame_exclusive <= 0
        ):
            raise ValueError("available_end_frame_exclusive must be a positive integer")
        if (
            len(self.bundles) > MAX_EVIDENCE_BUILD_FRAMES
            or len(self.crop_contexts) > MAX_EVIDENCE_BUILD_FRAMES
            or len(self.state_transition_frame_ids) > MAX_EVIDENCE_BUILD_FRAMES
        ):
            raise BudgetExceeded("evidence build request exceeds its contract budget")
        if any(not isinstance(bundle, FrameBundle) for bundle in self.bundles):
            raise TypeError("bundles must contain FrameBundle values")
        if any(len(bundle.detections) > MAX_DETECTIONS_PER_FRAME for bundle in self.bundles):
            raise BudgetExceeded("evidence build request has too many detections per frame")
        if any(
            len(detection.keypoints) > MAX_KEYPOINTS_PER_DETECTION
            for bundle in self.bundles
            for detection in bundle.detections
        ):
            raise BudgetExceeded("evidence build request has too many detection keypoints")
        frame_ids = tuple(bundle.frame.frame_id for bundle in self.bundles)
        if len(frame_ids) != len(set(frame_ids)):
            raise ValueError("evidence build bundles must be unique by frame")
        if any(bundle.frame.content_sha256 is None for bundle in self.bundles):
            raise ValueError("evidence build frames require decoded LCPIX1 hashes")
        if any(
            (bundle.frame.camera_id, bundle.frame.stream_id)
            != (self.event.camera_id, self.event.stream_id)
            for bundle in self.bundles
        ):
            raise ValueError("evidence build frames must belong to the event stream")
        detection_ids = tuple(
            detection.detection_id for bundle in self.bundles for detection in bundle.detections
        )
        if len(detection_ids) != len(set(detection_ids)):
            raise ValueError("evidence build detection IDs must be globally unique")
        if any(not isinstance(context, FrameCropContext) for context in self.crop_contexts):
            raise TypeError("crop_contexts must contain FrameCropContext values")
        context_ids = tuple(context.frame_id for context in self.crop_contexts)
        if len(context_ids) != len(set(context_ids)):
            raise ValueError("crop contexts must be unique by frame_id")
        if not set(context_ids).issubset(frame_ids):
            raise ValueError("crop context refers to an unavailable frame")
        for frame_id in self.state_transition_frame_ids:
            parse_frame_id(frame_id)
        if len(self.state_transition_frame_ids) != len(set(self.state_transition_frame_ids)):
            raise ValueError("state transition frame IDs must be unique")


@dataclass(frozen=True, slots=True)
class EvidenceBuildResult:
    """Observable result of one application-level evidence publication."""

    window: EvidenceWindow
    selection: KeyFrameSelection
    draft: EvidencePackDraft
    publication: PublishResult


class EvidenceBuilder:
    """Build privacy-safe evidence and commit it through the authoritative repository."""

    __slots__ = (
        "_config",
        "_frame_store",
        "_manifest",
        "_max_window_frames",
        "_repository",
        "_run_id",
    )

    def __init__(
        self,
        *,
        config: AppConfig,
        manifest: RunManifest,
        frame_store: FrameStore,
        repository: EvidenceRepository,
        max_window_frames: int = MAX_EVIDENCE_BUILD_FRAMES,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        if not isinstance(manifest, RunManifest):
            raise TypeError("manifest must be a RunManifest")
        if (
            not isinstance(max_window_frames, int)
            or isinstance(max_window_frames, bool)
            or not 0 < max_window_frames <= MAX_EVIDENCE_BUILD_FRAMES
        ):
            raise ValueError(
                f"max_window_frames must be an integer in [1, {MAX_EVIDENCE_BUILD_FRAMES}]"
            )
        mismatches = sorted(
            name
            for name, matches in {
                "schema_version": manifest.schema_version == config.schema_version,
                "config_sha256": manifest.config_sha256 == config.config_sha256,
                "rule_version": manifest.rule_version == config.rule_version,
                "privacy_transform_version": (
                    manifest.privacy_transform_version == config.evidence.privacy_transform_version
                ),
                "image_encoding_version": (
                    manifest.image_encoding_version == config.evidence.encoding_version
                ),
                "reproducibility_mode": (
                    manifest.reproducibility_mode == config.run.reproducibility_mode
                ),
                "random_seed": manifest.random_seed == config.run.random_seed,
                "storage_boundary": (manifest.storage_boundary == config.run.storage_boundary),
            }.items()
            if not matches
        )
        if mismatches:
            raise ManifestMismatch(f"evidence builder manifest mismatch: {', '.join(mismatches)}")
        try:
            frame_store_run_id = require_reference_token(
                frame_store.run_id,
                "FrameStore run_id",
            )
            frame_store_component = frame_store.software_component
        except (AttributeError, TypeError, ValueError):
            raise ManifestMismatch(
                "evidence FrameStore lacks a valid run or software-component binding"
            ) from None
        manifest_component = manifest.software_components.get(frame_store_component.component)
        if manifest_component != frame_store_component:
            raise ManifestMismatch(
                "evidence FrameStore software component differs from the run manifest"
            )
        self._config = config
        self._manifest = manifest
        self._frame_store = frame_store
        self._repository = repository
        self._max_window_frames = max_window_frames
        self._run_id = frame_store_run_id

    def build_and_publish(self, request: EvidenceBuildRequest) -> EvidenceBuildResult:
        """Publish evidence or atomically escalate an expected evidence failure."""

        if not isinstance(request, EvidenceBuildRequest):
            raise TypeError("request must be an EvidenceBuildRequest")
        if request.run_id != self._run_id:
            raise ManifestMismatch("evidence request belongs to another FrameStore run")
        event = request.event
        if event.manifest_id != self._manifest.manifest_id:
            raise ManifestMismatch("candidate event uses another run manifest")
        self._stream_manifest(event)

        self._repository.register_run(request.run_id, self._manifest)
        case_snapshot = self._repository.create_or_get_case(request.run_id, event)
        try:
            return self._build_and_publish_attempt(request, case_snapshot)
        except (
            ArtifactConflict,
            ArtifactIntegrityViolation,
            BudgetExceeded,
            CreationClosureFailed,
            EvidenceMissing,
            PathBoundaryViolation,
            PrivacyPolicyViolation,
        ) as error:
            self._repository.record_evidence_failure(
                request.run_id,
                case_snapshot.revision,
                case_snapshot.case.case_id,
                self._failure_code(error),
            )
            raise

    def _build_and_publish_attempt(
        self,
        request: EvidenceBuildRequest,
        case_snapshot: CaseSnapshot,
    ) -> EvidenceBuildResult:
        """Create media first, then atomically publish pack/case/audit state.

        Media publication intentionally precedes the SQLite transaction. A failed
        database commit can therefore leave only a content-addressed orphan, which the
        retention/recovery coordinator may later quarantine without risking a broken
        database reference.
        """

        if not isinstance(request, EvidenceBuildRequest):
            raise TypeError("request must be an EvidenceBuildRequest")
        if request.run_id != self._run_id:
            raise ManifestMismatch("evidence request belongs to another FrameStore run")
        event = request.event
        if event.manifest_id != self._manifest.manifest_id:
            raise ManifestMismatch("candidate event uses another run manifest")
        stream = self._stream_manifest(event)
        if (
            len(request.bundles) > self._max_window_frames
            or len(request.crop_contexts) > self._max_window_frames
            or len(request.state_transition_frame_ids) > self._max_window_frames
        ):
            raise BudgetExceeded("evidence build input exceeds its artifact budget")
        detection_count = sum(len(bundle.detections) for bundle in request.bundles)
        if detection_count > self._max_window_frames * MAX_DETECTIONS_PER_FRAME or any(
            len(detection.keypoints) > MAX_KEYPOINTS_PER_DETECTION
            for bundle in request.bundles
            for detection in bundle.detections
        ):
            raise BudgetExceeded("evidence build detections exceed their bounded budget")
        bundles = self._validate_bundles(request.bundles, stream)
        frames = tuple(bundle.frame for bundle in bundles)
        window = build_evidence_window(
            event,
            fps_num=stream.fps_num,
            fps_den=stream.fps_den,
            pre_seconds=self._config.evidence.pre_seconds,
            post_seconds=self._config.evidence.post_seconds,
            stream_start_frame=0,
            stream_end_frame_exclusive=stream.frame_count,
        )
        if window.frame_count > self._max_window_frames:
            raise BudgetExceeded("evidence window exceeds the configured frame budget")
        watermark = request.available_end_frame_exclusive
        if not event.end_frame_exclusive <= watermark <= window.end_frame_exclusive:
            raise EvidenceMissing("evidence availability watermark is outside the valid window")
        if request.complete != (watermark == window.end_frame_exclusive):
            raise EvidenceMissing("evidence completeness conflicts with its availability watermark")
        expected_indices = set(range(window.start_frame, watermark))
        available_indices = {frame.frame_index for frame in frames}
        if available_indices != expected_indices:
            raise EvidenceMissing(
                "evidence input must be the contiguous prefix through its availability watermark"
            )

        contexts = {context.frame_id: context for context in request.crop_contexts}
        observability_candidates = tuple(
            ObservabilityCandidate(
                frame_id=context.frame_id,
                score=context.observability.total,
            )
            for context in request.crop_contexts
            if context.observability is not None
            and event.start_frame <= parse_frame_id(context.frame_id)[2] < event.end_frame_exclusive
        )
        selection = select_key_frames(
            event,
            window,
            frames,
            observability_candidates=observability_candidates,
            state_transition_frame_ids=request.state_transition_frame_ids,
            top_m=(
                self._config.absence.temporal_crop_count
                if event.evidence_class == EvidenceClass.ABSENCE
                else 0
            ),
        )

        for bundle in bundles:
            self._repository.register_frame(request.run_id, bundle.frame)
            for detection in bundle.detections:
                self._repository.register_detection(request.run_id, detection)

        bundle_by_id = {bundle.frame.frame_id: bundle for bundle in bundles}
        frame_by_id = {frame.frame_id: frame for frame in frames}
        panorama_crops = (
            self._frame_store.create_crop(
                self._panorama_request(
                    frame_by_id[self._trigger_frame_id(event)],
                )
            ),
        )
        subject_crops = self._subject_crops(event, bundle_by_id)
        focus_crops, temporal_crops = self._focus_crops(
            event,
            selection,
            bundle_by_id,
            contexts,
        )
        sufficiency = self._observation_sufficiency(event, temporal_crops)
        draft = EvidencePackDraft(
            run_id=request.run_id,
            case_id=case_snapshot.case.case_id,
            version=len(case_snapshot.case.evidence_packs) + 1,
            complete=request.complete,
            event=event,
            key_frame_ids=selection.frame_ids,
            panorama_crops=self._sort_crops(panorama_crops),
            subject_crops=self._sort_crops(subject_crops),
            focus_crops=self._sort_crops(focus_crops),
            temporal_crops=self._sort_crops(temporal_crops),
            objective_facts=event.objective_facts,
            track_summary=TrackSummary(
                primary_track_ref=event.primary_track_ref,
                start_frame=window.start_frame,
                end_frame_exclusive=window.end_frame_exclusive,
                observed_frame_count=len(frames),
            ),
            confirmation_record=event.confirmation,
            observation_sufficiency_input=sufficiency,
            manifest_id=self._manifest.manifest_id,
        )
        publication = self._repository.publish_pack(
            request.run_id,
            case_snapshot.revision,
            draft,
        )
        return EvidenceBuildResult(
            window=window,
            selection=selection,
            draft=draft,
            publication=publication,
        )

    @staticmethod
    def _failure_code(
        error: (
            ArtifactConflict
            | ArtifactIntegrityViolation
            | BudgetExceeded
            | CreationClosureFailed
            | EvidenceMissing
            | PathBoundaryViolation
            | PrivacyPolicyViolation
        ),
    ) -> EvidenceFailureCode:
        if isinstance(error, CreationClosureFailed):
            return evidence_failure_code_for_closure(error.defect_codes)
        if isinstance(error, PrivacyPolicyViolation):
            return EvidenceFailureCode.PRIVACY_POLICY_UNSATISFIED
        if isinstance(error, PathBoundaryViolation):
            return EvidenceFailureCode.PATH_SECURITY_FAILURE
        if isinstance(error, (ArtifactConflict, ArtifactIntegrityViolation)):
            return EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE
        if isinstance(error, BudgetExceeded):
            return EvidenceFailureCode.EVIDENCE_BUDGET_EXCEEDED
        return EvidenceFailureCode.EVIDENCE_MISSING

    def _stream_manifest(self, event: CandidateEvent) -> StreamManifest:
        matching = tuple(
            stream
            for stream in self._manifest.streams
            if (stream.camera_id, stream.stream_id) == (event.camera_id, event.stream_id)
        )
        if len(matching) != 1:
            raise ManifestMismatch(
                "run manifest must contain exactly one authoritative event stream"
            )
        return matching[0]

    def _validate_bundles(
        self,
        bundles: tuple[FrameBundle, ...],
        stream: StreamManifest,
    ) -> tuple[FrameBundle, ...]:
        ordered = tuple(
            sorted(
                bundles,
                key=lambda bundle: (
                    bundle.frame.frame_index,
                    bundle.frame.frame_id,
                ),
            )
        )
        for bundle in ordered:
            frame = bundle.frame
            if (
                frame.fps_num,
                frame.fps_den,
                frame.width,
                frame.height,
            ) != (
                stream.fps_num,
                stream.fps_den,
                stream.width,
                stream.height,
            ):
                raise ManifestMismatch(
                    "frame geometry or timebase differs from the stream manifest"
                )
            if not 0 <= frame.frame_index < stream.frame_count:
                raise ManifestMismatch("frame lies outside the stream manifest")
            detector_manifest_id = self._manifest.models["detector"].model_manifest_id
            if any(
                detection.model_manifest_id != detector_manifest_id
                for detection in bundle.detections
            ):
                raise ManifestMismatch(
                    "evidence detection does not use the pinned detector manifest"
                )
        return ordered

    def _panorama_request(self, frame: FrameRef) -> CropRequest:
        plan = plan_panorama(
            frame_width=frame.width,
            frame_height=frame.height,
            long_edge_limit=self._config.evidence.panorama_long_edge,
        )
        return self._crop_request(
            frame=frame,
            plan=plan,
            authority_refs=(),
            privacy_policy=PrivacyPolicy.FULL_REDACTION,
        )

    def _subject_crops(
        self,
        event: CandidateEvent,
        bundle_by_id: dict[str, FrameBundle],
    ) -> tuple[Crop, ...]:
        if event.primary_track_ref is None:
            return ()
        trigger_id = self._trigger_frame_id(event)
        bundle = bundle_by_id[trigger_id]
        subject = self._tracked_detection(bundle, event.primary_track_ref)
        if event.evidence_class == EvidenceClass.ABSENCE and subject.label != "person":
            raise EvidenceMissing("absence subject track is not a person detection")
        frame = bundle.frame
        plan = plan_subject(
            subject.bbox,
            frame_width=frame.width,
            frame_height=frame.height,
            expand_ratio=self._config.evidence.subject_expand_ratio,
        )
        request = self._crop_request(
            frame=frame,
            plan=plan,
            authority_refs=(self._detection_ref(subject),),
            privacy_policy=PrivacyPolicy.FULL_REDACTION,
            primary_track_ref=event.primary_track_ref,
        )
        return (self._frame_store.create_crop(request),)

    def _focus_crops(
        self,
        event: CandidateEvent,
        selection: KeyFrameSelection,
        bundle_by_id: dict[str, FrameBundle],
        contexts: dict[str, FrameCropContext],
    ) -> tuple[tuple[Crop, ...], tuple[Crop, ...]]:
        if event.evidence_class == EvidenceClass.PRESENCE:
            trigger_id = self._trigger_frame_id(event)
            context = self._required_context(contexts, trigger_id)
            detection_id = context.presence_focus_detection_id
            if detection_id is None:
                raise EvidenceMissing("presence focus requires a detection ID")
            bundle = bundle_by_id[trigger_id]
            matching = tuple(
                detection
                for detection in bundle.detections
                if detection.detection_id == detection_id
            )
            if len(matching) != 1:
                raise EvidenceMissing("presence focus detection is absent from its frame")
            detection = matching[0]
            definition = VIOLATION_REGISTRY[event.violation_type]
            if detection.label not in definition.required_targets:
                raise EvidenceMissing(
                    "presence focus detection label is not authoritative for the violation"
                )
            frame = bundle.frame
            plan = plan_presence_focus(
                detection.bbox,
                frame_width=frame.width,
                frame_height=frame.height,
            )
            request = self._crop_request(
                frame=frame,
                plan=plan,
                authority_refs=(self._detection_ref(detection),),
                privacy_policy=PrivacyPolicy.FULL_REDACTION,
                primary_track_ref=event.primary_track_ref,
            )
            return (self._frame_store.create_crop(request),), ()

        definition = VIOLATION_REGISTRY[event.violation_type]
        if len(definition.required_ppe) != 1 or definition.anchor_type is None:
            raise ContractViolation("absence violation has no singular PPE anchor authority")
        if self._config.evidence.privacy_policy != PrivacyPolicy.PPE_PRESERVING_REDACTION:
            raise PrivacyPolicyViolation(
                "configured privacy policy cannot persist absence-focus evidence"
            )
        temporal: list[Crop] = []
        for frame_id in selection.temporal_top_m_frame_ids:
            context = self._required_context(contexts, frame_id)
            if context.observability is None:
                raise EvidenceMissing("absence temporal focus requires observability")
            bundle = bundle_by_id[frame_id]
            frame = bundle.frame
            primary_track_ref = event.primary_track_ref
            assert primary_track_ref is not None
            person = self._person_detection(bundle, primary_track_ref)
            association = associate_ppe(
                bundle,
                primary_track_ref,
                definition.required_ppe[0],
                score_threshold=self._config.perception.detector.score_threshold,
                config=self._config.perception.association,
            )
            plan = plan_absence_focus(
                association.anchor_bbox,
                frame_width=frame.width,
                frame_height=frame.height,
            )
            detections_by_id = {
                detection.detection_id: detection for detection in bundle.detections
            }
            authority_detections = (
                person,
                *(
                    detections_by_id[detection_id]
                    for detection_id in association.matched_detection_ids
                ),
            )
            request = self._crop_request(
                frame=frame,
                plan=plan,
                authority_refs=tuple(
                    self._detection_ref(detection) for detection in authority_detections
                ),
                privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
                primary_track_ref=primary_track_ref,
                ppe_type=definition.required_ppe[0],
                anchor_type=definition.anchor_type,
                keypoints=person.keypoints,
                association_method=association.method,
                observability=context.observability,
            )
            temporal.append(self._frame_store.create_crop(request))
        return (), tuple(temporal)

    @staticmethod
    def _required_context(
        contexts: dict[str, FrameCropContext],
        frame_id: str,
    ) -> FrameCropContext:
        context = contexts.get(frame_id)
        if context is None:
            raise EvidenceMissing(f"selected frame lacks typed selection context: {frame_id}")
        return context

    @staticmethod
    def _person_detection(bundle: FrameBundle, track_ref: str) -> Detection:
        detection = EvidenceBuilder._tracked_detection(bundle, track_ref)
        if detection.label != "person":
            raise EvidenceMissing("evidence frame requires an authoritative person detection")
        return detection

    @staticmethod
    def _tracked_detection(bundle: FrameBundle, track_ref: str) -> Detection:
        matching = tuple(
            detection for detection in bundle.detections if detection.track_ref == track_ref
        )
        if len(matching) != 1:
            raise EvidenceMissing(
                "evidence frame requires exactly one authoritative tracked detection"
            )
        return matching[0]

    @staticmethod
    def _detection_ref(detection: Detection) -> ArtifactRef:
        return ArtifactRef(
            kind=ArtifactKind.DETECTION,
            artifact_id=detection.detection_id,
        )

    def _crop_request(
        self,
        *,
        frame: FrameRef,
        plan: CropGeometryPlan,
        authority_refs: tuple[ArtifactRef, ...],
        privacy_policy: PrivacyPolicy,
        primary_track_ref: str | None = None,
        ppe_type: PpeType | None = None,
        anchor_type: AnchorType | None = None,
        keypoints: tuple[Keypoint, ...] = (),
        association_method: AssociationMethod | None = None,
        observability: ObservabilityScore | None = None,
    ) -> CropRequest:
        frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
        source_refs = {ref.sort_key: ref for ref in (*authority_refs, frame_ref)}
        return CropRequest(
            frame_id=frame.frame_id,
            source=plan.source,
            bbox=plan.bbox,
            output_width=plan.output_size.width,
            output_height=plan.output_size.height,
            panorama_long_edge_limit=plan.panorama_long_edge_limit,
            source_refs=tuple(source_refs[key] for key in sorted(source_refs)),
            privacy_policy=privacy_policy,
            privacy_transform_version=self._config.evidence.privacy_transform_version,
            encoding_version=self._config.evidence.encoding_version,
            primary_track_ref=primary_track_ref,
            ppe_type=ppe_type,
            anchor_type=anchor_type,
            anchor_bbox=plan.bbox if ppe_type is not None else None,
            keypoints=tuple(sorted(keypoints, key=lambda keypoint: keypoint.name)),
            association_method=association_method,
            observability=observability,
        )

    def _observation_sufficiency(
        self,
        event: CandidateEvent,
        temporal_crops: tuple[Crop, ...],
    ) -> ObservationSufficiencyInput | None:
        if event.evidence_class != EvidenceClass.ABSENCE:
            return None
        threshold = self._config.perception.observability.clear_frame_threshold
        clear = tuple(
            sorted(
                crop.crop_id
                for crop in temporal_crops
                if crop.observability is not None and crop.observability.total >= threshold
            )
        )
        unclear = tuple(
            sorted(crop.crop_id for crop in temporal_crops if crop.crop_id not in clear)
        )
        return ObservationSufficiencyInput(
            clear_crop_ids=clear,
            unclear_crop_ids=unclear,
            clear_threshold=threshold,
            required_clear_count=self._config.absence.minimum_consistent_clear_frames,
            selected_by_observability=True,
        )

    @staticmethod
    def _sort_crops(crops: tuple[Crop, ...]) -> tuple[Crop, ...]:
        return tuple(
            sorted(
                crops,
                key=lambda crop: (parse_frame_id(crop.frame_id)[2], crop.crop_id),
            )
        )

    @staticmethod
    def _trigger_frame_id(event: CandidateEvent) -> str:
        return f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}"


__all__ = [
    "MAX_DETECTIONS_PER_FRAME",
    "MAX_EVIDENCE_BUILD_FRAMES",
    "MAX_KEYPOINTS_PER_DETECTION",
    "EvidenceBuildRequest",
    "EvidenceBuildResult",
    "EvidenceBuilder",
    "FrameCropContext",
]
