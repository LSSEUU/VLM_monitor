"""A2 orchestration from sealed real perception to authoritative evidence packs."""

from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
from pathlib import Path
from typing import cast

from pydantic import BaseModel, ValidationError

from labcourt.adapters.opencv_video import (
    OpenCvDecoderBackend,
    OpenCvVideoSource,
    VerifiedVideoInput,
    VideoDecoderBackend,
)
from labcourt.adapters.perception.local_worker import RawPerceptionWorkerTransport
from labcourt.adapters.pillow_frame_store import PillowFrameStore
from labcourt.adapters.pixel_observability import score_person_rgb8_observability
from labcourt.adapters.precomputed import PrecomputedFrameSource
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.evidence import (
    EvidenceBuilder,
    EvidenceBuildRequest,
    FrameCropContext,
)
from labcourt.application.perception import PerceptionPipeline
from labcourt.application.screening_request import FROZEN_M3_PROMPT_BUNDLE_SHA256
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig, VlmProviderProfile
from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    DeviceClass,
    MediaAccess,
    OperatingSystemFamily,
    PrivacyPolicy,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.manifests import (
    DecodingParameters,
    ModelManifest,
    PlatformSummary,
    RunManifest,
    SoftwareComponentManifest,
)
from labcourt.contracts.pilot import (
    PilotA2Report,
    PilotEvidencePackSummary,
    PilotRunRequest,
)
from labcourt.contracts.registry import VIOLATION_REGISTRY
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.domain.evidence_window import build_evidence_window
from labcourt.exceptions import (
    ArtifactConflict,
    BudgetExceeded,
    ManifestMismatch,
    PathBoundaryViolation,
)
from labcourt.ports.evidence_repository import EvidenceRepository
from labcourt.services.pilot_operations import (
    MAX_PILOT_FRAMES,
    MAX_PILOT_VIDEO_BYTES,
    CompletedPilotPerception,
    load_completed_pilot_perception,
    run_pilot_perception,
)


class _PilotEvidenceVerifier:
    """Verify crop bytes and only references present in the sealed A1 inventory."""

    __slots__ = ("_detection_ids", "_frame_ids", "_store")

    def __init__(self, store: PillowFrameStore, bundles: tuple[FrameBundle, ...]) -> None:
        self._store = store
        self._frame_ids = frozenset(bundle.frame.frame_id for bundle in bundles)
        self._detection_ids = frozenset(
            detection.detection_id for bundle in bundles for detection in bundle.detections
        )

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        return self._store.verify_crop(crop)

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id
        if ref.kind == ArtifactKind.FRAME:
            return ref.artifact_id in self._frame_ids
        if ref.kind == ArtifactKind.DETECTION:
            return ref.artifact_id in self._detection_ids
        return False


def _model_from_profile(component: str, profile: VlmProviderProfile) -> ModelManifest:
    return ModelManifest(
        component=component,
        provider=profile.provider,
        model=profile.model,
        revision=profile.revision,
        quantization=profile.quantization,
        weights_sha256=None,
        license_id="no-weights",
        provider_revision_guarantee=True,
    )


def _not_invoked_model(component: str) -> ModelManifest:
    return ModelManifest(
        component=component,
        provider="not-invoked",
        model=f"pilot-a2-{component}-disabled",
        revision="1.0.0",
        quantization=None,
        weights_sha256=None,
        license_id="no-weights",
        provider_revision_guarantee=True,
    )


def _operating_system_family() -> OperatingSystemFamily:
    if sys.platform.startswith("win"):
        return OperatingSystemFamily.WINDOWS
    if sys.platform.startswith("linux"):
        return OperatingSystemFamily.LINUX
    if sys.platform == "darwin":
        return OperatingSystemFamily.MACOS
    return OperatingSystemFamily.OTHER


def _resolve_code_commit(project_root: Path) -> str:
    try:
        completed = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable-local-workspace"
    commit = completed.stdout.strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        return "unavailable-local-workspace"
    return commit


def _rule_bundle_sha256() -> str:
    definitions = [
        VIOLATION_REGISTRY[key].model_dump(mode="json")
        for key in sorted(VIOLATION_REGISTRY, key=lambda item: item.value)
    ]
    return sha256_hex(["violation-registry", 1, definitions])


def _build_run_manifest(
    *,
    config: AppConfig,
    completed: CompletedPilotPerception,
    frame_store: PillowFrameStore,
    code_commit: str,
) -> RunManifest:
    detector = config.perception.detector_manifest
    tracker = config.perception.tracker_manifest
    worker = config.perception.worker
    if detector is None or tracker is None or worker is None:
        raise ManifestMismatch("pilot A2 requires the sealed local-worker model pins")
    profiles = {
        "screening": config.providers[config.screening.provider_profile],
        "prosecutor": config.providers[config.hearing.prosecutor_profile],
        "defender": config.providers[config.hearing.defender_profile],
        "judge": config.providers[config.hearing.judge_profile],
    }
    stream = completed.stream_manifest
    decoder_component = SoftwareComponentManifest(
        component=stream.software_component,
        package=stream.library,
        version=stream.library_version,
        license_id="Apache-2.0",
    )
    components = {
        decoder_component.component: decoder_component,
        frame_store.software_component.component: frame_store.software_component,
    }
    return RunManifest(
        code_commit=code_commit,
        schema_version=config.schema_version,
        config_sha256=config.config_sha256,
        rule_version=config.rule_version,
        rule_bundle_sha256=_rule_bundle_sha256(),
        prompt_bundle_sha256=FROZEN_M3_PROMPT_BUNDLE_SHA256,
        models={
            "detector": detector,
            "tracker": tracker,
            "pose": _not_invoked_model("pose"),
            "screening": _model_from_profile("screening", profiles["screening"]),
            "prosecutor": _model_from_profile("prosecutor", profiles["prosecutor"]),
            "defender": _model_from_profile("defender", profiles["defender"]),
            "judge": _model_from_profile("judge", profiles["judge"]),
            "text_embedding": _not_invoked_model("text_embedding"),
            "visual_embedding": _not_invoked_model("visual_embedding"),
        },
        privacy_transform_version=config.evidence.privacy_transform_version,
        reproducibility_mode=config.run.reproducibility_mode,
        random_seed=config.run.random_seed,
        decoding_parameters=DecodingParameters(
            temperature=0.0,
            seed=config.run.random_seed,
            max_output_tokens=config.hearing.max_total_output_tokens,
        ),
        platform_summary=PlatformSummary(
            os_family=_operating_system_family(),
            architecture=platform.machine() or "unknown",
            python_version=platform.python_version(),
            device_class=(
                DeviceClass.GPU_AVAILABLE
                if worker.device.startswith("cuda")
                else DeviceClass.CPU_ONLY
            ),
        ),
        storage_boundary=config.run.storage_boundary,
        streams=(stream,),
        software_components=components,
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
        image_encoding_version=config.evidence.encoding_version,
    )


def _artifact_bytes(model: BaseModel) -> bytes:
    payload = model.model_dump(mode="json")
    return (canonical_json(payload) + "\n").encode("utf-8")


def _publish_immutable(workspace: SecureWorkspace, relative_path: str, data: bytes) -> None:
    digest = hashlib.sha256(data).hexdigest()
    try:
        workspace.create_new(relative_path, data, digest)
    except ArtifactConflict:
        workspace.read_verified(relative_path, digest)


def _summary(pack: EvidencePack) -> PilotEvidencePackSummary:
    crops = pack.panorama_crops + pack.subject_crops + pack.focus_crops + pack.temporal_crops
    return PilotEvidencePackSummary(
        event_id=pack.event.event_id,
        case_id=pack.case_id,
        pack_id=pack.pack_id,
        violation_type=pack.event.violation_type,
        confirmation_policy=pack.event.confirmation.policy,
        complete=pack.complete,
        closure_passed=pack.closure_report.passed,
        panorama_crop_count=len(pack.panorama_crops),
        subject_crop_count=len(pack.subject_crops),
        focus_crop_count=len(pack.focus_crops),
        temporal_crop_count=len(pack.temporal_crops),
        cloud_allowed_crop_count=sum(
            crop.privacy_receipt.media_access == MediaAccess.CLOUD_ALLOWED for crop in crops
        ),
        local_only_crop_count=sum(
            crop.privacy_receipt.media_access == MediaAccess.LOCAL_ONLY for crop in crops
        ),
        privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
    )


def _resume_report(
    *,
    workspace: SecureWorkspace,
    request: PilotRunRequest,
    completed: CompletedPilotPerception,
    manifest: RunManifest,
    repository: EvidenceRepository,
) -> PilotA2Report | None:
    if not request.resume:
        return None
    try:
        snapshot = workspace.read_verified(f"{request.run_id}/pilot/a2-report.json")
    except PathBoundaryViolation as error:
        if error.reason_code == "FILE_MISSING":
            return None
        raise
    try:
        manifest_snapshot = workspace.read_verified(f"{request.run_id}/pilot/run-manifest.json")
    except PathBoundaryViolation:
        raise ManifestMismatch("persisted pilot A2 run manifest is unavailable") from None
    try:
        report = PilotA2Report.model_validate_json(snapshot.bytes)
        persisted_manifest = RunManifest.model_validate_json(manifest_snapshot.bytes)
    except ValidationError:
        raise ManifestMismatch("persisted pilot A2 authority is invalid") from None
    if (
        report.run_id != request.run_id
        or report.config_sha256 != request.config_sha256
        or report.video_sha256 != request.video_sha256
        or report.perception_manifest_id != completed.execution_manifest.manifest_id
        or report.perception_completion_id != completed.completion_manifest.completion_id
        or report.run_manifest_id != manifest.manifest_id
        or persisted_manifest != manifest
    ):
        raise ManifestMismatch("persisted pilot A2 report does not match its authorities")
    if repository.load_run_manifest(request.run_id) != manifest:
        raise ManifestMismatch("persisted pilot A2 database has another run manifest")
    summaries: list[PilotEvidencePackSummary] = []
    for expected in report.evidence_packs:
        pack = repository.load_pack(request.run_id, expected.pack_id)
        closure = repository.verify_current_pack(request.run_id, expected.pack_id)
        if not closure.passed:
            raise ManifestMismatch("persisted pilot A2 pack no longer passes closure")
        summaries.append(_summary(pack))
    if tuple(summaries) != report.evidence_packs:
        raise ManifestMismatch("persisted pilot A2 report diverges from SQLite authority")
    return report


def _observability_contexts(
    *,
    source: OpenCvVideoSource,
    completed: CompletedPilotPerception,
    events: tuple[CandidateEvent, ...],
    config: AppConfig,
) -> dict[tuple[str, str], FrameCropContext]:
    wanted: dict[str, list[tuple[str, str]]] = {}
    for event in events:
        primary_track_ref = event.primary_track_ref
        if primary_track_ref is None:
            continue
        for frame_index in range(
            event.start_frame,
            event.end_frame_exclusive,
        ):
            frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
            wanted.setdefault(frame_id, []).append((event.event_id, primary_track_ref))
    if not wanted:
        return {}
    bundles = {bundle.frame.frame_id: bundle for bundle in completed.bundles}
    contexts: dict[tuple[str, str], FrameCropContext] = {}
    for rgb8 in source.iter_rgb8():
        targets = wanted.get(rgb8.frame.frame_id)
        if targets is None:
            continue
        bundle = bundles[rgb8.frame.frame_id]
        for event_id, track_ref in targets:
            people = tuple(
                detection
                for detection in bundle.detections
                if detection.label == "person" and detection.track_ref == track_ref
            )
            if len(people) != 1:
                continue
            contexts[(event_id, rgb8.frame.frame_id)] = FrameCropContext(
                frame_id=rgb8.frame.frame_id,
                observability=score_person_rgb8_observability(
                    rgb8,
                    people[0],
                    config.perception.observability.weights,
                ),
            )
    return contexts


def run_pilot_a2(
    *,
    config: AppConfig,
    request: PilotRunRequest,
    config_path: Path,
    project_root: Path,
    decoder_backend: VideoDecoderBackend | None = None,
    raw_transport: RawPerceptionWorkerTransport | None = None,
    code_commit: str | None = None,
) -> PilotA2Report:
    """Run or resume A1, then stop after real evidence reaches EVIDENCE_READY."""

    if request.config_sha256 != config.config_sha256:
        raise ManifestMismatch("pilot A2 request configuration identity changed")
    pilot = config.pilot
    if pilot is None or request.selected_rules != (ViolationType.PPE_GOGGLES_MISSING,):
        raise ManifestMismatch("pilot A2 requires the single goggles rule scope")
    root = project_root.absolute()
    selected_backend = decoder_backend if decoder_backend is not None else OpenCvDecoderBackend()
    run_pilot_perception(
        config=config,
        request=request,
        config_path=config_path,
        project_root=root,
        decoder_backend=selected_backend,
        raw_transport=raw_transport,
    )
    runs_root = root / config.run.workspace
    with (
        SecureWorkspace(root, max_file_bytes=MAX_PILOT_VIDEO_BYTES) as input_workspace,
        SecureWorkspace(runs_root, max_file_bytes=config.storage.max_media_bytes) as run_workspace,
    ):
        completed = load_completed_pilot_perception(
            workspace=run_workspace,
            config=config,
            request=request,
        )
        source = OpenCvVideoSource(
            manifest=completed.stream_manifest,
            verified_input=cast(VerifiedVideoInput, input_workspace),
            relative_path=request.video_relative_path,
            max_input_bytes=MAX_PILOT_VIDEO_BYTES,
            max_frame_pixels=config.storage.max_image_pixels,
            max_total_decoded_pixels=config.storage.max_image_pixels * MAX_PILOT_FRAMES,
            backend=selected_backend,
        )
        run_workspace.ensure_private_directory(f"{request.run_id}/pilot")
        run_workspace.ensure_private_directory(f"{request.run_id}/frames")
        store = PillowFrameStore(
            run_id=request.run_id,
            workspace=run_workspace,
            pixels=source,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        manifest = _build_run_manifest(
            config=config,
            completed=completed,
            frame_store=store,
            code_commit=code_commit or _resolve_code_commit(root),
        )
        database = runs_root / request.run_id / config.storage.database_filename
        MigrationRunner(database, config.storage.busy_timeout_ms).apply_all()
        repository = SQLiteEvidenceRepository(
            database,
            config.storage.busy_timeout_ms,
            verifier=_PilotEvidenceVerifier(store, completed.bundles),
        )
        resumed = _resume_report(
            workspace=run_workspace,
            request=request,
            completed=completed,
            manifest=manifest,
            repository=repository,
        )
        if resumed is not None:
            return resumed

        perception = PerceptionPipeline(config=config, run_manifest=manifest).run(
            PrecomputedFrameSource(completed.bundles)
        )
        events = tuple(
            event for event in perception.events if event.violation_type in request.selected_rules
        )
        if len(events) != len(perception.events):
            raise ManifestMismatch("pilot perception emitted an event outside selected rules")
        if len(events) > request.max_cases:
            raise BudgetExceeded("pilot candidate count exceeds max_cases")
        repository.register_run(request.run_id, manifest)
        contexts = _observability_contexts(
            source=source,
            completed=completed,
            events=events,
            config=config,
        )
        builder = EvidenceBuilder(
            config=config,
            manifest=manifest,
            frame_store=store,
            repository=repository,
        )
        summaries: list[PilotEvidencePackSummary] = []
        for event in events:
            window = build_evidence_window(
                event,
                fps_num=completed.stream_manifest.fps_num,
                fps_den=completed.stream_manifest.fps_den,
                pre_seconds=config.evidence.pre_seconds,
                post_seconds=config.evidence.post_seconds,
                stream_start_frame=0,
                stream_end_frame_exclusive=completed.stream_manifest.frame_count,
            )
            bundles = tuple(
                bundle
                for bundle in completed.bundles
                if window.start_frame <= bundle.frame.frame_index < window.end_frame_exclusive
            )
            result = builder.build_and_publish(
                EvidenceBuildRequest(
                    run_id=request.run_id,
                    event=event,
                    bundles=bundles,
                    crop_contexts=tuple(
                        contexts[(event.event_id, bundle.frame.frame_id)]
                        for bundle in bundles
                        if (event.event_id, bundle.frame.frame_id) in contexts
                    ),
                    available_end_frame_exclusive=window.end_frame_exclusive,
                    state_transition_frame_ids=tuple(
                        dict.fromkeys(
                            (
                                f"{event.camera_id}:{event.stream_id}:{event.start_frame}",
                                f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}",
                            )
                        )
                    ),
                    complete=True,
                )
            )
            pack = result.publication.pack
            if result.publication.case.case.status != CaseStatus.EVIDENCE_READY:
                raise ManifestMismatch("pilot A2 evidence did not reach EVIDENCE_READY")
            closure = repository.verify_current_pack(request.run_id, pack.pack_id)
            if not closure.passed:
                raise ManifestMismatch("pilot A2 evidence closure failed")
            summaries.append(_summary(pack))

        report = PilotA2Report(
            run_id=request.run_id,
            state="EVIDENCE_READY" if summaries else "NO_CANDIDATE",
            config_sha256=request.config_sha256,
            video_sha256=request.video_sha256,
            perception_manifest_id=completed.execution_manifest.manifest_id,
            perception_completion_id=completed.completion_manifest.completion_id,
            run_manifest_id=manifest.manifest_id,
            selected_rules=request.selected_rules,
            frames_processed=perception.frames_processed,
            association_count=len(perception.associations),
            l0_reminder_count=len(perception.reminders),
            suppression_count=len(perception.suppressions),
            candidate_event_count=len(events),
            evidence_pack_count=len(summaries),
            evidence_packs=tuple(summaries),
        )
        _publish_immutable(
            run_workspace,
            f"{request.run_id}/pilot/run-manifest.json",
            _artifact_bytes(manifest),
        )
        _publish_immutable(
            run_workspace,
            f"{request.run_id}/pilot/a2-report.json",
            _artifact_bytes(report),
        )
        return report


__all__ = ["run_pilot_a2"]
