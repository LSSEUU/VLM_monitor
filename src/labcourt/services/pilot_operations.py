"""Fail-closed A0 preflight for the v0.2 real-video pilot."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import BaseModel, ValidationError

from labcourt.adapters.opencv_video import (
    OpenCvDecoderBackend,
    OpenCvVideoSource,
    VerifiedVideoInput,
    VideoDecoderBackend,
    probe_caller_attested_stream_manifest,
)
from labcourt.adapters.perception.local_worker import (
    CachedPerceptionWorkerTransport,
    JsonlPerceptionWorkerClient,
    LocalWorkerPerceptionProvider,
    RawPerceptionWorkerTransport,
    map_perception_worker_detections,
    parse_perception_worker_result,
)
from labcourt.adapters.perception.opencv_preview import OpenCvPerceptionPreview
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.frames import FrameData
from labcourt.contracts.manifests import StreamManifest
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.pilot import (
    PilotPerceptionArtifactReceipt,
    PilotPerceptionArtifactRole,
    PilotPerceptionCompletionManifest,
    PilotPerceptionExecutionManifest,
    PilotPerceptionFrameReceipt,
    PilotPerceptionReport,
    PilotPerceptionWorkerResponse,
    PilotRunRequest,
)
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import (
    ArtifactConflict,
    BudgetExceeded,
    LabCourtError,
    ManifestMismatch,
    PathBoundaryViolation,
    PerceptionWorkerCrashed,
)
from labcourt.ports.pixels import RGB8Frame

MAX_PILOT_VIDEO_BYTES = 8 * 1024 * 1024 * 1024
MAX_PILOT_FRAMES = 108_000


class PilotOperationsBoundaryCode(StrEnum):
    PILOT_CONFIG_MISSING = "PILOT_CONFIG_MISSING"
    RUN_ID_INVALID = "RUN_ID_INVALID"
    VIDEO_PATH_INVALID = "VIDEO_PATH_INVALID"
    VIDEO_MISSING = "VIDEO_MISSING"
    VIDEO_EMPTY = "VIDEO_EMPTY"
    VIDEO_BOUNDARY_REJECTED = "VIDEO_BOUNDARY_REJECTED"
    WORKSPACE_BOUNDARY_REJECTED = "WORKSPACE_BOUNDARY_REJECTED"
    STAGE_NOT_AVAILABLE = "STAGE_NOT_AVAILABLE"
    PERCEPTION_FAILED = "PERCEPTION_FAILED"
    EVIDENCE_FAILED = "EVIDENCE_FAILED"


class PilotOperationsBoundaryError(LabCourtError):
    """A sanitized pilot boundary failure safe for CLI output."""

    def __init__(self, code: PilotOperationsBoundaryCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class CompletedPilotPerception:
    """Fully verified A1 authority made available to the next pilot stage."""

    report: PilotPerceptionReport
    execution_manifest: PilotPerceptionExecutionManifest
    stream_manifest: StreamManifest
    bundles: tuple[FrameBundle, ...]
    completion_manifest: PilotPerceptionCompletionManifest


def require_pilot_config(config: AppConfig) -> None:
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    if config.pilot is None:
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.PILOT_CONFIG_MISSING)


def validate_pilot_run_scope(
    *,
    config: AppConfig,
    run_id: str,
    project_root: Path,
) -> str:
    """Validate one future run root without creating files or directories."""

    require_pilot_config(config)
    try:
        controlled_run_id = require_portable_run_id(run_id, "pilot run_id")
    except (TypeError, ValueError):
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.RUN_ID_INVALID) from None

    workspace_root = project_root.absolute() / config.run.workspace
    try:
        with SecureWorkspace(
            workspace_root,
            max_file_bytes=config.storage.max_media_bytes,
        ):
            pass
    except (OSError, PathBoundaryViolation):
        raise PilotOperationsBoundaryError(
            PilotOperationsBoundaryCode.WORKSPACE_BOUNDARY_REJECTED
        ) from None
    return controlled_run_id


def build_pilot_run_request(
    *,
    config: AppConfig,
    run_id: str,
    video_path: Path,
    project_root: Path,
    resume: bool,
) -> PilotRunRequest:
    """Bind a safe local MP4 to its content hash and the validated pilot config."""

    controlled_run_id = validate_pilot_run_scope(
        config=config,
        run_id=run_id,
        project_root=project_root,
    )
    if not isinstance(video_path, Path) or video_path.is_absolute():
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_PATH_INVALID)
    try:
        relative_video = require_safe_relative_posix_path(video_path.as_posix())
    except (TypeError, ValueError):
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_PATH_INVALID) from None
    if not relative_video.lower().endswith(".mp4"):
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_PATH_INVALID)

    try:
        with (
            SecureWorkspace(
                project_root.absolute(),
                max_file_bytes=MAX_PILOT_VIDEO_BYTES,
            ) as input_workspace,
            input_workspace.open_verified_video(
                relative_video,
                max_bytes=MAX_PILOT_VIDEO_BYTES,
            ) as video,
        ):
            if video.size_bytes == 0:
                raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.VIDEO_EMPTY)
            video_sha256 = video.input_file_sha256
    except PilotOperationsBoundaryError:
        raise
    except PathBoundaryViolation as error:
        code = (
            PilotOperationsBoundaryCode.VIDEO_MISSING
            if error.reason_code == "FILE_MISSING"
            else PilotOperationsBoundaryCode.VIDEO_BOUNDARY_REJECTED
        )
        raise PilotOperationsBoundaryError(code) from None
    except OSError:
        raise PilotOperationsBoundaryError(
            PilotOperationsBoundaryCode.VIDEO_BOUNDARY_REJECTED
        ) from None

    pilot = config.pilot
    if pilot is None:  # Kept local so type narrowing survives future refactors.
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.PILOT_CONFIG_MISSING)
    return PilotRunRequest(
        run_id=controlled_run_id,
        config_sha256=config.config_sha256,
        video_relative_path=relative_video,
        video_sha256=video_sha256,
        selected_rules=pilot.selected_rules,
        resume=resume,
        max_cases=pilot.max_cases,
    )


def build_expected_perception_manifest(config: AppConfig) -> PilotPerceptionExecutionManifest:
    """Build the manifest the isolated worker must reproduce after runtime checks."""

    perception = config.perception
    worker = perception.worker
    detector = perception.detector_manifest
    tracker = perception.tracker_manifest
    tracker_thresholds = perception.tracker_thresholds
    if (
        perception.provider != "local-worker"
        or worker is None
        or detector is None
        or tracker is None
        or tracker_thresholds is None
    ):
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.PILOT_CONFIG_MISSING)
    return PilotPerceptionExecutionManifest(
        protocol_version=worker.protocol_version,
        detector=detector,
        tracker=tracker,
        prompts={
            "person": perception.detector.prompts["person"],
            "goggles": perception.detector.prompts["goggles"],
        },
        device=worker.device,
        score_threshold=perception.detector.score_threshold,
        high_confidence_threshold=perception.detector.high_confidence_threshold,
        bbox_policy="CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1",
        empty_detection_policy="TRANSFORMERS_EMPTY_TEXT_LABEL_SENTINEL_V1",
        goggles_nms_iou_threshold=0.95,
        tracker_initialization_policy="ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1",
        tracker_thresholds=tracker_thresholds,
        software_versions=dict(worker.required_software_versions),
    )


def _resolve_worker_python(config: AppConfig, project_root: Path) -> str:
    worker = config.perception.worker
    if worker is None:
        raise PerceptionWorkerCrashed("perception worker configuration is unavailable")
    configured = os.environ.get(worker.python_executable_env)
    candidates = ((Path(configured),) if configured else ()) + (
        project_root / ".venv-perception" / "Scripts" / "python.exe",
        project_root / ".venv-perception" / "bin" / "python",
    )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file():
            return str(resolved)
    raise PerceptionWorkerCrashed("isolated perception Python is unavailable")


def _artifact_bytes(model: object) -> bytes:
    payload = model.model_dump(mode="json") if isinstance(model, BaseModel) else model
    return (canonical_json(payload) + "\n").encode("utf-8")


def _publish_immutable(
    workspace: SecureWorkspace,
    relative_path: str,
    data: bytes,
) -> None:
    digest = hashlib.sha256(data).hexdigest()
    try:
        workspace.create_new(relative_path, data, digest)
    except ArtifactConflict:
        workspace.read_verified(relative_path, digest)


def _publish_first_receipts(
    workspace: SecureWorkspace,
    relative_path: str,
    data: bytes,
) -> None:
    digest = hashlib.sha256(data).hexdigest()
    try:
        workspace.create_new(relative_path, data, digest)
    except ArtifactConflict:
        workspace.read_verified(relative_path)


def _completion_artifact_receipt(
    *,
    workspace: SecureWorkspace,
    role: PilotPerceptionArtifactRole,
    relative_path: str,
) -> PilotPerceptionArtifactReceipt:
    snapshot = workspace.read_verified(relative_path)
    return PilotPerceptionArtifactReceipt(
        role=role,
        artifact_ref=f"runs/{relative_path}",
        artifact_sha256=snapshot.sha256,
        artifact_size_bytes=snapshot.size_bytes,
    )


def _completed_artifact_payloads(
    *,
    workspace: SecureWorkspace,
    completion: PilotPerceptionCompletionManifest,
) -> dict[PilotPerceptionArtifactRole, bytes]:
    payloads: dict[PilotPerceptionArtifactRole, bytes] = {}
    for artifact in completion.artifacts:
        relative_path = artifact.artifact_ref.removeprefix("runs/")
        snapshot = workspace.read_verified(
            relative_path,
            artifact.artifact_sha256,
            max_bytes=artifact.artifact_size_bytes,
        )
        if snapshot.size_bytes != artifact.artifact_size_bytes:
            raise ManifestMismatch("completed A1 artifact size does not match its receipt")
        payloads[artifact.role] = snapshot.bytes
    return payloads


def _parse_completed_jsonl(
    data: bytes,
    *,
    artifact_name: str,
) -> tuple[bytes, ...]:
    if not data or not data.endswith(b"\n"):
        raise ManifestMismatch(f"completed {artifact_name} is not canonical JSONL")
    lines = tuple(data.splitlines())
    if not lines or any(not line for line in lines):
        raise ManifestMismatch(f"completed {artifact_name} contains an empty record")
    return lines


def _validate_completed_perception_artifacts(
    *,
    workspace: SecureWorkspace,
    request: PilotRunRequest,
    expected_manifest: PilotPerceptionExecutionManifest,
    completion: PilotPerceptionCompletionManifest,
) -> CompletedPilotPerception:
    try:
        payloads = _completed_artifact_payloads(
            workspace=workspace,
            completion=completion,
        )
        report = PilotPerceptionReport.model_validate_json(payloads["REPORT"])
        execution = PilotPerceptionExecutionManifest.model_validate_json(
            payloads["EXECUTION_MANIFEST"]
        )
        stream = StreamManifest.model_validate_json(payloads["VIDEO_MANIFEST"])
        bundles = tuple(
            FrameBundle.model_validate_json(line)
            for line in _parse_completed_jsonl(
                payloads["FRAME_BUNDLES"],
                artifact_name="FrameBundle inventory",
            )
        )
        receipts = tuple(
            PilotPerceptionFrameReceipt.model_validate_json(line)
            for line in _parse_completed_jsonl(
                payloads["FRAME_RECEIPTS"],
                artifact_name="frame receipt inventory",
            )
        )
    except (LabCourtError, ValidationError, UnicodeError, ValueError):
        raise ManifestMismatch("completed A1 artifact inventory is invalid") from None

    if (
        report.run_id != request.run_id
        or report.manifest_id != expected_manifest.manifest_id
        or report.provider_failures != 0
        or execution != expected_manifest
        or stream.input_file_sha256 != request.video_sha256
        or report.frames_processed != stream.frame_count
        or len(bundles) != stream.frame_count
        or len(receipts) != stream.frame_count
    ):
        raise ManifestMismatch("completed A1 artifacts do not match the request and report")

    expected_preview = f"runs/{request.run_id}/debug/perception-preview.mp4"
    has_preview = "PREVIEW" in payloads
    if (report.preview_path == expected_preview) != has_preview:
        raise ManifestMismatch("completed A1 preview inventory is inconsistent")

    receipt_by_frame = {receipt.frame_id: receipt for receipt in receipts}
    if len(receipt_by_frame) != len(receipts):
        raise ManifestMismatch("completed A1 receipts contain duplicate frame identities")

    detection_count = 0
    person_count = 0
    goggles_count = 0
    tracks: set[str] = set()
    tracker_epoch = f"t{request.video_sha256[:16]}"
    for frame_index, bundle in enumerate(bundles):
        frame = bundle.frame
        if (
            frame.camera_id != stream.camera_id
            or frame.stream_id != stream.stream_id
            or frame.frame_index != frame_index
            or frame.fps_num != stream.fps_num
            or frame.fps_den != stream.fps_den
            or frame.width != stream.width
            or frame.height != stream.height
            or frame.content_sha256 is None
        ):
            raise ManifestMismatch("completed A1 FrameBundle stream identity is invalid")
        receipt = receipt_by_frame.get(frame.frame_id)
        if receipt is None or receipt.frame_content_sha256 != frame.content_sha256:
            raise ManifestMismatch("completed A1 frame receipt does not bind its FrameBundle")
        expected_raw_ref = f"runs/{request.run_id}/raw/perception/{receipt.request_id}.json"
        if receipt.raw_response_ref != expected_raw_ref:
            raise ManifestMismatch("completed A1 raw response path is not request-scoped")
        try:
            raw_snapshot = workspace.read_verified(
                receipt.raw_response_ref.removeprefix("runs/"),
                receipt.raw_response_sha256,
            )
            raw_result = parse_perception_worker_result(raw_snapshot.bytes)
        except LabCourtError:
            raise ManifestMismatch("completed A1 raw response is missing or invalid") from None
        if not isinstance(raw_result, PilotPerceptionWorkerResponse) or (
            raw_result.request_id != receipt.request_id
            or raw_result.frame_id != receipt.frame_id
            or raw_result.frame_content_sha256 != receipt.frame_content_sha256
            or raw_result.manifest_id != expected_manifest.manifest_id
        ):
            raise ManifestMismatch("completed A1 raw response identity is invalid")
        mapped = map_perception_worker_detections(
            frame=frame,
            manifest=expected_manifest,
            tracker_epoch=tracker_epoch,
            request_id=receipt.request_id,
            detections=raw_result.detections,
        )
        if mapped != bundle.detections:
            raise ManifestMismatch("completed A1 detections diverge from the raw response")
        detection_count += len(mapped)
        person_count += sum(item.label == "person" for item in mapped)
        goggles_count += sum(item.label == "goggles" for item in mapped)
        tracks.update(item.track_ref for item in mapped if item.track_ref is not None)

    if (
        report.detection_count != detection_count
        or report.person_count != person_count
        or report.goggles_count != goggles_count
        or report.track_count != len(tracks)
    ):
        raise ManifestMismatch("completed A1 report counts diverge from its FrameBundles")
    return CompletedPilotPerception(
        report=report,
        execution_manifest=execution,
        stream_manifest=stream,
        bundles=bundles,
        completion_manifest=completion,
    )


class _CurrentFramePixels:
    __slots__ = ("_current",)

    def __init__(self) -> None:
        self._current: RGB8Frame | None = None

    def bind(self, frame: RGB8Frame) -> None:
        self._current = frame

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        current = self._current
        if current is None or current.frame.frame_id != frame_id:
            raise ManifestMismatch("sequential pixel provider received a stale frame request")
        return current


def _resume_perception_report(
    *,
    workspace: SecureWorkspace,
    request: PilotRunRequest,
    expected_manifest: PilotPerceptionExecutionManifest,
) -> PilotPerceptionReport | None:
    if not request.resume:
        return None
    completion_path = f"{request.run_id}/perception/completion-manifest.json"
    try:
        completion_snapshot = workspace.read_verified(completion_path)
    except PathBoundaryViolation as error:
        if error.reason_code == "FILE_MISSING":
            return None
        raise
    try:
        completion = PilotPerceptionCompletionManifest.model_validate_json(
            completion_snapshot.bytes
        )
    except ValidationError:
        raise ManifestMismatch("persisted pilot perception completion is invalid") from None
    if (
        completion.run_id != request.run_id
        or completion.config_sha256 != request.config_sha256
        or completion.video_sha256 != request.video_sha256
        or completion.manifest_id != expected_manifest.manifest_id
    ):
        raise ManifestMismatch("persisted pilot perception completion does not match the request")
    return _validate_completed_perception_artifacts(
        workspace=workspace,
        request=request,
        expected_manifest=expected_manifest,
        completion=completion,
    ).report


def load_completed_pilot_perception(
    *,
    workspace: SecureWorkspace,
    config: AppConfig,
    request: PilotRunRequest,
) -> CompletedPilotPerception:
    """Load A1 only through its completion seal and raw-response verification."""

    if not isinstance(workspace, SecureWorkspace):
        raise TypeError("workspace must be a SecureWorkspace")
    expected_manifest = build_expected_perception_manifest(config)
    completion_path = f"{request.run_id}/perception/completion-manifest.json"
    try:
        completion_snapshot = workspace.read_verified(completion_path)
        completion = PilotPerceptionCompletionManifest.model_validate_json(
            completion_snapshot.bytes
        )
    except (LabCourtError, ValidationError):
        raise ManifestMismatch("completed pilot perception seal is unavailable") from None
    if (
        completion.run_id != request.run_id
        or completion.config_sha256 != request.config_sha256
        or completion.video_sha256 != request.video_sha256
        or completion.manifest_id != expected_manifest.manifest_id
    ):
        raise ManifestMismatch("completed pilot perception seal does not match the request")
    return _validate_completed_perception_artifacts(
        workspace=workspace,
        request=request,
        expected_manifest=expected_manifest,
        completion=completion,
    )


def run_pilot_perception(
    *,
    config: AppConfig,
    request: PilotRunRequest,
    config_path: Path,
    project_root: Path,
    decoder_backend: VideoDecoderBackend | None = None,
    raw_transport: RawPerceptionWorkerTransport | None = None,
) -> PilotPerceptionReport:
    """Decode a verified MP4 and publish a complete, resumable A1 perception run."""

    if request.config_sha256 != config.config_sha256:
        raise ManifestMismatch("pilot request configuration identity changed")
    pilot = config.pilot
    worker_config = config.perception.worker
    if pilot is None or worker_config is None:
        raise PilotOperationsBoundaryError(PilotOperationsBoundaryCode.PILOT_CONFIG_MISSING)
    expected_manifest = build_expected_perception_manifest(config)
    root = project_root.absolute()
    runs_root = root / config.run.workspace
    backend = decoder_backend if decoder_backend is not None else OpenCvDecoderBackend()

    with (
        SecureWorkspace(root, max_file_bytes=MAX_PILOT_VIDEO_BYTES) as input_workspace,
        SecureWorkspace(
            runs_root,
            max_file_bytes=config.storage.max_media_bytes,
        ) as run_workspace,
    ):
        resumed = _resume_perception_report(
            workspace=run_workspace,
            request=request,
            expected_manifest=expected_manifest,
        )
        if resumed is not None:
            return resumed

        stream_id = f"video-{request.video_sha256[:16]}"
        camera_ids = {zone.camera_id for zone in config.zones}
        if len(camera_ids) != 1:
            raise ManifestMismatch("pilot perception requires exactly one configured camera")
        stream_manifest = probe_caller_attested_stream_manifest(
            camera_id=next(iter(camera_ids)),
            stream_id=stream_id,
            input_file_sha256=request.video_sha256,
            verified_input=cast(VerifiedVideoInput, input_workspace),
            relative_path=request.video_relative_path,
            max_input_bytes=MAX_PILOT_VIDEO_BYTES,
            max_frame_pixels=config.storage.max_image_pixels,
            max_total_decoded_pixels=config.storage.max_image_pixels * MAX_PILOT_FRAMES,
            backend=backend,
        )
        if stream_manifest.frame_count > MAX_PILOT_FRAMES:
            raise BudgetExceeded("pilot video exceeds the maximum frame count")
        source = OpenCvVideoSource(
            manifest=stream_manifest,
            verified_input=cast(VerifiedVideoInput, input_workspace),
            relative_path=request.video_relative_path,
            max_input_bytes=MAX_PILOT_VIDEO_BYTES,
            max_frame_pixels=config.storage.max_image_pixels,
            max_total_decoded_pixels=config.storage.max_image_pixels * MAX_PILOT_FRAMES,
            backend=backend,
        )

        selected_transport = raw_transport
        if selected_transport is None:
            python = _resolve_worker_python(config, root)
            selected_transport = JsonlPerceptionWorkerClient(
                command=(
                    python,
                    "-u",
                    "-m",
                    worker_config.module,
                    "--config",
                    str(config_path.resolve(strict=True)),
                ),
                expected_manifest=expected_manifest,
                startup_timeout_seconds=worker_config.startup_timeout_seconds,
                frame_timeout_seconds=worker_config.frame_timeout_seconds,
                max_request_bytes=worker_config.max_request_bytes,
                max_response_bytes=worker_config.max_response_bytes,
            )
        if selected_transport.manifest != expected_manifest:
            selected_transport.close()
            raise ManifestMismatch("perception transport manifest does not match configuration")

        cached_transport = CachedPerceptionWorkerTransport(
            transport=selected_transport,
            workspace=run_workspace,
            run_id=request.run_id,
        )
        for directory in (
            f"{request.run_id}/input",
            f"{request.run_id}/perception",
            f"{request.run_id}/debug",
        ):
            run_workspace.ensure_private_directory(directory)

        preview_relative = f"{request.run_id}/debug/perception-preview.mp4"
        preview_ref = f"runs/{preview_relative}" if pilot.write_debug_preview else None
        preview: OpenCvPerceptionPreview | None = None
        if pilot.write_debug_preview:
            preview = OpenCvPerceptionPreview(
                width=stream_manifest.width,
                height=stream_manifest.height,
                fps=stream_manifest.fps_num / stream_manifest.fps_den,
            )

        pixels = _CurrentFramePixels()
        provider = LocalWorkerPerceptionProvider(
            pixels=pixels,
            transport=cached_transport,
            tracker_epoch=f"t{request.video_sha256[:16]}",
        )
        bundle_lines = bytearray()
        detection_count = 0
        person_count = 0
        goggles_count = 0
        tracks: set[str] = set()
        frames_processed = 0
        try:
            for rgb8 in source.iter_rgb8():
                pixels.bind(rgb8)
                frame_data = FrameData(
                    frame=rgb8.frame,
                    media_ref=(
                        f"verified-video/{rgb8.frame.camera_id}/"
                        f"{rgb8.frame.stream_id}/{rgb8.frame.frame_index}"
                    ),
                    ephemeral=True,
                )
                detections = tuple(provider.detect(frame_data))
                bundle = FrameBundle(frame=rgb8.frame, detections=detections)
                line = _artifact_bytes(bundle)
                if len(bundle_lines) + len(line) > config.storage.max_media_bytes:
                    raise BudgetExceeded("pilot FrameBundle artifact exceeded its byte budget")
                bundle_lines.extend(line)
                frames_processed += 1
                detection_count += len(detections)
                person_count += sum(item.label == "person" for item in detections)
                goggles_count += sum(item.label == "goggles" for item in detections)
                tracks.update(item.track_ref for item in detections if item.track_ref is not None)
                if preview is not None:
                    preview.add(rgb8, detections)
            if preview is not None:
                preview_bytes = preview.finish(max_bytes=config.storage.max_media_bytes)
                _publish_immutable(run_workspace, preview_relative, preview_bytes)
                preview = None
        finally:
            if preview is not None:
                preview.close()
            cached_transport.close()

        report = PilotPerceptionReport(
            run_id=request.run_id,
            frames_processed=frames_processed,
            detection_count=detection_count,
            person_count=person_count,
            goggles_count=goggles_count,
            track_count=len(tracks),
            provider_failures=0,
            manifest_id=expected_manifest.manifest_id,
            preview_path=preview_ref,
        )
        _publish_immutable(
            run_workspace,
            f"{request.run_id}/input/video-manifest.json",
            _artifact_bytes(stream_manifest),
        )
        _publish_immutable(
            run_workspace,
            f"{request.run_id}/perception/execution-manifest.json",
            _artifact_bytes(expected_manifest),
        )
        _publish_immutable(
            run_workspace,
            f"{request.run_id}/perception/frame-bundles.jsonl",
            bytes(bundle_lines),
        )
        receipt_bytes = b"".join(_artifact_bytes(item) for item in cached_transport.receipts)
        _publish_first_receipts(
            run_workspace,
            f"{request.run_id}/perception/frame-receipts.jsonl",
            receipt_bytes,
        )
        _publish_immutable(
            run_workspace,
            f"{request.run_id}/perception/report.json",
            _artifact_bytes(report),
        )
        artifact_specs: list[tuple[PilotPerceptionArtifactRole, str]] = [
            ("VIDEO_MANIFEST", f"{request.run_id}/input/video-manifest.json"),
            (
                "EXECUTION_MANIFEST",
                f"{request.run_id}/perception/execution-manifest.json",
            ),
            ("FRAME_BUNDLES", f"{request.run_id}/perception/frame-bundles.jsonl"),
            ("FRAME_RECEIPTS", f"{request.run_id}/perception/frame-receipts.jsonl"),
            ("REPORT", f"{request.run_id}/perception/report.json"),
        ]
        if preview_ref is not None:
            artifact_specs.append(("PREVIEW", f"{request.run_id}/debug/perception-preview.mp4"))
        completion = PilotPerceptionCompletionManifest(
            run_id=request.run_id,
            config_sha256=request.config_sha256,
            video_sha256=request.video_sha256,
            manifest_id=expected_manifest.manifest_id,
            artifacts=tuple(
                _completion_artifact_receipt(
                    workspace=run_workspace,
                    role=role,
                    relative_path=relative_path,
                )
                for role, relative_path in artifact_specs
            ),
        )
        _publish_immutable(
            run_workspace,
            f"{request.run_id}/perception/completion-manifest.json",
            _artifact_bytes(completion),
        )
        return report
