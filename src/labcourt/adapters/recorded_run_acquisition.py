"""Real M8 acquisition tools over one immutable recorded-run source."""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn, cast

from pydantic import BaseModel, ValidationError

from labcourt.adapters.m8_run_source import (
    M8RecordedRunSourceResolutionError,
    ManifestBoundRecordedRunSourceResolver,
)
from labcourt.adapters.opencv_video import (
    OpenCvDecoderBackend,
    OpenCvVideoSource,
    VerifiedVideoInput,
    VideoDecoderBackend,
)
from labcourt.adapters.pillow_frame_store import PillowFrameStore
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    ArtifactKind,
    CropSource,
    ObjectiveFactKind,
    VerificationStatus,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    RecropParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    ToolResult,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    ToolExecutionManifest,
    derive_m4_tool_result_id,
)
from labcourt.contracts.m8_acquisition_v2 import (
    M8AcquisitionFailureCode,
    M8AcquisitionM4ExecutionV1,
    M8AcquisitionM4Representability,
    M8AcquisitionOutcomeStatus,
    M8AcquisitionRawReceiptV1,
    M8HearingAcquisitionResultV2,
    M8RedetectionDetectorRequestV1,
    M8RedetectionOutcomeV1,
    M8ResolvedRecordedRunSourceV1,
    M8TrackConfidencePointStatus,
    M8TrackConfidencePointV1,
    M8TrackConfidenceSeriesV1,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import parse_frame_id, parse_track_ref
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    EvidenceAuthority,
    EvidenceAuthorityError,
    LoadedEvidenceObjects,
    derive_evidence_authority,
    derive_evidence_pack_successor,
    derive_recrop_source_refs,
)
from labcourt.exceptions import ArtifactConflict, LabCourtError, PathBoundaryViolation
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionDeliveryCertainty,
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)
from labcourt.ports.m8_acquisition import (
    M8AcquisitionOutcomeRepository,
    M8HighResolutionRedetector,
    M8RecordedRunSourceResolver,
)

_RECORDED_COMPONENT_ID = sha256_hex(
    ["m8-recorded-run-acquisition-component", 2, "labcourt", "0.1.0"]
)


class _InvalidRedetectionResponse(ValueError):
    def __init__(self, receipt: M8AcquisitionRawReceiptV1) -> None:
        self.receipt = receipt
        super().__init__("redetection response violates its strict contract")


class _RedetectionInvocationFailure(RuntimeError):
    def __init__(
        self,
        failure_code: M8AcquisitionFailureCode,
        certainty: HearingAcquisitionDeliveryCertainty,
    ) -> None:
        self.failure_code = failure_code
        self.certainty = certainty
        super().__init__(f"redetection invocation failed: {failure_code.value}")


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _strict_json_object(raw: bytes) -> Mapping[str, object]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise ValueError("redetection worker emitted invalid strict JSON") from None
    if not isinstance(parsed, dict):
        raise ValueError("redetection worker response must be one JSON object")
    return cast(Mapping[str, object], parsed)


def _parameter_schema_sha256(action: AcquisitionAction, model: type[BaseModel]) -> str:
    schema = model.model_json_schema
    return sha256_hex(
        ["m4-acquisition-parameters-schema", 1, action.value, schema(mode="validation")]
    )


class RecordedRunFrameAcquisitionExecutor:
    """Execute recorded-video acquisition without fixture or provider fallback."""

    __slots__ = (
        "_backend",
        "_manifest",
        "_max_frame_pixels",
        "_max_input_bytes",
        "_max_media_bytes",
        "_outcome_repository",
        "_project_root",
        "_redetector",
        "_source_resolver",
        "_workspace",
    )

    def __init__(
        self,
        *,
        project_root: Path,
        manifest: RunManifest,
        max_input_bytes: int,
        max_frame_pixels: int,
        input_relative_path: str | None = None,
        source_resolver: M8RecordedRunSourceResolver | None = None,
        workspace: SecureWorkspace | None = None,
        max_media_bytes: int | None = None,
        redetector: M8HighResolutionRedetector | None = None,
        outcome_repository: M8AcquisitionOutcomeRepository | None = None,
        decoder_backend: VideoDecoderBackend | None = None,
    ) -> None:
        if not isinstance(project_root, Path):
            raise TypeError("recorded acquisition project_root must be a Path")
        if not isinstance(manifest, RunManifest):
            raise TypeError("recorded acquisition requires a RunManifest")
        for name, value in (
            ("max_input_bytes", max_input_bytes),
            ("max_frame_pixels", max_frame_pixels),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        selected_media_limit = max_input_bytes if max_media_bytes is None else max_media_bytes
        if (
            not isinstance(selected_media_limit, int)
            or isinstance(selected_media_limit, bool)
            or selected_media_limit <= 0
        ):
            raise ValueError("max_media_bytes must be a positive integer")
        selected_root = project_root.absolute()
        if source_resolver is None:
            if input_relative_path is None:
                raise ValueError("recorded acquisition requires a persisted source resolver")
            selected_resolver: M8RecordedRunSourceResolver = ManifestBoundRecordedRunSourceResolver(
                project_root=selected_root,
                input_relative_path=input_relative_path,
            )
        else:
            selected_resolver = source_resolver
            if selected_resolver.project_root.absolute() != selected_root:
                raise ValueError("source resolver project root conflicts with executor root")
            if input_relative_path is not None:
                raise ValueError("persisted source resolver cannot be mixed with a global path")
        if workspace is not None and not isinstance(workspace, SecureWorkspace):
            raise TypeError("recorded acquisition workspace must be a SecureWorkspace")

        self._project_root = selected_root
        self._manifest = manifest
        self._max_input_bytes = max_input_bytes
        self._max_frame_pixels = max_frame_pixels
        self._max_media_bytes = selected_media_limit
        self._backend = decoder_backend or OpenCvDecoderBackend()
        self._source_resolver = selected_resolver
        self._workspace = workspace
        self._redetector = redetector
        self._outcome_repository = outcome_repository

    @property
    def execution_mode(self) -> AcquisitionExecutionMode:
        return (
            AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL
            if self._redetector is not None
            else AcquisitionExecutionMode.PURE
        )

    def execute(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> AcquisitionExecution:
        typed_request = self._require_request(request)
        typed_authority = self._require_authority(authority)
        if idempotency_key != typed_request.request_id:
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        self._validate_scope(typed_request, typed_authority)
        binding = self._resolve_source(typed_request)

        existing = self._load_outcome(typed_request)
        if existing is not None:
            return self._replay_outcome(existing, typed_request, typed_authority)

        try:
            if typed_request.action == AcquisitionAction.REQUEST_MORE_FRAMES:
                return self._execute_more_frames(typed_request, typed_authority, binding)
            if typed_request.action == AcquisitionAction.RECROP:
                return self._execute_recrop(typed_request, typed_authority, binding)
            if typed_request.action == AcquisitionAction.TRACK_CONFIDENCE_CURVE:
                return self._execute_track_curve(typed_request, typed_authority, binding)
            if typed_request.action == AcquisitionAction.REDETECT_HIGH_RES:
                return self._execute_redetection(
                    typed_request,
                    typed_authority,
                    binding,
                    recovery_only=False,
                )
            self._record_unavailable(
                typed_request,
                M8AcquisitionFailureCode.OTHER_CAMERA_UNAVAILABLE,
            )
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        except HearingAcquisitionExecutorError:
            raise
        except (EvidenceAuthorityError, LabCourtError, OSError, TypeError, ValueError):
            self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)

    def recover(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> HearingAcquisitionRecovery:
        typed_request = self._require_request(request)
        typed_authority = self._require_authority(authority)
        if idempotency_key != typed_request.request_id:
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        self._validate_scope(typed_request, typed_authority)
        binding = self._resolve_source(typed_request)
        existing = self._load_outcome(typed_request)
        if existing is not None:
            if existing.m4_execution is None:
                return HearingAcquisitionRecovery(status=HearingAcquisitionRecoveryStatus.UNKNOWN)
            execution = self._execution_from_snapshot(
                existing.m4_execution,
                typed_request,
                typed_authority,
            )
            return HearingAcquisitionRecovery(
                status=HearingAcquisitionRecoveryStatus.COMPLETED,
                execution=execution,
            )
        if typed_request.action == AcquisitionAction.REDETECT_HIGH_RES:
            try:
                execution = self._execute_redetection(
                    typed_request,
                    typed_authority,
                    binding,
                    recovery_only=True,
                )
            except HearingAcquisitionExecutorError:
                return HearingAcquisitionRecovery(status=HearingAcquisitionRecoveryStatus.UNKNOWN)
            return HearingAcquisitionRecovery(
                status=HearingAcquisitionRecoveryStatus.COMPLETED,
                execution=execution,
            )
        return HearingAcquisitionRecovery(
            status=HearingAcquisitionRecoveryStatus.DEFINITELY_NOT_STARTED
        )

    def load_m8_outcome(
        self,
        request_id: str,
        run_id: str,
    ) -> M8HearingAcquisitionResultV2 | None:
        """Read the additive result without exposing workspace paths to callers."""

        if self._outcome_repository is not None:
            return self._outcome_repository.get(run_id, request_id)
        if self._workspace is None:
            return None
        path = self._outcome_path(run_id, request_id)
        try:
            snapshot = self._workspace.read_verified(path)
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
        return M8HearingAcquisitionResultV2.model_validate_json(snapshot.bytes)

    def list_m8_outcomes(
        self,
        run_id: str,
        case_id: str,
    ) -> tuple[M8HearingAcquisitionResultV2, ...]:
        """List durable results for one platform/M4 Case after service restart."""

        if self._outcome_repository is None:
            raise RuntimeError("M8 outcome listing requires a persisted outcome repository")
        return self._outcome_repository.list_for_case(run_id, case_id)

    def _execute_more_frames(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        binding: M8ResolvedRecordedRunSourceV1,
    ) -> AcquisitionExecution:
        parameters = request.validated_parameters
        if not isinstance(parameters, RequestMoreFramesParameters):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        stream = self._manifest.streams[0]
        if (parameters.camera_id, parameters.stream_id) != (
            binding.camera_id,
            binding.stream_id,
        ) or parameters.end_frame_exclusive > binding.frame_count:
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        requested_frame_ids = {
            f"{parameters.camera_id}:{parameters.stream_id}:{frame_index}"
            for frame_index in range(
                parameters.start_frame,
                parameters.end_frame_exclusive,
                parameters.step,
            )
        }
        existing_frame_ids = {
            ref.artifact_id
            for ref in authority.pack.expected_closure_refs()
            if ref.kind == ArtifactKind.FRAME
        }
        if requested_frame_ids & existing_frame_ids:
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        with self._video_source(binding) as source:
            selected = source.get_range(
                parameters.camera_id,
                parameters.stream_id,
                parameters.start_frame,
                parameters.end_frame_exclusive,
                parameters.step,
            )
        frames = tuple(item.frame for item in selected)
        expected_indexes = tuple(
            range(
                parameters.start_frame,
                parameters.end_frame_exclusive,
                parameters.step,
            )
        )
        if tuple(frame.frame_index for frame in frames) != expected_indexes:
            self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
        component = self._manifest.software_components.get(stream.software_component)
        if component is None:
            self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
        component_id = hashlib.sha256(
            canonical_json(component.model_dump(mode="json")).encode("utf-8")
        ).hexdigest()
        execution = self._build_execution(
            request=request,
            authority=authority,
            outputs=LoadedEvidenceObjects(frames=frames),
            input_refs=(self._pack_ref(request),),
            tool_id="recorded-run-request-more-frames",
            component_manifest_id=component_id,
            parameter_model=RequestMoreFramesParameters,
        )
        self._record_success(execution)
        return execution

    def _execute_recrop(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        binding: M8ResolvedRecordedRunSourceV1,
    ) -> AcquisitionExecution:
        parameters = request.validated_parameters
        if not isinstance(parameters, RecropParameters):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        if self._workspace is None:
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        camera_id, stream_id, frame_index = parse_frame_id(parameters.frame_id)
        stream = self._manifest.streams[0]
        if (camera_id, stream_id) != (
            binding.camera_id,
            binding.stream_id,
        ) or frame_index >= binding.frame_count:
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        parameters.bbox.require_within(stream.width, stream.height)
        source_refs = derive_recrop_source_refs(authority, parameters)
        crop_source_ref = next(
            (ref for ref in source_refs if ref.kind == ArtifactKind.CROP),
            None,
        )
        source_crop = next(
            (
                crop
                for crop in authority.crops
                if crop_source_ref is not None and crop.crop_id == crop_source_ref.artifact_id
            ),
            None,
        )
        if source_crop is None:
            self._record_unavailable(
                request,
                M8AcquisitionFailureCode.RECROP_AUTHORITY_MISSING,
            )
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        privacy = source_crop.privacy_receipt
        if (
            privacy.transform_version != self._manifest.privacy_transform_version
            or source_crop.encoding_version != self._manifest.image_encoding_version
        ):
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        crop_request = CropRequest(
            frame_id=parameters.frame_id,
            source=CropSource.RECROP,
            bbox=parameters.bbox,
            output_width=parameters.bbox.width,
            output_height=parameters.bbox.height,
            source_refs=source_refs,
            privacy_policy=privacy.policy,
            privacy_transform_version=privacy.transform_version,
            encoding_version=source_crop.encoding_version,
            primary_track_ref=source_crop.primary_track_ref,
            ppe_type=privacy.ppe_type,
            anchor_type=privacy.anchor_type,
            anchor_bbox=privacy.anchor_bbox,
            keypoints=privacy.keypoints,
            association_method=privacy.association_method,
            observability=source_crop.observability,
            tags=source_crop.tags,
        )
        with self._video_source(binding) as source:
            store = PillowFrameStore(
                run_id=request.run_id,
                workspace=self._workspace,
                pixels=source,
                max_media_bytes=self._max_media_bytes,
                max_image_pixels=self._max_frame_pixels,
            )
            if store.verify_crop(source_crop).status != VerificationStatus.VERIFIED:
                self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
            crop = store.create_crop(crop_request)
            component_id = hashlib.sha256(
                canonical_json(store.software_component.model_dump(mode="json")).encode("utf-8")
            ).hexdigest()
        execution = self._build_execution(
            request=request,
            authority=authority,
            outputs=LoadedEvidenceObjects(crops=(crop,)),
            input_refs=tuple(
                sorted((self._pack_ref(request), *source_refs), key=lambda ref: ref.sort_key)
            ),
            tool_id="recorded-run-recrop",
            component_manifest_id=component_id,
            parameter_model=RecropParameters,
            crop_request=crop_request,
        )
        self._record_success(execution)
        return execution

    def _execute_track_curve(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        binding: M8ResolvedRecordedRunSourceV1,
    ) -> AcquisitionExecution:
        parameters = request.validated_parameters
        if not isinstance(parameters, TrackConfidenceCurveParameters):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        track_camera, _, _ = parse_track_ref(parameters.track_ref)
        if (
            track_camera != binding.camera_id
            or parameters.end_frame_exclusive > binding.frame_count
        ):
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        by_index: dict[int, Detection] = {}
        for detection in authority.loaded_objects.detections:
            if detection.track_ref != parameters.track_ref:
                continue
            camera_id, stream_id, frame_index = parse_frame_id(detection.frame_id)
            if (
                camera_id != binding.camera_id
                or stream_id != binding.stream_id
                or not parameters.start_frame <= frame_index < parameters.end_frame_exclusive
            ):
                continue
            if frame_index in by_index:
                self._record_failure(
                    request,
                    M8AcquisitionFailureCode.TRACK_DATA_AMBIGUOUS,
                )
                self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
            by_index[frame_index] = detection
        if not by_index:
            self._record_failure(request, M8AcquisitionFailureCode.TRACK_DATA_MISSING)
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        points = tuple(
            (
                M8TrackConfidencePointV1(
                    frame_index=index,
                    frame_id=by_index[index].frame_id,
                    status=M8TrackConfidencePointStatus.OBSERVED,
                    score=by_index[index].score,
                    detection_id=by_index[index].detection_id,
                )
                if index in by_index
                else M8TrackConfidencePointV1(
                    frame_index=index,
                    status=M8TrackConfidencePointStatus.MISSING,
                )
            )
            for index in range(parameters.start_frame, parameters.end_frame_exclusive)
        )
        scores = tuple(float(item.score) for item in points if item.score is not None)
        series = M8TrackConfidenceSeriesV1(
            run_id=request.run_id,
            case_id=request.case_id,
            acquisition_request_id=request.request_id,
            track_ref=parameters.track_ref,
            start_frame=parameters.start_frame,
            end_frame_exclusive=parameters.end_frame_exclusive,
            points=points,
            observed_count=len(scores),
            mean_score=math.fsum(scores) / len(scores),
            minimum_score=min(scores),
            maximum_score=max(scores),
        )
        manifest = self._tool_manifest(
            request,
            tool_id="recorded-run-track-confidence",
            component_manifest_id=_RECORDED_COMPONENT_ID,
            parameter_model=TrackConfidenceCurveParameters,
        )
        fact_id = f"f{sha256_hex(['m8-track-confidence-aggregate', series.series_id])[:63]}"
        output_refs = (ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id=fact_id),)
        input_refs = (self._pack_ref(request),)
        result_id = derive_m4_tool_result_id(
            request.action,
            input_refs,
            output_refs,
            parameters,
            manifest.execution_manifest_id,
        )
        fact = ObjectiveFact(
            fact_id=fact_id,
            kind=ObjectiveFactKind.DETECTION_SCORE,
            value=series.mean_score,
            source_ref=ArtifactRef(kind=ArtifactKind.TOOL_RESULT, artifact_id=result_id),
            source_manifest_id=manifest.execution_manifest_id,
            unit="mean_score_over_requested_interval",
        )
        result = ToolResult(
            tool_result_id=result_id,
            action=request.action,
            input_refs=input_refs,
            output_refs=output_refs,
            validated_parameters=parameters,
            execution_manifest_id=manifest.execution_manifest_id,
        )
        execution = AcquisitionExecution(
            request=request,
            execution_manifest=manifest,
            tool_result=result,
            output_objects=LoadedEvidenceObjects(objective_facts=(fact,)),
        )
        self._validate_successor(authority, execution)
        self._persist_outcome(
            M8HearingAcquisitionResultV2(
                run_id=request.run_id,
                case_id=request.case_id,
                acquisition_request_id=request.request_id,
                action=request.action,
                status=M8AcquisitionOutcomeStatus.SUCCEEDED,
                m4_representability=(M8AcquisitionM4Representability.M4_V1_REPRESENTABLE),
                track_confidence_series=series,
                m4_execution=self._snapshot(execution),
            )
        )
        return execution

    def _execute_redetection(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        binding: M8ResolvedRecordedRunSourceV1,
        *,
        recovery_only: bool,
    ) -> AcquisitionExecution:
        parameters = request.validated_parameters
        if not isinstance(parameters, RedetectHighResolutionParameters):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        if self._workspace is None or self._redetector is None:
            self._record_unavailable(request, M8AcquisitionFailureCode.DETECTOR_UNAVAILABLE)
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        crop = next((item for item in authority.crops if item.crop_id == parameters.crop_id), None)
        if crop is None or crop.local_path is None:
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        with self._video_source(binding) as source:
            store = PillowFrameStore(
                run_id=request.run_id,
                workspace=self._workspace,
                pixels=source,
                max_media_bytes=self._max_media_bytes,
                max_image_pixels=self._max_frame_pixels,
            )
            if store.verify_crop(crop).status != VerificationStatus.VERIFIED:
                self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        image = self._workspace.read_verified(
            crop.local_path,
            crop.media_sha256,
            max_bytes=self._max_media_bytes,
        ).bytes
        detector_request = M8RedetectionDetectorRequestV1(
            request_id=request.request_id,
            run_id=request.run_id,
            crop_id=crop.crop_id,
            crop_media_sha256=crop.media_sha256,
            frame_id=crop.frame_id,
            crop_bbox=crop.bbox,
            width=crop.output_width,
            height=crop.output_height,
            prompts=parameters.prompts,
            image_base64=base64.b64encode(image).decode("ascii"),
            image_sha256=hashlib.sha256(image).hexdigest(),
            expected_model_manifest_id=self._redetector.model_manifest_id,
        )
        try:
            response, receipt = self._redetection_response(
                detector_request,
                recovery_only=recovery_only,
            )
        except _RedetectionInvocationFailure as failure:
            self._record_failure(request, failure.failure_code)
            self._fail(
                HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID,
                failure.certainty,
            )
        except _InvalidRedetectionResponse as invalid:
            self._persist_outcome(
                M8HearingAcquisitionResultV2(
                    run_id=request.run_id,
                    case_id=request.case_id,
                    acquisition_request_id=request.request_id,
                    action=request.action,
                    status=M8AcquisitionOutcomeStatus.FAILED,
                    m4_representability=(M8AcquisitionM4Representability.V1_UNREPRESENTABLE),
                    failure_code=M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID,
                    raw_receipt=invalid.receipt,
                )
            )
            self._fail(
                HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID,
                HearingAcquisitionDeliveryCertainty.COMPLETED,
            )
        if (
            response.request_id != request.request_id
            or response.crop_id != crop.crop_id
            or response.crop_media_sha256 != crop.media_sha256
            or response.model_manifest_id != self._redetector.model_manifest_id
        ):
            self._record_redetection_failure(
                request,
                response,
                receipt,
                M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID,
                include_response=False,
            )
            self._fail(
                HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID,
                HearingAcquisitionDeliveryCertainty.COMPLETED,
            )
        if response.status == "FAILED":
            self._record_redetection_failure(
                request,
                response,
                receipt,
                M8AcquisitionFailureCode.DETECTOR_FAILED,
            )
            self._fail(
                HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID,
                HearingAcquisitionDeliveryCertainty.COMPLETED,
            )
        if not response.detections:
            self._persist_outcome(
                M8HearingAcquisitionResultV2(
                    run_id=request.run_id,
                    case_id=request.case_id,
                    acquisition_request_id=request.request_id,
                    action=request.action,
                    status=M8AcquisitionOutcomeStatus.SUCCEEDED_EMPTY,
                    m4_representability=(M8AcquisitionM4Representability.V1_UNREPRESENTABLE),
                    failure_code=(M8AcquisitionFailureCode.V1_EMPTY_OUTPUT_UNREPRESENTABLE),
                    raw_receipt=receipt,
                    redetection_outcome=response,
                )
            )
            self._fail(
                HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID,
                HearingAcquisitionDeliveryCertainty.COMPLETED,
            )
        try:
            detections = self._map_redetections(crop, parameters, response)
            execution = self._build_execution(
                request=request,
                authority=authority,
                outputs=LoadedEvidenceObjects(detections=detections),
                input_refs=tuple(
                    sorted(
                        (
                            self._pack_ref(request),
                            ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
                        ),
                        key=lambda ref: ref.sort_key,
                    )
                ),
                tool_id="recorded-run-redetect-high-res",
                component_manifest_id=self._redetector.component_manifest_id,
                parameter_model=RedetectHighResolutionParameters,
                model_manifest_id=self._redetector.model_manifest_id,
            )
        except HearingAcquisitionExecutorError:
            self._record_redetection_failure(
                request,
                response,
                receipt,
                M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID,
            )
            raise
        except (EvidenceAuthorityError, LabCourtError, TypeError, ValueError):
            self._record_redetection_failure(
                request,
                response,
                receipt,
                M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID,
            )
            self._fail(
                HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID,
                HearingAcquisitionDeliveryCertainty.COMPLETED,
            )
        self._persist_outcome(
            M8HearingAcquisitionResultV2(
                run_id=request.run_id,
                case_id=request.case_id,
                acquisition_request_id=request.request_id,
                action=request.action,
                status=M8AcquisitionOutcomeStatus.SUCCEEDED,
                m4_representability=(M8AcquisitionM4Representability.M4_V1_REPRESENTABLE),
                raw_receipt=receipt,
                redetection_outcome=response,
                m4_execution=self._snapshot(execution),
            )
        )
        return execution

    def _redetection_response(
        self,
        request: M8RedetectionDetectorRequestV1,
        *,
        recovery_only: bool,
    ) -> tuple[M8RedetectionOutcomeV1, M8AcquisitionRawReceiptV1]:
        assert self._workspace is not None
        assert self._redetector is not None
        relative_path = f"{request.run_id}/raw/acquisition/{request.request_id}.json"
        cache_hit = False
        try:
            raw_snapshot = self._workspace.read_verified(relative_path)
            raw = raw_snapshot.bytes
            raw_sha256 = raw_snapshot.sha256
            cache_hit = True
        except PathBoundaryViolation as error:
            if error.reason_code != "FILE_MISSING":
                raise
            raw = None
            try:
                if recovery_only:
                    raw = self._redetector.recover(
                        request,
                        idempotency_key=request.request_id,
                    )
                else:
                    raw = self._redetector.execute(
                        request,
                        idempotency_key=request.request_id,
                    )
            except Exception:
                if not recovery_only:
                    try:
                        raw = self._redetector.recover(
                            request,
                            idempotency_key=request.request_id,
                        )
                    except Exception:
                        raw = None
                if raw is None:
                    raise _RedetectionInvocationFailure(
                        M8AcquisitionFailureCode.DETECTOR_FAILED,
                        HearingAcquisitionDeliveryCertainty.UNKNOWN,
                    ) from None
            if raw is None:
                raise _RedetectionInvocationFailure(
                    M8AcquisitionFailureCode.DETECTOR_FAILED,
                    HearingAcquisitionDeliveryCertainty.UNKNOWN,
                ) from None
            if not isinstance(raw, bytes) or not raw or len(raw) > self._max_media_bytes:
                raise _RedetectionInvocationFailure(
                    M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID,
                    HearingAcquisitionDeliveryCertainty.COMPLETED,
                ) from None
            assert raw is not None
            raw_sha256 = hashlib.sha256(raw).hexdigest()
            self._workspace.ensure_private_directory(request.run_id)
            self._workspace.ensure_private_directory(f"{request.run_id}/raw")
            self._workspace.ensure_private_directory(f"{request.run_id}/raw/acquisition")
            try:
                self._workspace.create_new(relative_path, raw, raw_sha256)
            except ArtifactConflict:
                raw_snapshot = self._workspace.read_verified(relative_path)
                raw = raw_snapshot.bytes
                raw_sha256 = raw_snapshot.sha256
                cache_hit = True
        if not isinstance(raw, bytes):
            raise _RedetectionInvocationFailure(
                M8AcquisitionFailureCode.DETECTOR_OUTPUT_INVALID,
                HearingAcquisitionDeliveryCertainty.UNKNOWN,
            )
        receipt = M8AcquisitionRawReceiptV1(
            request_id=request.request_id,
            raw_response_ref=relative_path,
            raw_response_sha256=raw_sha256,
            cache_hit=cache_hit,
        )
        try:
            response = M8RedetectionOutcomeV1.model_validate(_strict_json_object(raw))
        except (TypeError, ValueError, ValidationError):
            raise _InvalidRedetectionResponse(receipt) from None
        return response, receipt

    def _map_redetections(
        self,
        crop: Crop,
        parameters: RedetectHighResolutionParameters,
        response: M8RedetectionOutcomeV1,
    ) -> tuple[Detection, ...]:
        stream = self._manifest.streams[0]
        mapped: list[Detection] = []
        for index, candidate in enumerate(response.detections):
            if candidate.label not in parameters.prompts:
                self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
            candidate.bbox.require_within(crop.output_width, crop.output_height)
            x1 = crop.bbox.x1 + math.floor(candidate.bbox.x1 * crop.bbox.width / crop.output_width)
            y1 = crop.bbox.y1 + math.floor(
                candidate.bbox.y1 * crop.bbox.height / crop.output_height
            )
            x2 = crop.bbox.x1 + math.ceil(candidate.bbox.x2 * crop.bbox.width / crop.output_width)
            y2 = crop.bbox.y1 + math.ceil(candidate.bbox.y2 * crop.bbox.height / crop.output_height)
            bbox = BBoxXYXY(x1=x1, y1=y1, x2=x2, y2=y2).require_within(
                stream.width,
                stream.height,
            )
            identity = sha256_hex(
                [
                    "m8-recorded-redetection",
                    1,
                    response.request_id,
                    index,
                    candidate.model_dump(mode="json"),
                    bbox.model_dump(mode="json"),
                    response.model_manifest_id,
                ]
            )
            mapped.append(
                Detection(
                    detection_id=f"d{identity[:63]}",
                    frame_id=crop.frame_id,
                    label=candidate.label,
                    bbox=bbox,
                    score=candidate.score,
                    attributes={
                        "observation_source": "PIXEL_COMPUTED",
                        "source_label": candidate.label,
                    },
                    model_manifest_id=response.model_manifest_id,
                )
            )
        return tuple(sorted(mapped, key=lambda item: item.detection_id))

    def _build_execution(
        self,
        *,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        outputs: LoadedEvidenceObjects,
        input_refs: tuple[ArtifactRef, ...],
        tool_id: str,
        component_manifest_id: str,
        parameter_model: type[BaseModel],
        model_manifest_id: str | None = None,
        crop_request: CropRequest | None = None,
    ) -> AcquisitionExecution:
        manifest = self._tool_manifest(
            request,
            tool_id=tool_id,
            component_manifest_id=component_manifest_id,
            parameter_model=parameter_model,
            model_manifest_id=model_manifest_id,
        )
        result = ToolResult(
            tool_result_id=derive_m4_tool_result_id(
                request.action,
                input_refs,
                outputs.refs,
                request.validated_parameters,
                manifest.execution_manifest_id,
            ),
            action=request.action,
            input_refs=input_refs,
            output_refs=outputs.refs,
            validated_parameters=request.validated_parameters,
            execution_manifest_id=manifest.execution_manifest_id,
        )
        execution = AcquisitionExecution(
            request=request,
            execution_manifest=manifest,
            tool_result=result,
            output_objects=outputs,
            crop_request=crop_request,
        )
        self._validate_successor(authority, execution)
        return execution

    def _tool_manifest(
        self,
        request: AcquisitionRequest,
        *,
        tool_id: str,
        component_manifest_id: str,
        parameter_model: type[BaseModel],
        model_manifest_id: str | None = None,
    ) -> ToolExecutionManifest:
        return ToolExecutionManifest(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            acquisition_request_id=request.request_id,
            action=request.action,
            tool_id=tool_id,
            tool_revision="2.0.0",
            parameters_schema_sha256=_parameter_schema_sha256(
                request.action,
                parameter_model,
            ),
            component_manifest_id=component_manifest_id,
            model_manifest_id=model_manifest_id,
            manifest_id=request.manifest_id,
        )

    @contextmanager
    def _video_source(
        self,
        binding: M8ResolvedRecordedRunSourceV1,
    ) -> Iterator[OpenCvVideoSource]:
        stream = self._manifest.streams[0]
        with SecureWorkspace(
            self._project_root,
            max_file_bytes=self._max_input_bytes,
        ) as input_workspace:
            yield OpenCvVideoSource(
                manifest=stream,
                verified_input=cast(VerifiedVideoInput, input_workspace),
                relative_path=binding.source.relative_path,
                max_input_bytes=self._max_input_bytes,
                max_frame_pixels=self._max_frame_pixels,
                max_total_decoded_pixels=self._max_frame_pixels * stream.frame_count,
                backend=self._backend,
            )

    def _resolve_source(self, request: AcquisitionRequest) -> M8ResolvedRecordedRunSourceV1:
        try:
            resolved = self._source_resolver.resolve(
                request.run_id,
                self._manifest,
                max_input_bytes=self._max_input_bytes,
            )
        except M8RecordedRunSourceResolutionError as error:
            if error.reason_code in {
                M8AcquisitionFailureCode.SOURCE_BINDING_MISSING,
                M8AcquisitionFailureCode.SOURCE_MEDIA_UNAVAILABLE,
            }:
                self._record_unavailable(request, error.reason_code)
                self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
            self._record_failure(request, error.reason_code)
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        except (LabCourtError, OSError, TypeError, ValueError):
            self._record_failure(
                request,
                M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH,
            )
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        if (
            resolved.source.run_id != request.run_id
            or resolved.run_manifest_id != request.manifest_id
            or resolved.run_manifest_id != self._manifest.manifest_id
        ):
            self._record_failure(
                request,
                M8AcquisitionFailureCode.SOURCE_AUTHORITY_MISMATCH,
            )
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        return resolved

    def _validate_scope(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
    ) -> None:
        if (
            request.run_id != authority.pack.run_id
            or request.case_id != authority.pack.case_id
            or request.current_evidence_pack_id != authority.pack.pack_id
            or request.current_evidence_pack_version != authority.pack.version
            or request.manifest_id != authority.pack.manifest_id
            or request.manifest_id != self._manifest.manifest_id
        ):
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)

    @staticmethod
    def _pack_ref(request: AcquisitionRequest) -> ArtifactRef:
        return ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=request.current_evidence_pack_id,
        )

    @staticmethod
    def _validate_successor(
        authority: EvidenceAuthority,
        execution: AcquisitionExecution,
    ) -> None:
        derive_evidence_pack_successor(
            authority.pack,
            execution,
            current_receipts=authority.receipts,
            current_loaded_objects=authority.loaded_objects,
        )

    @staticmethod
    def _snapshot(execution: AcquisitionExecution) -> M8AcquisitionM4ExecutionV1:
        outputs = execution.output_objects
        return M8AcquisitionM4ExecutionV1(
            request=execution.request,
            execution_manifest=execution.execution_manifest,
            tool_result=execution.tool_result,
            frames=outputs.frames,
            crops=outputs.crops,
            objective_facts=outputs.objective_facts,
            detections=outputs.detections,
            crop_request=execution.crop_request,
        )

    def _execution_from_snapshot(
        self,
        snapshot: M8AcquisitionM4ExecutionV1,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
    ) -> AcquisitionExecution:
        if snapshot.request != request:
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        execution = AcquisitionExecution(
            request=snapshot.request,
            execution_manifest=snapshot.execution_manifest,
            tool_result=snapshot.tool_result,
            output_objects=LoadedEvidenceObjects(
                frames=snapshot.frames,
                crops=snapshot.crops,
                objective_facts=snapshot.objective_facts,
                detections=snapshot.detections,
            ),
            crop_request=snapshot.crop_request,
        )
        self._validate_successor(authority, execution)
        return execution

    def _record_success(self, execution: AcquisitionExecution) -> None:
        self._persist_outcome(
            M8HearingAcquisitionResultV2(
                run_id=execution.request.run_id,
                case_id=execution.request.case_id,
                acquisition_request_id=execution.request.request_id,
                action=execution.request.action,
                status=M8AcquisitionOutcomeStatus.SUCCEEDED,
                m4_representability=(M8AcquisitionM4Representability.M4_V1_REPRESENTABLE),
                m4_execution=self._snapshot(execution),
            )
        )

    def _record_unavailable(
        self,
        request: AcquisitionRequest,
        failure_code: M8AcquisitionFailureCode,
    ) -> None:
        self._persist_outcome(
            M8HearingAcquisitionResultV2(
                run_id=request.run_id,
                case_id=request.case_id,
                acquisition_request_id=request.request_id,
                action=request.action,
                status=M8AcquisitionOutcomeStatus.UNAVAILABLE,
                m4_representability=M8AcquisitionM4Representability.V1_UNREPRESENTABLE,
                failure_code=failure_code,
            )
        )

    def _record_failure(
        self,
        request: AcquisitionRequest,
        failure_code: M8AcquisitionFailureCode,
    ) -> None:
        self._persist_outcome(
            M8HearingAcquisitionResultV2(
                run_id=request.run_id,
                case_id=request.case_id,
                acquisition_request_id=request.request_id,
                action=request.action,
                status=M8AcquisitionOutcomeStatus.FAILED,
                m4_representability=M8AcquisitionM4Representability.V1_UNREPRESENTABLE,
                failure_code=failure_code,
            )
        )

    def _record_redetection_failure(
        self,
        request: AcquisitionRequest,
        response: M8RedetectionOutcomeV1,
        receipt: M8AcquisitionRawReceiptV1,
        failure_code: M8AcquisitionFailureCode,
        *,
        include_response: bool = True,
    ) -> None:
        self._persist_outcome(
            M8HearingAcquisitionResultV2(
                run_id=request.run_id,
                case_id=request.case_id,
                acquisition_request_id=request.request_id,
                action=request.action,
                status=M8AcquisitionOutcomeStatus.FAILED,
                m4_representability=M8AcquisitionM4Representability.V1_UNREPRESENTABLE,
                failure_code=failure_code,
                raw_receipt=receipt,
                redetection_outcome=response if include_response else None,
            )
        )

    def _persist_outcome(self, outcome: M8HearingAcquisitionResultV2) -> None:
        if self._outcome_repository is not None:
            self._outcome_repository.put(outcome)
            return
        if self._workspace is None:
            return
        path = self._outcome_path(outcome.run_id, outcome.acquisition_request_id)
        body = canonical_json(outcome.model_dump(mode="json", exclude_computed_fields=True)).encode(
            "utf-8"
        )
        digest = hashlib.sha256(body).hexdigest()
        self._workspace.ensure_private_directory(outcome.run_id)
        self._workspace.ensure_private_directory(f"{outcome.run_id}/acquisition-v2")
        try:
            self._workspace.create_new(path, body, digest)
        except ArtifactConflict:
            existing = self._workspace.read_verified(path)
            if existing.bytes != body:
                self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)

    def _load_outcome(
        self,
        request: AcquisitionRequest,
    ) -> M8HearingAcquisitionResultV2 | None:
        outcome = self.load_m8_outcome(request.request_id, request.run_id)
        if outcome is not None and (
            outcome.run_id != request.run_id
            or outcome.case_id != request.case_id
            or outcome.acquisition_request_id != request.request_id
            or outcome.action != request.action
        ):
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        return outcome

    def _replay_outcome(
        self,
        outcome: M8HearingAcquisitionResultV2,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
    ) -> AcquisitionExecution:
        if outcome.m4_execution is not None:
            return self._execution_from_snapshot(outcome.m4_execution, request, authority)
        if outcome.status == M8AcquisitionOutcomeStatus.UNAVAILABLE:
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        self._fail(
            HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID,
            HearingAcquisitionDeliveryCertainty.COMPLETED,
        )

    @staticmethod
    def _outcome_path(run_id: str, request_id: str) -> str:
        return f"{run_id}/acquisition-v2/{request_id}.json"

    @staticmethod
    def _require_request(request: object) -> AcquisitionRequest:
        if type(request) is not AcquisitionRequest:
            RecordedRunFrameAcquisitionExecutor._fail(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        try:
            rebuilt = AcquisitionRequest.model_validate(request.model_dump(mode="json"))
        except (TypeError, ValueError, ValidationError):
            RecordedRunFrameAcquisitionExecutor._fail(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        if rebuilt != request:
            RecordedRunFrameAcquisitionExecutor._fail(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        return rebuilt

    @staticmethod
    def _require_authority(authority: object) -> EvidenceAuthority:
        if not isinstance(authority, EvidenceAuthority):
            RecordedRunFrameAcquisitionExecutor._fail(
                HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT
            )
        try:
            rebuilt = derive_evidence_authority(
                authority.pack,
                authority.receipts,
                authority.loaded_objects,
            )
        except EvidenceAuthorityError:
            RecordedRunFrameAcquisitionExecutor._fail(
                HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH
            )
        if rebuilt != authority:
            RecordedRunFrameAcquisitionExecutor._fail(
                HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH
            )
        return authority

    @staticmethod
    def _fail(
        reason: HearingAcquisitionExecutorFailureCode,
        certainty: HearingAcquisitionDeliveryCertainty = (
            HearingAcquisitionDeliveryCertainty.DEFINITELY_NOT_STARTED
        ),
    ) -> NoReturn:
        raise HearingAcquisitionExecutorError(reason, certainty)


__all__ = ["RecordedRunFrameAcquisitionExecutor"]
