"""Deterministic M4 frame acquisition over one immutable recorded run input."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import NoReturn, cast

from pydantic import ValidationError

from labcourt.adapters.opencv_video import (
    OpenCvDecoderBackend,
    OpenCvVideoSource,
    VerifiedVideoInput,
    VideoDecoderBackend,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import AcquisitionAction, AcquisitionExecutionMode, ArtifactKind
from labcourt.contracts.evidence import RequestMoreFramesParameters, ToolResult
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    ToolExecutionManifest,
    derive_m4_tool_result_id,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    EvidenceAuthority,
    EvidenceAuthorityError,
    LoadedEvidenceObjects,
    derive_evidence_authority,
    derive_evidence_pack_successor,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionDeliveryCertainty,
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)


class RecordedRunFrameAcquisitionExecutor:
    """Fulfil only REQUEST_MORE_FRAMES from the run's hash-bound source video."""

    __slots__ = (
        "_backend",
        "_input_relative_path",
        "_manifest",
        "_max_frame_pixels",
        "_max_input_bytes",
        "_project_root",
    )

    def __init__(
        self,
        *,
        project_root: Path,
        input_relative_path: str,
        manifest: RunManifest,
        max_input_bytes: int,
        max_frame_pixels: int,
        decoder_backend: VideoDecoderBackend | None = None,
    ) -> None:
        if not isinstance(project_root, Path):
            raise TypeError("recorded acquisition project_root must be a Path")
        if not isinstance(manifest, RunManifest):
            raise TypeError("recorded acquisition requires a RunManifest")
        if not isinstance(max_input_bytes, int) or isinstance(max_input_bytes, bool):
            raise TypeError("max_input_bytes must be an integer")
        if not isinstance(max_frame_pixels, int) or isinstance(max_frame_pixels, bool):
            raise TypeError("max_frame_pixels must be an integer")
        if max_input_bytes <= 0 or max_frame_pixels <= 0:
            raise ValueError("recorded acquisition limits must be positive")
        self._project_root = project_root.absolute()
        self._input_relative_path = require_safe_relative_posix_path(input_relative_path)
        self._manifest = manifest
        self._max_input_bytes = max_input_bytes
        self._max_frame_pixels = max_frame_pixels
        self._backend = decoder_backend or OpenCvDecoderBackend()

    @property
    def execution_mode(self) -> AcquisitionExecutionMode:
        return AcquisitionExecutionMode.PURE

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
        if typed_request.action != AcquisitionAction.REQUEST_MORE_FRAMES:
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        if (
            typed_request.run_id != typed_authority.pack.run_id
            or typed_request.case_id != typed_authority.pack.case_id
            or typed_request.current_evidence_pack_id != typed_authority.pack.pack_id
            or typed_request.current_evidence_pack_version != typed_authority.pack.version
            or typed_request.manifest_id != typed_authority.pack.manifest_id
            or typed_request.manifest_id != self._manifest.manifest_id
        ):
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)
        parameters = typed_request.validated_parameters
        if not isinstance(parameters, RequestMoreFramesParameters):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        stream = next(
            (
                item
                for item in self._manifest.streams
                if (item.camera_id, item.stream_id)
                == (parameters.camera_id, parameters.stream_id)
            ),
            None,
        )
        if stream is None or parameters.end_frame_exclusive > stream.frame_count:
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
            for ref in typed_authority.pack.expected_closure_refs()
            if ref.kind == ArtifactKind.FRAME
        }
        if requested_frame_ids & existing_frame_ids:
            self._fail(HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH)

        try:
            with SecureWorkspace(
                self._project_root,
                max_file_bytes=self._max_input_bytes,
            ) as input_workspace:
                source = OpenCvVideoSource(
                    manifest=stream,
                    verified_input=cast(VerifiedVideoInput, input_workspace),
                    relative_path=self._input_relative_path,
                    max_input_bytes=self._max_input_bytes,
                    max_frame_pixels=self._max_frame_pixels,
                    max_total_decoded_pixels=self._max_frame_pixels * stream.frame_count,
                    backend=self._backend,
                )
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
            outputs = LoadedEvidenceObjects(frames=frames)
            component = self._manifest.software_components.get(stream.software_component)
            if component is None:
                self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
            component_manifest_id = hashlib.sha256(
                canonical_json(component.model_dump(mode="json")).encode("utf-8")
            ).hexdigest()
            execution_manifest = ToolExecutionManifest(
                run_id=typed_request.run_id,
                case_id=typed_request.case_id,
                hearing_session_id=typed_request.hearing_session_id,
                acquisition_request_id=typed_request.request_id,
                action=typed_request.action,
                tool_id="recorded-run-request-more-frames",
                tool_revision="1.0.0",
                parameters_schema_sha256=sha256_hex(
                    [
                        "m4-acquisition-parameters-schema",
                        1,
                        AcquisitionAction.REQUEST_MORE_FRAMES.value,
                        RequestMoreFramesParameters.model_json_schema(mode="validation"),
                    ]
                ),
                component_manifest_id=component_manifest_id,
                manifest_id=typed_request.manifest_id,
            )
            input_refs = (
                ArtifactRef(
                    kind=ArtifactKind.EVIDENCE_PACK,
                    artifact_id=typed_request.current_evidence_pack_id,
                ),
            )
            result = ToolResult(
                tool_result_id=derive_m4_tool_result_id(
                    typed_request.action,
                    input_refs,
                    outputs.refs,
                    parameters,
                    execution_manifest.execution_manifest_id,
                ),
                action=typed_request.action,
                input_refs=input_refs,
                output_refs=outputs.refs,
                validated_parameters=parameters,
                execution_manifest_id=execution_manifest.execution_manifest_id,
            )
            execution = AcquisitionExecution(
                request=typed_request,
                execution_manifest=execution_manifest,
                tool_result=result,
                output_objects=outputs,
            )
            derive_evidence_pack_successor(
                typed_authority.pack,
                execution,
                current_receipts=typed_authority.receipts,
                current_loaded_objects=typed_authority.loaded_objects,
            )
            return execution
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
        self._require_authority(authority)
        if idempotency_key != typed_request.request_id:
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        return HearingAcquisitionRecovery(
            status=HearingAcquisitionRecoveryStatus.DEFINITELY_NOT_STARTED
        )

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
    def _fail(reason: HearingAcquisitionExecutorFailureCode) -> NoReturn:
        raise HearingAcquisitionExecutorError(
            reason,
            HearingAcquisitionDeliveryCertainty.DEFINITELY_NOT_STARTED,
        )


__all__ = ["RecordedRunFrameAcquisitionExecutor"]
