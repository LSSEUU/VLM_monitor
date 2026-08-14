"""Bounded local recrop adapter over one sealed synthetic supplementary image."""

from __future__ import annotations

import hashlib
from io import BytesIO
from typing import NoReturn

from PIL import Image, UnidentifiedImageError

from labcourt.adapters.acquisition_fake import (
    DeterministicFakeHearingAcquisitionExecutor,
    FakeAcquisitionFixture,
    FakeAcquisitionToolSpec,
    acquisition_parameters_schema_sha256,
)
from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
)
from labcourt.contracts.evidence import Crop, CropRequest, PrivacyReceipt, RecropParameters
from labcourt.contracts.hearing_acquisition import AcquisitionRequest
from labcourt.contracts.manifests import RunManifest, SoftwareComponentManifest
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    EvidenceAuthority,
    LoadedEvidenceObjects,
    derive_recrop_source_refs,
)
from labcourt.exceptions import ArtifactConflict
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionDeliveryCertainty,
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)
from labcourt.ports.pixels import rgb8_pixel_sha256

M8_QWEN_DEMO_ACQUISITION_COMPONENT_KEY = "m8-qwen-demo-sealed-recrop"
M8_QWEN_DEMO_ACQUISITION_COMPONENT = SoftwareComponentManifest(
    component=M8_QWEN_DEMO_ACQUISITION_COMPONENT_KEY,
    package="labcourt",
    version="0.1.0",
    license_id="Proprietary",
)


def m8_qwen_demo_acquisition_component_manifest_id() -> str:
    document = canonical_json(M8_QWEN_DEMO_ACQUISITION_COMPONENT.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class M8QwenDemoSealedRecropExecutor:
    """Expose only RECROP; every other frozen M4 action is typed unavailable."""

    __slots__ = (
        "_manifest",
        "_max_image_pixels",
        "_supplementary_relative_path",
        "_workspace",
    )

    def __init__(
        self,
        *,
        workspace: SecureWorkspace,
        manifest: RunManifest,
        supplementary_relative_path: str,
        max_image_pixels: int,
    ) -> None:
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("sealed recrop executor requires a SecureWorkspace")
        if not isinstance(manifest, RunManifest):
            raise TypeError("sealed recrop executor requires a RunManifest")
        if (
            manifest.software_components.get(M8_QWEN_DEMO_ACQUISITION_COMPONENT_KEY)
            != M8_QWEN_DEMO_ACQUISITION_COMPONENT
        ):
            raise ValueError("sealed recrop component is absent from the RunManifest")
        if not isinstance(max_image_pixels, int) or isinstance(max_image_pixels, bool):
            raise TypeError("max_image_pixels must be an integer")
        if max_image_pixels <= 0:
            raise ValueError("max_image_pixels must be positive")
        self._workspace = workspace
        self._manifest = manifest
        self._supplementary_relative_path = supplementary_relative_path
        self._max_image_pixels = max_image_pixels

    @property
    def execution_mode(self) -> AcquisitionExecutionMode:
        return AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL

    def execute(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> AcquisitionExecution:
        if idempotency_key != getattr(request, "request_id", None):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        if getattr(request, "action", None) != AcquisitionAction.RECROP:
            self._fail(HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE)
        return self._build_execution(request, authority)

    def recover(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> HearingAcquisitionRecovery:
        if idempotency_key != getattr(request, "request_id", None):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        if getattr(request, "action", None) != AcquisitionAction.RECROP:
            return HearingAcquisitionRecovery(
                status=HearingAcquisitionRecoveryStatus.DEFINITELY_NOT_STARTED
            )
        return HearingAcquisitionRecovery(
            status=HearingAcquisitionRecoveryStatus.COMPLETED,
            execution=self._build_execution(request, authority),
        )

    def _build_execution(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
    ) -> AcquisitionExecution:
        parameters = getattr(request, "validated_parameters", None)
        if not isinstance(parameters, RecropParameters) or not isinstance(
            authority, EvidenceAuthority
        ):
            self._fail(HearingAcquisitionExecutorFailureCode.INVALID_ARGUMENT)
        if parameters.bbox.width * parameters.bbox.height > self._max_image_pixels:
            self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
        source_refs = derive_recrop_source_refs(authority, parameters)
        crop_request = CropRequest(
            frame_id=parameters.frame_id,
            source=CropSource.RECROP,
            bbox=parameters.bbox,
            output_width=parameters.bbox.width,
            output_height=parameters.bbox.height,
            source_refs=source_refs,
            privacy_policy=PrivacyPolicy.FULL_REDACTION,
            privacy_transform_version=self._manifest.privacy_transform_version,
            encoding_version=self._manifest.image_encoding_version,
            primary_track_ref=authority.pack.event.primary_track_ref,
            tags={"zone_id": authority.pack.event.zone_id},
        )
        pixels = self._resized_supplementary_pixels(
            crop_request.output_width,
            crop_request.output_height,
        )
        png_bytes = encode_rgb_png(crop_request.output_width, crop_request.output_height, pixels)
        pixel_sha256 = rgb8_pixel_sha256(
            crop_request.output_width,
            crop_request.output_height,
            pixels,
        )
        media_sha256 = hashlib.sha256(png_bytes).hexdigest()
        relative_path = f"{authority.pack.run_id}/frames/{media_sha256}.png"
        self._workspace.ensure_private_directory(authority.pack.run_id)
        self._workspace.ensure_private_directory(f"{authority.pack.run_id}/frames")
        try:
            self._workspace.create_new(relative_path, png_bytes, media_sha256)
        except ArtifactConflict as error:
            if error.reason_code != "TARGET_ALREADY_EXISTS":
                raise
            snapshot = self._workspace.read_verified(
                relative_path,
                media_sha256,
                max_bytes=len(png_bytes),
            )
            if snapshot.bytes != png_bytes:
                self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)
        source_frame = next(
            (
                frame
                for frame in authority.loaded_objects.frames
                if frame.frame_id == parameters.frame_id
            ),
            None,
        )
        source_media_sha256 = (
            source_frame.content_sha256
            if source_frame is not None and source_frame.content_sha256 is not None
            else hashlib.sha256(parameters.frame_id.encode("utf-8")).hexdigest()
        )
        crop = Crop(
            frame_id=parameters.frame_id,
            source=CropSource.RECROP,
            bbox=parameters.bbox,
            source_refs=source_refs,
            local_path=relative_path,
            availability=MediaAvailability.AVAILABLE,
            source_media_sha256=source_media_sha256,
            pixel_sha256=pixel_sha256,
            media_sha256=media_sha256,
            output_width=crop_request.output_width,
            output_height=crop_request.output_height,
            size_bytes=len(png_bytes),
            media_type=MediaType.IMAGE_PNG,
            encoding_version=crop_request.encoding_version,
            privacy_receipt=PrivacyReceipt(
                policy=PrivacyPolicy.FULL_REDACTION,
                transform_version=crop_request.privacy_transform_version,
                media_access=MediaAccess.CLOUD_ALLOWED,
                reason_code=PrivacyReasonCode.SUBJECT_FULL_REDACTION,
                input_refs=source_refs,
                fill_rgb=(0, 0, 0),
            ),
            primary_track_ref=crop_request.primary_track_ref,
            tags=crop_request.tags,
        )
        delegate = DeterministicFakeHearingAcquisitionExecutor(
            tool_specs=self._tool_specs(),
            fixtures=(
                FakeAcquisitionFixture(
                    request=request,
                    output_objects=LoadedEvidenceObjects(crops=(crop,)),
                    crop_request=crop_request,
                ),
            ),
        )
        return delegate.execute(request, authority, idempotency_key=request.request_id)

    def _resized_supplementary_pixels(self, width: int, height: int) -> bytes:
        try:
            snapshot = self._workspace.read_verified(self._supplementary_relative_path)
            with Image.open(BytesIO(snapshot.bytes)) as source:
                if source.format != "PNG" or getattr(source, "n_frames", 1) != 1:
                    raise ValueError
                converted = source.convert("RGB")
                resized = converted.resize((width, height), Image.Resampling.LANCZOS)
                return resized.tobytes()
        except (OSError, UnidentifiedImageError, ValueError):
            self._fail(HearingAcquisitionExecutorFailureCode.OUTPUT_INVALID)

    def _tool_specs(self) -> tuple[FakeAcquisitionToolSpec, ...]:
        component_manifest_id = m8_qwen_demo_acquisition_component_manifest_id()
        return tuple(
            sorted(
                (
                    FakeAcquisitionToolSpec(
                        action=action,
                        tool_id=f"m8-qwen-demo-{action.value.lower().replace('_', '-')}",
                        tool_revision="1.0.0",
                        parameters_schema_sha256=acquisition_parameters_schema_sha256(action),
                        component_manifest_id=component_manifest_id,
                        model_manifest_id=(
                            self._manifest.models["detector"].model_manifest_id
                            if action == AcquisitionAction.REDETECT_HIGH_RES
                            else None
                        ),
                    )
                    for action in AcquisitionAction
                ),
                key=lambda item: item.sort_key,
            )
        )

    @staticmethod
    def _fail(reason: HearingAcquisitionExecutorFailureCode) -> NoReturn:
        raise HearingAcquisitionExecutorError(
            reason,
            HearingAcquisitionDeliveryCertainty.DEFINITELY_NOT_STARTED,
        )


__all__ = [
    "M8_QWEN_DEMO_ACQUISITION_COMPONENT",
    "M8_QWEN_DEMO_ACQUISITION_COMPONENT_KEY",
    "M8QwenDemoSealedRecropExecutor",
    "m8_qwen_demo_acquisition_component_manifest_id",
]
