"""Evidence pack and privacy-aware crop contracts."""

from __future__ import annotations

from typing import Annotated, Literal, Self, TypeAlias

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AcquisitionAction,
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    ConsistencyEvaluationStatus,
    CropSource,
    EvidenceClass,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ObservationSource,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
)
from labcourt.contracts.events import (
    CandidateEvent,
    ConfirmationRecord,
    ObjectiveFact,
    derive_case_id,
)
from labcourt.contracts.frames import SHA256_PATTERN, Sha256Hex
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.metadata import validate_safe_scalar_metadata
from labcourt.contracts.paths import (
    SAFE_RELATIVE_PATH_PATTERN,
    require_safe_relative_posix_path,
)
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    TrackRef,
    parse_frame_id,
    parse_track_ref,
    require_reference_token,
    require_track_ref_camera,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport

_ALLOWED_CROP_TAGS = {
    "scenario_id",
    "zone_id",
}
RgbChannel = Annotated[int, Field(ge=0, le=255, strict=True)]
_PPE_ANCHOR = {
    PpeType.GOGGLES: AnchorType.HEAD,
    PpeType.GLOVES: AnchorType.HANDS,
    PpeType.LAB_COAT: AnchorType.TORSO,
}


def derive_crop_id(
    *,
    frame_id: str,
    bbox: BBoxXYXY,
    output_width: int,
    output_height: int,
    crop_source: CropSource,
    source_media_sha256: str,
    privacy_policy: PrivacyPolicy,
    privacy_transform_version: str,
    encoding_version: str,
) -> str:
    import re

    if re.fullmatch(SHA256_PATTERN, source_media_sha256) is None:
        raise ValueError("source_media_sha256 must be a lowercase SHA-256 digest")
    if not privacy_transform_version or not encoding_version:
        raise ValueError("transform and encoding versions cannot be empty")
    if (
        not isinstance(output_width, int)
        or isinstance(output_width, bool)
        or not isinstance(output_height, int)
        or isinstance(output_height, bool)
        or not 0 < output_width <= 0xFFFFFFFF
        or not 0 < output_height <= 0xFFFFFFFF
    ):
        raise ValueError("crop output dimensions must fit positive uint32 values")
    return sha256_hex(
        [
            "crop",
            2,
            frame_id,
            [bbox.x1, bbox.y1, bbox.x2, bbox.y2],
            [output_width, output_height],
            crop_source.value,
            source_media_sha256,
            privacy_policy.value,
            privacy_transform_version,
            encoding_version,
        ]
    )


def _panorama_output_dimensions(
    width: int,
    height: int,
    long_edge_limit: int,
) -> tuple[int, int]:
    if max(width, height) <= long_edge_limit:
        return width, height
    if width >= height:
        scaled_height = max(1, (2 * height * long_edge_limit + width) // (2 * width))
        return long_edge_limit, scaled_height
    scaled_width = max(1, (2 * width * long_edge_limit + height) // (2 * height))
    return scaled_width, long_edge_limit


class ObservabilityComponents(FrozenContractModel):
    person_confidence: StrictFloat = Field(ge=0, le=1)
    keypoint_visibility: StrictFloat = Field(ge=0, le=1)
    frontality: StrictFloat = Field(ge=0, le=1)
    sharpness: StrictFloat = Field(ge=0, le=1)
    exposure: StrictFloat = Field(ge=0, le=1)
    non_occlusion: StrictFloat = Field(ge=0, le=1)


class ObservabilityScore(FrozenContractModel):
    total: StrictFloat = Field(ge=0, le=1)
    components: ObservabilityComponents
    source: ObservationSource


class PrivacyReceipt(FrozenContractModel):
    policy: PrivacyPolicy
    transform_version: str = Field(min_length=1, max_length=128)
    media_access: MediaAccess
    reason_code: PrivacyReasonCode
    input_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    ppe_type: PpeType | None = None
    anchor_type: AnchorType | None = None
    preserved_regions: tuple[BBoxXYXY, ...] = ()
    keypoints: tuple[Keypoint, ...] = ()
    anchor_bbox: BBoxXYXY | None = None
    association_method: AssociationMethod | None = None
    fill_rgb: tuple[RgbChannel, RgbChannel, RgbChannel]
    fallback_used: StrictBool = False

    @model_validator(mode="after")
    def validate_policy_result(self) -> PrivacyReceipt:
        ref_keys = tuple(ref.sort_key for ref in self.input_refs)
        if len(ref_keys) != len(set(ref_keys)) or ref_keys != tuple(sorted(ref_keys)):
            raise ValueError("privacy input_refs must be unique and use stable artifact order")
        keypoint_names = tuple(keypoint.name for keypoint in self.keypoints)
        if len(keypoint_names) != len(set(keypoint_names)):
            raise ValueError("privacy keypoints must have unique names")
        if keypoint_names != tuple(sorted(keypoint_names)):
            raise ValueError("privacy keypoints must use stable name order")
        region_keys = tuple(
            (region.x1, region.y1, region.x2, region.y2) for region in self.preserved_regions
        )
        if len(region_keys) != len(set(region_keys)) or region_keys != tuple(sorted(region_keys)):
            raise ValueError("privacy preserved regions must be unique and use stable order")
        if (
            self.policy == PrivacyPolicy.EPHEMERAL_RAW
            and self.media_access != MediaAccess.LOCAL_ONLY
        ):
            raise ValueError("ephemeral raw media must remain local")
        if self.policy == PrivacyPolicy.PPE_PRESERVING_REDACTION:
            if (
                self.ppe_type is None
                or self.anchor_type is None
                or self.anchor_bbox is None
                or self.association_method is None
            ):
                raise ValueError("PPE-preserving output requires typed PPE and anchor context")
            if _PPE_ANCHOR[self.ppe_type] != self.anchor_type:
                raise ValueError("PPE type does not match its required anchor")
            if self.fallback_used:
                if self.media_access != MediaAccess.LOCAL_ONLY:
                    raise ValueError("privacy fallback media must remain local")
                if self.reason_code != PrivacyReasonCode.KEYPOINTS_INSUFFICIENT_LOCAL_ONLY:
                    raise ValueError("privacy fallback requires the insufficient-keypoints reason")
                if self.preserved_regions:
                    raise ValueError("privacy fallback cannot preserve an unverified region")
            else:
                if self.reason_code != PrivacyReasonCode.PPE_REGION_PRESERVED:
                    raise ValueError("PPE-preserving output requires the preserved-region reason")
                if not self.preserved_regions or not self.keypoints:
                    raise ValueError("PPE-preserving output requires regions and keypoint names")
        elif self.policy == PrivacyPolicy.FULL_REDACTION:
            if self.preserved_regions or self.keypoints:
                raise ValueError("full redaction cannot claim preserved regions or keypoints")
            if (
                self.ppe_type is not None
                or self.anchor_type is not None
                or self.anchor_bbox is not None
                or self.association_method is not None
            ):
                raise ValueError("full redaction cannot claim an anchor association")
            if self.fallback_used:
                raise ValueError("full redaction is a policy result, not a privacy fallback")
        if (
            self.reason_code == PrivacyReasonCode.POLICY_LOCAL_ONLY
            and self.media_access != MediaAccess.LOCAL_ONLY
        ):
            raise ValueError("the local-only privacy reason requires local media access")
        return self


class CropRequest(FrozenContractModel):
    frame_id: FrameId
    source: CropSource
    bbox: BBoxXYXY
    output_width: int = Field(gt=0, le=0xFFFFFFFF, strict=True)
    output_height: int = Field(gt=0, le=0xFFFFFFFF, strict=True)
    panorama_long_edge_limit: int | None = Field(
        default=None,
        gt=0,
        le=0xFFFFFFFF,
        strict=True,
    )
    source_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    privacy_policy: PrivacyPolicy
    privacy_transform_version: str = Field(min_length=1, max_length=128)
    encoding_version: str = Field(min_length=1, max_length=128)
    primary_track_ref: TrackRef | None = None
    ppe_type: PpeType | None = None
    anchor_type: AnchorType | None = None
    anchor_bbox: BBoxXYXY | None = None
    keypoints: tuple[Keypoint, ...] = ()
    association_method: AssociationMethod | None = None
    observability: ObservabilityScore | None = None
    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("frame_id")
    @classmethod
    def validate_frame_id(cls, value: str) -> str:
        parse_frame_id(value)
        return value

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: dict[str, str]) -> dict[str, str]:
        validate_safe_scalar_metadata(value, allowed_keys=_ALLOWED_CROP_TAGS)
        return value

    @model_validator(mode="after")
    def validate_request_context(self) -> CropRequest:
        camera_id, _, _ = parse_frame_id(self.frame_id)
        if self.primary_track_ref is not None:
            require_track_ref_camera(self.primary_track_ref, camera_id)
        ref_keys = tuple(ref.sort_key for ref in self.source_refs)
        if len(ref_keys) != len(set(ref_keys)) or ref_keys != tuple(sorted(ref_keys)):
            raise ValueError("crop source_refs must be unique and use stable artifact order")
        frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=self.frame_id)
        if frame_ref not in self.source_refs:
            raise ValueError("crop source_refs must contain the requested frame")
        keypoint_names = tuple(keypoint.name for keypoint in self.keypoints)
        if len(keypoint_names) != len(set(keypoint_names)):
            raise ValueError("crop request keypoint names must be unique")
        if keypoint_names != tuple(sorted(keypoint_names)):
            raise ValueError("crop request keypoints must use stable name order")

        ppe_context = (
            self.ppe_type,
            self.anchor_type,
            self.anchor_bbox,
            self.association_method,
        )
        if self.source == CropSource.PANORAMA:
            if self.panorama_long_edge_limit is None:
                raise ValueError("panorama requests require their long-edge limit")
            expected_width, expected_height = _panorama_output_dimensions(
                self.bbox.width,
                self.bbox.height,
                self.panorama_long_edge_limit,
            )
            if (self.output_width, self.output_height) != (
                expected_width,
                expected_height,
            ):
                raise ValueError(
                    "panorama output dimensions do not match the declared long-edge limit"
                )
            if self.privacy_policy != PrivacyPolicy.FULL_REDACTION:
                raise ValueError("panorama requests require full redaction")
            if self.primary_track_ref is not None or any(item is not None for item in ppe_context):
                raise ValueError("panorama requests cannot carry subject or PPE authority")
        elif self.source == CropSource.SUBJECT:
            if self.primary_track_ref is None:
                raise ValueError("subject requests require a primary track")
            if self.privacy_policy != PrivacyPolicy.FULL_REDACTION:
                raise ValueError("subject requests require full redaction")
            if any(item is not None for item in ppe_context):
                raise ValueError("subject requests cannot carry PPE authority")
        elif self.source == CropSource.DETECTION_FOCUS:
            if self.privacy_policy != PrivacyPolicy.FULL_REDACTION:
                raise ValueError("detection-focus requests require full redaction")
            if not any(ref.kind == ArtifactKind.DETECTION for ref in self.source_refs):
                raise ValueError("detection-focus requests require a typed detection source")
            if any(item is not None for item in ppe_context):
                raise ValueError("detection-focus requests cannot carry PPE authority")
        elif self.source == CropSource.ANCHOR_FOCUS:
            if self.privacy_policy != PrivacyPolicy.PPE_PRESERVING_REDACTION:
                raise ValueError("anchor-focus requests require PPE-preserving redaction")
            if self.primary_track_ref is None or self.observability is None:
                raise ValueError("anchor-focus requests require a track and observability")
            if any(item is None for item in ppe_context):
                raise ValueError("anchor-focus requests require typed PPE and anchor context")
            assert self.ppe_type is not None
            if _PPE_ANCHOR[self.ppe_type] != self.anchor_type:
                raise ValueError("PPE type does not match its required anchor")
        elif self.source == CropSource.RECROP:
            if not any(
                ref.kind in {ArtifactKind.CROP, ArtifactKind.TOOL_RESULT}
                for ref in self.source_refs
            ):
                raise ValueError("recrop requests require a crop or tool-result source")
            if self.privacy_policy == PrivacyPolicy.PPE_PRESERVING_REDACTION and any(
                item is None for item in ppe_context
            ):
                raise ValueError("PPE-preserving recrops require typed PPE and anchor context")
            if (
                self.privacy_policy == PrivacyPolicy.PPE_PRESERVING_REDACTION
                and self.ppe_type is not None
                and _PPE_ANCHOR[self.ppe_type] != self.anchor_type
            ):
                raise ValueError("PPE type does not match its required anchor")
        if self.source != CropSource.PANORAMA:
            if self.panorama_long_edge_limit is not None:
                raise ValueError("non-panorama requests cannot carry a panorama limit")
            if (self.output_width, self.output_height) != (
                self.bbox.width,
                self.bbox.height,
            ):
                raise ValueError("non-panorama output dimensions must equal the crop bbox")
        return self


class Crop(FrozenContractModel):
    frame_id: FrameId
    source: CropSource
    bbox: BBoxXYXY
    panorama_long_edge_limit: int | None = Field(
        default=None,
        gt=0,
        le=0xFFFFFFFF,
        strict=True,
    )
    source_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    local_path: str | None = Field(
        default=None,
        json_schema_extra={"pattern": SAFE_RELATIVE_PATH_PATTERN},
    )
    availability: MediaAvailability
    source_media_sha256: Sha256Hex
    pixel_sha256: Sha256Hex
    media_sha256: Sha256Hex
    output_width: int = Field(gt=0, le=0xFFFFFFFF, strict=True)
    output_height: int = Field(gt=0, le=0xFFFFFFFF, strict=True)
    size_bytes: int = Field(gt=0, strict=True)
    media_type: Literal[MediaType.IMAGE_PNG]
    encoding_version: str = Field(min_length=1, max_length=128)
    privacy_receipt: PrivacyReceipt
    observability: ObservabilityScore | None = None
    primary_track_ref: TrackRef | None = None
    tags: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_crop_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "crop_id" in payload
        claimed = payload.pop("crop_id", None)
        crop = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized crop_id must be a string")
        if claimed_present and claimed != crop.crop_id:
            raise ValueError("serialized crop_id does not match crop identity fields")
        return crop

    @computed_field  # type: ignore[prop-decorator]
    @property
    def crop_id(self) -> Sha256Hex:
        return derive_crop_id(
            frame_id=self.frame_id,
            bbox=self.bbox,
            output_width=self.output_width,
            output_height=self.output_height,
            crop_source=self.source,
            source_media_sha256=self.source_media_sha256,
            privacy_policy=self.privacy_receipt.policy,
            privacy_transform_version=self.privacy_receipt.transform_version,
            encoding_version=self.encoding_version,
        )

    def semantic_projection(self) -> dict[str, object]:
        """Return the exact M2 crop identity contribution without mutable location."""

        return {
            "crop_id": self.crop_id,
            "frame_id": self.frame_id,
            "source": self.source.value,
            "bbox": self.bbox.model_dump(mode="json"),
            "panorama_long_edge_limit": self.panorama_long_edge_limit,
            "source_refs": [ref.model_dump(mode="json") for ref in self.source_refs],
            "source_media_sha256": self.source_media_sha256,
            "pixel_sha256": self.pixel_sha256,
            "media_sha256": self.media_sha256,
            "output_width": self.output_width,
            "output_height": self.output_height,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type.value,
            "encoding_version": self.encoding_version,
            "privacy_receipt": self.privacy_receipt.model_dump(mode="json"),
            "observability": (
                self.observability.model_dump(mode="json")
                if self.observability is not None
                else None
            ),
            "primary_track_ref": self.primary_track_ref,
        }

    @field_validator("local_path")
    @classmethod
    def validate_relative_posix_path(cls, value: str | None) -> str | None:
        return require_safe_relative_posix_path(value) if value is not None else None

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: dict[str, str]) -> dict[str, str]:
        validate_safe_scalar_metadata(value, allowed_keys=_ALLOWED_CROP_TAGS)
        return value

    @field_validator("frame_id")
    @classmethod
    def validate_frame_id(cls, value: str) -> str:
        parse_frame_id(value)
        return value

    @model_validator(mode="after")
    def validate_crop_result(self) -> Crop:
        frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=self.frame_id)
        ref_keys = tuple(ref.sort_key for ref in self.source_refs)
        if len(ref_keys) != len(set(ref_keys)) or ref_keys != tuple(sorted(ref_keys)):
            raise ValueError("crop source_refs must be unique and use stable artifact order")
        if frame_ref not in self.source_refs:
            raise ValueError("crop source_refs must contain its frame")
        if not set(self.privacy_receipt.input_refs).issubset(self.source_refs):
            raise ValueError("privacy receipt inputs must be crop source references")
        if self.primary_track_ref is not None:
            camera_id, _, _ = parse_frame_id(self.frame_id)
            require_track_ref_camera(self.primary_track_ref, camera_id)
        if self.availability == MediaAvailability.PURGED_BY_RETENTION:
            if self.local_path is not None:
                raise ValueError("purged crop media cannot retain a locator")
        elif self.local_path is None:
            raise ValueError("available or purging crop media requires a locator")
        if self.privacy_receipt.policy == PrivacyPolicy.EPHEMERAL_RAW:
            raise ValueError("ephemeral raw media cannot enter a persisted crop")
        if self.source == CropSource.PANORAMA:
            if self.panorama_long_edge_limit is None:
                raise ValueError("panorama crops require their long-edge limit")
            expected_width, expected_height = _panorama_output_dimensions(
                self.bbox.width,
                self.bbox.height,
                self.panorama_long_edge_limit,
            )
            if (self.output_width, self.output_height) != (
                expected_width,
                expected_height,
            ):
                raise ValueError("panorama crop dimensions do not match its long-edge limit")
            if self.privacy_receipt.policy != PrivacyPolicy.FULL_REDACTION:
                raise ValueError("panorama crops require full redaction")
            if self.privacy_receipt.media_access != MediaAccess.LOCAL_ONLY:
                raise ValueError("panorama crops must remain local")
            if self.privacy_receipt.reason_code != PrivacyReasonCode.PANORAMA_FULL_REDACTION:
                raise ValueError("panorama crops require the panorama privacy receipt")
        if self.privacy_receipt.fallback_used and (
            self.privacy_receipt.media_access != MediaAccess.LOCAL_ONLY
        ):
            raise ValueError("privacy fallback crops must remain local")
        if any(
            not region.is_within(self.output_width, self.output_height)
            for region in self.privacy_receipt.preserved_regions
        ):
            raise ValueError("privacy preserved regions must be inside the output image")
        if self.source == CropSource.SUBJECT and (
            self.privacy_receipt.policy != PrivacyPolicy.FULL_REDACTION
            or self.privacy_receipt.reason_code != PrivacyReasonCode.SUBJECT_FULL_REDACTION
        ):
            raise ValueError("subject crops require the subject full-redaction receipt")
        if self.source == CropSource.DETECTION_FOCUS:
            if self.privacy_receipt.policy != PrivacyPolicy.FULL_REDACTION:
                raise ValueError("detection-focus crops require full redaction")
            if not any(ref.kind == ArtifactKind.DETECTION for ref in self.source_refs):
                raise ValueError("detection-focus crops require a typed detection source")
        if self.source == CropSource.ANCHOR_FOCUS and (
            self.privacy_receipt.policy != PrivacyPolicy.PPE_PRESERVING_REDACTION
        ):
            raise ValueError("anchor-focus crops require PPE-preserving redaction")
        if self.source != CropSource.PANORAMA:
            if self.panorama_long_edge_limit is not None:
                raise ValueError("non-panorama crops cannot carry a panorama limit")
            if (self.output_width, self.output_height) != (
                self.bbox.width,
                self.bbox.height,
            ):
                raise ValueError("non-panorama crop dimensions must equal its bbox")
        return self


class RequestMoreFramesParameters(FrozenContractModel):
    action: Literal[AcquisitionAction.REQUEST_MORE_FRAMES]
    camera_id: ReferenceToken
    stream_id: ReferenceToken
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    step: int = Field(default=1, gt=0, strict=True)

    @field_validator("camera_id", "stream_id")
    @classmethod
    def validate_stream_reference(cls, value: str) -> str:
        return require_reference_token(value, "camera or stream reference")

    @model_validator(mode="after")
    def validate_interval(self) -> RequestMoreFramesParameters:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("requested frame interval must be non-empty")
        return self


class RecropParameters(FrozenContractModel):
    action: Literal[AcquisitionAction.RECROP]
    frame_id: FrameId
    bbox: BBoxXYXY

    @field_validator("frame_id")
    @classmethod
    def validate_frame_id(cls, value: str) -> str:
        parse_frame_id(value)
        return value


class OtherCameraSameTimeParameters(FrozenContractModel):
    action: Literal[AcquisitionAction.OTHER_CAMERA_SAME_TIME]
    source_frame_id: FrameId
    target_camera_id: ReferenceToken

    @field_validator("source_frame_id")
    @classmethod
    def validate_source_frame_id(cls, value: str) -> str:
        parse_frame_id(value)
        return value

    @field_validator("target_camera_id")
    @classmethod
    def validate_target_camera_id(cls, value: str) -> str:
        return require_reference_token(value, "target_camera_id")

    @model_validator(mode="after")
    def validate_distinct_camera(self) -> OtherCameraSameTimeParameters:
        source_camera_id, _, _ = parse_frame_id(self.source_frame_id)
        if source_camera_id == self.target_camera_id:
            raise ValueError("other-camera request must target a different camera")
        return self


class TrackConfidenceCurveParameters(FrozenContractModel):
    action: Literal[AcquisitionAction.TRACK_CONFIDENCE_CURVE]
    track_ref: TrackRef
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)

    @field_validator("track_ref")
    @classmethod
    def validate_track_ref(cls, value: str) -> str:
        parse_track_ref(value)
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> TrackConfidenceCurveParameters:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("track confidence interval must be non-empty")
        return self


class RedetectHighResolutionParameters(FrozenContractModel):
    action: Literal[AcquisitionAction.REDETECT_HIGH_RES]
    crop_id: Sha256Hex
    prompts: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("prompts")
    @classmethod
    def validate_prompts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not prompt or len(prompt) > 128 for prompt in value):
            raise ValueError("redetection prompts must contain bounded non-empty text")
        return value


AcquisitionParameters: TypeAlias = Annotated[
    RequestMoreFramesParameters
    | RecropParameters
    | OtherCameraSameTimeParameters
    | TrackConfidenceCurveParameters
    | RedetectHighResolutionParameters,
    Field(discriminator="action"),
]


class ToolResult(FrozenContractModel):
    tool_result_id: ReferenceToken
    action: AcquisitionAction
    input_refs: tuple[ArtifactRef, ...]
    output_refs: tuple[ArtifactRef, ...]
    validated_parameters: AcquisitionParameters
    execution_manifest_id: Sha256Hex

    @model_validator(mode="after")
    def validate_result(self) -> ToolResult:
        if self.action != self.validated_parameters.action:
            raise ValueError("tool action must match its validated parameter model")
        input_keys = tuple(ref.sort_key for ref in self.input_refs)
        output_keys = tuple(ref.sort_key for ref in self.output_refs)
        if len(input_keys) != len(set(input_keys)) or input_keys != tuple(sorted(input_keys)):
            raise ValueError("tool input_refs must be unique and use stable artifact order")
        if len(output_keys) != len(set(output_keys)) or output_keys != tuple(sorted(output_keys)):
            raise ValueError("tool output_refs must be unique and use stable artifact order")
        parameters = self.validated_parameters
        if isinstance(parameters, RequestMoreFramesParameters):
            expected_outputs = {
                (
                    ArtifactKind.FRAME,
                    f"{parameters.camera_id}:{parameters.stream_id}:{frame_index}",
                )
                for frame_index in range(
                    parameters.start_frame,
                    parameters.end_frame_exclusive,
                    parameters.step,
                )
            }
            if {(ref.kind, ref.artifact_id) for ref in self.output_refs} != expected_outputs:
                raise ValueError("request-more-frames outputs must exactly match its frame range")
        elif isinstance(parameters, RecropParameters):
            required_input = ArtifactRef(
                kind=ArtifactKind.FRAME,
                artifact_id=parameters.frame_id,
            )
            if required_input not in self.input_refs:
                raise ValueError("recrop tool input must include its requested frame")
            if len(self.output_refs) != 1 or self.output_refs[0].kind != ArtifactKind.CROP:
                raise ValueError("recrop tool output must be exactly one crop")
        elif isinstance(parameters, OtherCameraSameTimeParameters):
            required_input = ArtifactRef(
                kind=ArtifactKind.FRAME,
                artifact_id=parameters.source_frame_id,
            )
            if required_input not in self.input_refs:
                raise ValueError("other-camera input must include its source frame")
            if not self.output_refs or any(
                ref.kind != ArtifactKind.FRAME
                or parse_frame_id(ref.artifact_id)[0] != parameters.target_camera_id
                for ref in self.output_refs
            ):
                raise ValueError("other-camera outputs must be frames from the target camera")
        elif isinstance(parameters, RedetectHighResolutionParameters):
            required_input = ArtifactRef(
                kind=ArtifactKind.CROP,
                artifact_id=parameters.crop_id,
            )
            if required_input not in self.input_refs:
                raise ValueError("redetection input must include its source crop")
            if not self.output_refs or any(
                ref.kind != ArtifactKind.DETECTION for ref in self.output_refs
            ):
                raise ValueError("redetection outputs must be typed detections")
        return self


class ObservationSufficiencyInput(FrozenContractModel):
    clear_crop_ids: tuple[Sha256Hex, ...] = ()
    unclear_crop_ids: tuple[Sha256Hex, ...] = ()
    clear_threshold: StrictFloat = Field(ge=0, le=1)
    required_clear_count: int = Field(gt=0, strict=True)
    selected_by_observability: StrictBool
    consistency_status: Literal[ConsistencyEvaluationStatus.NOT_EVALUATED] = (
        ConsistencyEvaluationStatus.NOT_EVALUATED
    )

    @model_validator(mode="after")
    def validate_disjoint_sets(self) -> ObservationSufficiencyInput:
        if set(self.clear_crop_ids) & set(self.unclear_crop_ids):
            raise ValueError("clear and unclear crop sets must be disjoint")
        return self


class TrackSummary(FrozenContractModel):
    primary_track_ref: TrackRef | None = None
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    observed_frame_count: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def validate_track_interval(self) -> TrackSummary:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("track summary interval must be non-empty")
        if self.primary_track_ref is not None:
            parse_track_ref(self.primary_track_ref)
        if self.observed_frame_count > self.end_frame_exclusive - self.start_frame:
            raise ValueError("observed_frame_count cannot exceed the summarized interval")
        return self


def _crop_semantic_projection(crop: Crop) -> dict[str, object]:
    """Return the explicit, locator-free crop projection used by pack identity."""

    return crop.semantic_projection()


class EvidencePackDraft(FrozenContractModel):
    run_id: ReferenceToken
    case_id: ReferenceToken
    version: int = Field(gt=0, strict=True)
    complete: StrictBool = True
    event: CandidateEvent
    key_frame_ids: tuple[FrameId, ...]
    panorama_crops: tuple[Crop, ...] = ()
    subject_crops: tuple[Crop, ...] = ()
    focus_crops: tuple[Crop, ...] = ()
    temporal_crops: tuple[Crop, ...] = ()
    objective_facts: tuple[ObjectiveFact, ...] = ()
    track_summary: TrackSummary
    confirmation_record: ConfirmationRecord
    observation_sufficiency_input: ObservationSufficiencyInput | None = None
    tool_results: tuple[ToolResult, ...] = ()
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_pack_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "pack_id" in payload
        claimed = payload.pop("pack_id", None)
        pack = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized pack_id must be a string")
        if claimed_present and claimed != pack.pack_id:
            raise ValueError("serialized pack_id does not match pack identity fields")
        return pack

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pack_id(self) -> Sha256Hex:
        return sha256_hex(["evidence-pack", 2, self.semantic_projection()])

    @property
    def crops(self) -> tuple[Crop, ...]:
        return self.panorama_crops + self.subject_crops + self.focus_crops + self.temporal_crops

    def closure_input_projection(self) -> dict[str, object]:
        """Return all immutable inputs checked by creation closure, excluding its report."""

        return {
            "case_id": self.case_id,
            "complete": self.complete,
            "event": self.event.model_dump(mode="json"),
            "key_frame_ids": list(self.key_frame_ids),
            "panorama_crops": [_crop_semantic_projection(crop) for crop in self.panorama_crops],
            "subject_crops": [_crop_semantic_projection(crop) for crop in self.subject_crops],
            "focus_crops": [_crop_semantic_projection(crop) for crop in self.focus_crops],
            "temporal_crops": [_crop_semantic_projection(crop) for crop in self.temporal_crops],
            "objective_facts": [fact.model_dump(mode="json") for fact in self.objective_facts],
            "track_summary": self.track_summary.model_dump(mode="json"),
            "confirmation_record": self.confirmation_record.model_dump(mode="json"),
            "observation_sufficiency_input": (
                self.observation_sufficiency_input.model_dump(mode="json")
                if self.observation_sufficiency_input is not None
                else None
            ),
            "tool_results": [result.model_dump(mode="json") for result in self.tool_results],
            "manifest_id": self.manifest_id,
        }

    @property
    def closure_input_sha256(self) -> Sha256Hex:
        return sha256_hex(["evidence-closure-input", 1, self.closure_input_projection()])

    @property
    def pack_input_sha256(self) -> Sha256Hex:
        """Idempotency key excluding assigned version, run scope, and local locators."""

        return sha256_hex(["evidence-pack-input", 1, self.semantic_projection()])

    def semantic_projection(self) -> dict[str, object]:
        """Return the exact M2 pack identity projection.

        Operational locators and current availability are absent by construction.
        Creation-closure proof metadata is also excluded, so a validator upgrade
        cannot silently create a new semantic evidence object.
        """

        return self.closure_input_projection()

    def expected_closure_refs(self) -> tuple[ArtifactRef, ...]:
        references: dict[tuple[str, str], ArtifactRef] = {}

        def include(ref: ArtifactRef) -> None:
            references[ref.sort_key] = ref

        include(ArtifactRef(kind=ArtifactKind.CASE, artifact_id=self.case_id))
        include(ArtifactRef(kind=ArtifactKind.EVENT, artifact_id=self.event.event_id))
        include(ArtifactRef(kind=ArtifactKind.MANIFEST, artifact_id=self.manifest_id))
        confirmation_frames = (
            self.confirmation_record.examined_frame_ids
            + self.confirmation_record.counterevidence_frame_ids
            + (
                (self.confirmation_record.post_threshold_recovery_frame_id,)
                if self.confirmation_record.post_threshold_recovery_frame_id is not None
                else ()
            )
        )
        for frame_id in self.key_frame_ids + confirmation_frames:
            include(ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id))
        for crop in self.crops:
            include(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id))
            include(ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=crop.media_sha256))
            for ref in crop.source_refs:
                include(ref)
        for fact in self.objective_facts:
            include(ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id=fact.fact_id))
            include(fact.source_ref)
            include(
                ArtifactRef(
                    kind=ArtifactKind.MANIFEST,
                    artifact_id=fact.source_manifest_id,
                )
            )
        for result in self.tool_results:
            include(
                ArtifactRef(
                    kind=ArtifactKind.TOOL_RESULT,
                    artifact_id=result.tool_result_id,
                )
            )
            for ref in result.input_refs + result.output_refs:
                include(ref)
            include(
                ArtifactRef(
                    kind=ArtifactKind.MANIFEST,
                    artifact_id=result.execution_manifest_id,
                )
            )
        return tuple(references[key] for key in sorted(references))

    @model_validator(mode="after")
    def validate_semantic_content(self) -> EvidencePackDraft:
        crop_ids = [crop.crop_id for crop in self.crops]
        if len(crop_ids) != len(set(crop_ids)):
            raise ValueError("crop_id values must be unique within a pack")
        if len(self.key_frame_ids) != len(set(self.key_frame_ids)):
            raise ValueError("key_frame_ids must be unique")
        parsed_key_frames = tuple(parse_frame_id(frame_id) for frame_id in self.key_frame_ids)
        if any(
            camera_id != self.event.camera_id or stream_id != self.event.stream_id
            for camera_id, stream_id, _ in parsed_key_frames
        ):
            raise ValueError("key frames must belong to the event camera and stream")
        if tuple(index for _, _, index in parsed_key_frames) != tuple(
            sorted(index for _, _, index in parsed_key_frames)
        ):
            raise ValueError("key frames must use stable frame-index order")
        trigger_frame_id = (
            f"{self.event.camera_id}:{self.event.stream_id}:{self.event.trigger_frame}"
        )
        if trigger_frame_id not in self.key_frame_ids:
            raise ValueError("key frames must contain the event trigger frame")
        if any(
            not self.track_summary.start_frame <= index < self.track_summary.end_frame_exclusive
            for _, _, index in parsed_key_frames
        ):
            raise ValueError("key frames must be inside the summarized evidence window")
        if self.confirmation_record != self.event.confirmation:
            raise ValueError("pack confirmation_record must match its event")
        if self.case_id != derive_case_id(self.event.event_id):
            raise ValueError("evidence pack case_id does not match its event")
        if self.manifest_id != self.event.manifest_id:
            raise ValueError("evidence pack and event must use the same manifest")
        if self.track_summary.primary_track_ref != self.event.primary_track_ref:
            raise ValueError("track summary must describe the event primary track")
        if (
            self.track_summary.start_frame > self.event.start_frame
            or self.track_summary.end_frame_exclusive < self.event.end_frame_exclusive
        ):
            raise ValueError("track summary must cover the complete event interval")
        expected_focus_source = (
            CropSource.ANCHOR_FOCUS
            if self.event.evidence_class == EvidenceClass.ABSENCE
            else CropSource.DETECTION_FOCUS
        )
        if any(crop.source != CropSource.PANORAMA for crop in self.panorama_crops):
            raise ValueError("panorama_crops must contain only PANORAMA crops")
        if any(crop.source != CropSource.SUBJECT for crop in self.subject_crops):
            raise ValueError("subject_crops must contain only SUBJECT crops")
        if any(crop.source != expected_focus_source for crop in self.focus_crops):
            raise ValueError("focus crop source does not match the event evidence class")
        if any(crop.source != expected_focus_source for crop in self.temporal_crops):
            raise ValueError("temporal crop source does not match the event evidence class")
        key_frame_set = set(self.key_frame_ids)
        if any(crop.frame_id not in key_frame_set for crop in self.crops):
            raise ValueError("every crop frame must be a key frame")
        for collection in (
            self.panorama_crops,
            self.subject_crops,
            self.focus_crops,
            self.temporal_crops,
        ):
            order = tuple((parse_frame_id(crop.frame_id)[2], crop.crop_id) for crop in collection)
            if order != tuple(sorted(order)):
                raise ValueError("crop collections must use stable frame and crop order")
        for crop in self.temporal_crops:
            if crop.primary_track_ref != self.event.primary_track_ref:
                raise ValueError("temporal crops must belong to the event primary track")
            if crop.observability is None:
                raise ValueError("temporal crops require observability")
            _, _, frame_index = parse_frame_id(crop.frame_id)
            if not self.event.start_frame <= frame_index < self.event.end_frame_exclusive:
                raise ValueError("temporal crops must fall inside the alleged event interval")

        fact_ids = tuple(fact.fact_id for fact in self.objective_facts)
        if len(fact_ids) != len(set(fact_ids)) or fact_ids != tuple(sorted(fact_ids)):
            raise ValueError("objective facts must be unique and use stable fact_id order")
        pack_facts = {fact.fact_id: fact for fact in self.objective_facts}
        event_fact_ids = [fact.fact_id for fact in self.event.objective_facts]
        if len(event_fact_ids) != len(set(event_fact_ids)):
            raise ValueError("event objective facts must have unique fact_id values")
        if any(pack_facts.get(fact.fact_id) != fact for fact in self.event.objective_facts):
            raise ValueError("pack must include event objective facts without rewriting them")
        tool_ids = tuple(result.tool_result_id for result in self.tool_results)
        if len(tool_ids) != len(set(tool_ids)) or tool_ids != tuple(sorted(tool_ids)):
            raise ValueError("tool results must be unique and use stable result order")

        if self.event.evidence_class == EvidenceClass.ABSENCE:
            sufficiency = self.observation_sufficiency_input
            if sufficiency is None:
                raise ValueError("absence evidence requires observation sufficiency input")
            temporal_ids = {crop.crop_id for crop in self.temporal_crops}
            classified_ids = set(sufficiency.clear_crop_ids) | set(sufficiency.unclear_crop_ids)
            if classified_ids != temporal_ids:
                raise ValueError("absence sufficiency must classify every temporal crop")
            clear_ids = {
                crop.crop_id
                for crop in self.temporal_crops
                if crop.observability is not None
                and crop.observability.total >= sufficiency.clear_threshold
            }
            if clear_ids != set(sufficiency.clear_crop_ids):
                raise ValueError("clear crop IDs must match the observability threshold")
        elif self.observation_sufficiency_input is not None:
            raise ValueError("presence evidence cannot contain absence sufficiency input")

        return self


class EvidencePack(EvidencePackDraft):
    closure_report: ClosureReport

    @model_validator(mode="after")
    def validate_creation_closure(self) -> EvidencePack:
        root_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=self.case_id)
        if self.closure_report.run_id != self.run_id:
            raise ValueError("closure report belongs to another run")
        if self.closure_report.root_ref != root_ref:
            raise ValueError("closure report must be rooted at the evidence case")
        if self.closure_report.manifest_id != self.manifest_id:
            raise ValueError("closure report uses another manifest")
        if self.closure_report.input_sha256 != self.closure_input_sha256:
            raise ValueError("closure report is not bound to these pack inputs")
        if self.closure_report.checked_refs != self.expected_closure_refs():
            raise ValueError("closure report does not cover the exact pack reference graph")
        if not self.closure_report.passed:
            raise ValueError("all persisted evidence packs require passing creation closure")
        return self
