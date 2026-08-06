"""Immutable model and run manifests."""

from __future__ import annotations

from math import gcd
from typing import Literal, Self

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
from labcourt.contracts.enums import (
    DeviceClass,
    OperatingSystemFamily,
    ReproducibilityMode,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

REQUIRED_MODEL_COMPONENTS = {
    "detector",
    "tracker",
    "pose",
    "screening",
    "prosecutor",
    "defender",
    "judge",
    "text_embedding",
    "visual_embedding",
}


def _versioned_digest(kind: str, payload: object) -> str:
    return sha256_hex([kind, 1, payload])


class ModelManifest(FrozenContractModel):
    component: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    quantization: str | None = None
    weights_sha256: Sha256Hex | None = None
    license_id: str = Field(min_length=1)
    provider_revision_guarantee: StrictBool = True

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_model_manifest_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "model_manifest_id" in payload
        claimed = payload.pop("model_manifest_id", None)
        manifest = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized model_manifest_id must be a string")
        if claimed_present and claimed != manifest.model_manifest_id:
            raise ValueError("serialized model_manifest_id does not match model content")
        return manifest

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_manifest_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"model_manifest_id"})
        return _versioned_digest("model-manifest", payload)


class DecodingParameters(FrozenContractModel):
    temperature: StrictFloat = Field(ge=0)
    seed: int | None = Field(default=None, strict=True)
    max_output_tokens: int | None = Field(default=None, gt=0, strict=True)


class PlatformSummary(FrozenContractModel):
    os_family: OperatingSystemFamily
    architecture: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    python_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    device_class: DeviceClass


class SoftwareComponentManifest(FrozenContractModel):
    component: ReferenceToken
    package: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=128)
    license_id: str = Field(min_length=1, max_length=128)

    @field_validator("component")
    @classmethod
    def validate_component(cls, value: str) -> str:
        return require_reference_token(value, "software component")


class StreamManifest(FrozenContractModel):
    camera_id: ReferenceToken
    stream_id: ReferenceToken
    input_file_sha256: Sha256Hex
    fps_num: int = Field(gt=0, strict=True)
    fps_den: int = Field(gt=0, strict=True)
    timing_mode: Literal["CFR"]
    timing_authority: Literal["CALLER_ATTESTED", "TRUSTED_SIDECAR"]
    timing_evidence_type: Literal["CALLER_DECLARATION", "TRUSTED_SIDECAR_JSON"]
    timing_evidence_sha256: Sha256Hex
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)
    frame_count: int = Field(gt=0, strict=True)
    decoder: str = Field(min_length=1, max_length=128)
    decoder_version: str = Field(min_length=1, max_length=128)
    backend: str = Field(min_length=1, max_length=128)
    software_component: ReferenceToken
    library: str = Field(min_length=1, max_length=128)
    library_version: str = Field(min_length=1, max_length=128)
    codec: str = Field(pattern=r"^[\x20-\x7e]{4}$")
    color_conversion: str = Field(min_length=1, max_length=128)
    pixel_format: Literal["RGB8"]
    pixel_hash_algorithm: Literal["LCPIX1"]

    @field_validator("camera_id", "stream_id", "software_component")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "stream camera or stream reference")

    @model_validator(mode="after")
    def validate_canonical_fps(self) -> StreamManifest:
        if gcd(self.fps_num, self.fps_den) != 1:
            raise ValueError("stream FPS numerator and denominator must be in lowest terms")
        expected_evidence_type = (
            "CALLER_DECLARATION"
            if self.timing_authority == "CALLER_ATTESTED"
            else "TRUSTED_SIDECAR_JSON"
        )
        if self.timing_evidence_type != expected_evidence_type:
            raise ValueError("stream timing evidence type does not match its timing authority")
        return self


class RunManifest(FrozenContractModel):
    code_commit: str = Field(min_length=1)
    schema_version: Literal["2.0.0"]
    config_sha256: Sha256Hex
    rule_version: str = Field(min_length=1)
    rule_bundle_sha256: Sha256Hex
    prompt_bundle_sha256: Sha256Hex
    models: dict[str, ModelManifest] = Field(min_length=len(REQUIRED_MODEL_COMPONENTS))
    privacy_transform_version: str = Field(min_length=1)
    reproducibility_mode: ReproducibilityMode
    random_seed: int = Field(strict=True)
    decoding_parameters: DecodingParameters
    platform_summary: PlatformSummary
    storage_boundary: Literal["LOCAL_FILESYSTEM"]
    streams: tuple[StreamManifest, ...]
    software_components: dict[str, SoftwareComponentManifest]
    pixel_format: Literal["RGB8"]
    pixel_hash_algorithm: Literal["LCPIX1"]
    image_encoding_version: str = Field(min_length=1, max_length=128)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_manifest_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "manifest_id" in payload
        claimed = payload.pop("manifest_id", None)
        manifest = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized manifest_id must be a string")
        if claimed_present and claimed != manifest.manifest_id:
            raise ValueError("serialized manifest_id does not match manifest content")
        return manifest

    @computed_field  # type: ignore[prop-decorator]
    @property
    def manifest_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"manifest_id"})
        return _versioned_digest("run-manifest", payload)

    @model_validator(mode="after")
    def validate_model_components(self) -> RunManifest:
        missing = REQUIRED_MODEL_COMPONENTS - set(self.models)
        if missing:
            raise ValueError(f"run manifest missing model components: {sorted(missing)}")
        for key, model in self.models.items():
            if key != model.component:
                raise ValueError(
                    f"model mapping key {key} does not match component {model.component}"
                )
        stream_keys = tuple((stream.camera_id, stream.stream_id) for stream in self.streams)
        if len(stream_keys) != len(set(stream_keys)):
            raise ValueError("run manifest streams must be unique by camera_id and stream_id")
        if stream_keys != tuple(sorted(stream_keys)):
            raise ValueError("run manifest streams must use stable order")
        for key, component in self.software_components.items():
            require_reference_token(key, "software component mapping key")
            if key != component.component:
                raise ValueError(
                    f"software component mapping key {key} does not match component "
                    f"{component.component}"
                )
        for stream in self.streams:
            stream_component = self.software_components.get(stream.software_component)
            if stream_component is None:
                raise ValueError("run manifest stream references an unknown software component")
            if (
                stream_component.package != stream.library
                or stream_component.version != stream.library_version
            ):
                raise ValueError("stream decoder library does not match its software component")
        return self
