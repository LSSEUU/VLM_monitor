"""Authoritative frame references."""

from __future__ import annotations

from typing import Annotated, TypeAlias

from pydantic import Field, StrictBool, computed_field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.references import FrameId, ReferenceToken, require_reference_token

SHA256_PATTERN = r"^[0-9a-f]{64}$"
Sha256Hex: TypeAlias = Annotated[str, Field(pattern=SHA256_PATTERN)]


class FrameRef(FrozenContractModel):
    camera_id: ReferenceToken
    stream_id: ReferenceToken
    frame_index: int = Field(ge=0, strict=True)
    fps_num: int = Field(gt=0, strict=True)
    fps_den: int = Field(gt=0, strict=True)
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)
    content_sha256: Sha256Hex | None = None

    @field_validator("camera_id", "stream_id")
    @classmethod
    def validate_unambiguous_id_token(cls, value: str) -> str:
        return require_reference_token(value, "camera_id or stream_id")

    @model_validator(mode="before")
    @classmethod
    def validate_serialized_derived_fields(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        payload = dict(value)
        frame_id_present = "frame_id" in payload
        timestamp_present = "timestamp_ms" in payload
        claimed_frame_id = payload.pop("frame_id", None)
        claimed_timestamp = payload.pop("timestamp_ms", None)
        camera_id = payload.get("camera_id")
        stream_id = payload.get("stream_id")
        frame_index = payload.get("frame_index")
        fps_num = payload.get("fps_num")
        fps_den = payload.get("fps_den")
        if frame_id_present and not isinstance(claimed_frame_id, str):
            raise ValueError("serialized frame_id must be a string")
        if (
            frame_id_present
            and isinstance(camera_id, str)
            and isinstance(stream_id, str)
            and isinstance(frame_index, int)
            and claimed_frame_id != f"{camera_id}:{stream_id}:{frame_index}"
        ):
            raise ValueError("serialized frame_id does not match authoritative fields")
        if timestamp_present and (
            not isinstance(claimed_timestamp, int) or isinstance(claimed_timestamp, bool)
        ):
            raise ValueError("serialized timestamp_ms must be an integer")
        if (
            timestamp_present
            and isinstance(frame_index, int)
            and isinstance(fps_num, int)
            and isinstance(fps_den, int)
            and fps_num > 0
            and fps_den > 0
            and claimed_timestamp != (frame_index * 1000 * fps_den) // fps_num
        ):
            raise ValueError("serialized timestamp_ms does not match frame timebase")
        return payload

    @computed_field  # type: ignore[prop-decorator]
    @property
    def frame_id(self) -> FrameId:
        return f"{self.camera_id}:{self.stream_id}:{self.frame_index}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timestamp_ms(self) -> int:
        return (self.frame_index * 1000 * self.fps_den) // self.fps_num


class FrameData(FrozenContractModel):
    frame: FrameRef
    media_ref: str = Field(min_length=1)
    ephemeral: StrictBool = True
