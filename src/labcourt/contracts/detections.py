"""Perception input contracts."""

from __future__ import annotations

from pydantic import Field, StrictBool, StrictFloat, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel, Scalar
from labcourt.contracts.enums import AssociationMethod
from labcourt.contracts.frames import FrameRef, Sha256Hex
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.metadata import validate_safe_scalar_metadata
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    TrackRef,
    parse_track_ref,
    require_track_ref_camera,
)

_ALLOWED_DETECTION_ATTRIBUTES = {
    "cap_detected",
    "observation_source",
    "occluded",
    "pose_source",
    "source_label",
}


class Keypoint(FrozenContractModel):
    name: str = Field(min_length=1)
    x: StrictFloat = Field(ge=0)
    y: StrictFloat = Field(ge=0)
    score: StrictFloat = Field(ge=0, le=1)


class Detection(FrozenContractModel):
    detection_id: ReferenceToken
    frame_id: FrameId
    label: str = Field(min_length=1)
    bbox: BBoxXYXY
    score: StrictFloat = Field(ge=0, le=1)
    track_ref: TrackRef | None = None
    keypoints: tuple[Keypoint, ...] = ()
    attributes: dict[str, Scalar] = Field(default_factory=dict)
    model_manifest_id: Sha256Hex

    @field_validator("track_ref")
    @classmethod
    def validate_track_ref(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parse_track_ref(value)
        return value

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict[str, Scalar]) -> dict[str, Scalar]:
        validate_safe_scalar_metadata(value, allowed_keys=_ALLOWED_DETECTION_ATTRIBUTES)
        return value


class FrameBundle(FrozenContractModel):
    frame: FrameRef
    detections: tuple[Detection, ...] = ()

    @model_validator(mode="after")
    def validate_detection_references(self) -> FrameBundle:
        detection_ids: set[str] = set()
        for detection in self.detections:
            if detection.frame_id != self.frame.frame_id:
                raise ValueError(f"detection {detection.detection_id} references a different frame")
            detection.bbox.require_within(self.frame.width, self.frame.height)
            if detection.track_ref is not None:
                try:
                    require_track_ref_camera(detection.track_ref, self.frame.camera_id)
                except ValueError as exc:
                    raise ValueError(
                        f"detection {detection.detection_id} track_ref belongs to another camera"
                    ) from exc
            if detection.detection_id in detection_ids:
                raise ValueError(f"duplicate detection_id: {detection.detection_id}")
            keypoint_names = [keypoint.name for keypoint in detection.keypoints]
            if len(keypoint_names) != len(set(keypoint_names)):
                raise ValueError(f"detection {detection.detection_id} has duplicate keypoint names")
            if any(
                keypoint.x >= self.frame.width or keypoint.y >= self.frame.height
                for keypoint in detection.keypoints
            ):
                raise ValueError(
                    f"detection {detection.detection_id} has a keypoint outside frame bounds"
                )
            detection_ids.add(detection.detection_id)
        return self


class AssociationResult(FrozenContractModel):
    present: StrictBool
    anchor_bbox: BBoxXYXY
    matched_detection_ids: tuple[str, ...] = ()
    method: AssociationMethod
    quality_flags: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_unique_matches(self) -> AssociationResult:
        if len(self.matched_detection_ids) != len(set(self.matched_detection_ids)):
            raise ValueError("matched_detection_ids must be unique")
        return self
