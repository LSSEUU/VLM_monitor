"""Quality-tiered detector feedback labels."""

from __future__ import annotations

from pydantic import Field, field_validator

from labcourt.contracts.base import FrozenContractModel, Scalar
from labcourt.contracts.enums import DatasetFormat, TrainingLabelQuality
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.paths import require_safe_relative_posix_path


class TrainingLabel(FrozenContractModel):
    label_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    crop_id: Sha256Hex
    bbox: BBoxXYXY
    label_name: str = Field(min_length=1)
    label_value: Scalar
    quality: TrainingLabelQuality
    source: str = Field(min_length=1)
    reviewer_id: str | None = None
    rule_version: str = Field(min_length=1)
    detector_manifest_id: Sha256Hex
    excluded_reason: str | None = None


class DatasetArtifact(FrozenContractModel):
    dataset_id: str = Field(min_length=1)
    format: DatasetFormat
    relative_path: str = Field(min_length=1)
    content_sha256: Sha256Hex
    label_count: int = Field(ge=0, strict=True)
    minimum_quality: TrainingLabelQuality
    rule_version: str = Field(min_length=1)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)
