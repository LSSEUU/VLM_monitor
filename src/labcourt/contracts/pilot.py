"""Command-boundary contracts for the v0.2 real-video pilot."""

from __future__ import annotations

from pydantic import Field, StrictBool, field_validator, model_validator

from labcourt.contracts.base import ContractModel
from labcourt.contracts.enums import ViolationType
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import ReferenceToken, require_portable_run_id


class PilotRunRequest(ContractModel):
    """Validated, content-bound input for a pilot run or perception preflight."""

    run_id: ReferenceToken
    config_sha256: Sha256Hex
    video_relative_path: str = Field(min_length=1)
    video_sha256: Sha256Hex
    selected_rules: tuple[ViolationType, ...] = Field(min_length=1)
    resume: StrictBool
    max_cases: int = Field(gt=0, le=1_000, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot run_id")

    @field_validator("video_relative_path")
    @classmethod
    def validate_video_relative_path(cls, value: str) -> str:
        controlled = require_safe_relative_posix_path(value)
        if not controlled.lower().endswith(".mp4"):
            raise ValueError("pilot video must use the .mp4 extension")
        return controlled

    @model_validator(mode="after")
    def validate_selected_rules(self) -> PilotRunRequest:
        if len(self.selected_rules) != len(set(self.selected_rules)):
            raise ValueError("selected_rules must be unique")
        return self
