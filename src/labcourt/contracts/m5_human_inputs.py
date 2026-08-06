"""Small validation-only M5 inputs authored directly by human reviewers."""

from __future__ import annotations

from typing import Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel, Scalar
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m3_models import require_bounded_public_text


class M5AppealTrainingLabelInput(FrozenContractModel):
    """Reviewer-authored label facts; authority fields are bound by the application."""

    crop_id: Sha256Hex
    bbox: BBoxXYXY
    label_name: str = Field(min_length=1, max_length=128)
    label_value: Scalar

    @field_validator("label_name")
    @classmethod
    def validate_label_name(cls, value: str) -> str:
        return require_bounded_public_text(value, "appeal label name", max_length=128)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_input_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "input_id" in payload
        claimed = payload.pop("input_id", None)
        authored = handler(payload)
        if present and claimed != authored.input_id:
            raise ValueError("serialized appeal training input ID does not match")
        return authored

    @computed_field  # type: ignore[prop-decorator]
    @property
    def input_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-appeal-training-label-input",
                1,
                self.crop_id,
                self.bbox.model_dump(mode="json"),
                self.label_name,
                self.label_value,
            ]
        )


__all__ = ["M5AppealTrainingLabelInput"]
