"""Fail-closed, constant-size provenance receipts for M5 training labels."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import AppealStatus, TrainingLabelQuality
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.references import ReferenceToken
from labcourt.contracts.training import TrainingLabel

STRONG_TRAINING_LABEL_QUALITIES = frozenset(
    {
        TrainingLabelQuality.HUMAN_CONFIRMED,
        TrainingLabelQuality.APPEAL_CONFIRMED,
    }
)


def _label_document_sha256(label: TrainingLabel) -> Sha256Hex:
    return sha256_hex(label.model_dump(mode="json"))


class M5StrongTrainingLabelProvenanceReceipt(FrozenContractModel):
    """Constant-size roots needed to resolve one strong label's appeal provenance."""

    schema_version: Literal["m5-strong-training-label-provenance-receipt-v1"] = (
        "m5-strong-training-label-provenance-receipt-v1"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    appeal_id: ReferenceToken
    label_id: ReferenceToken
    label_document_sha256: Sha256Hex
    crop_id: Sha256Hex
    reviewer_id: ReferenceToken
    quality: Literal[
        TrainingLabelQuality.HUMAN_CONFIRMED,
        TrainingLabelQuality.APPEAL_CONFIRMED,
    ]
    authored_input: M5AppealTrainingLabelInput
    review_authority_sha256: Sha256Hex
    terminal_authority_sha256: Sha256Hex
    terminal_status: Literal[AppealStatus.UPHELD, AppealStatus.OVERTURNED]
    resolution_intent_id: Sha256Hex
    resolution_document_sha256: Sha256Hex
    resolution_commit_receipt_id: Sha256Hex
    resolution_commit_effect_root_sha256: Sha256Hex
    manifest_id: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)
    detector_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_provenance_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "provenance_id" in payload
        claimed = payload.pop("provenance_id", None)
        receipt = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != receipt.provenance_id):
            raise ValueError("serialized provenance_id does not match strong label provenance")
        return receipt

    @model_validator(mode="after")
    def validate_root_bindings(self) -> Self:
        expected_quality = {
            AppealStatus.UPHELD: TrainingLabelQuality.HUMAN_CONFIRMED,
            AppealStatus.OVERTURNED: TrainingLabelQuality.APPEAL_CONFIRMED,
        }[self.terminal_status]
        if self.quality != expected_quality:
            raise ValueError("strong label quality conflicts with the terminal Appeal outcome")
        if self.crop_id != self.authored_input.crop_id:
            raise ValueError("strong label Crop conflicts with its human-authored input")

        expected_label_id = sha256_hex(
            [
                "m5-appeal-training-label",
                1,
                self.review_authority_sha256,
                self.terminal_status,
                self.reviewer_id,
                self.authored_input.input_id,
            ]
        )
        if self.label_id != expected_label_id:
            raise ValueError("strong label ID is not derived from its human review authority")

        expected_commit_receipt_id = sha256_hex(
            [
                "m5-appeal-resolution-commit-receipt",
                1,
                self.resolution_commit_effect_root_sha256,
            ]
        )
        if self.resolution_commit_receipt_id != expected_commit_receipt_id:
            raise ValueError("strong label final commit receipt ID does not match its effect root")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provenance_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-strong-training-label-provenance-receipt",
                1,
                self.model_dump(mode="json", exclude={"provenance_id"}),
            ]
        )


class M5TrainingLabelAuthority(FrozenContractModel):
    """The formal M5 wrapper that prevents strong labels from bypassing provenance."""

    schema_version: Literal["m5-training-label-authority-v1"] = "m5-training-label-authority-v1"
    label: TrainingLabel
    strong_provenance: M5StrongTrainingLabelProvenanceReceipt | None = None

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claims = {
            name: (name in payload, payload.pop(name, None))
            for name in ("label_document_sha256", "authority_sha256")
        }
        authority = handler(payload)
        for name, (present, claimed) in claims.items():
            if present and (not isinstance(claimed, str) or claimed != getattr(authority, name)):
                raise ValueError(f"serialized {name} does not match training label authority")
        return authority

    @model_validator(mode="after")
    def validate_quality_provenance_matrix(self) -> Self:
        label = self.label
        provenance = self.strong_provenance
        strong = label.quality in STRONG_TRAINING_LABEL_QUALITIES
        if strong and provenance is None:
            raise ValueError("strong training labels require closed strong provenance")
        if not strong and provenance is not None:
            raise ValueError("weak training labels cannot carry strong provenance")
        if provenance is not None and (
            provenance.label_id != label.label_id
            or provenance.label_document_sha256 != self.label_document_sha256
            or provenance.case_id != label.case_id
            or provenance.crop_id != label.crop_id
            or provenance.reviewer_id != label.reviewer_id
            or provenance.quality != label.quality
            or provenance.authored_input.crop_id != label.crop_id
            or provenance.authored_input.bbox != label.bbox
            or provenance.authored_input.label_name != label.label_name
            or provenance.authored_input.label_value != label.label_value
            or provenance.rule_version != label.rule_version
            or provenance.detector_manifest_id != label.detector_manifest_id
            or label.source != f"appeal-review:{provenance.appeal_id}"
            or label.excluded_reason is not None
        ):
            raise ValueError("training label authority conflicts with its strong provenance")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def label_document_sha256(self) -> Sha256Hex:
        return _label_document_sha256(self.label)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-training-label-authority",
                1,
                self.label_document_sha256,
                (
                    self.strong_provenance.provenance_id
                    if self.strong_provenance is not None
                    else None
                ),
            ]
        )


__all__ = [
    "STRONG_TRAINING_LABEL_QUALITIES",
    "M5StrongTrainingLabelProvenanceReceipt",
    "M5TrainingLabelAuthority",
]
