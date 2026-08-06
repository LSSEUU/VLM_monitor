"""Content-addressed persistence roots for M4 acquisition and rework transitions."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ProceduralDefectCode
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token


class EvidencePackDerivation(FrozenContractModel):
    """Exact predecessor/tool/successor authority for one acquired pack version."""

    schema_version: Literal["m4-evidence-pack-derivation-v1"] = "m4-evidence-pack-derivation-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    source_cycle_scope_id: Sha256Hex
    source_cycle_scope_sha256: Sha256Hex
    previous_evidence_pack_id: Sha256Hex
    previous_evidence_pack_version: int = Field(gt=0, strict=True)
    new_evidence_pack_id: Sha256Hex
    new_evidence_pack_version: int = Field(gt=0, strict=True)
    tool_execution_receipt_id: Sha256Hex
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "evidence pack derivation reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_identity(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        names = ("derivation_id", "derivation_sha256")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        derivation = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(derivation, name):
                raise ValueError(f"serialized {name} conflicts with pack derivation")
        return derivation

    def derivation_projection(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude_computed_fields=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def derivation_id(self) -> Sha256Hex:
        return sha256_hex(["m4-evidence-pack-derivation", 1, self.derivation_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def derivation_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m4-evidence-pack-derivation-document",
                1,
                self.derivation_id,
                self.derivation_projection(),
            ]
        )

    @model_validator(mode="after")
    def validate_successor(self) -> EvidencePackDerivation:
        if self.new_evidence_pack_version != self.previous_evidence_pack_version + 1:
            raise ValueError("pack derivation successor version must advance by one")
        if self.new_evidence_pack_id == self.previous_evidence_pack_id:
            raise ValueError("pack derivation successor must have a new content address")
        return self


class HearingReworkReceipt(FrozenContractModel):
    """Failed-review authority opening exactly one adjacent rework cycle."""

    schema_version: Literal["m4-hearing-rework-receipt-v1"] = "m4-hearing-rework-receipt-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    failed_review_id: Sha256Hex
    prior_round_id: Sha256Hex
    next_cycle_scope_id: Sha256Hex
    next_cycle_scope_sha256: Sha256Hex
    rework_index: int = Field(gt=0, le=2, strict=True)
    defect_codes: tuple[ProceduralDefectCode, ...] = Field(min_length=1, max_length=14)
    prompt_defect_summary_sha256: Sha256Hex
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing rework receipt reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_identity(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        names = ("defect_set_sha256", "receipt_id", "receipt_sha256")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        receipt = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(receipt, name):
                raise ValueError(f"serialized rework {name} conflicts with content")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def defect_set_sha256(self) -> Sha256Hex:
        return sha256_hex(
            ["m4-hearing-rework-defect-set", 1, [code.value for code in self.defect_codes]]
        )

    def receipt_projection(self) -> dict[str, object]:
        return {
            **self.model_dump(mode="json", exclude_computed_fields=True),
            "defect_set_sha256": self.defect_set_sha256,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(["m4-hearing-rework-receipt", 1, self.receipt_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m4-hearing-rework-receipt-document",
                1,
                self.receipt_id,
                self.receipt_projection(),
            ]
        )

    @model_validator(mode="after")
    def validate_defects(self) -> HearingReworkReceipt:
        values = tuple(code.value for code in self.defect_codes)
        if len(values) != len(set(values)) or values != tuple(sorted(values)):
            raise ValueError("rework defect codes must be unique and use stable order")
        return self


__all__ = ["EvidencePackDerivation", "HearingReworkReceipt"]
