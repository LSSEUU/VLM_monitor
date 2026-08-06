"""Sealed source-input authority for M6 locked Gate replay.

The historical ``ClosureReport`` value is deterministic, but a passing shape
alone does not prove that privacy-processed media was physically read.  These
contracts keep the exact Gate closure together with the current-media
verification receipts captured before retention.  They remain M6-only derived
artifacts and do not alter any frozen M0--M5 wire contract.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    VerificationStatus,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactVerification, ClosureReport

MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE = 64


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M6 source authority")


class M6GateCurrentClosureBasis(StrEnum):
    CURRENT_PRIVACY_CROP_REVERIFIED = "CURRENT_PRIVACY_CROP_REVERIFIED"
    SEMANTIC_ONLY_NO_CROPS = "SEMANTIC_ONLY_NO_CROPS"


class M6GateCurrentClosureReceipt(FrozenContractModel):
    """One review-scoped current closure sealed before media retention."""

    schema_version: Literal["m6-gate-current-closure-receipt-v1"] = (
        "m6-gate-current-closure-receipt-v1"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    manifest_id: Sha256Hex
    review_version: int = Field(gt=0, strict=True)
    source_review_id: Sha256Hex
    source_review_document_sha256: Sha256Hex
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    evidence_pack_document_sha256: Sha256Hex
    basis: M6GateCurrentClosureBasis
    current_closure: ClosureReport
    crop_verifications: tuple[ArtifactVerification, ...] = Field(
        default=(),
        max_length=256,
    )

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 Gate current-closure receipt reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            ("receipt_id", "receipt_document_sha256"),
        )
        receipt = handler(payload)
        _verify_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_closure_and_media(self) -> Self:
        closure = ClosureReport.model_validate(
            self.current_closure.model_dump(mode="json", exclude_computed_fields=True)
        )
        verifications = tuple(
            ArtifactVerification.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.crop_verifications
        )
        if closure != self.current_closure or verifications != self.crop_verifications:
            raise ValueError("M6 Gate closure receipt contains a non-canonical nested document")
        if (
            not closure.passed
            or closure.run_id != self.run_id
            or closure.manifest_id != self.manifest_id
            or closure.root_ref.kind != ArtifactKind.EVIDENCE_PACK
            or closure.root_ref.artifact_id != self.evidence_pack_id
        ):
            raise ValueError("M6 Gate current closure is not an exact passing pack closure")
        verification_keys = tuple(item.artifact_ref.sort_key for item in verifications)
        if verification_keys != tuple(sorted(verification_keys)) or len(verification_keys) != len(
            set(verification_keys)
        ):
            raise ValueError("M6 Gate crop verifications must be unique and ordered")
        if any(
            item.artifact_ref.kind != ArtifactKind.CROP
            or item.status != VerificationStatus.CURRENT_MEDIA_VERIFIED
            or item.reason_code is not None
            for item in verifications
        ):
            raise ValueError("M6 Gate media authority requires current Crop verification")
        checked_refs = frozenset(closure.checked_refs)
        if any(item.artifact_ref not in checked_refs for item in verifications):
            raise ValueError("M6 Gate Crop verification lies outside the current closure")
        if self.basis == M6GateCurrentClosureBasis.SEMANTIC_ONLY_NO_CROPS:
            if verifications:
                raise ValueError("semantic-only Gate closure cannot carry Crop verification")
        elif not verifications:
            raise ValueError("reverified Gate closure requires Crop verification receipts")
        object.__setattr__(self, "current_closure", closure)
        object.__setattr__(self, "crop_verifications", verifications)
        return self

    def receipt_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "manifest_id": self.manifest_id,
            "review_version": self.review_version,
            "source_review_id": self.source_review_id,
            "source_review_document_sha256": self.source_review_document_sha256,
            "evidence_pack_id": self.evidence_pack_id,
            "evidence_pack_version": self.evidence_pack_version,
            "evidence_pack_document_sha256": self.evidence_pack_document_sha256,
            "basis": self.basis.value,
            "current_closure": self.current_closure.model_dump(mode="json"),
            "crop_verifications": [
                item.model_dump(mode="json") for item in self.crop_verifications
            ],
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(["m6-gate-current-closure-receipt", 1, self.receipt_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_document_sha256(self) -> Sha256Hex:
        return hashlib.sha256(canonical_json(self.receipt_projection()).encode("utf-8")).hexdigest()

    @property
    def sort_key(self) -> tuple[int, str]:
        return self.review_version, self.source_review_id


class M6ReplayInputAuthority(FrozenContractModel):
    """Content-addressed source catalog dereferenced by locked replay."""

    schema_version: Literal["m6-replay-input-authority-v1"] = "m6-replay-input-authority-v1"
    sample_id: ReferenceToken
    source_run_id: ReferenceToken
    source_case_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    source_case_document_sha256: Sha256Hex
    source_manifest_id: Sha256Hex
    source_manifest_document_sha256: Sha256Hex
    source_config_sha256: Sha256Hex
    source_m4_authority_root_sha256: Sha256Hex
    source_m5_authority_root_sha256: Sha256Hex
    source_validation_report_id: Sha256Hex
    source_validation_report_document_sha256: Sha256Hex
    frame_inventory_root_sha256: Sha256Hex
    detection_inventory_root_sha256: Sha256Hex
    model_call_inventory_root_sha256: Sha256Hex
    embedding_inventory_root_sha256: Sha256Hex
    tool_result_inventory_root_sha256: Sha256Hex
    historical_causal_cut_id: Sha256Hex
    gate_current_closures: tuple[M6GateCurrentClosureReceipt, ...] = Field(
        default=(),
        max_length=MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE,
    )

    @field_validator("sample_id", "source_run_id", "source_case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 replay input authority reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "gate_current_closure_count",
                "gate_current_closure_inventory_root_sha256",
                "input_authority_id",
                "input_authority_document_sha256",
            ),
        )
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_gate_closure_inventory(self) -> Self:
        receipts = tuple(
            M6GateCurrentClosureReceipt.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.gate_current_closures
        )
        if receipts != self.gate_current_closures:
            raise ValueError("M6 replay input authority contains a non-canonical receipt")
        keys = tuple(item.sort_key for item in receipts)
        review_ids = tuple(item.source_review_id for item in receipts)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M6 Gate current closures must use stable unique review order")
        if len(review_ids) != len(set(review_ids)):
            raise ValueError("M6 Gate current closures must bind unique source reviews")
        if any(
            item.run_id != self.source_run_id
            or item.case_id != self.source_case_id
            or item.manifest_id != self.source_manifest_id
            for item in receipts
        ):
            raise ValueError("M6 Gate current closure differs from input authority scope")
        object.__setattr__(self, "gate_current_closures", receipts)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def gate_current_closure_count(self) -> int:
        return len(self.gate_current_closures)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def gate_current_closure_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-gate-current-closure-inventory",
                1,
                [item.receipt_id for item in self.gate_current_closures],
            ]
        )

    def authority_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sample_id": self.sample_id,
            "source_run_id": self.source_run_id,
            "source_case_id": self.source_case_id,
            "source_case_revision": self.source_case_revision,
            "source_case_document_sha256": self.source_case_document_sha256,
            "source_manifest_id": self.source_manifest_id,
            "source_manifest_document_sha256": self.source_manifest_document_sha256,
            "source_config_sha256": self.source_config_sha256,
            "source_m4_authority_root_sha256": self.source_m4_authority_root_sha256,
            "source_m5_authority_root_sha256": self.source_m5_authority_root_sha256,
            "source_validation_report_id": self.source_validation_report_id,
            "source_validation_report_document_sha256": (
                self.source_validation_report_document_sha256
            ),
            "frame_inventory_root_sha256": self.frame_inventory_root_sha256,
            "detection_inventory_root_sha256": self.detection_inventory_root_sha256,
            "model_call_inventory_root_sha256": self.model_call_inventory_root_sha256,
            "embedding_inventory_root_sha256": self.embedding_inventory_root_sha256,
            "tool_result_inventory_root_sha256": self.tool_result_inventory_root_sha256,
            "historical_causal_cut_id": self.historical_causal_cut_id,
            "gate_current_closure_inventory_root_sha256": (
                self.gate_current_closure_inventory_root_sha256
            ),
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def input_authority_id(self) -> Sha256Hex:
        return sha256_hex(["m6-replay-input-authority", 1, self.authority_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def input_authority_document_sha256(self) -> Sha256Hex:
        document = {
            **self.authority_projection(),
            "gate_current_closures": [
                item.model_dump(mode="json") for item in self.gate_current_closures
            ],
        }
        return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()


__all__ = [
    "MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE",
    "M6GateCurrentClosureBasis",
    "M6GateCurrentClosureReceipt",
    "M6ReplayInputAuthority",
]
