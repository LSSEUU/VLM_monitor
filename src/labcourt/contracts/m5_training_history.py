"""Strict-causal, bounded authority snapshots for registered M5 datasets.

Dataset files and :class:`DatasetExportReport` keep their existing identities.
These additive contracts bind one immutable report to the exact training-label
ledger prefix and historical Case/Crop authorities from which it was built.
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
from labcourt.contracts.canonical import canonical_bytes, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_training import (
    MAX_COCO_EXPORT_LABELS,
    TrainingCropAuthority,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

M5_TRAINING_CAUSAL_GENESIS_SHA256 = "0" * 64
MAX_M5_TRAINING_CAUSAL_EVENTS = 100_000
MAX_M5_DATASET_SNAPSHOT_LABELS = MAX_COCO_EXPORT_LABELS
MAX_M5_DATASET_SNAPSHOT_CROPS = MAX_COCO_EXPORT_LABELS


class M5TrainingCausalEventKind(StrEnum):
    TRAINING_LABEL_APPENDED = "TRAINING_LABEL_APPENDED"
    DATASET_REGISTRATION_COMMITTED = "DATASET_REGISTRATION_COMMITTED"


class M5DatasetLabelSnapshotRole(StrEnum):
    EXPORTED = "EXPORTED"
    QUARANTINED = "QUARANTINED"


class M5TrainingCausalEvent(FrozenContractModel):
    """One source authority at one exact position in the per-run training chain."""

    schema_version: Literal["m5-training-causal-event-v1"] = "m5-training-causal-event-v1"
    run_id: ReferenceToken
    sequence: int = Field(gt=0, le=MAX_M5_TRAINING_CAUSAL_EVENTS, strict=True)
    event_kind: M5TrainingCausalEventKind
    source_id: Sha256Hex
    source_document_sha256: Sha256Hex
    manifest_id: Sha256Hex
    previous_event_sha256: Sha256Hex
    label_id: ReferenceToken | None = None

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M5 training causal event run_id")

    @field_validator("label_id")
    @classmethod
    def validate_label_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M5 training causal event label_id")

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
            for name in ("source_identity", "event_id", "event_sha256")
        }
        event = handler(payload)
        for name, (present, claimed) in claims.items():
            if present and (not isinstance(claimed, str) or claimed != getattr(event, name)):
                raise ValueError(f"serialized {name} does not match training event content")
        return event

    @model_validator(mode="after")
    def validate_chain_and_source_matrix(self) -> Self:
        if self.sequence == 1:
            if self.previous_event_sha256 != M5_TRAINING_CAUSAL_GENESIS_SHA256:
                raise ValueError("first training causal event must use the genesis predecessor")
        elif self.previous_event_sha256 == M5_TRAINING_CAUSAL_GENESIS_SHA256:
            raise ValueError("later training causal event must not use the genesis predecessor")

        has_label = self.label_id is not None
        if self.event_kind == M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED:
            if not has_label:
                raise ValueError("training-label append event requires label_id")
        elif has_label:
            raise ValueError("dataset-registration commit event must not claim label_id")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_identity(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-training-causal-source",
                1,
                self.run_id,
                self.event_kind,
                self.source_id,
                self.label_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_id(self) -> Sha256Hex:
        return sha256_hex(["m5-training-causal-event", 1, self.source_identity])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_sha256(self) -> Sha256Hex:
        body = [
            "m5-training-causal-event-chain",
            1,
            self.event_id,
            self.run_id,
            self.sequence,
            self.event_kind,
            self.source_id,
            self.source_document_sha256,
            self.manifest_id,
            self.label_id,
        ]
        return hashlib.sha256(
            self.previous_event_sha256.encode("ascii") + canonical_bytes(body)
        ).hexdigest()


class M5TrainingCausalWatermark(FrozenContractModel):
    """The exact training-ledger head observed before dataset registration."""

    schema_version: Literal["m5-training-causal-watermark-v1"] = "m5-training-causal-watermark-v1"
    run_id: ReferenceToken
    sequence: int = Field(ge=0, le=MAX_M5_TRAINING_CAUSAL_EVENTS, strict=True)
    event_id: Sha256Hex | None = None
    event_sha256: Sha256Hex

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M5 training causal watermark run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_watermark_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "watermark_id" in payload
        claimed = payload.pop("watermark_id", None)
        watermark = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != watermark.watermark_id):
            raise ValueError("serialized watermark_id does not match training causal cut")
        return watermark

    @model_validator(mode="after")
    def validate_genesis_or_real_head(self) -> Self:
        if self.sequence == 0:
            if self.event_id is not None or self.event_sha256 != M5_TRAINING_CAUSAL_GENESIS_SHA256:
                raise ValueError("zero training watermark must be genesis without event_id")
        elif self.event_id is None or self.event_sha256 == M5_TRAINING_CAUSAL_GENESIS_SHA256:
            raise ValueError("nonzero training watermark requires a real causal head")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def watermark_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-training-causal-watermark",
                1,
                self.run_id,
                self.sequence,
                self.event_id,
                self.event_sha256,
            ]
        )


class M5DatasetLabelSnapshotReceipt(FrozenContractModel):
    """One exact label authority and its append-event proof inside a dataset cut."""

    schema_version: Literal["m5-dataset-label-snapshot-receipt-v1"] = (
        "m5-dataset-label-snapshot-receipt-v1"
    )
    label_id: ReferenceToken
    role: M5DatasetLabelSnapshotRole
    authority_sha256: Sha256Hex
    causal_event_id: Sha256Hex
    causal_event_sequence: int = Field(
        gt=0,
        le=MAX_M5_TRAINING_CAUSAL_EVENTS,
        strict=True,
    )
    causal_event_sha256: Sha256Hex

    @field_validator("label_id")
    @classmethod
    def validate_label_id(cls, value: str) -> str:
        return require_reference_token(value, "M5 dataset snapshot label_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "receipt_id" in payload
        claimed = payload.pop("receipt_id", None)
        receipt = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != receipt.receipt_id):
            raise ValueError("serialized receipt_id does not match label snapshot receipt")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-dataset-label-snapshot-receipt",
                1,
                self.label_id,
                self.role,
                self.authority_sha256,
                self.causal_event_id,
                self.causal_event_sequence,
                self.causal_event_sha256,
            ]
        )


class M5DatasetCropSnapshotAuthority(FrozenContractModel):
    """One exact historical Case/pack cut for a physically verified training Crop."""

    schema_version: Literal["m5-dataset-crop-snapshot-authority-v1"] = (
        "m5-dataset-crop-snapshot-authority-v1"
    )
    run_id: ReferenceToken
    dataset_id: ReferenceToken
    report_id: Sha256Hex
    crop_authority: TrainingCropAuthority
    case_revision: int = Field(gt=0, strict=True)
    case_document_sha256: Sha256Hex
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    evidence_pack_document_sha256: Sha256Hex

    @field_validator("run_id", "dataset_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M5 dataset Crop snapshot reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "authority_id" in payload
        claimed = payload.pop("authority_id", None)
        authority = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != authority.authority_id):
            raise ValueError("serialized authority_id does not match dataset Crop snapshot")
        return authority

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if self.crop_authority.run_id != self.run_id:
            raise ValueError("dataset Crop snapshot crosses run scope")
        return self

    @property
    def sort_key(self) -> str:
        return self.crop_authority.crop.crop_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-dataset-crop-snapshot-authority",
                1,
                self.model_dump(mode="json", exclude={"authority_id"}),
            ]
        )


def m5_dataset_label_inventory_root_sha256(
    *,
    run_id: str,
    dataset_id: str,
    report_id: str,
    receipts: tuple[M5DatasetLabelSnapshotReceipt, ...],
) -> Sha256Hex:
    """Hash one complete label inventory independently of caller input order."""

    require_reference_token(run_id, "M5 dataset label inventory run_id")
    require_reference_token(dataset_id, "M5 dataset label inventory dataset_id")
    _require_sha256(report_id, "M5 dataset label inventory report_id")
    if not isinstance(receipts, tuple):
        raise TypeError("M5 dataset label inventory receipts must be a tuple")
    if any(not isinstance(item, M5DatasetLabelSnapshotReceipt) for item in receipts):
        raise TypeError("M5 dataset label inventory contains another receipt type")
    if len(receipts) > MAX_M5_DATASET_SNAPSHOT_LABELS:
        raise ValueError("M5 dataset label inventory exceeds its hard limit")
    ordered = tuple(sorted(receipts, key=lambda item: item.label_id))
    label_ids = tuple(item.label_id for item in ordered)
    event_ids = tuple(item.causal_event_id for item in ordered)
    if len(label_ids) != len(set(label_ids)):
        raise ValueError("M5 dataset label inventory contains duplicate label IDs")
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("M5 dataset label inventory contains duplicate causal events")
    return sha256_hex(
        [
            "m5-dataset-label-inventory-root",
            1,
            run_id,
            dataset_id,
            report_id,
            [item.receipt_id for item in ordered],
        ]
    )


def m5_dataset_crop_inventory_root_sha256(
    *,
    run_id: str,
    dataset_id: str,
    report_id: str,
    authorities: tuple[M5DatasetCropSnapshotAuthority, ...],
) -> Sha256Hex:
    """Hash one complete Crop authority inventory independently of input order."""

    require_reference_token(run_id, "M5 dataset Crop inventory run_id")
    require_reference_token(dataset_id, "M5 dataset Crop inventory dataset_id")
    _require_sha256(report_id, "M5 dataset Crop inventory report_id")
    if not isinstance(authorities, tuple):
        raise TypeError("M5 dataset Crop inventory authorities must be a tuple")
    if any(not isinstance(item, M5DatasetCropSnapshotAuthority) for item in authorities):
        raise TypeError("M5 dataset Crop inventory contains another authority type")
    if len(authorities) > MAX_M5_DATASET_SNAPSHOT_CROPS:
        raise ValueError("M5 dataset Crop inventory exceeds its hard limit")
    ordered = tuple(sorted(authorities, key=lambda item: item.sort_key))
    crop_ids = tuple(item.sort_key for item in ordered)
    if any(
        item.run_id != run_id or item.dataset_id != dataset_id or item.report_id != report_id
        for item in ordered
    ):
        raise ValueError("M5 dataset Crop inventory crosses snapshot scope")
    if len(crop_ids) != len(set(crop_ids)):
        raise ValueError("M5 dataset Crop inventory contains duplicate Crop IDs")
    return sha256_hex(
        [
            "m5-dataset-crop-inventory-root",
            1,
            run_id,
            dataset_id,
            report_id,
            [item.authority_id for item in ordered],
        ]
    )


class M5DatasetRegistrationSnapshotAuthority(FrozenContractModel):
    """Fixed-size roots for one causal label cut and historical Crop cut."""

    schema_version: Literal["m5-dataset-registration-snapshot-authority-v1"] = (
        "m5-dataset-registration-snapshot-authority-v1"
    )
    run_id: ReferenceToken
    dataset_id: ReferenceToken
    report_id: Sha256Hex
    command_id: Sha256Hex
    report_document_sha256: Sha256Hex
    causal_cut: M5TrainingCausalWatermark
    label_count: int = Field(
        ge=0,
        le=MAX_M5_DATASET_SNAPSHOT_LABELS,
        strict=True,
    )
    label_inventory_root_sha256: Sha256Hex
    crop_count: int = Field(
        ge=0,
        le=MAX_M5_DATASET_SNAPSHOT_CROPS,
        strict=True,
    )
    crop_inventory_root_sha256: Sha256Hex
    manifest_id: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)
    detector_manifest_id: Sha256Hex

    @field_validator("run_id", "dataset_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M5 dataset registration snapshot reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "authority_id" in payload
        claimed = payload.pop("authority_id", None)
        authority = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != authority.authority_id):
            raise ValueError("serialized authority_id does not match dataset registration snapshot")
        return authority

    @model_validator(mode="after")
    def validate_header_scope_and_counts(self) -> Self:
        if self.causal_cut.run_id != self.run_id:
            raise ValueError("dataset registration snapshot crosses causal run scope")
        if self.label_count > 0 and self.causal_cut.sequence == 0:
            raise ValueError("nonempty dataset label snapshot cannot use the genesis cut")
        if self.crop_count > self.label_count:
            raise ValueError("dataset snapshot Crop count cannot exceed label count")
        if self.label_count == 0 and self.label_inventory_root_sha256 != (
            m5_dataset_label_inventory_root_sha256(
                run_id=self.run_id,
                dataset_id=self.dataset_id,
                report_id=self.report_id,
                receipts=(),
            )
        ):
            raise ValueError("empty dataset label snapshot must use the canonical empty root")
        if self.crop_count == 0 and self.crop_inventory_root_sha256 != (
            m5_dataset_crop_inventory_root_sha256(
                run_id=self.run_id,
                dataset_id=self.dataset_id,
                report_id=self.report_id,
                authorities=(),
            )
        ):
            raise ValueError("empty dataset Crop snapshot must use the canonical empty root")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-dataset-registration-snapshot-authority",
                1,
                self.model_dump(mode="json", exclude={"authority_id"}),
            ]
        )


def _require_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be sha256")
    return value


__all__ = [
    "M5_TRAINING_CAUSAL_GENESIS_SHA256",
    "MAX_M5_DATASET_SNAPSHOT_CROPS",
    "MAX_M5_DATASET_SNAPSHOT_LABELS",
    "MAX_M5_TRAINING_CAUSAL_EVENTS",
    "M5DatasetCropSnapshotAuthority",
    "M5DatasetLabelSnapshotReceipt",
    "M5DatasetLabelSnapshotRole",
    "M5DatasetRegistrationSnapshotAuthority",
    "M5TrainingCausalEvent",
    "M5TrainingCausalEventKind",
    "M5TrainingCausalWatermark",
    "m5_dataset_crop_inventory_root_sha256",
    "m5_dataset_label_inventory_root_sha256",
]
