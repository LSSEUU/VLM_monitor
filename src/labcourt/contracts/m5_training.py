"""Additive M5 authorities and reports for deterministic training export."""

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
from labcourt.contracts.enums import (
    ArtifactKind,
    DatasetFormat,
    MediaAvailability,
    MediaType,
    RetentionHoldKind,
    TrainingLabelQuality,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import ReferenceToken
from labcourt.contracts.storage import ArtifactVerification
from labcourt.contracts.training import DatasetArtifact

MAX_COCO_EXPORT_LABELS = 10_000
MAX_COCO_EXPORT_BYTES = 64 * 1024 * 1024
DEFAULT_TRAINING_EXPORT_QUALITIES = (
    TrainingLabelQuality.APPEAL_CONFIRMED,
    TrainingLabelQuality.HUMAN_CONFIRMED,
)


class TrainingCropAuthority(FrozenContractModel):
    """A Case-scoped Crop whose current bytes and pixels were already verified."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    crop: Crop
    verification: ArtifactVerification
    detector_manifest_id: Sha256Hex
    manifest_id: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_sha256(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "authority_sha256" in payload
        claimed = payload.pop("authority_sha256", None)
        authority = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != authority.authority_sha256):
            raise ValueError("serialized training Crop authority hash does not match")
        return authority

    @model_validator(mode="after")
    def validate_verified_crop_binding(self) -> Self:
        crop = self.crop
        verification = self.verification
        if crop.availability != MediaAvailability.AVAILABLE or crop.local_path is None:
            raise ValueError("training export requires an available Crop with a safe locator")
        if (
            verification.artifact_ref.kind != ArtifactKind.CROP
            or verification.artifact_ref.artifact_id != crop.crop_id
            or verification.status
            not in {VerificationStatus.VERIFIED, VerificationStatus.CURRENT_MEDIA_VERIFIED}
            or verification.availability != MediaAvailability.AVAILABLE
            or verification.media_type != MediaType.IMAGE_PNG
            or verification.expected_source_pixel_sha256 != crop.source_media_sha256
            or verification.expected_output_pixel_sha256 != crop.pixel_sha256
            or verification.expected_media_sha256 != crop.media_sha256
            or verification.expected_width != crop.output_width
            or verification.expected_height != crop.output_height
            or verification.expected_size_bytes != crop.size_bytes
        ):
            raise ValueError("training Crop conflicts with its integrity verification")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "training-crop-authority",
                1,
                self.model_dump(mode="json", exclude={"authority_sha256"}),
            ]
        )


class CocoDatasetExportCommand(FrozenContractModel):
    run_id: ReferenceToken
    target: Literal[DatasetFormat.COCO] = DatasetFormat.COCO
    relative_path: str = Field(min_length=1)
    detector_manifest_id: Sha256Hex
    manifest_id: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)
    purpose: Literal["DETECTOR_TRAINING_FROM_REVIEWED_LABELS"]
    retention_hold_kind: Literal[RetentionHoldKind.GOLD_SET]
    retention_policy_version: Literal["m5-gold-set-retention-v1"]
    retention_period: Literal["UNTIL_EXPLICIT_RELEASE"]
    max_input_labels: int = Field(
        default=MAX_COCO_EXPORT_LABELS,
        gt=0,
        le=MAX_COCO_EXPORT_LABELS,
        strict=True,
    )
    max_content_bytes: int = Field(
        default=MAX_COCO_EXPORT_BYTES,
        gt=0,
        le=MAX_COCO_EXPORT_BYTES,
        strict=True,
    )
    selection_policy: Literal["HUMAN_OR_APPEAL_CONFIRMED_V1"] = "HUMAN_OR_APPEAL_CONFIRMED_V1"

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_command_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "command_id" in payload
        claimed = payload.pop("command_id", None)
        command = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != command.command_id):
            raise ValueError("serialized COCO export command ID does not match")
        return command

    @computed_field  # type: ignore[prop-decorator]
    @property
    def command_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "coco-dataset-export-command",
                1,
                self.model_dump(mode="json", exclude={"command_id"}),
            ]
        )


class DatasetExportCropReceipt(FrozenContractModel):
    crop_id: Sha256Hex
    authority_sha256: Sha256Hex

    @property
    def sort_key(self) -> str:
        return self.crop_id


class DatasetExportReport(FrozenContractModel):
    """Auditable default-selection and byte-identity report for one COCO export."""

    command_id: Sha256Hex
    run_id: ReferenceToken
    dataset: DatasetArtifact
    requested_relative_path: str = Field(min_length=1)
    detector_manifest_id: Sha256Hex
    manifest_id: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)
    purpose: Literal["DETECTOR_TRAINING_FROM_REVIEWED_LABELS"]
    retention_hold_kind: Literal[RetentionHoldKind.GOLD_SET]
    retention_policy_version: Literal["m5-gold-set-retention-v1"]
    retention_period: Literal["UNTIL_EXPLICIT_RELEASE"]
    selection_policy: Literal["HUMAN_OR_APPEAL_CONFIRMED_V1"] = "HUMAN_OR_APPEAL_CONFIRMED_V1"
    max_input_labels: int = Field(gt=0, le=MAX_COCO_EXPORT_LABELS, strict=True)
    max_content_bytes: int = Field(gt=0, le=MAX_COCO_EXPORT_BYTES, strict=True)
    input_label_count: int = Field(ge=0, le=MAX_COCO_EXPORT_LABELS, strict=True)
    exported_label_ids: tuple[ReferenceToken, ...] = Field(
        default=(), max_length=MAX_COCO_EXPORT_LABELS
    )
    quarantined_label_ids: tuple[ReferenceToken, ...] = Field(
        default=(), max_length=MAX_COCO_EXPORT_LABELS
    )
    weak_auto_count: int = Field(ge=0, strict=True)
    consensus_reviewed_count: int = Field(ge=0, strict=True)
    excluded_reason_count: int = Field(ge=0, strict=True)
    exported_image_count: int = Field(ge=0, le=MAX_COCO_EXPORT_LABELS, strict=True)
    exported_category_count: int = Field(ge=0, le=MAX_COCO_EXPORT_LABELS, strict=True)
    content_size_bytes: int = Field(ge=0, le=MAX_COCO_EXPORT_BYTES, strict=True)
    crop_receipts: tuple[DatasetExportCropReceipt, ...] = Field(
        default=(), max_length=MAX_COCO_EXPORT_LABELS
    )

    @field_validator("requested_relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_report_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "report_id" in payload
        claimed = payload.pop("report_id", None)
        report = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != report.report_id):
            raise ValueError("serialized dataset export report ID does not match")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "dataset-export-report",
                1,
                self.model_dump(mode="json", exclude={"report_id"}),
            ]
        )

    @model_validator(mode="after")
    def validate_complete_accounting(self) -> Self:
        command = CocoDatasetExportCommand(
            run_id=self.run_id,
            relative_path=self.requested_relative_path,
            detector_manifest_id=self.detector_manifest_id,
            manifest_id=self.manifest_id,
            rule_version=self.rule_version,
            purpose=self.purpose,
            retention_hold_kind=self.retention_hold_kind,
            retention_policy_version=self.retention_policy_version,
            retention_period=self.retention_period,
            max_input_labels=self.max_input_labels,
            max_content_bytes=self.max_content_bytes,
            selection_policy=self.selection_policy,
        )
        if self.command_id != command.command_id:
            raise ValueError("dataset export report command ID is not canonical")
        exported = self.exported_label_ids
        quarantined = self.quarantined_label_ids
        if (
            exported != tuple(sorted(exported))
            or len(exported) != len(set(exported))
            or quarantined != tuple(sorted(quarantined))
            or len(quarantined) != len(set(quarantined))
            or set(exported) & set(quarantined)
        ):
            raise ValueError("dataset export label IDs must be disjoint, unique, and stable")
        if self.input_label_count != len(exported) + len(quarantined):
            raise ValueError("dataset export report does not account for every input label")
        if self.input_label_count > self.max_input_labels:
            raise ValueError("dataset export report exceeds its input label budget")
        if self.content_size_bytes > self.max_content_bytes:
            raise ValueError("dataset export report exceeds its content byte budget")
        if any(
            count > len(quarantined)
            for count in (
                self.weak_auto_count,
                self.consensus_reviewed_count,
                self.excluded_reason_count,
            )
        ):
            raise ValueError("quarantine reason count exceeds quarantined labels")
        if (
            self.dataset.format != DatasetFormat.COCO
            or self.dataset.relative_path != self.requested_relative_path
            or self.dataset.label_count != len(exported)
            or self.dataset.minimum_quality != TrainingLabelQuality.HUMAN_CONFIRMED
            or self.dataset.rule_version != self.rule_version
        ):
            raise ValueError("dataset artifact conflicts with its export report")
        receipt_keys = tuple(item.sort_key for item in self.crop_receipts)
        if (
            receipt_keys != tuple(sorted(receipt_keys))
            or len(receipt_keys) != len(set(receipt_keys))
            or self.exported_image_count != len(self.crop_receipts)
        ):
            raise ValueError("dataset Crop receipts must be unique, stable, and complete")
        if not exported and (self.exported_image_count or self.exported_category_count):
            raise ValueError("an empty label export cannot contain images or categories")
        return self


__all__ = [
    "DEFAULT_TRAINING_EXPORT_QUALITIES",
    "MAX_COCO_EXPORT_BYTES",
    "MAX_COCO_EXPORT_LABELS",
    "CocoDatasetExportCommand",
    "DatasetExportCropReceipt",
    "DatasetExportReport",
    "TrainingCropAuthority",
]
