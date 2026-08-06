"""Deterministic, bounded COCO JSON construction without filesystem writes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.base import Scalar
from labcourt.contracts.canonical import canonical_bytes, canonical_json, sha256_hex
from labcourt.contracts.enums import DatasetFormat, TrainingLabelQuality
from labcourt.contracts.m5_training import (
    CocoDatasetExportCommand,
    DatasetExportCropReceipt,
    DatasetExportReport,
    TrainingCropAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.training import DatasetArtifact, TrainingLabel
from labcourt.domain.training_quality_gate import training_label_is_exportable
from labcourt.exceptions import LabCourtError


class DatasetExportFailureCode(StrEnum):
    OUTPUT_PATH_INVALID = "OUTPUT_PATH_INVALID"
    INPUT_LABEL_BUDGET_EXCEEDED = "INPUT_LABEL_BUDGET_EXCEEDED"
    DUPLICATE_LABEL_ID = "DUPLICATE_LABEL_ID"
    LABEL_ID_INVALID = "LABEL_ID_INVALID"
    DUPLICATE_CROP_AUTHORITY = "DUPLICATE_CROP_AUTHORITY"
    CROP_AUTHORITY_SCOPE_MISMATCH = "CROP_AUTHORITY_SCOPE_MISMATCH"
    CROP_AUTHORITY_MISSING = "CROP_AUTHORITY_MISSING"
    LABEL_CROP_SCOPE_MISMATCH = "LABEL_CROP_SCOPE_MISMATCH"
    LABEL_BBOX_OUTSIDE_CROP = "LABEL_BBOX_OUTSIDE_CROP"
    LABEL_MANIFEST_MISMATCH = "LABEL_MANIFEST_MISMATCH"
    LABEL_RULE_MISMATCH = "LABEL_RULE_MISMATCH"
    REVIEW_AUTHORITY_MISSING = "REVIEW_AUTHORITY_MISSING"
    LABEL_TEXT_BUDGET_EXCEEDED = "LABEL_TEXT_BUDGET_EXCEEDED"
    AMBIGUOUS_CATEGORY_VALUE = "AMBIGUOUS_CATEGORY_VALUE"
    CONTENT_BUDGET_EXCEEDED = "CONTENT_BUDGET_EXCEEDED"


class DatasetExportError(LabCourtError):
    def __init__(self, reason_code: DatasetExportFailureCode) -> None:
        if not isinstance(reason_code, DatasetExportFailureCode):
            raise TypeError("reason_code must be a DatasetExportFailureCode")
        self.reason_code = reason_code
        super().__init__(f"dataset export failed: {reason_code.value}")


def _fail(reason_code: DatasetExportFailureCode) -> NoReturn:
    raise DatasetExportError(reason_code)


@dataclass(frozen=True, slots=True)
class BuiltCocoDataset:
    """In-memory content plus its immutable public report."""

    content: bytes
    report: DatasetExportReport

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise TypeError("COCO dataset content must be bytes")
        if not isinstance(self.report, DatasetExportReport):
            raise TypeError("COCO dataset report must be a DatasetExportReport")
        if (
            len(self.content) != self.report.content_size_bytes
            or hashlib.sha256(self.content).hexdigest() != self.report.dataset.content_sha256
        ):
            raise ValueError("COCO dataset bytes conflict with their export report")


def _index_crop_authorities(
    command: CocoDatasetExportCommand,
    crop_authorities: tuple[TrainingCropAuthority, ...],
) -> dict[str, TrainingCropAuthority]:
    indexed: dict[str, TrainingCropAuthority] = {}
    for authority in crop_authorities:
        if not isinstance(authority, TrainingCropAuthority):
            raise TypeError("crop_authorities must contain TrainingCropAuthority values")
        crop_id = authority.crop.crop_id
        if crop_id in indexed:
            _fail(DatasetExportFailureCode.DUPLICATE_CROP_AUTHORITY)
        if (
            authority.run_id != command.run_id
            or authority.detector_manifest_id != command.detector_manifest_id
            or authority.manifest_id != command.manifest_id
            or authority.rule_version != command.rule_version
        ):
            _fail(DatasetExportFailureCode.CROP_AUTHORITY_SCOPE_MISMATCH)
        indexed[crop_id] = authority
    return indexed


def _partition_labels(
    command: CocoDatasetExportCommand,
    labels: tuple[TrainingLabel, ...],
) -> tuple[tuple[TrainingLabel, ...], tuple[TrainingLabel, ...]]:
    if len(labels) > command.max_input_labels:
        _fail(DatasetExportFailureCode.INPUT_LABEL_BUDGET_EXCEEDED)
    seen: set[str] = set()
    for label in labels:
        if not isinstance(label, TrainingLabel):
            raise TypeError("labels must contain TrainingLabel values")
        try:
            require_reference_token(label.label_id, "training label_id")
        except ValueError:
            _fail(DatasetExportFailureCode.LABEL_ID_INVALID)
        if label.label_id in seen:
            _fail(DatasetExportFailureCode.DUPLICATE_LABEL_ID)
        seen.add(label.label_id)
    selected = tuple(
        sorted(
            (
                label
                for label in labels
                if training_label_is_exportable(
                    quality=label.quality,
                    excluded_reason=label.excluded_reason,
                )
            ),
            key=lambda item: item.label_id,
        )
    )
    selected_ids = {item.label_id for item in selected}
    quarantined = tuple(
        sorted(
            (label for label in labels if label.label_id not in selected_ids),
            key=lambda item: item.label_id,
        )
    )
    return selected, quarantined


def _validate_selected_label(
    command: CocoDatasetExportCommand,
    label: TrainingLabel,
    authority: TrainingCropAuthority,
) -> None:
    if label.case_id != authority.case_id:
        _fail(DatasetExportFailureCode.LABEL_CROP_SCOPE_MISMATCH)
    if not label.bbox.is_within(authority.crop.output_width, authority.crop.output_height):
        _fail(DatasetExportFailureCode.LABEL_BBOX_OUTSIDE_CROP)
    if label.detector_manifest_id != command.detector_manifest_id:
        _fail(DatasetExportFailureCode.LABEL_MANIFEST_MISMATCH)
    if label.rule_version != command.rule_version:
        _fail(DatasetExportFailureCode.LABEL_RULE_MISMATCH)
    if label.reviewer_id is None:
        _fail(DatasetExportFailureCode.REVIEW_AUTHORITY_MISSING)
    if len(label.label_name.encode("utf-8")) > 256 or len(label.source.encode("utf-8")) > 512:
        _fail(DatasetExportFailureCode.LABEL_TEXT_BUDGET_EXCEEDED)


def _coco_payload(
    command: CocoDatasetExportCommand,
    selected: tuple[TrainingLabel, ...],
    crops: dict[str, TrainingCropAuthority],
) -> tuple[dict[str, object], tuple[DatasetExportCropReceipt, ...], int]:
    selected_crop_ids = tuple(sorted({label.crop_id for label in selected}))
    image_ids = {crop_id: index for index, crop_id in enumerate(selected_crop_ids, start=1)}

    category_values: dict[str, Scalar] = {}
    for label in selected:
        existing = category_values.get(label.label_name)
        if label.label_name in category_values and canonical_json(existing) != canonical_json(
            label.label_value
        ):
            _fail(DatasetExportFailureCode.AMBIGUOUS_CATEGORY_VALUE)
        category_values[label.label_name] = label.label_value
    category_names = tuple(sorted(category_values))
    category_ids = {name: index for index, name in enumerate(category_names, start=1)}

    images: list[dict[str, object]] = []
    receipts: list[DatasetExportCropReceipt] = []
    for crop_id in selected_crop_ids:
        authority = crops[crop_id]
        crop = authority.crop
        if crop.local_path is None:
            raise AssertionError("validated TrainingCropAuthority lost its locator")
        images.append(
            {
                "id": image_ids[crop_id],
                "file_name": crop.local_path,
                "width": crop.output_width,
                "height": crop.output_height,
                "labcourt_crop_id": crop_id,
                "labcourt_media_sha256": crop.media_sha256,
                "labcourt_pixel_sha256": crop.pixel_sha256,
            }
        )
        receipts.append(
            DatasetExportCropReceipt(
                crop_id=crop_id,
                authority_sha256=authority.authority_sha256,
            )
        )

    annotations: list[dict[str, object]] = []
    for annotation_id, label in enumerate(selected, start=1):
        bbox = label.bbox
        annotations.append(
            {
                "id": annotation_id,
                "image_id": image_ids[label.crop_id],
                "category_id": category_ids[label.label_name],
                "bbox": [bbox.x1, bbox.y1, bbox.width, bbox.height],
                "area": bbox.area,
                "iscrowd": 0,
                "labcourt_label_id": label.label_id,
                "labcourt_label_value": label.label_value,
                "labcourt_quality": label.quality.value,
                "labcourt_source": label.source,
                "labcourt_reviewer_id": label.reviewer_id,
            }
        )

    categories = [
        {
            "id": category_ids[name],
            "name": name,
            "supercategory": "labcourt",
            "labcourt_label_value": category_values[name],
        }
        for name in category_names
    ]
    payload: dict[str, object] = {
        "info": {
            "description": "LabCourt deterministic reviewed-label export",
            "version": "coco-export-v1",
        },
        "licenses": [],
        "images": images,
        "annotations": annotations,
        "categories": categories,
        "labcourt": {
            "command_id": command.command_id,
            "run_id": command.run_id,
            "manifest_id": command.manifest_id,
            "detector_manifest_id": command.detector_manifest_id,
            "rule_version": command.rule_version,
            "purpose": command.purpose,
            "retention_hold_kind": command.retention_hold_kind,
            "retention_policy_version": command.retention_policy_version,
            "retention_period": command.retention_period,
            "selection_policy": command.selection_policy,
            "max_input_labels": command.max_input_labels,
            "max_content_bytes": command.max_content_bytes,
        },
    }
    return payload, tuple(receipts), len(category_names)


def build_coco_dataset(
    *,
    command: CocoDatasetExportCommand,
    labels: tuple[TrainingLabel, ...],
    crop_authorities: tuple[TrainingCropAuthority, ...],
) -> BuiltCocoDataset:
    """Build canonical COCO JSON and a complete selection/quarantine report."""

    if not isinstance(command, CocoDatasetExportCommand):
        raise TypeError("command must be a CocoDatasetExportCommand")
    if not command.relative_path.endswith(".json"):
        _fail(DatasetExportFailureCode.OUTPUT_PATH_INVALID)
    if not isinstance(labels, tuple):
        raise TypeError("labels must be a tuple")
    if not isinstance(crop_authorities, tuple):
        raise TypeError("crop_authorities must be a tuple")

    crops = _index_crop_authorities(command, crop_authorities)
    selected, quarantined = _partition_labels(command, labels)
    for label in selected:
        authority = crops.get(label.crop_id)
        if authority is None:
            _fail(DatasetExportFailureCode.CROP_AUTHORITY_MISSING)
        _validate_selected_label(command, label, authority)

    payload, crop_receipts, category_count = _coco_payload(command, selected, crops)
    content = canonical_bytes(payload)
    if len(content) > command.max_content_bytes:
        _fail(DatasetExportFailureCode.CONTENT_BUDGET_EXCEEDED)
    content_sha256 = hashlib.sha256(content).hexdigest()
    dataset = DatasetArtifact(
        dataset_id=sha256_hex(["dataset-artifact", 1, command.command_id, content_sha256]),
        format=DatasetFormat.COCO,
        relative_path=command.relative_path,
        content_sha256=content_sha256,
        label_count=len(selected),
        minimum_quality=TrainingLabelQuality.HUMAN_CONFIRMED,
        rule_version=command.rule_version,
    )
    report = DatasetExportReport(
        command_id=command.command_id,
        run_id=command.run_id,
        dataset=dataset,
        requested_relative_path=command.relative_path,
        detector_manifest_id=command.detector_manifest_id,
        manifest_id=command.manifest_id,
        rule_version=command.rule_version,
        purpose=command.purpose,
        retention_hold_kind=command.retention_hold_kind,
        retention_policy_version=command.retention_policy_version,
        retention_period=command.retention_period,
        max_input_labels=command.max_input_labels,
        max_content_bytes=command.max_content_bytes,
        input_label_count=len(labels),
        exported_label_ids=tuple(label.label_id for label in selected),
        quarantined_label_ids=tuple(label.label_id for label in quarantined),
        weak_auto_count=sum(
            label.quality == TrainingLabelQuality.WEAK_AUTO for label in quarantined
        ),
        consensus_reviewed_count=sum(
            label.quality == TrainingLabelQuality.CONSENSUS_REVIEWED for label in quarantined
        ),
        excluded_reason_count=sum(label.excluded_reason is not None for label in quarantined),
        exported_image_count=len(crop_receipts),
        exported_category_count=category_count,
        content_size_bytes=len(content),
        crop_receipts=crop_receipts,
    )
    return BuiltCocoDataset(content=content, report=report)


__all__ = [
    "BuiltCocoDataset",
    "DatasetExportError",
    "DatasetExportFailureCode",
    "build_coco_dataset",
]
