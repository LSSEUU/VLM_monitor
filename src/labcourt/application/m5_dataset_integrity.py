"""Rebuild one M5 training artifact from durable authority before trusting it."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from labcourt.application.dataset_export import BuiltCocoDataset, build_coco_dataset
from labcourt.contracts.m5_training import (
    CocoDatasetExportCommand,
    DatasetExportReport,
    TrainingCropAuthority,
)
from labcourt.contracts.training import TrainingLabel
from labcourt.exceptions import LabCourtError


class M5DatasetIntegrityFailureCode(StrEnum):
    REPORT_REBUILD_MISMATCH = "REPORT_REBUILD_MISMATCH"
    CONTENT_SIZE_MISMATCH = "CONTENT_SIZE_MISMATCH"
    CONTENT_SHA256_MISMATCH = "CONTENT_SHA256_MISMATCH"
    CONTENT_REBUILD_MISMATCH = "CONTENT_REBUILD_MISMATCH"


class M5DatasetIntegrityError(LabCourtError):
    def __init__(self, reason_code: M5DatasetIntegrityFailureCode) -> None:
        if not isinstance(reason_code, M5DatasetIntegrityFailureCode):
            raise TypeError("reason_code must be an M5DatasetIntegrityFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M5 dataset integrity failed: {reason_code.value}")


def command_from_m5_dataset_report(report: DatasetExportReport) -> CocoDatasetExportCommand:
    """Recover the exact hashed export command represented by a validated report."""

    if not isinstance(report, DatasetExportReport):
        raise TypeError("report must be a DatasetExportReport")
    command = CocoDatasetExportCommand(
        run_id=report.run_id,
        relative_path=report.requested_relative_path,
        detector_manifest_id=report.detector_manifest_id,
        manifest_id=report.manifest_id,
        rule_version=report.rule_version,
        purpose=report.purpose,
        retention_hold_kind=report.retention_hold_kind,
        retention_policy_version=report.retention_policy_version,
        retention_period=report.retention_period,
        max_input_labels=report.max_input_labels,
        max_content_bytes=report.max_content_bytes,
        selection_policy=report.selection_policy,
    )
    if command.command_id != report.command_id:
        raise M5DatasetIntegrityError(M5DatasetIntegrityFailureCode.REPORT_REBUILD_MISMATCH)
    return command


def rebuild_and_verify_m5_dataset(
    *,
    report: DatasetExportReport,
    content: bytes,
    labels: tuple[TrainingLabel, ...],
    crop_authorities: tuple[TrainingCropAuthority, ...],
) -> BuiltCocoDataset:
    """Require exact report and byte equality with a deterministic durable rebuild."""

    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    command = command_from_m5_dataset_report(report)
    if len(content) != report.content_size_bytes:
        raise M5DatasetIntegrityError(M5DatasetIntegrityFailureCode.CONTENT_SIZE_MISMATCH)
    if hashlib.sha256(content).hexdigest() != report.dataset.content_sha256:
        raise M5DatasetIntegrityError(M5DatasetIntegrityFailureCode.CONTENT_SHA256_MISMATCH)
    rebuilt = build_coco_dataset(
        command=command,
        labels=labels,
        crop_authorities=crop_authorities,
    )
    if rebuilt.report != report:
        raise M5DatasetIntegrityError(M5DatasetIntegrityFailureCode.REPORT_REBUILD_MISMATCH)
    if rebuilt.content != content:
        raise M5DatasetIntegrityError(M5DatasetIntegrityFailureCode.CONTENT_REBUILD_MISMATCH)
    return rebuilt


__all__ = [
    "M5DatasetIntegrityError",
    "M5DatasetIntegrityFailureCode",
    "command_from_m5_dataset_report",
    "rebuild_and_verify_m5_dataset",
]
