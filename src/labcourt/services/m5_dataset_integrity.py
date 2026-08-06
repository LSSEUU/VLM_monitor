"""Secure filesystem composition for deterministic M5 dataset validation."""

from __future__ import annotations

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.dataset_export import BuiltCocoDataset
from labcourt.application.m5_dataset_integrity import rebuild_and_verify_m5_dataset
from labcourt.contracts.m5_training import DatasetExportReport, TrainingCropAuthority
from labcourt.contracts.training import TrainingLabel


def verify_published_m5_dataset(
    *,
    workspace: SecureWorkspace,
    report: DatasetExportReport,
    labels: tuple[TrainingLabel, ...],
    crop_authorities: tuple[TrainingCropAuthority, ...],
) -> BuiltCocoDataset:
    """Read exactly the registered bytes and require a full durable rebuild."""

    if not isinstance(workspace, SecureWorkspace):
        raise TypeError("workspace must be a SecureWorkspace")
    if not isinstance(report, DatasetExportReport):
        raise TypeError("report must be a DatasetExportReport")
    snapshot = workspace.read_verified(
        report.dataset.relative_path,
        expected_sha256=report.dataset.content_sha256,
        max_bytes=report.content_size_bytes,
    )
    return rebuild_and_verify_m5_dataset(
        report=report,
        content=snapshot.bytes,
        labels=labels,
        crop_authorities=crop_authorities,
    )


__all__ = ["verify_published_m5_dataset"]
