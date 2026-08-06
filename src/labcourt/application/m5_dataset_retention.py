"""Derive dataset-owned GOLD_SET holds from one canonical export report."""

from __future__ import annotations

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.m5_training import DatasetExportReport
from labcourt.contracts.storage import ArtifactRef, RetentionHold, ScopedArtifactRef


def m5_dataset_retention_holds(report: DatasetExportReport) -> tuple[RetentionHold, ...]:
    """Build one stable, indefinite hold for every exported Crop authority."""

    if not isinstance(report, DatasetExportReport):
        raise TypeError("report must be a DatasetExportReport")
    owner = ScopedArtifactRef(
        run_id=report.run_id,
        ref=ArtifactRef(
            kind=ArtifactKind.DATASET,
            artifact_id=report.dataset.dataset_id,
        ),
    )
    return tuple(
        RetentionHold(
            run_id=report.run_id,
            hold_id=sha256_hex(
                [
                    "m5-dataset-gold-set-retention-hold",
                    1,
                    report.report_id,
                    receipt.crop_id,
                ]
            ),
            target_ref=ScopedArtifactRef(
                run_id=report.run_id,
                ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=receipt.crop_id),
            ),
            kind=report.retention_hold_kind,
            owner_ref=owner,
            manifest_id=report.manifest_id,
            policy_version=report.retention_policy_version,
            reason_code="reviewed-training-dataset",
        )
        for receipt in report.crop_receipts
    )


__all__ = ["m5_dataset_retention_holds"]
