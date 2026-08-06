from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.dataset_export import build_coco_dataset
from labcourt.contracts.enums import RetentionHoldKind
from labcourt.contracts.m5_training import CocoDatasetExportCommand
from labcourt.services.m5_dataset_integrity import verify_published_m5_dataset

SHA_C = "c" * 64
SHA_D = "d" * 64


def test_published_dataset_validation_reads_and_rebuilds_exact_file(tmp_path: Path) -> None:
    built = build_coco_dataset(
        command=CocoDatasetExportCommand(
            run_id="run-1",
            relative_path="datasets/reviewed.coco.json",
            detector_manifest_id=SHA_C,
            manifest_id=SHA_D,
            rule_version="rules-v1",
            purpose="DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
            retention_hold_kind=RetentionHoldKind.GOLD_SET,
            retention_policy_version="m5-gold-set-retention-v1",
            retention_period="UNTIL_EXPLICIT_RELEASE",
        ),
        labels=(),
        crop_authorities=(),
    )
    root = tmp_path / "workspace"
    root.mkdir()

    with SecureWorkspace(root, max_file_bytes=1024 * 1024) as workspace:
        workspace.ensure_private_directory("datasets")
        workspace.create_new(
            built.report.dataset.relative_path,
            built.content,
            built.report.dataset.content_sha256,
        )
        assert (
            verify_published_m5_dataset(
                workspace=workspace,
                report=built.report,
                labels=(),
                crop_authorities=(),
            )
            == built
        )
