from __future__ import annotations

import pytest

from labcourt.application.dataset_export import BuiltCocoDataset, build_coco_dataset
from labcourt.application.m5_dataset_integrity import (
    M5DatasetIntegrityError,
    M5DatasetIntegrityFailureCode,
    command_from_m5_dataset_report,
    rebuild_and_verify_m5_dataset,
)
from labcourt.contracts.enums import RetentionHoldKind, TrainingLabelQuality
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_training import CocoDatasetExportCommand
from labcourt.contracts.training import TrainingLabel

SHA_C = "c" * 64
SHA_D = "d" * 64


def _built_empty() -> BuiltCocoDataset:
    return build_coco_dataset(
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


def _weak_label() -> TrainingLabel:
    return TrainingLabel(
        label_id="weak-1",
        case_id="case-1",
        crop_id=SHA_D,
        bbox=BBoxXYXY(x1=0, y1=0, x2=1, y2=1),
        label_name="machine-observation",
        label_value=True,
        quality=TrainingLabelQuality.WEAK_AUTO,
        source="controlled-fake-detector",
        rule_version="rules-v1",
        detector_manifest_id=SHA_C,
    )


def test_exact_dataset_rebuild_restores_command_report_and_bytes() -> None:
    built = _built_empty()

    assert command_from_m5_dataset_report(built.report).command_id == built.report.command_id
    assert (
        rebuild_and_verify_m5_dataset(
            report=built.report,
            content=built.content,
            labels=(),
            crop_authorities=(),
        )
        == built
    )


def test_dataset_rebuild_rejects_missing_durable_label_inventory() -> None:
    built = _built_empty()

    with pytest.raises(M5DatasetIntegrityError) as failure:
        rebuild_and_verify_m5_dataset(
            report=built.report,
            content=built.content,
            labels=(_weak_label(),),
            crop_authorities=(),
        )

    assert failure.value.reason_code == M5DatasetIntegrityFailureCode.REPORT_REBUILD_MISMATCH


@pytest.mark.parametrize(
    ("content", "reason_code"),
    [
        (b"", M5DatasetIntegrityFailureCode.CONTENT_SIZE_MISMATCH),
        (b"x" * 529, M5DatasetIntegrityFailureCode.CONTENT_SHA256_MISMATCH),
    ],
)
def test_dataset_rebuild_rejects_physical_byte_tampering(
    content: bytes,
    reason_code: M5DatasetIntegrityFailureCode,
) -> None:
    built = _built_empty()
    candidate = content
    if reason_code == M5DatasetIntegrityFailureCode.CONTENT_SHA256_MISMATCH:
        candidate = b"x" * len(built.content)

    with pytest.raises(M5DatasetIntegrityError) as failure:
        rebuild_and_verify_m5_dataset(
            report=built.report,
            content=candidate,
            labels=(),
            crop_authorities=(),
        )

    assert failure.value.reason_code == reason_code
