from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.storage.secure_dataset_publisher import (
    DatasetPublishError,
    DatasetPublishFailureCode,
    SecureDatasetArtifactPublisher,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.dataset_export import build_coco_dataset
from labcourt.contracts.enums import RetentionHoldKind
from labcourt.contracts.m5_training import CocoDatasetExportCommand, DatasetExportReport
from labcourt.contracts.training import DatasetArtifact
from labcourt.exceptions import ArtifactConflict, LabCourtError

SHA_C = "c" * 64
SHA_D = "d" * 64


class _RegistrationFailure(LabCourtError):
    pass


class _Registry:
    def __init__(self, *, fail_once: bool = False) -> None:
        self.fail_once = fail_once
        self.calls: list[tuple[DatasetExportReport, bytes]] = []
        self.artifacts: dict[str, DatasetArtifact] = {}

    def register_dataset_artifact(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact:
        self.calls.append((report, content))
        if self.fail_once:
            self.fail_once = False
            raise _RegistrationFailure("injected registration failure")
        dataset = report.dataset
        existing = self.artifacts.setdefault(dataset.dataset_id, dataset)
        if existing != dataset:
            raise _RegistrationFailure("dataset identity collision")
        return existing


def _built_dataset() -> tuple[bytes, DatasetExportReport]:
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
    return built.content, built.report


def test_dataset_publication_is_exact_no_overwrite_and_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    content, report = _built_dataset()
    registry = _Registry()

    with SecureWorkspace(root, max_file_bytes=1024 * 1024) as workspace:
        publisher = SecureDatasetArtifactPublisher(
            workspace=workspace,
            repository=registry,
        )
        first = publisher.publish(report, content)
        replay = publisher.publish(report, content)

    assert first == replay == report.dataset
    assert (root / "datasets" / "reviewed.coco.json").read_bytes() == content
    assert registry.calls == [(report, content), (report, content)]


def test_dataset_publication_validates_bytes_before_any_write_or_registration(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    content, report = _built_dataset()
    registry = _Registry()

    with SecureWorkspace(root, max_file_bytes=1024 * 1024) as workspace:
        publisher = SecureDatasetArtifactPublisher(
            workspace=workspace,
            repository=registry,
        )
        with pytest.raises(DatasetPublishError) as failure:
            publisher.publish(report, content + b"tampered")

    assert failure.value.reason_code == DatasetPublishFailureCode.CONTENT_SIZE_MISMATCH
    assert registry.calls == []
    assert not (root / "datasets").exists()


def test_dataset_publication_never_replaces_conflicting_final_bytes(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    content, report = _built_dataset()
    conflicting = b"different immutable bytes"
    (root / "datasets").mkdir()
    target = root / "datasets" / "reviewed.coco.json"
    target.write_bytes(conflicting)
    registry = _Registry()

    with SecureWorkspace(root, max_file_bytes=1024 * 1024) as workspace:
        publisher = SecureDatasetArtifactPublisher(
            workspace=workspace,
            repository=registry,
        )
        with pytest.raises(ArtifactConflict, match="DESTINATION_CONTENT_CONFLICT"):
            publisher.publish(report, content)

    assert target.read_bytes() == conflicting
    assert registry.calls == []


def test_registration_failure_leaves_exact_file_for_safe_replay(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    content, report = _built_dataset()
    registry = _Registry(fail_once=True)

    with SecureWorkspace(root, max_file_bytes=1024 * 1024) as workspace:
        publisher = SecureDatasetArtifactPublisher(
            workspace=workspace,
            repository=registry,
        )
        with pytest.raises(_RegistrationFailure):
            publisher.publish(report, content)
        assert (root / "datasets" / "reviewed.coco.json").read_bytes() == content
        replay = publisher.publish(report, content)

    assert replay == report.dataset
    assert registry.calls == [(report, content), (report, content)]


def test_registration_must_return_the_exact_report_artifact(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    content, report = _built_dataset()

    class _WrongRegistry:
        def register_dataset_artifact(
            self,
            candidate: DatasetExportReport,
            content: bytes,
        ) -> DatasetArtifact:
            del content
            return candidate.dataset.model_copy(update={"dataset_id": "wrong-id"})

    with SecureWorkspace(root, max_file_bytes=1024 * 1024) as workspace:
        publisher = SecureDatasetArtifactPublisher(
            workspace=workspace,
            repository=_WrongRegistry(),
        )
        with pytest.raises(DatasetPublishError) as failure:
            publisher.publish(report, content)

    assert failure.value.reason_code == DatasetPublishFailureCode.REGISTRATION_MISMATCH
