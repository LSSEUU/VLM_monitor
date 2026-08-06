"""Secure, no-overwrite publication of deterministic M5 dataset bytes."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import PurePosixPath

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.m5_training import DatasetExportReport
from labcourt.contracts.training import DatasetArtifact
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    LabCourtError,
    PathBoundaryViolation,
)
from labcourt.ports.dataset_export import DatasetArtifactRegistrationRepository


class DatasetPublishFailureCode(StrEnum):
    CONTENT_SIZE_MISMATCH = "CONTENT_SIZE_MISMATCH"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    PUBLISHED_CONTENT_MISMATCH = "PUBLISHED_CONTENT_MISMATCH"
    REGISTRATION_MISMATCH = "REGISTRATION_MISMATCH"


class DatasetPublishError(LabCourtError):
    def __init__(self, reason_code: DatasetPublishFailureCode) -> None:
        if not isinstance(reason_code, DatasetPublishFailureCode):
            raise TypeError("reason_code must be a DatasetPublishFailureCode")
        self.reason_code = reason_code
        super().__init__(f"dataset publication failed: {reason_code.value}")


class DatasetArtifactVerificationFailureCode(StrEnum):
    FILE_UNAVAILABLE = "FILE_UNAVAILABLE"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    CONTENT_SIZE_MISMATCH = "CONTENT_SIZE_MISMATCH"
    CONTENT_BYTES_MISMATCH = "CONTENT_BYTES_MISMATCH"


class DatasetArtifactVerificationError(LabCourtError):
    def __init__(self, reason_code: DatasetArtifactVerificationFailureCode) -> None:
        if not isinstance(reason_code, DatasetArtifactVerificationFailureCode):
            raise TypeError("reason_code must be a DatasetArtifactVerificationFailureCode")
        self.reason_code = reason_code
        super().__init__(f"published dataset verification failed: {reason_code.value}")


class SecureDatasetArtifactVerifier:
    """Re-open one published dataset through the anchored workspace boundary."""

    def __init__(self, workspace: SecureWorkspace) -> None:
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("SecureDatasetArtifactVerifier requires a SecureWorkspace")
        self._workspace = workspace

    def verify_published_dataset(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact:
        if not isinstance(report, DatasetExportReport):
            raise TypeError("report must be a DatasetExportReport")
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        try:
            snapshot = self._workspace.read_verified(
                report.dataset.relative_path,
                report.dataset.content_sha256,
            )
        except PathBoundaryViolation:
            raise DatasetArtifactVerificationError(
                DatasetArtifactVerificationFailureCode.FILE_UNAVAILABLE
            ) from None
        except ArtifactIntegrityViolation:
            raise DatasetArtifactVerificationError(
                DatasetArtifactVerificationFailureCode.CONTENT_HASH_MISMATCH
            ) from None
        if snapshot.size_bytes != report.content_size_bytes:
            raise DatasetArtifactVerificationError(
                DatasetArtifactVerificationFailureCode.CONTENT_SIZE_MISMATCH
            )
        if snapshot.bytes != content:
            raise DatasetArtifactVerificationError(
                DatasetArtifactVerificationFailureCode.CONTENT_BYTES_MISMATCH
            )
        return report.dataset


class SecureDatasetArtifactPublisher:
    """Publish exact bytes first, then idempotently register their authority."""

    def __init__(
        self,
        *,
        workspace: SecureWorkspace,
        repository: DatasetArtifactRegistrationRepository,
    ) -> None:
        self._workspace = workspace
        self._repository = repository

    def publish(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact:
        if not isinstance(report, DatasetExportReport):
            raise TypeError("report must be a DatasetExportReport")
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")

        dataset = report.dataset
        if len(content) != report.content_size_bytes:
            raise DatasetPublishError(DatasetPublishFailureCode.CONTENT_SIZE_MISMATCH)
        if hashlib.sha256(content).hexdigest() != dataset.content_sha256:
            raise DatasetPublishError(DatasetPublishFailureCode.CONTENT_HASH_MISMATCH)

        existing = self._read_existing(dataset, content)
        if existing is None:
            self._stage_and_publish(report, content)

        registered = self._repository.register_dataset_artifact(report, content)
        if registered != dataset:
            raise DatasetPublishError(DatasetPublishFailureCode.REGISTRATION_MISMATCH)
        return registered

    def _read_existing(
        self,
        dataset: DatasetArtifact,
        content: bytes,
    ) -> bytes | None:
        try:
            snapshot = self._workspace.read_verified(
                dataset.relative_path,
                dataset.content_sha256,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
        except ArtifactIntegrityViolation:
            raise ArtifactConflict(
                "DESTINATION_CONTENT_CONFLICT",
                dataset.relative_path,
            ) from None
        if snapshot.bytes != content or snapshot.size_bytes != len(content):
            raise ArtifactConflict(
                "DESTINATION_CONTENT_CONFLICT",
                dataset.relative_path,
            )
        return snapshot.bytes

    def _stage_and_publish(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> None:
        dataset = report.dataset
        operation_directory = f".staging/{report.run_id}/dataset-{report.report_id}"
        staged_path = f"{operation_directory}/dataset.json"

        self._ensure_directory_chain(operation_directory)
        self._ensure_parent_directory_chain(dataset.relative_path)
        try:
            self._workspace.create_new(
                staged_path,
                content,
                dataset.content_sha256,
            )
        except ArtifactConflict as error:
            if error.reason_code != "TARGET_ALREADY_EXISTS":
                raise
            try:
                staged = self._workspace.read_verified(
                    staged_path,
                    dataset.content_sha256,
                )
            except (ArtifactIntegrityViolation, PathBoundaryViolation):
                raise ArtifactConflict("STAGING_CONTENT_CONFLICT", staged_path) from None
            if staged.bytes != content:
                raise ArtifactConflict("STAGING_CONTENT_CONFLICT", staged_path) from error

        published = self._workspace.publish_staged(
            staged_path,
            dataset.relative_path,
            dataset.content_sha256,
        )
        if (
            published.sha256 != dataset.content_sha256
            or published.size_bytes != len(content)
            or published.bytes != content
        ):
            raise DatasetPublishError(DatasetPublishFailureCode.PUBLISHED_CONTENT_MISMATCH)

    def _ensure_parent_directory_chain(self, relative_path: str) -> None:
        parent = PurePosixPath(relative_path).parent
        if parent == PurePosixPath("."):
            return
        self._ensure_directory_chain(parent.as_posix())

    def _ensure_directory_chain(self, relative_path: str) -> None:
        parts = PurePosixPath(relative_path).parts
        for index in range(1, len(parts) + 1):
            self._workspace.ensure_private_directory("/".join(parts[:index]))


__all__ = [
    "DatasetArtifactRegistrationRepository",
    "DatasetArtifactVerificationError",
    "DatasetArtifactVerificationFailureCode",
    "DatasetPublishError",
    "DatasetPublishFailureCode",
    "SecureDatasetArtifactPublisher",
    "SecureDatasetArtifactVerifier",
]
