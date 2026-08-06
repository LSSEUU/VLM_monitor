"""Durable publication boundary for an already-built dataset artifact."""

from typing import Protocol

from labcourt.contracts.evidence import Crop
from labcourt.contracts.m5_training import DatasetExportReport
from labcourt.contracts.m5_training_provenance import M5TrainingLabelAuthority
from labcourt.contracts.storage import ArtifactVerification
from labcourt.contracts.training import DatasetArtifact


class DatasetArtifactPublisher(Protocol):
    def publish(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact: ...


class M5TrainingCropVerifier(Protocol):
    """Trusted current-byte verifier for a durable training Crop."""

    def verify_crop(self, crop: Crop) -> ArtifactVerification: ...


class M5DatasetArtifactVerifier(Protocol):
    """Trusted proof that exact dataset bytes already exist at their locator."""

    def verify_published_dataset(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact: ...


class DatasetArtifactRegistrationRepository(Protocol):
    """Register a dataset only after rebuilding its exact report and bytes."""

    def register_dataset_artifact(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact: ...


class TrainingDatasetRepository(Protocol):
    """Complete, provenance-resolved label authorities plus dataset registration."""

    def load_registered_dataset_report(
        self,
        run_id: str,
        command_id: str,
    ) -> DatasetExportReport | None: ...

    def list_training_label_authorities(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[M5TrainingLabelAuthority, ...]: ...

    def register_dataset_artifact(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact: ...


__all__ = [
    "DatasetArtifactPublisher",
    "DatasetArtifactRegistrationRepository",
    "M5DatasetArtifactVerifier",
    "M5TrainingCropVerifier",
    "TrainingDatasetRepository",
]
