"""Detector training boundary; v0.1 only requires dataset export."""

from collections.abc import Sequence
from typing import Protocol

from labcourt.contracts.enums import DatasetFormat
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.training import DatasetArtifact, TrainingLabel


class DetectorTrainingConfig(Protocol):
    strategy: str


class DetectorTrainer(Protocol):
    def export_dataset(
        self,
        labels: Sequence[TrainingLabel],
        target: DatasetFormat,
    ) -> DatasetArtifact: ...

    def train(
        self,
        dataset: DatasetArtifact,
        base_manifest: ModelManifest,
        config: DetectorTrainingConfig,
    ) -> ModelManifest: ...
