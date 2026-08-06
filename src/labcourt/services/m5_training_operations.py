"""Offline composition root for secure M5 reviewed-label dataset export."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.secure_dataset_publisher import (
    SecureDatasetArtifactPublisher,
    SecureDatasetArtifactVerifier,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.application.m5_training_operations import (
    M5TrainingExportCoordinator,
    M5TrainingExportError,
    M5TrainingExportFailureCode,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import RetentionHoldKind, TrainingLabelQuality
from labcourt.contracts.m5_training import (
    MAX_COCO_EXPORT_BYTES,
    MAX_COCO_EXPORT_LABELS,
    CocoDatasetExportCommand,
    DatasetExportReport,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.training import DatasetArtifact
from labcourt.exceptions import LabCourtError


def _controlled_paths(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
) -> tuple[Path, Path]:
    try:
        supplied_root = Path(workspace_root)
        supplied_database = Path(database_path)
    except TypeError:
        raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT) from None
    if ".." in supplied_root.parts or ".." in supplied_database.parts:
        raise M5TrainingExportError(M5TrainingExportFailureCode.PATH_SCOPE_MISMATCH)
    root = supplied_root.absolute()
    database = supplied_database.absolute()
    expected = root / config.storage.database_filename
    if database != expected or database.parent != root:
        raise M5TrainingExportError(M5TrainingExportFailureCode.PATH_SCOPE_MISMATCH)
    return root, database


def export_m5_training_dataset(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    run_id: str,
    relative_path: str,
    max_input_labels: int = MAX_COCO_EXPORT_LABELS,
    max_content_bytes: int = MAX_COCO_EXPORT_BYTES,
) -> DatasetExportReport:
    """Replay a registered command or securely publish its first COCO dataset."""

    if not isinstance(config, AppConfig):
        raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT)
    try:
        controlled_run_id = require_reference_token(run_id, "M5 training export run_id")
    except (TypeError, ValueError):
        raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT) from None
    if (
        isinstance(max_input_labels, bool)
        or not isinstance(max_input_labels, int)
        or not 1 <= max_input_labels <= MAX_COCO_EXPORT_LABELS
        or isinstance(max_content_bytes, bool)
        or not isinstance(max_content_bytes, int)
        or not 1 <= max_content_bytes <= MAX_COCO_EXPORT_BYTES
    ):
        raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT)
    if (
        config.training.include_weak_labels
        or config.training.export_minimum_quality != TrainingLabelQuality.HUMAN_CONFIRMED
    ):
        raise M5TrainingExportError(M5TrainingExportFailureCode.UNSAFE_TRAINING_POLICY)

    root, database = _controlled_paths(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    )
    with SecureWorkspace(
        root,
        max_file_bytes=max(config.storage.max_media_bytes, max_content_bytes),
    ) as workspace:
        verifier = StoredPngVerifier(
            run_id=controlled_run_id,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            database,
            config.storage.busy_timeout_ms,
            verifier=verifier,
        )
        manifest = evidence.load_run_manifest(controlled_run_id)
        if manifest.config_sha256 != config.config_sha256:
            raise M5TrainingExportError(M5TrainingExportFailureCode.CONFIG_MANIFEST_MISMATCH)
        try:
            command = CocoDatasetExportCommand(
                run_id=controlled_run_id,
                relative_path=relative_path,
                detector_manifest_id=manifest.models["detector"].model_manifest_id,
                manifest_id=manifest.manifest_id,
                rule_version=manifest.rule_version,
                purpose="DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
                retention_hold_kind=RetentionHoldKind.GOLD_SET,
                retention_policy_version="m5-gold-set-retention-v1",
                retention_period="UNTIL_EXPLICIT_RELEASE",
                max_input_labels=max_input_labels,
                max_content_bytes=max_content_bytes,
            )
        except (KeyError, TypeError, ValueError):
            raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT) from None

        repository = SQLiteM5Repository(
            database,
            config.storage.busy_timeout_ms,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        try:
            existing = repository.load_registered_dataset_report(
                command.run_id,
                command.command_id,
            )
        except (LabCourtError, TypeError, ValueError) as error:
            raise M5TrainingExportError(
                M5TrainingExportFailureCode.REGISTERED_DATASET_REPLAY_FAILED
            ) from error
        if existing is not None:
            try:
                if (
                    not isinstance(existing, DatasetExportReport)
                    or existing.run_id != command.run_id
                    or existing.command_id != command.command_id
                ):
                    raise ValueError("registered report does not match the requested command")
                snapshot = workspace.read_verified(
                    existing.dataset.relative_path,
                    expected_sha256=existing.dataset.content_sha256,
                    max_bytes=existing.content_size_bytes,
                )
                if (
                    snapshot.relative_path != existing.dataset.relative_path
                    or snapshot.sha256 != existing.dataset.content_sha256
                    or snapshot.size_bytes != existing.content_size_bytes
                    or len(snapshot.bytes) != existing.content_size_bytes
                ):
                    raise ValueError("registered dataset bytes do not match the report")
                registered = repository.register_dataset_artifact(existing, snapshot.bytes)
                if not isinstance(registered, DatasetArtifact) or registered != existing.dataset:
                    raise ValueError("registered dataset replay returned another artifact")
            except (LabCourtError, TypeError, ValueError) as error:
                raise M5TrainingExportError(
                    M5TrainingExportFailureCode.REGISTERED_DATASET_REPLAY_FAILED
                ) from error
            return existing

        publisher = SecureDatasetArtifactPublisher(
            workspace=workspace,
            repository=repository,
        )
        return M5TrainingExportCoordinator(
            repository=repository,
            evidence=evidence,
            crop_verifier=verifier,
            publisher=publisher,
            manifest=manifest,
        ).export(command)


__all__ = ["export_m5_training_dataset"]
