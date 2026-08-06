"""Secure one-snapshot M5 artifact validation service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from labcourt.adapters.storage.readonly_m5_artifacts import (
    M5AuthorityBudgetExceeded,
    ReadonlyM5ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import (
    DEFAULT_MAX_DATABASE_BYTES,
    readonly_sqlite_snapshot,
    snapshot_contains_run,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.application.m5_artifact_validation import (
    M5ArtifactValidator,
    M5AuthorityPreflightObservation,
    M5AuthoritySnapshotObservation,
    M5DatasetArtifactReader,
    M5ProjectionArtifactReader,
)
from labcourt.contracts.artifact_validation import M3ArtifactValidationReport
from labcourt.contracts.config import AppConfig
from labcourt.contracts.evidence import Crop
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationBudget,
    M5ArtifactValidationReport,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactVerification
from labcourt.exceptions import BudgetExceeded, ContractViolation, PathBoundaryViolation


@dataclass(frozen=True, slots=True)
class _SecureM5DatasetReader:
    workspace: SecureWorkspace
    crop_verifier: StoredPngVerifier

    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> object:
        return self.workspace.read_verified(
            relative_path,
            expected_sha256,
            max_bytes=max_bytes,
        )

    def list_dataset_directory(
        self,
        run_id: str,
        max_items: int,
        max_name_bytes: int,
    ) -> object:
        return self.workspace.list_dataset_directory(run_id, max_items, max_name_bytes)

    def inspect_verified(self, relative_path: str) -> object:
        return self.workspace.inspect_verified(relative_path)

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        return self.crop_verifier.verify_crop(crop)


def _physical_dataset_authority_present(
    *,
    run_id: str,
    workspace_root: str | Path,
    config: AppConfig,
    budget: M5ArtifactValidationBudget,
) -> bool:
    with SecureWorkspace(
        Path(workspace_root).absolute(),
        max_file_bytes=max(
            budget.max_dataset_file_bytes,
            config.storage.max_media_bytes,
        ),
    ) as workspace:
        try:
            return bool(
                workspace.list_dataset_directory(
                    run_id,
                    max_items=1,
                    max_name_bytes=512,
                )
            )
        except BudgetExceeded:
            return True
        except PathBoundaryViolation as error:
            return error.reason_code != "DIRECTORY_MISSING"


def validate_m5_artifacts(
    *,
    config: AppConfig,
    run_id: str,
    database_path: str | Path,
    workspace_root: str | Path,
    budget: M5ArtifactValidationBudget | None = None,
    max_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
) -> M5ArtifactValidationReport:
    controlled = require_reference_token(run_id, "M5 validation run reference")
    selected_budget = budget or M5ArtifactValidationBudget()
    with readonly_sqlite_snapshot(
        Path(database_path).absolute(),
        max_database_bytes=max_database_bytes,
    ) as snapshot:
        if not snapshot_contains_run(snapshot, controlled):
            raise ContractViolation("M5 validation run does not exist")
        report = validate_m5_snapshot(
            config=config,
            run_id=controlled,
            snapshot_path=snapshot,
            workspace_root=workspace_root,
            budget=selected_budget,
        )
        if report is None:
            raise ContractViolation("M5 standalone validation did not produce a report")
        return report


def validate_m5_snapshot(
    *,
    config: AppConfig,
    run_id: str,
    snapshot_path: str | Path,
    workspace_root: str | Path,
    budget: M5ArtifactValidationBudget | None = None,
    predecessor_report: M3ArtifactValidationReport | M4ArtifactValidationReport | None = None,
    only_if_authority: bool = False,
) -> M5ArtifactValidationReport | None:
    """Validate M5 from an existing immutable snapshot used by the main CLI."""

    controlled = require_reference_token(run_id, "M5 validation run reference")
    selected_budget = budget or M5ArtifactValidationBudget()
    repository = ReadonlyM5ArtifactRepository(
        snapshot_path,
        config=config,
        budget=selected_budget,
    )
    if (
        only_if_authority
        and not repository.has_authority(controlled)
        and not _physical_dataset_authority_present(
            run_id=controlled,
            workspace_root=workspace_root,
            config=config,
            budget=selected_budget,
        )
    ):
        return None
    try:
        authority = repository.scan(controlled)
    except M5AuthorityBudgetExceeded as error:
        return M5ArtifactValidator(budget=selected_budget).validate_preflight_failure(
            controlled,
            cast(M5AuthorityPreflightObservation, error.preflight),
            error.issue_codes,
            predecessor_report,
        )
    with SecureWorkspace(
        Path(workspace_root).absolute(),
        max_file_bytes=max(
            selected_budget.max_projection_file_bytes,
            selected_budget.max_dataset_file_bytes,
            config.storage.max_media_bytes,
        ),
    ) as workspace:
        crop_verifier = StoredPngVerifier(
            run_id=controlled,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        return M5ArtifactValidator(
            artifact_reader=cast(M5ProjectionArtifactReader, workspace),
            dataset_reader=cast(
                M5DatasetArtifactReader,
                _SecureM5DatasetReader(workspace, crop_verifier),
            ),
            budget=selected_budget,
        ).validate(
            controlled,
            cast(M5AuthoritySnapshotObservation, authority),
            predecessor_report,
        )


__all__ = ["validate_m5_artifacts", "validate_m5_snapshot"]
