"""One-shot production sealing of an M6 replay source input."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, cast

from pydantic import ValidationError

from labcourt.adapters.storage._m6_snapshot_identity import (
    capture_m6_readonly_snapshot_identity,
)
from labcourt.adapters.storage.m4_artifact_preflight import m4_artifact_preflight
from labcourt.adapters.storage.m6_source_authority_store import (
    M6SourceAuthorityPublicationResult,
    M6SourceAuthorityPublisher,
    M6SourceAuthorityStoreError,
)
from labcourt.adapters.storage.readonly_m3_artifacts import ReadonlyM3ArtifactRepository
from labcourt.adapters.storage.readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import (
    ReadOnlySnapshotError,
    readonly_sqlite_snapshot,
    snapshot_contains_run,
    snapshot_run_counts,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.application.artifact_validation import (
    ArtifactReader,
    ArtifactValidator,
    M3ArtifactReader,
    M3ArtifactValidator,
    artifact_budget_preflight_report,
)
from labcourt.application.m4_artifact_validation import (
    M4ArtifactAuthorityReader,
    M4ArtifactValidator,
    M4MediaVerifier,
)
from labcourt.application.m4_current_projection_validation import M4ProjectionArtifactReader
from labcourt.application.m6_source_authority_builder import (
    M6SealedSourceBundle,
    M6SourceAuthorityBuildError,
    build_m6_sealed_source_bundle,
)
from labcourt.application.m6_source_authority_sealing import (
    M6SealedGateSource,
    M6SourceAuthoritySealingError,
    seal_m6_gate_current_closures,
)
from labcourt.contracts.artifact_validation import (
    ArtifactValidationBudget,
    ArtifactValidationCounts,
    ArtifactValidationReport,
    M3ArtifactValidationBudget,
    M3ArtifactValidationCounts,
    M3ArtifactValidationReport,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationBudget
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationBudget,
    M5ArtifactValidationReport,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ContractViolation, LabCourtError, PathBoundaryViolation
from labcourt.ports.m6_source_authority_builder import M6ReplayInputSelection
from labcourt.services.m5_artifact_validation import validate_m5_snapshot


class M6SourceInputSealErrorCode(StrEnum):
    """Stable reason-code namespace for one-shot source sealing."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    M4_AUTHORITY_REQUIRED = "M4_AUTHORITY_REQUIRED"
    M5_AUTHORITY_REQUIRED = "M5_AUTHORITY_REQUIRED"
    CURRENT_CLOSURE_CAPTURE_INVALID = "CURRENT_CLOSURE_CAPTURE_INVALID"
    SOURCE_VALIDATION_FAILED = "SOURCE_VALIDATION_FAILED"
    SOURCE_VALIDATION_CHAIN_INVALID = "SOURCE_VALIDATION_CHAIN_INVALID"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    SOURCE_BUILD_FAILED = "SOURCE_BUILD_FAILED"
    PUBLICATION_FAILED = "PUBLICATION_FAILED"
    REPOSITORY_BOUNDARY_ERROR = "REPOSITORY_BOUNDARY_ERROR"
    PRODUCER_INVARIANT_VIOLATION = "PRODUCER_INVARIANT_VIOLATION"


class M6SourceInputSealError(LabCourtError):
    """The one-shot source producer failed before a complete seal was proven."""

    def __init__(self, code: M6SourceInputSealErrorCode) -> None:
        if not isinstance(code, M6SourceInputSealErrorCode):
            raise TypeError("code must be an M6SourceInputSealErrorCode")
        self.code = code
        super().__init__(f"M6 source input seal failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6SourceInputValidationBudgets:
    m2: ArtifactValidationBudget = field(default_factory=ArtifactValidationBudget)
    m3: M3ArtifactValidationBudget = field(default_factory=M3ArtifactValidationBudget)
    m4: M4ArtifactValidationBudget = field(default_factory=M4ArtifactValidationBudget)
    m5: M5ArtifactValidationBudget = field(default_factory=M5ArtifactValidationBudget)

    def __post_init__(self) -> None:
        for value, expected, label in (
            (self.m2, ArtifactValidationBudget, "M2"),
            (self.m3, M3ArtifactValidationBudget, "M3"),
            (self.m4, M4ArtifactValidationBudget, "M4"),
            (self.m5, M5ArtifactValidationBudget, "M5"),
        ):
            if not isinstance(value, expected):
                raise TypeError(f"{label} validation budget has the wrong type")


@dataclass(frozen=True, slots=True)
class M6SealedSourceInput:
    bundle: M6SealedSourceBundle
    publication: M6SourceAuthorityPublicationResult


def _fail(code: M6SourceInputSealErrorCode) -> NoReturn:
    raise M6SourceInputSealError(code)


def _controlled_config(value: object) -> AppConfig:
    if not isinstance(value, AppConfig):
        _fail(M6SourceInputSealErrorCode.INVALID_ARGUMENT)
    try:
        controlled = AppConfig.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SourceInputSealErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SourceInputSealErrorCode.INVALID_ARGUMENT)
    return controlled


def _capture_live_gate_source(
    *,
    config: AppConfig,
    database_path: Path,
    workspace_root: Path,
    selection: M6ReplayInputSelection,
) -> M6SealedGateSource:
    try:
        with SecureWorkspace(
            workspace_root,
            max_file_bytes=config.storage.max_media_bytes,
        ) as media_workspace:
            verifier = StoredPngVerifier(
                run_id=selection.source_run_id,
                workspace=media_workspace,
                max_media_bytes=config.storage.max_media_bytes,
                max_image_pixels=config.storage.max_image_pixels,
            )
            repository = SQLiteEvidenceRepository(
                database_path,
                config.storage.busy_timeout_ms,
                verifier=verifier,
            )
            observation = repository.observe_m6_gate_source(
                selection.source_run_id,
                selection.source_case_id,
                selection.source_case_revision,
            )
        return seal_m6_gate_current_closures(observation=observation)
    except M6SourceAuthoritySealingError as exc:
        raise M6SourceInputSealError(
            M6SourceInputSealErrorCode.CURRENT_CLOSURE_CAPTURE_INVALID
        ) from exc


def _m2_and_m3_reports(
    *,
    config: AppConfig,
    run_id: str,
    snapshot_path: Path,
    workspace_root: Path,
    budgets: M6SourceInputValidationBudgets,
) -> tuple[ArtifactValidationReport, M3ArtifactValidationReport]:
    observed = snapshot_run_counts(snapshot_path, run_id)
    authority_counts = ArtifactValidationCounts(
        max_document_bytes=observed.max_document_bytes,
        audit_entries=observed.audit_entries,
        events=observed.events,
        cases=observed.cases,
        packs=observed.packs,
        media=observed.media,
    )
    m3_counts = M3ArtifactValidationCounts(
        max_document_bytes=observed.m3_max_document_bytes,
        raw_response_bytes=observed.raw_response_bytes,
        max_raw_response_bytes=observed.max_raw_response_bytes,
        model_call_claims=observed.model_call_claims,
        model_call_failure_authorities=observed.model_call_failure_authorities,
        model_responses=observed.model_responses,
        parsed_screening_outputs=observed.parsed_screening_outputs,
        model_parse_receipts=observed.model_parse_receipts,
        model_cache_entries=observed.model_cache_entries,
        model_call_usage=observed.model_call_usage,
        screening_results=observed.screening_results,
        verdicts=observed.verdicts,
        procedural_reviews=observed.procedural_reviews,
        procedural_defects=observed.procedural_defects,
        backlog_items=observed.backlog_items,
        backlog_item_versions=observed.backlog_item_versions,
        backlog_heads=observed.backlog_heads,
        backlog_completion_receipts=observed.backlog_completion_receipts,
    )
    m2_report = artifact_budget_preflight_report(
        run_id=run_id,
        budget=budgets.m2,
        counts=authority_counts,
    )
    if m2_report is None:
        with (
            SecureWorkspace(
                workspace_root,
                max_file_bytes=config.storage.max_media_bytes,
            ) as media_workspace,
            SecureWorkspace(
                workspace_root,
                max_file_bytes=budgets.m2.max_projection_bytes,
            ) as projection_workspace,
        ):
            verifier = StoredPngVerifier(
                run_id=run_id,
                workspace=media_workspace,
                max_media_bytes=config.storage.max_media_bytes,
                max_image_pixels=config.storage.max_image_pixels,
            )
            m2_report = ArtifactValidator(
                repository=SQLiteEvidenceRepository(
                    snapshot_path,
                    config.storage.busy_timeout_ms,
                    verifier=verifier,
                ),
                artifact_reader=cast(ArtifactReader, projection_workspace),
                authority_counts=authority_counts,
                budget=budgets.m2,
            ).validate(run_id)
    with SecureWorkspace(
        workspace_root,
        max_file_bytes=budgets.m3.max_raw_response_bytes,
    ) as raw_workspace:
        m3_report = M3ArtifactValidator(
            authority=ReadonlyM3ArtifactRepository(snapshot_path),
            artifact_reader=cast(M3ArtifactReader, raw_workspace),
            authority_counts=m3_counts,
            budget=budgets.m3,
        ).validate(run_id, m2_report)
    return m2_report, m3_report


def _validate_m6_source_snapshot(
    *,
    config: AppConfig,
    run_id: str,
    snapshot_path: Path,
    workspace_root: Path,
    budgets: M6SourceInputValidationBudgets,
) -> tuple[M5ArtifactValidationReport, RunManifest]:
    before = capture_m6_readonly_snapshot_identity(snapshot_path)
    _, m3_report = _m2_and_m3_reports(
        config=config,
        run_id=run_id,
        snapshot_path=snapshot_path,
        workspace_root=workspace_root,
        budgets=budgets,
    )
    m4_preflight = m4_artifact_preflight(snapshot_path, run_id)
    if not m4_preflight.has_authority:
        _fail(M6SourceInputSealErrorCode.M4_AUTHORITY_REQUIRED)
    with (
        SecureWorkspace(
            workspace_root,
            max_file_bytes=budgets.m4.max_projection_file_bytes,
        ) as projection_workspace,
        SecureWorkspace(
            workspace_root,
            max_file_bytes=config.storage.max_media_bytes,
        ) as media_workspace,
    ):
        media_verifier = StoredPngVerifier(
            run_id=run_id,
            workspace=media_workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        m4_report = M4ArtifactValidator(
            authority=cast(
                M4ArtifactAuthorityReader,
                ReadonlyM4ArtifactRepository(snapshot_path),
            ),
            artifact_reader=cast(M4ProjectionArtifactReader, projection_workspace),
            authority_rows=m4_preflight.authority_rows,
            preflight_max_document_bytes=m4_preflight.max_document_bytes,
            media_verifier=cast(M4MediaVerifier, media_verifier),
            budget=budgets.m4,
        ).validate(run_id, m3_report)
    m5_repository = ReadonlyM5ArtifactRepository(
        snapshot_path,
        config=config,
        budget=budgets.m5,
    )
    if not m5_repository.has_authority(run_id):
        _fail(M6SourceInputSealErrorCode.M5_AUTHORITY_REQUIRED)
    report = validate_m5_snapshot(
        config=config,
        run_id=run_id,
        snapshot_path=snapshot_path,
        workspace_root=workspace_root,
        budget=budgets.m5,
        predecessor_report=m4_report,
        only_if_authority=False,
    )
    if report is None:
        _fail(M6SourceInputSealErrorCode.M5_AUTHORITY_REQUIRED)
    m4_authority = ReadonlyM4ArtifactRepository(snapshot_path, immutable=True).scan(run_id)
    m5_authority = ReadonlyM5ArtifactRepository(
        snapshot_path,
        config=config,
        budget=budgets.m5,
        immutable=True,
    ).scan(run_id)
    after = capture_m6_readonly_snapshot_identity(snapshot_path)
    if after != before:
        _fail(M6SourceInputSealErrorCode.SNAPSHOT_CHANGED)
    if (
        not report.passed
        or not m4_report.passed
        or not m3_report.passed
        or not m3_report.m2_report.passed
    ):
        _fail(M6SourceInputSealErrorCode.SOURCE_VALIDATION_FAILED)
    if (
        report.predecessor_report != m4_report
        or m4_authority.failures
        or m5_authority.failures
        or m4_report.authority_root_sha256 != m4_authority.authority_root_sha256
        or report.authority_root_sha256 != m5_authority.authority_root_sha256
    ):
        _fail(M6SourceInputSealErrorCode.SOURCE_VALIDATION_CHAIN_INVALID)
    manifest = SQLiteEvidenceRepository(
        snapshot_path,
        config.storage.busy_timeout_ms,
    ).load_run_manifest(run_id)
    return report, manifest


def seal_m6_source_input(
    *,
    config: object,
    database_path: str | Path,
    workspace_root: str | Path,
    output_root: str | Path,
    selection: object,
    budgets: M6SourceInputValidationBudgets | None = None,
) -> M6SealedSourceInput:
    """Capture, validate, build, publish, and read back one complete source seal."""

    controlled_config = _controlled_config(config)
    if not isinstance(selection, M6ReplayInputSelection):
        _fail(M6SourceInputSealErrorCode.INVALID_ARGUMENT)
    selected_budgets = budgets or M6SourceInputValidationBudgets(
        m3=M3ArtifactValidationBudget(
            max_raw_response_bytes=controlled_config.screening.max_response_bytes
        )
    )
    if not isinstance(selected_budgets, M6SourceInputValidationBudgets):
        _fail(M6SourceInputSealErrorCode.INVALID_ARGUMENT)
    database = Path(database_path).absolute()
    workspace = Path(workspace_root).absolute()
    try:
        gate_source = _capture_live_gate_source(
            config=controlled_config,
            database_path=database,
            workspace_root=workspace,
            selection=selection,
        )
        with readonly_sqlite_snapshot(
            database,
            max_database_bytes=selected_budgets.m2.max_database_bytes,
        ) as snapshot:
            if not snapshot_contains_run(snapshot, selection.source_run_id):
                _fail(M6SourceInputSealErrorCode.RUN_NOT_FOUND)
            report, manifest = _validate_m6_source_snapshot(
                config=controlled_config,
                run_id=selection.source_run_id,
                snapshot_path=Path(snapshot),
                workspace_root=workspace,
                budgets=selected_budgets,
            )
            bundle = build_m6_sealed_source_bundle(
                selection=selection,
                gate_source=gate_source,
                source_manifest=manifest,
                source_validation_report=report,
                config=controlled_config,
            )
        publication = M6SourceAuthorityPublisher(output_root).publish(
            bundle,
            config=controlled_config,
        )
        return M6SealedSourceInput(bundle=bundle, publication=publication)
    except M6SourceInputSealError:
        raise
    except ReadOnlySnapshotError as exc:
        raise M6SourceInputSealError(M6SourceInputSealErrorCode.SNAPSHOT_CHANGED) from exc
    except M6SourceAuthorityBuildError as exc:
        raise M6SourceInputSealError(M6SourceInputSealErrorCode.SOURCE_BUILD_FAILED) from exc
    except M6SourceAuthorityStoreError as exc:
        raise M6SourceInputSealError(M6SourceInputSealErrorCode.PUBLICATION_FAILED) from exc
    except (ContractViolation, PathBoundaryViolation, sqlite3.Error, OSError) as exc:
        raise M6SourceInputSealError(M6SourceInputSealErrorCode.REPOSITORY_BOUNDARY_ERROR) from exc
    except Exception as exc:
        raise M6SourceInputSealError(
            M6SourceInputSealErrorCode.PRODUCER_INVARIANT_VIOLATION
        ) from exc


__all__ = [
    "M6SealedSourceInput",
    "M6SourceInputSealError",
    "M6SourceInputSealErrorCode",
    "M6SourceInputValidationBudgets",
    "seal_m6_source_input",
]
