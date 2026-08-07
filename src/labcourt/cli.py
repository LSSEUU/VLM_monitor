"""M0 command-line boundary."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, NoReturn, cast

import typer

from labcourt import __version__
from labcourt.config_loader import load_config
from labcourt.exceptions import ContractViolation
from labcourt.m3_cli import register_m3_commands
from labcourt.m4_cli import register_m4_commands
from labcourt.m5_cli import register_m5_commands
from labcourt.pilot_cli import register_pilot_commands

app = typer.Typer(help="LabCourt auditable laboratory-safety pipeline.")
schemas_app = typer.Typer(help="Export and verify public JSON Schemas.")
artifacts_app = typer.Typer(help="Read-only validation of persisted run artifacts.")
maintenance_app = typer.Typer(help="Bounded, fail-closed maintenance for persisted runs.")
app.add_typer(schemas_app, name="schemas")
app.add_typer(artifacts_app, name="artifacts")
app.add_typer(maintenance_app, name="maintenance")
register_m3_commands(app)
register_m4_commands(app)
register_m5_commands(app, artifacts_app)
register_pilot_commands(app)
DEFAULT_SCHEMA_OUTPUT = Path("schemas")
DEFAULT_CONFIG = Path("configs/default.yaml")


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.")] = False,
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("validate-config")
def validate_config(
    config: Annotated[
        Path,
        typer.Option("--config", "-c", exists=True, dir_okay=False),
    ],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        parsed = load_config(config)
    except ContractViolation as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    summary = {
        "valid": True,
        "schema_version": parsed.schema_version,
        "rule_version": parsed.rule_version,
        "config_sha256": parsed.config_sha256,
        "zones": len(parsed.zones),
    }
    if json_output:
        typer.echo(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    else:
        typer.echo(
            f"valid config {parsed.schema_version}; "
            f"zones={len(parsed.zones)}; sha256={parsed.config_sha256}"
        )


@schemas_app.command("export")
def schemas_export(
    check: Annotated[bool, typer.Option("--check")] = False,
    output: Annotated[Path, typer.Option("--output")] = DEFAULT_SCHEMA_OUTPUT,
) -> None:
    from labcourt.schema_export import export_schemas

    errors = export_schemas(output.resolve(), check=check)
    if errors:
        for error in errors:
            typer.echo(error, err=True)
        raise typer.Exit(code=1)
    typer.echo("schemas verified" if check else "schemas exported")


@artifacts_app.command("validate")
def artifacts_validate(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    max_database_bytes: Annotated[
        int,
        typer.Option("--max-database-bytes", min=1),
    ] = 4 * 1024 * 1024 * 1024,
    max_audit_entries: Annotated[
        int,
        typer.Option("--max-audit-entries", min=1),
    ] = 100_000,
    max_document_bytes: Annotated[
        int,
        typer.Option("--max-document-bytes", min=1),
    ] = 16 * 1024 * 1024,
    max_events: Annotated[int, typer.Option("--max-events", min=1)] = 10_000,
    max_cases: Annotated[int, typer.Option("--max-cases", min=1)] = 10_000,
    max_packs: Annotated[int, typer.Option("--max-packs", min=1)] = 50_000,
    max_media: Annotated[int, typer.Option("--max-media", min=1)] = 200_000,
    max_projection_bytes: Annotated[
        int,
        typer.Option("--max-projection-bytes", min=1),
    ] = 256 * 1024 * 1024,
    max_m3_documents: Annotated[
        int,
        typer.Option("--max-m3-documents", min=1, max=10_000_000),
    ] = 1_000_000,
    max_m3_document_bytes: Annotated[
        int,
        typer.Option(
            "--max-m3-document-bytes",
            min=1,
            max=1024 * 1024 * 1024,
        ),
    ] = 16 * 1024 * 1024,
    max_raw_response_bytes: Annotated[
        int | None,
        typer.Option(
            "--max-raw-response-bytes",
            min=1,
            max=1024 * 1024 * 1024,
        ),
    ] = None,
    max_raw_response_total_bytes: Annotated[
        int,
        typer.Option(
            "--max-raw-response-total-bytes",
            min=1,
            max=64 * 1024 * 1024 * 1024,
        ),
    ] = 4 * 1024 * 1024 * 1024,
    max_raw_response_files: Annotated[
        int,
        typer.Option("--max-raw-response-files", min=1, max=10_000_000),
    ] = 1_000_000,
    max_raw_response_name_bytes: Annotated[
        int,
        typer.Option("--max-raw-response-name-bytes", min=1, max=4096),
    ] = 255,
    max_m4_documents: Annotated[
        int,
        typer.Option("--max-m4-documents", min=1, max=10_000_000),
    ] = 1_000_000,
    max_m4_document_bytes: Annotated[
        int,
        typer.Option(
            "--max-m4-document-bytes",
            min=1,
            max=1024 * 1024 * 1024,
        ),
    ] = 16 * 1024 * 1024,
    max_m4_projection_files: Annotated[
        int,
        typer.Option("--max-m4-projection-files", min=1, max=10_000_000),
    ] = 1_000_000,
    max_m4_projection_file_bytes: Annotated[
        int,
        typer.Option(
            "--max-m4-projection-file-bytes",
            min=1,
            max=1024 * 1024 * 1024,
        ),
    ] = 64 * 1024 * 1024,
    max_m4_projection_bytes: Annotated[
        int,
        typer.Option(
            "--max-m4-projection-bytes",
            min=1,
            max=4 * 1024 * 1024 * 1024,
        ),
    ] = 256 * 1024 * 1024,
    max_m4_projection_name_bytes: Annotated[
        int,
        typer.Option("--max-m4-projection-name-bytes", min=1, max=4096),
    ] = 512,
    max_m5_authority_records: Annotated[
        int,
        typer.Option("--max-m5-authority-records", min=1, max=10_000_000),
    ] = 1_000_000,
    max_m5_authority_record_bytes: Annotated[
        int,
        typer.Option(
            "--max-m5-authority-record-bytes",
            min=1,
            max=1024 * 1024 * 1024,
        ),
    ] = 16 * 1024 * 1024,
    max_m5_authority_total_bytes: Annotated[
        int,
        typer.Option(
            "--max-m5-authority-total-bytes",
            min=1,
            max=64 * 1024 * 1024 * 1024,
        ),
    ] = 1024 * 1024 * 1024,
    max_m5_projection_file_bytes: Annotated[
        int,
        typer.Option(
            "--max-m5-projection-file-bytes",
            min=1,
            max=1024 * 1024 * 1024,
        ),
    ] = 64 * 1024 * 1024,
    max_m5_projection_total_bytes: Annotated[
        int,
        typer.Option(
            "--max-m5-projection-total-bytes",
            min=1,
            max=4 * 1024 * 1024 * 1024,
        ),
    ] = 256 * 1024 * 1024,
) -> None:
    """Validate authority, current projections, and final physical artifacts read-only.

    Publication journals and staging files are operational recovery inputs, not
    authoritative final artifacts; inspect those with ``maintenance recover``.
    """

    from labcourt.adapters.storage.m4_artifact_preflight import m4_artifact_preflight
    from labcourt.adapters.storage.readonly_m3_artifacts import (
        ReadonlyM3ArtifactRepository,
    )
    from labcourt.adapters.storage.readonly_m4_artifacts import (
        ReadonlyM4ArtifactRepository,
    )
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
    from labcourt.application.m4_current_projection_validation import (
        M4ProjectionArtifactReader,
    )
    from labcourt.contracts.artifact_validation import (
        ArtifactValidationBudget,
        ArtifactValidationCounts,
        M3ArtifactValidationBudget,
        M3ArtifactValidationCounts,
        M3ArtifactValidationReport,
    )
    from labcourt.contracts.canonical import canonical_json
    from labcourt.contracts.m4_artifact_validation import (
        M4ArtifactValidationBudget,
        M4ArtifactValidationReport,
    )
    from labcourt.contracts.m5_artifact_validation import (
        M5ArtifactValidationBudget,
        M5ArtifactValidationReport,
    )
    from labcourt.exceptions import PathBoundaryViolation
    from labcourt.services.m5_artifact_validation import validate_m5_snapshot

    try:
        parsed = load_config(config)
        budget = ArtifactValidationBudget(
            max_database_bytes=max_database_bytes,
            max_audit_entries=max_audit_entries,
            max_document_bytes=max_document_bytes,
            max_events=max_events,
            max_cases=max_cases,
            max_packs=max_packs,
            max_media=max_media,
            max_projection_bytes=max_projection_bytes,
        )
        m3_budget = M3ArtifactValidationBudget(
            max_documents=max_m3_documents,
            max_document_bytes=max_m3_document_bytes,
            max_raw_response_bytes=(
                parsed.screening.max_response_bytes
                if max_raw_response_bytes is None
                else max_raw_response_bytes
            ),
            max_raw_response_total_bytes=max_raw_response_total_bytes,
            max_raw_response_files=max_raw_response_files,
            max_raw_response_name_bytes=max_raw_response_name_bytes,
        )
        m4_budget = M4ArtifactValidationBudget(
            max_authority_documents=max_m4_documents,
            max_authority_document_bytes=max_m4_document_bytes,
            max_projection_files=max_m4_projection_files,
            max_projection_file_bytes=max_m4_projection_file_bytes,
            max_projection_total_bytes=max_m4_projection_bytes,
            max_projection_name_bytes=max_m4_projection_name_bytes,
        )
        m5_budget = M5ArtifactValidationBudget(
            max_authority_records=max_m5_authority_records,
            max_authority_record_bytes=max_m5_authority_record_bytes,
            max_authority_total_bytes=max_m5_authority_total_bytes,
            max_projection_file_bytes=max_m5_projection_file_bytes,
            max_projection_total_bytes=max_m5_projection_total_bytes,
        )
    except (ContractViolation, TypeError, ValueError):
        _artifact_boundary_error(json_output, "CONFIG_OR_BUDGET_INVALID")

    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        with readonly_sqlite_snapshot(
            database,
            max_database_bytes=budget.max_database_bytes,
        ) as snapshot_database:
            if not snapshot_contains_run(snapshot_database, run_id):
                _artifact_boundary_error(json_output, "RUN_NOT_FOUND")
            observed = snapshot_run_counts(snapshot_database, run_id)
            authority_counts = ArtifactValidationCounts(
                max_document_bytes=observed.max_document_bytes,
                audit_entries=observed.audit_entries,
                events=observed.events,
                cases=observed.cases,
                packs=observed.packs,
                media=observed.media,
            )
            m3_authority_counts = M3ArtifactValidationCounts(
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
                budget=budget,
                counts=authority_counts,
            )
            if m2_report is None:
                with (
                    SecureWorkspace(
                        workspace_root,
                        max_file_bytes=parsed.storage.max_media_bytes,
                    ) as media_workspace,
                    SecureWorkspace(
                        workspace_root,
                        max_file_bytes=budget.max_projection_bytes,
                    ) as projection_workspace,
                ):
                    verifier = StoredPngVerifier(
                        run_id=run_id,
                        workspace=media_workspace,
                        max_media_bytes=parsed.storage.max_media_bytes,
                        max_image_pixels=parsed.storage.max_image_pixels,
                    )
                    repository = SQLiteEvidenceRepository(
                        snapshot_database,
                        parsed.storage.busy_timeout_ms,
                        verifier=verifier,
                    )
                    m2_report = ArtifactValidator(
                        repository=repository,
                        artifact_reader=cast(ArtifactReader, projection_workspace),
                        authority_counts=authority_counts,
                        budget=budget,
                    ).validate(run_id)
            with SecureWorkspace(
                workspace_root,
                max_file_bytes=m3_budget.max_raw_response_bytes,
            ) as raw_response_workspace:
                m3_report = M3ArtifactValidator(
                    authority=ReadonlyM3ArtifactRepository(snapshot_database),
                    artifact_reader=cast(M3ArtifactReader, raw_response_workspace),
                    authority_counts=m3_authority_counts,
                    budget=m3_budget,
                ).validate(run_id, m2_report)
            report: (
                M3ArtifactValidationReport | M4ArtifactValidationReport | M5ArtifactValidationReport
            ) = m3_report
            m4_preflight = m4_artifact_preflight(snapshot_database, run_id)
            if m4_preflight.has_authority:
                with (
                    SecureWorkspace(
                        workspace_root,
                        max_file_bytes=m4_budget.max_projection_file_bytes,
                    ) as m4_projection_workspace,
                    SecureWorkspace(
                        workspace_root,
                        max_file_bytes=parsed.storage.max_media_bytes,
                    ) as m4_media_workspace,
                ):
                    m4_media_verifier = StoredPngVerifier(
                        run_id=run_id,
                        workspace=m4_media_workspace,
                        max_media_bytes=parsed.storage.max_media_bytes,
                        max_image_pixels=parsed.storage.max_image_pixels,
                    )
                    report = M4ArtifactValidator(
                        authority=cast(
                            M4ArtifactAuthorityReader,
                            ReadonlyM4ArtifactRepository(snapshot_database),
                        ),
                        artifact_reader=cast(
                            M4ProjectionArtifactReader,
                            m4_projection_workspace,
                        ),
                        authority_rows=m4_preflight.authority_rows,
                        preflight_max_document_bytes=(m4_preflight.max_document_bytes),
                        media_verifier=cast(M4MediaVerifier, m4_media_verifier),
                        budget=m4_budget,
                    ).validate(run_id, m3_report)
            m5_report = validate_m5_snapshot(
                config=parsed,
                run_id=run_id,
                snapshot_path=snapshot_database,
                workspace_root=workspace_root,
                budget=m5_budget,
                predecessor_report=cast(
                    M3ArtifactValidationReport | M4ArtifactValidationReport,
                    report,
                ),
                only_if_authority=True,
            )
            if m5_report is not None:
                report = m5_report
    except ReadOnlySnapshotError as error:
        _artifact_boundary_error(json_output, error.reason_code)
    except PathBoundaryViolation as error:
        _artifact_boundary_error(json_output, error.reason_code)
    except (ContractViolation, sqlite3.Error, OSError, TypeError, ValueError):
        _artifact_boundary_error(json_output, "REPOSITORY_BOUNDARY_ERROR")

    if report is None:
        _artifact_boundary_error(json_output, "REPOSITORY_BOUNDARY_ERROR")
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        status = "valid" if report.passed else "invalid"
        predecessor = (
            report.predecessor_report if isinstance(report, M5ArtifactValidationReport) else report
        )
        if predecessor is None:
            _artifact_boundary_error(json_output, "M5_PREDECESSOR_REPORT_MISSING")
        m3_report = (
            predecessor.m3_report
            if isinstance(predecessor, M4ArtifactValidationReport)
            else predecessor
        )
        m2_report = m3_report.m2_report
        typer.echo(
            f"{status} artifacts run={report.run_id}; "
            f"audit={m2_report.counts.audit_entries}; "
            f"events={m2_report.counts.events}; "
            f"cases={m2_report.counts.cases}; "
            f"packs={m2_report.counts.packs}; media={m2_report.counts.media}; "
            f"m2_issues={len(m2_report.issues)}; "
            f"m3_documents={m3_report.counts.documents}; "
            f"m3_raw_responses={m3_report.counts.model_responses}; "
            f"m3_raw_bytes={m3_report.counts.raw_response_bytes}; "
            f"m3_physical_raw_entries={m3_report.counts.physical_raw_response_entries}; "
            f"m3_physical_raw_files={m3_report.counts.physical_raw_response_files}; "
            f"m3_physical_raw_bytes={m3_report.counts.physical_raw_response_bytes}; "
            f"m3_issues={len(m3_report.issues)}"
            + (
                f"; m4_documents={predecessor.counts.validated_authority_documents}; "
                f"m4_projection_files={predecessor.counts.projection_files}; "
                f"m4_projection_bytes={predecessor.counts.projection_bytes}; "
                f"m4_issues={len(predecessor.issues)}"
                if isinstance(predecessor, M4ArtifactValidationReport)
                else ""
            )
            + (
                f"; m5_authority_rows={report.counts.authority_rows}; "
                f"m5_authority_bytes={report.counts.authority_bytes}; "
                f"m5_projection_files={report.counts.projection_files}; "
                f"m5_projection_bytes={report.counts.projection_bytes}; "
                f"m5_issues={len(report.issues)}"
                if isinstance(report, M5ArtifactValidationReport)
                else ""
            )
        )
        for m2_issue in m2_report.issues:
            typer.echo(_artifact_issue_text(m2_issue))
        for m3_issue in m3_report.issues:
            typer.echo(_m3_artifact_issue_text(m3_issue))
        if isinstance(predecessor, M4ArtifactValidationReport):
            for m4_issue in predecessor.issues:
                typer.echo(_m4_artifact_issue_text(m4_issue))
        if isinstance(report, M5ArtifactValidationReport):
            for m5_issue in report.issues:
                typer.echo(_m5_artifact_issue_text(m5_issue))
    if not report.passed:
        raise typer.Exit(code=1)


@maintenance_app.command("recover")
def maintenance_recover(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    max_items: Annotated[
        int,
        typer.Option("--max-items", min=1, max=1_000),
    ] = 100,
    max_claim_items: Annotated[
        int,
        typer.Option("--max-claim-items", min=1, max=10_000),
    ] = 10_000,
    minimum_age_minutes: Annotated[
        int,
        typer.Option("--minimum-age-minutes", min=1, max=10_080),
    ] = 10,
) -> None:
    """Recover retention and model publications, then inspect staging/orphans."""

    from labcourt.adapters.storage.secure_workspace import SecureWorkspace
    from labcourt.adapters.storage.sqlite_authority import SQLiteAuthorityError
    from labcourt.adapters.storage.sqlite_repository import (
        MigrationIntegrityError,
        RepositoryIntegrityError,
        SQLiteEvidenceRepository,
    )
    from labcourt.application.model_response_recovery import ModelCallRecoveryError
    from labcourt.contracts.canonical import canonical_json
    from labcourt.contracts.enums import (
        PurgeDisposition,
        RecoveryDisposition,
    )
    from labcourt.contracts.model_response_recovery import (
        ModelResponseRecoveryDisposition,
    )
    from labcourt.contracts.references import require_reference_token
    from labcourt.exceptions import LabCourtError, PathBoundaryViolation
    from labcourt.services.maintenance_recovery import (
        build_maintenance_recovery_coordinator,
    )

    try:
        controlled_run_id = require_reference_token(run_id, "startup recovery run_id")
    except (TypeError, ValueError):
        _maintenance_boundary_error(json_output, "RUN_ID_INVALID")

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _maintenance_boundary_error(json_output, "CONFIG_INVALID")

    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    repository = SQLiteEvidenceRepository(
        database,
        parsed.storage.busy_timeout_ms,
    )

    # Prove that the authority and requested run exist before opening the
    # workspace or permitting any quarantine/unlink operation.
    try:
        repository.get_audit_head(controlled_run_id)
    except SQLiteAuthorityError as error:
        _maintenance_boundary_error(json_output, error.reason_code)
    except (MigrationIntegrityError, RepositoryIntegrityError):
        _maintenance_boundary_error(json_output, "DATABASE_INTEGRITY_ERROR")
    except ContractViolation:
        _maintenance_boundary_error(json_output, "RUN_NOT_FOUND")
    except (sqlite3.Error, OSError, TypeError, ValueError):
        _maintenance_boundary_error(json_output, "REPOSITORY_BOUNDARY_ERROR")

    try:
        with SecureWorkspace(
            workspace_root,
            max_file_bytes=parsed.storage.max_media_bytes,
        ) as workspace:
            report = build_maintenance_recovery_coordinator(
                database_path=database,
                busy_timeout_ms=parsed.storage.busy_timeout_ms,
                workspace=workspace,
                storage_repository=repository,
                max_items=max_items,
                max_claim_items=max_claim_items,
                max_response_bytes=parsed.screening.max_response_bytes,
            ).recover(
                controlled_run_id,
                datetime.now(UTC),
                timedelta(minutes=minimum_age_minutes),
            )
    except SQLiteAuthorityError as error:
        _maintenance_boundary_error(json_output, error.reason_code)
    except PathBoundaryViolation as error:
        _maintenance_boundary_error(json_output, error.reason_code)
    except ModelCallRecoveryError as error:
        _maintenance_boundary_error(json_output, error.code.value)
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError):
        _maintenance_boundary_error(json_output, "RECOVERY_BOUNDARY_ERROR")

    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        retention_attention = sum(
            item.disposition == PurgeDisposition.RECOVERY_REQUIRED
            for item in report.storage_report.retention_items
        )
        orphan_anomalies = sum(
            item.disposition == RecoveryDisposition.ANOMALY
            for item in report.storage_report.orphan_report.items
        )
        quarantined = sum(
            item.disposition == RecoveryDisposition.QUARANTINED
            for item in report.storage_report.orphan_report.items
        )
        cleaned = sum(
            item.disposition == RecoveryDisposition.CLEANED
            for item in report.storage_report.orphan_report.items
        )
        response_anomalies = sum(
            item.disposition == ModelResponseRecoveryDisposition.ANOMALY
            for item in report.model_response_report.items
        )
        response_resolved = sum(
            item.disposition
            in {
                ModelResponseRecoveryDisposition.VERIFIED,
                ModelResponseRecoveryDisposition.ACKNOWLEDGED,
                ModelResponseRecoveryDisposition.QUARANTINED,
                ModelResponseRecoveryDisposition.CLEANED,
            }
            for item in report.model_response_report.items
        )
        status = "recovered" if report.passed else "attention required"
        typer.echo(
            f"{status} run={report.run_id}; "
            f"retention={len(report.storage_report.retention_items)}; "
            f"retention_attention={retention_attention}; "
            f"quarantined={quarantined}; cleaned={cleaned}; "
            f"orphan_anomalies={orphan_anomalies}; "
            f"model_response_phase={report.model_response_report.artifact_phase.value}; "
            f"model_response_items={len(report.model_response_report.items)}; "
            f"model_response_resolved={response_resolved}; "
            f"model_response_anomalies={response_anomalies}"
        )
    if not report.passed:
        raise typer.Exit(code=1)


def _artifact_boundary_error(json_output: bool, reason_code: str) -> NoReturn:
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "error": "ARTIFACT_VALIDATION_BOUNDARY_ERROR",
                    "reason_code": reason_code,
                    "valid": False,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        typer.echo(f"artifact validation boundary error: {reason_code}", err=True)
    raise typer.Exit(code=2)


def _maintenance_boundary_error(json_output: bool, reason_code: str) -> NoReturn:
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "error": "STARTUP_RECOVERY_BOUNDARY_ERROR",
                    "reason_code": reason_code,
                    "recovered": False,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        typer.echo(f"startup recovery boundary error: {reason_code}", err=True)
    raise typer.Exit(code=2)


def _artifact_issue_text(issue: object) -> str:
    from labcourt.contracts.artifact_validation import ArtifactValidationIssue

    if not isinstance(issue, ArtifactValidationIssue):
        raise TypeError("artifact issue formatter requires ArtifactValidationIssue")
    details: list[str] = []
    if issue.root_ref is not None:
        details.append(f"root={issue.root_ref.kind.value}:{issue.root_ref.artifact_id}")
    if issue.artifact_ref is not None:
        details.append(f"artifact={issue.artifact_ref.kind.value}:{issue.artifact_ref.artifact_id}")
    if issue.closure_defect_code is not None:
        details.append(f"defect={issue.closure_defect_code.value}")
    if issue.audit_failure_reason is not None:
        details.append(f"audit={issue.audit_failure_reason.value}")
    if issue.media_availability is not None:
        details.append(f"availability={issue.media_availability.value}")
    if issue.projection_kind is not None:
        details.append(f"projection={issue.projection_kind.value}:{issue.projection_id}")
    if issue.sequence is not None:
        details.append(f"sequence={issue.sequence}")
    if issue.limit is not None:
        details.append(f"limit={issue.limit};observed={issue.observed}")
    if issue.inventory_kind is not None:
        details.append(
            f"inventory={issue.inventory_kind.value};"
            f"authority={issue.authoritative_count};traversed={issue.traversed_count}"
        )
    if issue.reason_code is not None:
        details.append(f"reason={issue.reason_code}")
    suffix = f" {' '.join(details)}" if details else ""
    return f"[{issue.area.value}] {issue.code.value}{suffix}"


def _m3_artifact_issue_text(issue: object) -> str:
    from labcourt.contracts.artifact_validation import M3ArtifactValidationIssue

    if not isinstance(issue, M3ArtifactValidationIssue):
        raise TypeError("M3 artifact issue formatter requires M3ArtifactValidationIssue")
    details: list[str] = []
    if issue.inventory_kind is not None:
        details.append(f"inventory={issue.inventory_kind.value}")
    if issue.record_identity_sha256 is not None:
        details.append(f"record={issue.record_identity_sha256}")
    if issue.artifact_id is not None:
        details.append(f"artifact={issue.artifact_id}")
    if issue.source_token is not None:
        details.append(f"source={issue.source_token}")
    if issue.reason_code is not None:
        details.append(f"reason={issue.reason_code}")
    if issue.authoritative_count is not None:
        details.append(f"authority={issue.authoritative_count};traversed={issue.traversed_count}")
    if issue.limit is not None:
        details.append(f"limit={issue.limit};observed={issue.observed}")
    if issue.expected_sha256 is not None:
        details.append(
            f"expected_sha256={issue.expected_sha256};actual_sha256={issue.actual_sha256}"
        )
    if issue.expected_size_bytes is not None:
        details.append(
            f"expected_size={issue.expected_size_bytes};actual_size={issue.actual_size_bytes}"
        )
    suffix = f" {' '.join(details)}" if details else ""
    return f"[{issue.area.value}] {issue.code.value}{suffix}"


def _m4_artifact_issue_text(issue: object) -> str:
    from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationIssue

    if not isinstance(issue, M4ArtifactValidationIssue):
        raise TypeError("M4 artifact issue formatter requires M4ArtifactValidationIssue")
    details: list[str] = []
    if issue.inventory_kind is not None:
        details.append(f"inventory={issue.inventory_kind.value}")
    if issue.record_identity_sha256 is not None:
        details.append(f"record={issue.record_identity_sha256}")
    if issue.artifact_id is not None:
        details.append(f"artifact={issue.artifact_id}")
    if issue.source_token is not None:
        details.append(f"source={issue.source_token}")
    if issue.reason_code is not None:
        details.append(f"reason={issue.reason_code}")
    if issue.authoritative_count is not None:
        details.append(f"authority={issue.authoritative_count};projected={issue.projected_count}")
    if issue.limit is not None:
        details.append(f"limit={issue.limit};observed={issue.observed}")
    if issue.expected_sha256 is not None:
        details.append(
            f"expected_sha256={issue.expected_sha256};actual_sha256={issue.actual_sha256}"
        )
    if issue.expected_size_bytes is not None:
        details.append(
            f"expected_size={issue.expected_size_bytes};actual_size={issue.actual_size_bytes}"
        )
    suffix = f" {' '.join(details)}" if details else ""
    return f"[{issue.area.value}] {issue.code.value}{suffix}"


def _m5_artifact_issue_text(issue: object) -> str:
    from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationIssue

    if not isinstance(issue, M5ArtifactValidationIssue):
        raise TypeError("M5 artifact issue formatter requires M5ArtifactValidationIssue")
    return f"[M5:{issue.area.value}] {issue.code.value} reason={issue.reason_code}"
