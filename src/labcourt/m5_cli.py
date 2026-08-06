"""Bounded offline CLI for M5 closure and alert outbox dispatch."""

from __future__ import annotations

import json
import sqlite3
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import ValidationError

from labcourt.adapters.strict_jsonl import load_strict_jsonl
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import AppealStatus, VerdictDecision
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationBudget
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_precedents import MAX_M5_PRECEDENTS
from labcourt.contracts.m5_projection import M5ProjectionCurrentPointer
from labcourt.exceptions import ContractViolation, LabCourtError
from labcourt.services.m5_artifact_validation import validate_m5_artifacts
from labcourt.services.m5_human_appeals import (
    begin_human_appeal_review,
    resolve_human_appeal,
    submit_human_appeal,
)
from labcourt.services.m5_operations import (
    MAX_M5_IMPORT_FILE_BYTES,
    MAX_M5_IMPORT_LINE_BYTES,
    activate_m5_precedents_for_run,
    dispatch_m5_alerts,
    finalize_m5_run,
    import_m5_precedent_file,
    reconcile_m5_precedents_for_run,
)
from labcourt.services.m5_projection import rebuild_m5_projection
from labcourt.services.m5_training_operations import export_m5_training_dataset

DEFAULT_CONFIG = Path("configs/default.yaml")

alert_app = typer.Typer(help="Restart-safe offline alert outbox operations.")
precedent_app = typer.Typer(help="Strict offline precedent administration.")
appeal_app = typer.Typer(help="Explicit human appeal submission and review.")
training_app = typer.Typer(help="Verified reviewed-label dataset publication.")
projection_app = typer.Typer(help="Rebuild immutable read-only projections from SQLite authority.")


class _TerminalAppealStatus(StrEnum):
    UPHELD = AppealStatus.UPHELD.value
    OVERTURNED = AppealStatus.OVERTURNED.value


def register_m5_commands(
    root: typer.Typer,
    artifacts_root: typer.Typer | None = None,
) -> None:
    root.command("finalize")(finalize)
    root.add_typer(alert_app, name="alert")
    root.add_typer(precedent_app, name="precedent")
    root.add_typer(appeal_app, name="appeal")
    root.add_typer(training_app, name="training")
    root.add_typer(projection_app, name="projection")
    if artifacts_root is not None:
        artifacts_root.command("validate-m5")(artifacts_validate_m5)


def _operation_error(
    *,
    operation: str,
    json_output: bool,
    reason_code: str,
) -> NoReturn:
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "error": "M5_OPERATION_BOUNDARY_ERROR",
                    "operation": operation,
                    "reason_code": reason_code,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        typer.echo(f"M5 {operation} failed: {reason_code}", err=True)
    raise typer.Exit(code=2)


def _error_reason(error: BaseException) -> str:
    for attribute in ("reason_code", "code"):
        value = getattr(error, attribute, None)
        if value is not None:
            return str(getattr(value, "value", value))
    return "REPOSITORY_BOUNDARY_ERROR"


def finalize(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    limit: Annotated[int, typer.Option("--limit", min=1, max=256)] = 256,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Close READY Cases and create alert/outbox/provisional-precedent authority."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="finalize",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = finalize_m5_run(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            limit=limit,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="finalize",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        alerts = sum(item.alert_id is not None for item in report.outcomes)
        typer.echo(
            f"finalized run={report.run_id}; cases={report.selected_count}; alerts={alerts}; "
            f"automatic_precedents={len(report.outcomes)}"
        )


@alert_app.command("dispatch")
def dispatch(
    run_id: Annotated[str, typer.Option("--run-id")],
    worker_id: Annotated[str, typer.Option("--worker-id")] = "offline-worker-01",
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    limit: Annotated[int, typer.Option("--limit", min=1, max=256)] = 256,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Deliver one pending batch through the deterministic offline fake channel."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="alert-dispatch",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = dispatch_m5_alerts(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            worker_id=worker_id,
            limit=limit,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="alert-dispatch",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"dispatched run={report.run_id}; selected={report.selected_count}; "
            f"succeeded={report.succeeded_count}; "
            f"retryable={report.retryable_failure_count}; "
            f"unknown={report.unknown_delivery_count}; "
            f"attention={report.attention_required_count}"
        )


@precedent_app.command("import")
def precedent_import(
    source: Annotated[Path, typer.Argument(dir_okay=False)],
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    max_file_bytes: Annotated[
        int,
        typer.Option("--max-file-bytes", min=1, max=MAX_M5_IMPORT_FILE_BYTES),
    ] = (MAX_M5_IMPORT_FILE_BYTES),
    max_line_bytes: Annotated[
        int,
        typer.Option("--max-line-bytes", min=1, max=MAX_M5_IMPORT_LINE_BYTES),
    ] = (MAX_M5_IMPORT_LINE_BYTES),
    max_entries: Annotated[
        int,
        typer.Option("--max-entries", min=1, max=MAX_M5_PRECEDENTS),
    ] = MAX_M5_PRECEDENTS,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Import full active PRESET authorities from strict UTF-8 JSONL."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="precedent-import",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = import_m5_precedent_file(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            source_path=source,
            max_file_bytes=max_file_bytes,
            max_line_bytes=max_line_bytes,
            max_entries=max_entries,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="precedent-import",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(f"imported run={report.run_id}; accepted={report.accepted_count}")


@precedent_app.command("activate")
def precedent_activate(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=MAX_M5_PRECEDENTS),
    ] = MAX_M5_PRECEDENTS,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Activate due automatic precedents only after a fresh no-appeal snapshot."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="precedent-activate",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = activate_m5_precedents_for_run(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            limit=limit,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="precedent-activate",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        activated = sum(item.outcome.value == "ACTIVATED" for item in report.receipts)
        typer.echo(
            f"activated run={report.run_id}; selected={report.selected_count}; "
            f"activated={activated}"
        )


@precedent_app.command("conflicts")
def precedent_conflicts(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            min=1,
            max=MAX_M5_PRECEDENTS,
            help=(
                "Complete active-candidate snapshot budget; fail closed when the active "
                "inventory exceeds it."
            ),
        ),
    ] = MAX_M5_PRECEDENTS,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Exact-reconcile all relevant active pairs and list current conflict heads."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="precedent-conflicts",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = reconcile_m5_precedents_for_run(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            limit=limit,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="precedent-conflicts",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"reconciled run={report.run_id}; candidates={report.candidate_count}; "
            f"pairs={report.evaluated_pair_count}; edges={report.conflict_edge_count}; "
            f"cut={report.causal_cut_id}; batch={report.batch_authority_id}; "
            f"receipt={report.batch_receipt_id}; "
            f"current_conflicts={len(report.current_conflict_precedent_ids)}"
        )


def _load_human_label_inputs(
    path: Path | None,
) -> tuple[M5AppealTrainingLabelInput, ...]:
    if path is None:
        return ()
    records = load_strict_jsonl(
        path,
        max_file_bytes=64 * 1024 * 1024,
        max_line_bytes=64 * 1024,
        max_entries=10_000,
    )
    try:
        inputs = tuple(M5AppealTrainingLabelInput.model_validate(item) for item in records)
    except ValidationError as exc:
        raise ContractViolation("appeal label JSONL contains an invalid human input") from exc
    input_ids = tuple(item.input_id for item in inputs)
    if len(input_ids) != len(set(input_ids)):
        raise ContractViolation("appeal label JSONL contains duplicate human inputs")
    return inputs


@appeal_app.command("submit")
def appeal_submit(
    case_id: Annotated[str, typer.Argument()],
    run_id: Annotated[str, typer.Option("--run-id")],
    reason: Annotated[str, typer.Option("--reason")],
    submitted_by: Annotated[str, typer.Option("--submitted-by")],
    appeal_id: Annotated[str | None, typer.Option("--appeal-id")] = None,
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Submit one explicit human-authored appeal against a CLOSED Case."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="appeal-submit",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = submit_human_appeal(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            case_id=case_id,
            reason=reason,
            submitted_by=submitted_by,
            appeal_id=appeal_id,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="appeal-submit",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"submitted run={report.run_id}; case={report.case_id}; "
            f"appeal={report.appeal_id}; version={report.appeal_version}"
        )


@appeal_app.command("review")
def appeal_review(
    appeal_id: Annotated[str, typer.Argument()],
    run_id: Annotated[str, typer.Option("--run-id")],
    reviewer_id: Annotated[str, typer.Option("--reviewer-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Assign the explicit human reviewer and enter UNDER_REVIEW."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="appeal-review",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = begin_human_appeal_review(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            appeal_id=appeal_id,
            reviewer_id=reviewer_id,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="appeal-review",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"reviewing run={report.run_id}; appeal={report.appeal_id}; "
            f"reviewer={report.reviewer_id}; version={report.appeal_version}"
        )


@appeal_app.command("resolve")
def appeal_resolve(
    appeal_id: Annotated[str, typer.Argument()],
    run_id: Annotated[str, typer.Option("--run-id")],
    reviewer_id: Annotated[str, typer.Option("--reviewer-id")],
    status: Annotated[_TerminalAppealStatus, typer.Option("--status")],
    resolved_decision: Annotated[VerdictDecision, typer.Option("--resolved-decision")],
    resolution_summary: Annotated[str, typer.Option("--resolution-summary")],
    labels_jsonl: Annotated[
        Path | None,
        typer.Option("--labels-jsonl", dir_okay=False),
    ] = None,
    precedent_situation: Annotated[
        str | None,
        typer.Option("--precedent-situation"),
    ] = None,
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Commit an explicit UPHELD or OVERTURNED human decision atomically."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="appeal-resolve",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        labels = _load_human_label_inputs(labels_jsonl)
        report = resolve_human_appeal(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            appeal_id=appeal_id,
            reviewer_id=reviewer_id,
            status=AppealStatus(status.value),
            resolved_decision=resolved_decision,
            resolution_summary=resolution_summary,
            authored_labels=labels,
            precedent_situation=precedent_situation,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="appeal-resolve",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"resolved run={report.run_id}; appeal={report.appeal_id}; "
            f"status={report.status.value}; final_decision={report.final_decision.value}; "
            f"labels={len(report.training_label_ids)}"
        )


@training_app.command("export")
def training_export(
    relative_path: Annotated[str, typer.Argument()],
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    max_input_labels: Annotated[
        int,
        typer.Option("--max-input-labels", min=1, max=10_000),
    ] = 10_000,
    max_content_bytes: Annotated[
        int,
        typer.Option("--max-content-bytes", min=1, max=64 * 1024 * 1024),
    ] = 64 * 1024 * 1024,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Publish canonical COCO JSON from currently verified reviewed labels."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="training-export",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = export_m5_training_dataset(
            config=parsed,
            workspace_root=workspace_root,
            database_path=database,
            run_id=run_id,
            relative_path=relative_path,
            max_input_labels=max_input_labels,
            max_content_bytes=max_content_bytes,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="training-export",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"exported run={report.run_id}; dataset={report.dataset.dataset_id}; "
            f"labels={len(report.exported_label_ids)}; "
            f"quarantined={len(report.quarantined_label_ids)}; "
            f"path={report.dataset.relative_path}"
        )


@projection_app.command("rebuild-m5")
def projection_rebuild_m5(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    max_database_bytes: Annotated[
        int,
        typer.Option("--max-database-bytes", min=1, max=64 * 1024**3),
    ] = 4 * 1024**3,
    max_projection_bytes: Annotated[
        int,
        typer.Option("--max-projection-bytes", min=1, max=4 * 1024**3),
    ] = 64 * 1024**2,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Publish one complete content-addressed M5 projection generation."""

    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="projection-rebuild-m5",
            json_output=json_output,
            reason_code="CONFIG_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        result = rebuild_m5_projection(
            config=parsed,
            run_id=run_id,
            database_path=database,
            workspace_root=workspace_root,
            max_database_bytes=max_database_bytes,
            max_projection_bytes=max_projection_bytes,
        )
        pointer = M5ProjectionCurrentPointer.model_validate_json(
            result.current_pointer_path.read_bytes()
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="projection-rebuild-m5",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(pointer.model_dump(mode="json")))
    else:
        typer.echo(
            f"rebuilt M5 projection run={pointer.run_id}; "
            f"generation={pointer.generation_id}; authority={pointer.authority_root_sha256}"
        )


def artifacts_validate_m5(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    max_database_bytes: Annotated[
        int,
        typer.Option("--max-database-bytes", min=1, max=64 * 1024**3),
    ] = 4 * 1024**3,
    max_authority_records: Annotated[
        int,
        typer.Option("--max-authority-records", min=1, max=10_000_000),
    ] = 1_000_000,
    max_authority_record_bytes: Annotated[
        int,
        typer.Option("--max-authority-record-bytes", min=1, max=1024**3),
    ] = 16 * 1024**2,
    max_authority_total_bytes: Annotated[
        int,
        typer.Option("--max-authority-total-bytes", min=1, max=64 * 1024**3),
    ] = 1024**3,
    max_projection_file_bytes: Annotated[
        int,
        typer.Option("--max-projection-file-bytes", min=1, max=1024**3),
    ] = 64 * 1024**2,
    max_projection_total_bytes: Annotated[
        int,
        typer.Option("--max-projection-total-bytes", min=1, max=4 * 1024**3),
    ] = 256 * 1024**2,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate M5 authority and the selected projection without mutation."""

    try:
        parsed = load_config(config)
        budget = M5ArtifactValidationBudget(
            max_authority_records=max_authority_records,
            max_authority_record_bytes=max_authority_record_bytes,
            max_authority_total_bytes=max_authority_total_bytes,
            max_projection_file_bytes=max_projection_file_bytes,
            max_projection_total_bytes=max_projection_total_bytes,
        )
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_error(
            operation="artifacts-validate-m5",
            json_output=json_output,
            reason_code="CONFIG_OR_BUDGET_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        report = validate_m5_artifacts(
            config=parsed,
            run_id=run_id,
            database_path=database,
            workspace_root=workspace_root,
            budget=budget,
            max_database_bytes=max_database_bytes,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError) as error:
        _operation_error(
            operation="artifacts-validate-m5",
            json_output=json_output,
            reason_code=_error_reason(error),
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        status = "valid" if report.passed else "invalid"
        typer.echo(
            f"{status} M5 artifacts run={report.run_id}; "
            f"authority={report.counts.validated_authority_documents}; "
            f"projection_files={report.counts.projection_files}; "
            f"projection_records={report.counts.projection_records}; "
            f"issues={len(report.issues)}"
        )
        for issue in report.issues:
            typer.echo(f"{issue.area.value}:{issue.code.value}:{issue.reason_code}")
    if not report.passed:
        raise typer.Exit(code=1)


__all__ = ["register_m5_commands"]
