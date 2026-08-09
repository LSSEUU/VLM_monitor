"""v0.2 pilot command group and fail-closed staged execution boundary."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import VerdictDecision
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.exceptions import ContractViolation, LabCourtError
from labcourt.pilot_ui_server import run_pilot_ui_server
from labcourt.services.m3_operations import open_pilot_a3_operations_service
from labcourt.services.pilot_a4 import (
    PilotA4ReviewError,
    publish_pilot_run,
    review_pilot_case,
)
from labcourt.services.pilot_a5 import PilotA5OperationsError, run_pilot_a5
from labcourt.services.pilot_operations import (
    PilotOperationsBoundaryCode,
    PilotOperationsBoundaryError,
    build_pilot_run_request,
    require_pilot_config,
    run_pilot_perception,
)

DEFAULT_PILOT_CONFIG = Path("configs/pilot.yaml")

pilot_app = typer.Typer(help="Run the local real-video pilot in bounded stages.")


def register_pilot_commands(root: typer.Typer) -> None:
    """Attach the v0.2 pilot group to the stable LabCourt CLI."""

    root.add_typer(pilot_app, name="pilot")


def _load_config(config_path: Path, operation: str, json_output: bool) -> AppConfig:
    try:
        config = load_config(config_path)
        require_pilot_config(config)
        return config
    except (ContractViolation, PilotOperationsBoundaryError, OSError, TypeError, ValueError):
        _pilot_boundary_error(json_output, operation, "CONFIG_INVALID")


@pilot_app.command("run")
def pilot_run(
    video: Annotated[Path, typer.Option("--video", dir_okay=False)],
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = (
        DEFAULT_PILOT_CONFIG
    ),
    resume: Annotated[bool, typer.Option("--resume/--no-resume")] = True,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run or resume the complete real-video pilot through the local report."""

    parsed = _load_config(config, "RUN", json_output)
    try:
        request = build_pilot_run_request(
            config=parsed,
            run_id=run_id,
            video_path=video,
            project_root=Path.cwd(),
            resume=resume,
        )
        report = run_pilot_a5(
            config=parsed,
            request=request,
            config_path=config,
            project_root=Path.cwd(),
        )
    except PilotA5OperationsError as error:
        _pilot_boundary_error(json_output, "RUN", error.code.value)
    except PilotOperationsBoundaryError as error:
        _pilot_boundary_error(json_output, "RUN", error.code.value)
    except (LabCourtError, OSError, TypeError, ValueError):
        _pilot_boundary_error(
            json_output,
            "RUN",
            PilotOperationsBoundaryCode.EVIDENCE_FAILED.value,
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"pilot run complete; state={report.state}; "
            f"candidates={report.evidence.candidate_event_count}; "
            f"cases={report.publication.metrics.case_count}; "
            f"index={report.publication.index_path}; report_id={report.report_id}"
        )
    if report.state == "ATTENTION_REQUIRED":
        raise typer.Exit(code=1)


@pilot_app.command("perceive")
def pilot_perceive(
    video: Annotated[Path, typer.Option("--video", dir_okay=False)],
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = (
        DEFAULT_PILOT_CONFIG
    ),
    resume: Annotated[bool, typer.Option("--resume/--no-resume")] = True,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Generate real person/goggles detections without calling a VLM."""

    parsed = _load_config(config, "PERCEIVE", json_output)
    try:
        request = build_pilot_run_request(
            config=parsed,
            run_id=run_id,
            video_path=video,
            project_root=Path.cwd(),
            resume=resume,
        )
        report = run_pilot_perception(
            config=parsed,
            request=request,
            config_path=config,
            project_root=Path.cwd(),
        )
    except PilotOperationsBoundaryError as error:
        _pilot_boundary_error(json_output, "PERCEIVE", error.code.value)
    except (LabCourtError, OSError, TypeError, ValueError):
        _pilot_boundary_error(
            json_output,
            "PERCEIVE",
            PilotOperationsBoundaryCode.PERCEPTION_FAILED.value,
        )
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
        return
    typer.echo(
        f"pilot perception complete; frames={report.frames_processed}; "
        f"detections={report.detection_count}; persons={report.person_count}; "
        f"goggles={report.goggles_count}; tracks={report.track_count}; "
        f"preview={report.preview_path or 'disabled'}"
    )


@pilot_app.command("screen")
def pilot_screen(
    run_id: Annotated[str, typer.Option("--run-id")],
    case_id: Annotated[str | None, typer.Option("--case-id")] = None,
    max_cases: Annotated[int, typer.Option("--max-cases", min=1, max=1_000)] = 10,
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = (
        DEFAULT_PILOT_CONFIG
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Screen existing A2 evidence through the configured real VLM provider."""

    parsed = _load_config(config, "SCREEN", json_output)
    try:
        controlled_run_id = require_portable_run_id(run_id, "pilot run_id")
        controlled_case_id = (
            require_reference_token(case_id, "pilot case_id") if case_id is not None else None
        )
        runs_root = Path.cwd() / parsed.run.workspace
        database = runs_root / controlled_run_id / parsed.storage.database_filename
        with open_pilot_a3_operations_service(
            config=parsed,
            run_id=controlled_run_id,
            workspace_root=runs_root,
            database_path=database,
        ) as service:
            report = service.process_run(case_id=controlled_case_id, max_cases=max_cases)
    except (LabCourtError, OSError, TypeError, ValueError):
        _pilot_boundary_error(json_output, "SCREEN", "SCREENING_FAILED")
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"pilot screening complete; selected={report.counts.selected_cases}; "
            f"processed={report.counts.processed_cases}; "
            f"backlogged={report.counts.deferred_to_backlog_cases}; "
            f"report_id={report.report_id}"
        )
    if report.counts.deferred_to_backlog_cases or any(
        outcome.status.value in {"ESCALATED", "REWORK_REQUIRED"} for outcome in report.outcomes
    ):
        raise typer.Exit(code=1)


@pilot_app.command("report")
def pilot_report(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = (
        DEFAULT_PILOT_CONFIG
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Close eligible cases and publish an offline operator report with local alerts."""

    parsed = _load_config(config, "REPORT", json_output)
    try:
        controlled_run_id = require_portable_run_id(run_id, "pilot run_id")
        runs_root = Path.cwd() / parsed.run.workspace
        database = runs_root / controlled_run_id / parsed.storage.database_filename
        report = publish_pilot_run(
            config=parsed,
            runs_root=runs_root,
            database_path=database,
            run_id=controlled_run_id,
        )
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError):
        _pilot_boundary_error(json_output, "REPORT", "REPORTING_FAILED")
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        typer.echo(
            f"pilot report published; cases={report.metrics.case_count}; "
            f"closed={report.metrics.closed_count}; "
            f"local_alerts={report.metrics.verified_local_alert_count}; "
            f"index={report.index_path}; publication_id={report.publication_id}"
        )
    if (
        report.dispatch.retryable_failure_count
        or report.dispatch.unknown_delivery_count
        or report.dispatch.attention_required_count
        or report.metrics.human_review_count
        or report.metrics.unresolved_count
    ):
        raise typer.Exit(code=1)


@pilot_app.command("review")
def pilot_review(
    run_id: Annotated[str, typer.Option("--run-id")],
    case_id: Annotated[str, typer.Option("--case-id")],
    decision: Annotated[VerdictDecision, typer.Option("--decision")],
    reason_file: Annotated[Path, typer.Option("--reason-file", dir_okay=False)],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = (
        DEFAULT_PILOT_CONFIG
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Apply one explicit human decision through the existing M5 appeal authority."""

    parsed = _load_config(config, "REVIEW", json_output)
    try:
        controlled_run_id = require_portable_run_id(run_id, "pilot run_id")
        controlled_case_id = require_reference_token(case_id, "pilot case_id")
        if reason_file.stat().st_size > 8_192:
            raise ValueError("pilot review reason file exceeds its input budget")
        reason = reason_file.read_text(encoding="utf-8").strip()
        runs_root = Path.cwd() / parsed.run.workspace
        database = runs_root / controlled_run_id / parsed.storage.database_filename
        report = review_pilot_case(
            config=parsed,
            runs_root=runs_root,
            database_path=database,
            run_id=controlled_run_id,
            case_id=controlled_case_id,
            decision=decision,
            reason=reason,
        )
    except PilotA4ReviewError as error:
        _pilot_boundary_error(json_output, "REVIEW", error.reason_code.value)
    except (LabCourtError, OSError, UnicodeError, TypeError, ValueError):
        _pilot_boundary_error(json_output, "REVIEW", "REVIEW_FAILED")
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
        return
    typer.echo(
        f"pilot review complete; status={report.resolution.status}; "
        f"decision={report.requested_decision}; appeal={report.resolution.appeal_id}; "
        f"index={report.index_path}; review_id={report.review_id}"
    )


@pilot_app.command("ui")
def pilot_ui(
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = (
        DEFAULT_PILOT_CONFIG
    ),
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8876,
    open_browser: Annotated[bool, typer.Option("--open/--no-open")] = True,
) -> None:
    """Open the loopback-only graphical pilot console."""

    _load_config(config, "UI", False)
    typer.echo(f"LabCourt pilot UI: http://127.0.0.1:{port}/")
    typer.echo("Press Ctrl+C to stop the local UI server.")
    try:
        run_pilot_ui_server(
            project_root=Path.cwd(),
            config_path=config,
            port=port,
            open_browser=open_browser,
        )
    except KeyboardInterrupt:
        typer.echo("LabCourt pilot UI stopped.")
    except (LabCourtError, OSError, TypeError, ValueError):
        _pilot_boundary_error(False, "UI", "UI_SERVER_FAILED")


def _validate_later_stage_boundary(
    *,
    operation: str,
    config_path: Path,
    run_id: str,
    case_id: str | None,
    json_output: bool,
) -> NoReturn:
    _load_config(config_path, operation, json_output)
    try:
        require_portable_run_id(run_id, "pilot run_id")
        if case_id is not None:
            require_reference_token(case_id, "pilot case_id")
    except (TypeError, ValueError):
        _pilot_boundary_error(json_output, operation, "REFERENCE_INVALID")
    _pilot_boundary_error(
        json_output,
        operation,
        PilotOperationsBoundaryCode.STAGE_NOT_AVAILABLE.value,
    )


def _pilot_boundary_error(json_output: bool, operation: str, reason_code: str) -> NoReturn:
    payload = {
        "operation": operation,
        "reason_code": reason_code,
        "status": "FAILED",
    }
    if json_output:
        typer.echo(canonical_json(payload), err=True)
    else:
        typer.echo(
            f"pilot {operation.lower()} failed: {reason_code}",
            err=True,
        )
    raise typer.Exit(code=2) from None
