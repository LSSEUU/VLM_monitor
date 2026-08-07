"""v0.2 pilot command group and A0 fail-closed preflight boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import VerdictDecision
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.exceptions import ContractViolation, LabCourtError
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


def _preflight(
    *,
    operation: str,
    config_path: Path,
    video_path: Path,
    run_id: str,
    resume: bool,
    json_output: bool,
) -> None:
    config = _load_config(config_path, operation, json_output)
    try:
        request = build_pilot_run_request(
            config=config,
            run_id=run_id,
            video_path=video_path,
            project_root=Path.cwd(),
            resume=resume,
        )
    except PilotOperationsBoundaryError as error:
        _pilot_boundary_error(json_output, operation, error.code.value)
    except (OSError, TypeError, ValueError):
        _pilot_boundary_error(json_output, operation, "PREFLIGHT_BOUNDARY_ERROR")

    if json_output:
        typer.echo(canonical_json(request.model_dump(mode="json")))
        return
    typer.echo(
        f"pilot {operation.lower()} preflight ready; run={request.run_id}; "
        f"video_sha256={request.video_sha256}; cases<={request.max_cases}; "
        "no detector or VLM was called"
    )


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
    """Validate and bind a local MP4 for the staged pilot (A0 preflight)."""

    _preflight(
        operation="RUN",
        config_path=config,
        video_path=video,
        run_id=run_id,
        resume=resume,
        json_output=json_output,
    )


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


@pilot_app.command("report")
def pilot_report(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = (
        DEFAULT_PILOT_CONFIG
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Publish an existing pilot run after reporting is enabled in A4."""

    _validate_later_stage_boundary(
        operation="REPORT",
        config_path=config,
        run_id=run_id,
        case_id=None,
        json_output=json_output,
    )


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
    """Apply a human review through existing M5 authority after A4 is enabled."""

    del decision, reason_file
    _validate_later_stage_boundary(
        operation="REVIEW",
        config_path=config,
        run_id=run_id,
        case_id=case_id,
        json_output=json_output,
    )


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
