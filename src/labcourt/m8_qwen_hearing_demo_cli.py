"""CLI for the local synthetic M8 Qwen hearing demonstration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from labcourt.contracts.canonical import canonical_json
from labcourt.exceptions import LabCourtError
from labcourt.services.m8_qwen_hearing_demo import (
    prepare_m8_qwen_hearing_demo,
    run_m8_qwen_hearing_demo,
    serve_m8_qwen_hearing_demo_results,
)

qwen_demo_app = typer.Typer(
    help="Prepare and run one explicit synthetic M8 hearing with real Qwen roles."
)


def _fail(reason_code: str) -> NoReturn:
    typer.echo(
        canonical_json(
            {
                "error": "M8_QWEN_HEARING_DEMO_FAILED",
                "reason_code": reason_code,
            }
        ),
        err=True,
    )
    raise typer.Exit(code=2)


@qwen_demo_app.command("prepare")
def prepare_command(
    output: Annotated[
        Path,
        typer.Option("--output", help="Ignored local demo output directory."),
    ] = Path(".labcourt-local/m8-qwen-hearing-demo"),
    primary_image: Annotated[Path | None, typer.Option("--primary-image")] = None,
    supplementary_image: Annotated[Path | None, typer.Option("--supplementary-image")] = None,
    base_config: Annotated[Path, typer.Option("--base-config")] = Path("configs/demo.yaml"),
) -> None:
    primary = primary_image or output / "source" / "primary.png"
    supplementary = supplementary_image or output / "source" / "supplementary.png"
    try:
        receipt = prepare_m8_qwen_hearing_demo(
            output_root=output.absolute(),
            primary_image=primary.absolute(),
            supplementary_image=supplementary.absolute(),
            base_config_path=base_config.absolute(),
        )
    except (AttributeError, LabCourtError, OSError, TypeError, ValueError, RuntimeError):
        _fail("PREPARATION_BOUNDARY_FAILURE")
    typer.echo(canonical_json(receipt.model_dump(mode="json")))


@qwen_demo_app.command("run")
def run_command(
    output: Annotated[
        Path,
        typer.Option("--output", help="Prepared ignored local demo output directory."),
    ] = Path(".labcourt-local/m8-qwen-hearing-demo"),
    port: Annotated[int, typer.Option("--port", min=0, max=65535)] = 0,
    confirmed: Annotated[
        bool,
        typer.Option(
            "--confirmed",
            help="Explicitly authorize this prepared run's single provider-backed POST.",
        ),
    ] = False,
) -> None:
    if not confirmed:
        _fail("EXPLICIT_CONFIRMATION_REQUIRED")
    try:
        receipt = run_m8_qwen_hearing_demo(
            output_root=output.absolute(),
            environment=os.environ,
            port=port,
        )
    except (LabCourtError, OSError, TypeError, ValueError, RuntimeError):
        _fail("EXECUTION_BOUNDARY_FAILURE")
    typer.echo(canonical_json(receipt.model_dump(mode="json")))
    if receipt.outcome.value != "COMPLETED":
        raise typer.Exit(code=1)


@qwen_demo_app.command("serve-results")
def serve_results_command(
    output: Annotated[
        Path,
        typer.Option("--output", help="Prepared ignored local demo output directory."),
    ] = Path(".labcourt-local/m8-qwen-hearing-demo"),
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8878,
) -> None:
    try:
        serve_m8_qwen_hearing_demo_results(output_root=output.absolute(), port=port)
    except (LabCourtError, OSError, TypeError, ValueError, RuntimeError):
        _fail("RESULT_SERVER_BOUNDARY_FAILURE")


def register_m8_qwen_hearing_demo_commands(hearing: typer.Typer) -> None:
    hearing.add_typer(qwen_demo_app, name="qwen-demo")


__all__ = ["qwen_demo_app", "register_m8_qwen_hearing_demo_commands"]
