"""Offline M3 process and one-item backlog command boundaries."""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import ValidationError

from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m3_command_reports import (
    M3BacklogRetryCommandReport,
    M3ProcessCommandReport,
    M3ProjectionBudget,
    M3ProjectionDisposition,
)
from labcourt.contracts.m3_operations import (
    MAX_FAKE_VLM_FIXTURE_ENTRIES,
    MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES,
    MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES,
    MAX_M3_PROCESS_CASES,
    FakeVLMFixtureBundle,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation, LabCourtError
from labcourt.services.m3_operations import (
    M3OperationsBoundaryError,
    open_m3_operations_service,
)
from labcourt.services.m3_projection import rebuild_m3_projection

DEFAULT_CONFIG = Path("configs/default.yaml")
_MAX_FIXTURE_FILE_BYTES = (
    MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES + (MAX_FAKE_VLM_FIXTURE_ENTRIES * 1024) + 4096
)
_MAX_FIXTURE_JSON_NUMBER_CHARS = 128
_MIN_FIXTURE_JSON_INTEGER = -(1 << 63)
_MAX_FIXTURE_JSON_INTEGER = (1 << 63) - 1
_MAX_FIXTURE_JSON_FLOAT_SIGNIFICANT_DIGITS = 64
_MAX_FIXTURE_JSON_FLOAT_EXPONENT_ABS = 308

_DEFAULT_PROJECTION_DATABASE_BYTES = 4 * 1024 * 1024 * 1024
_DEFAULT_PROJECTION_AUDIT_ENTRIES = 100_000
_DEFAULT_PROJECTION_CASES = 10_000
_DEFAULT_PROJECTION_PACKS = 50_000
_DEFAULT_PROJECTION_DOCUMENT_BYTES = 16 * 1024 * 1024
_DEFAULT_PROJECTION_FILE_BYTES = 64 * 1024 * 1024
_DEFAULT_PROJECTION_MATERIALIZATION_BYTES = 512 * 1024 * 1024

backlog_app = typer.Typer(help="Bounded retry workers for durable deferred work.")


class _FixtureInputError(ValueError):
    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _StrictFixtureJsonError(ValueError):
    pass


class _StrictFixtureUtf8Error(ValueError):
    pass


def _unique_fixture_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _StrictFixtureJsonError
        result[key] = value
    return result


def _reject_fixture_nonfinite(_value: str) -> object:
    raise _StrictFixtureJsonError


def _parse_fixture_integer(token: str) -> int:
    if len(token) > _MAX_FIXTURE_JSON_NUMBER_CHARS:
        raise _StrictFixtureJsonError
    digits = token.removeprefix("-")
    if len(digits) > 19:
        raise _StrictFixtureJsonError
    value = int(token)
    if not _MIN_FIXTURE_JSON_INTEGER <= value <= _MAX_FIXTURE_JSON_INTEGER:
        raise _StrictFixtureJsonError
    return value


def _parse_fixture_float(token: str) -> float:
    if len(token) > _MAX_FIXTURE_JSON_NUMBER_CHARS:
        raise _StrictFixtureJsonError
    unsigned = token.removeprefix("-")
    exponent_marker = "e" if "e" in unsigned else "E"
    if exponent_marker in unsigned:
        mantissa, exponent_text = unsigned.split(exponent_marker, maxsplit=1)
        exponent_digits = exponent_text.removeprefix("+").removeprefix("-")
        normalized_exponent = exponent_digits.lstrip("0") or "0"
        if len(normalized_exponent) > 3:
            raise _StrictFixtureJsonError
        exponent = int(exponent_text)
        if abs(exponent) > _MAX_FIXTURE_JSON_FLOAT_EXPONENT_ABS:
            raise _StrictFixtureJsonError
    else:
        mantissa = unsigned
    significant_digits = mantissa.replace(".", "").lstrip("0") or "0"
    if len(significant_digits) > _MAX_FIXTURE_JSON_FLOAT_SIGNIFICANT_DIGITS:
        raise _StrictFixtureJsonError
    value = float(token)
    if not math.isfinite(value):
        raise _StrictFixtureJsonError
    return value


def _load_strict_fixture_json(text: str) -> object:
    if "\x00" in text or text.startswith("\ufeff"):
        raise _StrictFixtureJsonError
    root = json.loads(
        text,
        object_pairs_hook=_unique_fixture_object,
        parse_constant=_reject_fixture_nonfinite,
        parse_int=_parse_fixture_integer,
        parse_float=_parse_fixture_float,
    )
    pending: list[object] = [root]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            if "\x00" in value or "\ufeff" in value:
                raise _StrictFixtureJsonError
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise _StrictFixtureUtf8Error from None
    return root


def register_m3_commands(root: typer.Typer) -> None:
    """Attach M3 commands without making the M0 CLI own their composition."""

    root.command("process")(process)
    root.add_typer(backlog_app, name="backlog")


def process(
    run_id: Annotated[str, typer.Option("--run-id")],
    case_id: Annotated[str | None, typer.Option("--case-id")] = None,
    max_cases: Annotated[
        int,
        typer.Option("--max-cases", min=1, max=MAX_M3_PROCESS_CASES),
    ] = 100,
    fixture_bundle: Annotated[
        Path | None,
        typer.Option("--fixture-bundle", dir_okay=False),
    ] = None,
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    projection_max_database_bytes: Annotated[
        int,
        typer.Option("--projection-max-database-bytes", min=1, max=64 * 1024**3),
    ] = _DEFAULT_PROJECTION_DATABASE_BYTES,
    projection_max_audit_entries: Annotated[
        int,
        typer.Option("--projection-max-audit-entries", min=1, max=1_000_000),
    ] = _DEFAULT_PROJECTION_AUDIT_ENTRIES,
    projection_max_cases: Annotated[
        int,
        typer.Option("--projection-max-cases", min=1, max=1_000_000),
    ] = _DEFAULT_PROJECTION_CASES,
    projection_max_packs: Annotated[
        int,
        typer.Option("--projection-max-packs", min=1, max=5_000_000),
    ] = _DEFAULT_PROJECTION_PACKS,
    projection_max_document_bytes: Annotated[
        int,
        typer.Option("--projection-max-document-bytes", min=1, max=1024**3),
    ] = _DEFAULT_PROJECTION_DOCUMENT_BYTES,
    projection_max_file_bytes: Annotated[
        int,
        typer.Option("--projection-max-file-bytes", min=1, max=64 * 1024**3),
    ] = _DEFAULT_PROJECTION_FILE_BYTES,
    projection_max_materialization_bytes: Annotated[
        int,
        typer.Option(
            "--projection-max-materialization-bytes",
            min=1,
            max=64 * 1024**3,
        ),
    ] = _DEFAULT_PROJECTION_MATERIALIZATION_BYTES,
) -> None:
    """Advance a bounded M3 case selection using the offline fake VLM."""

    controlled_run_id, parsed, bundle, projection_budget = _prepare_command(
        operation="PROCESS",
        run_id=run_id,
        config_path=config,
        fixture_path=fixture_bundle,
        json_output=json_output,
        projection_max_database_bytes=projection_max_database_bytes,
        projection_max_audit_entries=projection_max_audit_entries,
        projection_max_cases=projection_max_cases,
        projection_max_packs=projection_max_packs,
        projection_max_document_bytes=projection_max_document_bytes,
        projection_max_file_bytes=projection_max_file_bytes,
        projection_max_materialization_bytes=projection_max_materialization_bytes,
    )
    try:
        controlled_case_id = (
            None
            if case_id is None
            else require_reference_token(case_id, "M3 process case reference")
        )
    except (TypeError, ValueError):
        _operation_boundary_error(json_output, "PROCESS", "CASE_ID_INVALID")

    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        with open_m3_operations_service(
            config=parsed,
            run_id=controlled_run_id,
            workspace_root=workspace_root,
            database_path=database,
            fixture_bundle=bundle,
        ) as service:
            authority_report = service.process_run(
                case_id=controlled_case_id,
                max_cases=max_cases,
            )
    except M3OperationsBoundaryError as error:
        _operation_boundary_error(json_output, "PROCESS", error.code.value)
    except (ContractViolation, LabCourtError, sqlite3.Error, OSError, TypeError, ValueError):
        _operation_boundary_error(json_output, "PROCESS", "AUTHORITY_BOUNDARY_ERROR")

    projection = rebuild_m3_projection(
        config=parsed,
        run_id=controlled_run_id,
        workspace_root=workspace_root,
        database_path=database,
        budget=projection_budget,
    )
    envelope = M3ProcessCommandReport(
        run_id=controlled_run_id,
        authority_report=authority_report,
        projection=projection,
    )
    _emit_process(envelope, json_output)
    if projection.disposition == M3ProjectionDisposition.PENDING_REBUILD:
        raise typer.Exit(code=1)


@backlog_app.command("retry")
def backlog_retry(
    run_id: Annotated[str, typer.Option("--run-id")],
    worker_id: Annotated[str, typer.Option("--worker-id")],
    lease_duration_seconds: Annotated[
        int | None,
        typer.Option("--lease-duration-seconds", min=1, max=14_400),
    ] = None,
    reclaim_limit: Annotated[
        int,
        typer.Option("--reclaim-limit", min=1, max=10_000),
    ] = 100,
    fixture_bundle: Annotated[
        Path | None,
        typer.Option("--fixture-bundle", dir_okay=False),
    ] = None,
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    projection_max_database_bytes: Annotated[
        int,
        typer.Option("--projection-max-database-bytes", min=1, max=64 * 1024**3),
    ] = _DEFAULT_PROJECTION_DATABASE_BYTES,
    projection_max_audit_entries: Annotated[
        int,
        typer.Option("--projection-max-audit-entries", min=1, max=1_000_000),
    ] = _DEFAULT_PROJECTION_AUDIT_ENTRIES,
    projection_max_cases: Annotated[
        int,
        typer.Option("--projection-max-cases", min=1, max=1_000_000),
    ] = _DEFAULT_PROJECTION_CASES,
    projection_max_packs: Annotated[
        int,
        typer.Option("--projection-max-packs", min=1, max=5_000_000),
    ] = _DEFAULT_PROJECTION_PACKS,
    projection_max_document_bytes: Annotated[
        int,
        typer.Option("--projection-max-document-bytes", min=1, max=1024**3),
    ] = _DEFAULT_PROJECTION_DOCUMENT_BYTES,
    projection_max_file_bytes: Annotated[
        int,
        typer.Option("--projection-max-file-bytes", min=1, max=64 * 1024**3),
    ] = _DEFAULT_PROJECTION_FILE_BYTES,
    projection_max_materialization_bytes: Annotated[
        int,
        typer.Option(
            "--projection-max-materialization-bytes",
            min=1,
            max=64 * 1024**3,
        ),
    ] = _DEFAULT_PROJECTION_MATERIALIZATION_BYTES,
) -> None:
    """Reclaim expired leases and retry at most one SCREENING item."""

    controlled_run_id, parsed, bundle, projection_budget = _prepare_command(
        operation="BACKLOG_RETRY",
        run_id=run_id,
        config_path=config,
        fixture_path=fixture_bundle,
        json_output=json_output,
        projection_max_database_bytes=projection_max_database_bytes,
        projection_max_audit_entries=projection_max_audit_entries,
        projection_max_cases=projection_max_cases,
        projection_max_packs=projection_max_packs,
        projection_max_document_bytes=projection_max_document_bytes,
        projection_max_file_bytes=projection_max_file_bytes,
        projection_max_materialization_bytes=projection_max_materialization_bytes,
    )
    try:
        controlled_worker_id = require_reference_token(
            worker_id,
            "M3 backlog worker reference",
        )
    except (TypeError, ValueError):
        _operation_boundary_error(json_output, "BACKLOG_RETRY", "WORKER_ID_INVALID")

    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        with open_m3_operations_service(
            config=parsed,
            run_id=controlled_run_id,
            workspace_root=workspace_root,
            database_path=database,
            fixture_bundle=bundle,
        ) as service:
            authority_report = service.backlog_retry_run_once(
                worker_id=controlled_worker_id,
                lease_duration_seconds=lease_duration_seconds,
                reclaim_limit=reclaim_limit,
            )
    except M3OperationsBoundaryError as error:
        _operation_boundary_error(json_output, "BACKLOG_RETRY", error.code.value)
    except (ContractViolation, LabCourtError, sqlite3.Error, OSError, TypeError, ValueError):
        _operation_boundary_error(json_output, "BACKLOG_RETRY", "AUTHORITY_BOUNDARY_ERROR")

    projection = rebuild_m3_projection(
        config=parsed,
        run_id=controlled_run_id,
        workspace_root=workspace_root,
        database_path=database,
        budget=projection_budget,
    )
    envelope = M3BacklogRetryCommandReport(
        run_id=controlled_run_id,
        authority_report=authority_report,
        projection=projection,
    )
    _emit_backlog(envelope, json_output)
    if projection.disposition == M3ProjectionDisposition.PENDING_REBUILD:
        raise typer.Exit(code=1)


def _prepare_command(
    *,
    operation: str,
    run_id: str,
    config_path: Path,
    fixture_path: Path | None,
    json_output: bool,
    projection_max_database_bytes: int,
    projection_max_audit_entries: int,
    projection_max_cases: int,
    projection_max_packs: int,
    projection_max_document_bytes: int,
    projection_max_file_bytes: int,
    projection_max_materialization_bytes: int,
) -> tuple[str, AppConfig, FakeVLMFixtureBundle, M3ProjectionBudget]:
    try:
        controlled_run_id = require_reference_token(run_id, "M3 operation run reference")
    except (TypeError, ValueError):
        _operation_boundary_error(json_output, operation, "RUN_ID_INVALID")
    try:
        parsed = load_config(config_path)
    except (ContractViolation, OSError, TypeError, ValueError):
        _operation_boundary_error(json_output, operation, "CONFIG_INVALID")
    try:
        bundle = _load_fixture_bundle(fixture_path)
    except _FixtureInputError as error:
        _operation_boundary_error(json_output, operation, error.reason_code)
    try:
        projection_budget = M3ProjectionBudget(
            max_database_bytes=projection_max_database_bytes,
            max_audit_entries=projection_max_audit_entries,
            max_cases=projection_max_cases,
            max_packs=projection_max_packs,
            max_document_bytes=projection_max_document_bytes,
            max_projection_file_bytes=projection_max_file_bytes,
            max_materialization_bytes=projection_max_materialization_bytes,
        )
    except (TypeError, ValueError, ValidationError):
        _operation_boundary_error(json_output, operation, "PROJECTION_BUDGET_INVALID")
    return controlled_run_id, parsed, bundle, projection_budget


def _load_fixture_bundle(path: Path | None) -> FakeVLMFixtureBundle:
    if path is None:
        return FakeVLMFixtureBundle(
            schema_version="m3-fake-vlm-fixture-bundle-v1",
            fixtures=(),
        )
    try:
        with path.open("rb") as source:
            payload = source.read(_MAX_FIXTURE_FILE_BYTES + 1)
    except OSError:
        raise _FixtureInputError("FIXTURE_FILE_UNAVAILABLE") from None
    if len(payload) > _MAX_FIXTURE_FILE_BYTES:
        raise _FixtureInputError("FIXTURE_FILE_BYTES_BUDGET_EXCEEDED")
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise _FixtureInputError("FIXTURE_UTF8_INVALID") from None
    try:
        authored = _load_strict_fixture_json(decoded)
    except _StrictFixtureUtf8Error:
        raise _FixtureInputError("FIXTURE_UTF8_INVALID") from None
    except (ValueError, OverflowError, RecursionError):
        raise _FixtureInputError("FIXTURE_JSON_INVALID") from None
    _preflight_fixture_shape(authored)
    try:
        return FakeVLMFixtureBundle.model_validate(authored)
    except (TypeError, ValueError, ValidationError):
        raise _FixtureInputError("FIXTURE_CONTRACT_INVALID") from None


def _preflight_fixture_shape(authored: object) -> None:
    if not isinstance(authored, dict):
        raise _FixtureInputError("FIXTURE_CONTRACT_INVALID")
    fixtures = authored.get("fixtures")
    if not isinstance(fixtures, list):
        raise _FixtureInputError("FIXTURE_CONTRACT_INVALID")
    if len(fixtures) > MAX_FAKE_VLM_FIXTURE_ENTRIES:
        raise _FixtureInputError("FIXTURE_ENTRY_BUDGET_EXCEEDED")
    total_response_bytes = 0
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            continue
        response = fixture.get("raw_response_utf8")
        if not isinstance(response, str):
            continue
        try:
            response_bytes = len(response.encode("utf-8"))
        except UnicodeEncodeError:
            raise _FixtureInputError("FIXTURE_UTF8_INVALID") from None
        if response_bytes > MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES:
            raise _FixtureInputError("FIXTURE_RESPONSE_BYTES_BUDGET_EXCEEDED")
        total_response_bytes += response_bytes
        if total_response_bytes > MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES:
            raise _FixtureInputError("FIXTURE_RESPONSE_BYTES_BUDGET_EXCEEDED")


def _emit_process(report: M3ProcessCommandReport, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
        return
    reason = report.projection.reason_code
    typer.echo(
        "SIMULATED PERCEPTION / FAKE VLM | "
        f"process run={report.run_id}; authority=COMPLETE; "
        f"projection={report.projection.disposition.value}; "
        f"projection_reason={reason.value if reason is not None else 'NONE'}; "
        f"selected={report.authority_report.counts.selected_cases}; "
        f"processed={report.authority_report.counts.processed_cases}; "
        f"backlogged={report.authority_report.counts.deferred_to_backlog_cases}"
    )


def _emit_backlog(report: M3BacklogRetryCommandReport, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
        return
    reason = report.projection.reason_code
    typer.echo(
        "SIMULATED PERCEPTION / FAKE VLM | "
        f"backlog retry run={report.run_id}; authority=COMPLETE; "
        f"disposition={report.authority_report.disposition.value}; "
        f"reclaimed={report.authority_report.reclaimed_expired_count}; "
        f"reclaimed_exhausted={report.authority_report.reclaimed_exhausted_count}; "
        f"projection={report.projection.disposition.value}; "
        f"projection_reason={reason.value if reason is not None else 'NONE'}"
    )


def _operation_boundary_error(
    json_output: bool,
    operation: str,
    reason_code: str,
) -> NoReturn:
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "authority_complete": False,
                    "error": "M3_OPERATION_BOUNDARY_ERROR",
                    "model_mode": "FAKE VLM",
                    "operation": operation,
                    "perception_mode": "SIMULATED PERCEPTION",
                    "reason_code": reason_code,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        typer.echo(
            f"SIMULATED PERCEPTION / FAKE VLM | {operation.lower()} boundary error: {reason_code}",
            err=True,
        )
    raise typer.Exit(code=2)


__all__ = ["backlog_app", "backlog_retry", "process", "register_m3_commands"]
