"""Offline M4 hearing command boundary with bounded fixture ingestion."""

from __future__ import annotations

import json
import math
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import ValidationError

from labcourt.adapters.storage.m4_json_projector import (
    MAX_M4_PROJECTION_BYTES,
    M4ProjectionFailure,
)
from labcourt.adapters.storage.readonly_sqlite import DEFAULT_MAX_DATABASE_BYTES
from labcourt.application.hearing_backlog_retry import (
    HearingBacklogRetryRecoveryRequired,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m3_operations import (
    MAX_FAKE_VLM_FIXTURE_ENTRIES,
    MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES,
    MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES,
)
from labcourt.contracts.m4_operations import (
    MAX_M4_FAKE_ACQUISITION_FIXTURE_ENTRIES,
    MAX_M4_FAKE_ACQUISITION_FIXTURE_FILE_BYTES,
    M4BacklogRetryCommandReport,
    M4FakeVLMFixtureBundle,
    M4ProcessCommandReport,
    M4ProjectionDisposition,
    M4ProjectionOutcome,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation, LabCourtError
from labcourt.services.m4_operations import (
    M4OperationsBoundaryError,
    open_m4_operations_service,
)
from labcourt.services.m4_projection import rebuild_m4_projection

DEFAULT_CONFIG = Path("configs/default.yaml")
_MAX_FIXTURE_FILE_BYTES = (
    MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES
    + MAX_M4_FAKE_ACQUISITION_FIXTURE_FILE_BYTES
    + (MAX_FAKE_VLM_FIXTURE_ENTRIES * 1024)
    + 4096
)
_MAX_FIXTURE_JSON_NUMBER_CHARS = 128
_MIN_FIXTURE_JSON_INTEGER = -(1 << 63)
_MAX_FIXTURE_JSON_INTEGER = (1 << 63) - 1
_MAX_FIXTURE_JSON_FLOAT_SIGNIFICANT_DIGITS = 64
_MAX_FIXTURE_JSON_FLOAT_EXPONENT_ABS = 308

hearing_app = typer.Typer(help="Bounded offline M4 adversarial-hearing operations.")
hearing_backlog_app = typer.Typer(help="Exact-role HEARING backlog workers.")
hearing_app.add_typer(hearing_backlog_app, name="backlog")


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


def _preflight_fixture_shape(authored: object) -> None:
    if not isinstance(authored, dict):
        raise _FixtureInputError("FIXTURE_CONTRACT_INVALID")
    fixtures = authored.get("fixtures")
    if not isinstance(fixtures, list):
        raise _FixtureInputError("FIXTURE_CONTRACT_INVALID")
    if len(fixtures) > MAX_FAKE_VLM_FIXTURE_ENTRIES:
        raise _FixtureInputError("FIXTURE_ENTRY_BUDGET_EXCEEDED")
    acquisition_fixtures = authored.get("acquisition_fixtures", [])
    if not isinstance(acquisition_fixtures, list):
        raise _FixtureInputError("FIXTURE_CONTRACT_INVALID")
    if len(acquisition_fixtures) > MAX_M4_FAKE_ACQUISITION_FIXTURE_ENTRIES:
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


def _load_fixture_bundle(path: Path) -> M4FakeVLMFixtureBundle:
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
        return M4FakeVLMFixtureBundle.model_validate(authored)
    except (TypeError, ValueError, ValidationError):
        raise _FixtureInputError("FIXTURE_CONTRACT_INVALID") from None


def register_m4_commands(root: typer.Typer) -> None:
    """Attach the nested M4 command tree to the public CLI."""

    root.add_typer(hearing_app, name="hearing")


def _prepare_command(
    *,
    operation: str,
    run_id: str,
    config_path: Path,
    fixture_path: Path,
    json_output: bool,
) -> tuple[str, AppConfig, M4FakeVLMFixtureBundle]:
    try:
        controlled_run_id = require_reference_token(run_id, "M4 operation run reference")
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
    return controlled_run_id, parsed, bundle


@hearing_app.command("recover-responses")
def recover_responses(
    run_id: Annotated[str, typer.Option("--run-id")],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=10_000),
    ] = 10_000,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Converge exact M4 response journals without a provider or parser."""

    from labcourt.adapters.storage.secure_workspace import SecureWorkspace
    from labcourt.adapters.storage.sqlite_authority import SQLiteAuthorityError
    from labcourt.adapters.storage.sqlite_repository import (
        MigrationIntegrityError,
        RepositoryIntegrityError,
        SQLiteEvidenceRepository,
    )
    from labcourt.application.hearing_model_response_recovery import (
        HearingModelCallRecoveryError,
    )
    from labcourt.contracts.hearing_recovery import (
        HearingModelResponseRecoveryDisposition,
    )
    from labcourt.exceptions import PathBoundaryViolation
    from labcourt.services.m4_maintenance_recovery import (
        build_m4_hearing_model_response_recovery,
    )

    try:
        controlled_run_id = require_reference_token(
            run_id,
            "M4 hearing response recovery run reference",
        )
    except (TypeError, ValueError):
        _response_recovery_boundary_error(json_output, "RUN_ID_INVALID")
    try:
        parsed = load_config(config)
    except (ContractViolation, OSError, TypeError, ValueError):
        _response_recovery_boundary_error(json_output, "CONFIG_INVALID")

    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    repository = SQLiteEvidenceRepository(
        database,
        parsed.storage.busy_timeout_ms,
    )
    try:
        repository.get_audit_head(controlled_run_id)
    except SQLiteAuthorityError as error:
        _response_recovery_boundary_error(json_output, error.reason_code)
    except (MigrationIntegrityError, RepositoryIntegrityError):
        _response_recovery_boundary_error(json_output, "DATABASE_INTEGRITY_ERROR")
    except ContractViolation:
        _response_recovery_boundary_error(json_output, "RUN_NOT_FOUND")
    except (sqlite3.Error, OSError, TypeError, ValueError):
        _response_recovery_boundary_error(json_output, "REPOSITORY_BOUNDARY_ERROR")

    try:
        with SecureWorkspace(
            workspace_root,
            max_file_bytes=parsed.storage.max_media_bytes,
        ) as workspace:
            report = build_m4_hearing_model_response_recovery(
                database_path=database,
                busy_timeout_ms=parsed.storage.busy_timeout_ms,
                workspace=workspace,
                limit=limit,
            ).recover(controlled_run_id, datetime.now(UTC))
    except SQLiteAuthorityError as error:
        _response_recovery_boundary_error(json_output, error.reason_code)
    except PathBoundaryViolation as error:
        _response_recovery_boundary_error(json_output, error.reason_code)
    except HearingModelCallRecoveryError as error:
        _response_recovery_boundary_error(json_output, error.code.value)
    except (LabCourtError, sqlite3.Error, OSError, TypeError, ValueError):
        _response_recovery_boundary_error(json_output, "RECOVERY_BOUNDARY_ERROR")

    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
    else:
        acknowledged = sum(
            item.disposition == HearingModelResponseRecoveryDisposition.ACKNOWLEDGED
            for item in report.items
        )
        verified = sum(
            item.disposition == HearingModelResponseRecoveryDisposition.VERIFIED
            for item in report.items
        )
        deferred = sum(
            item.disposition == HearingModelResponseRecoveryDisposition.DEFERRED
            for item in report.items
        )
        anomalies = sum(
            item.disposition == HearingModelResponseRecoveryDisposition.ANOMALY
            for item in report.items
        )
        typer.echo(
            "SIMULATED PERCEPTION / NO PROVIDER / RECOVERY ONLY | "
            f"hearing response recovery run={report.run_id}; "
            f"scanned={report.claims_scanned}; complete={report.scan_complete}; "
            f"acknowledged={acknowledged}; verified={verified}; "
            f"deferred={deferred}; anomalies={anomalies}; "
            f"attention={report.requires_attention}"
        )
    if not report.passed:
        raise typer.Exit(code=1)


@hearing_app.command("process")
def process(
    run_id: Annotated[str, typer.Option("--run-id")],
    case_id: Annotated[str, typer.Option("--case-id")],
    fixture_bundle: Annotated[
        Path,
        typer.Option("--fixture-bundle", dir_okay=False),
    ],
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    projection_max_database_bytes: Annotated[
        int,
        typer.Option("--projection-max-database-bytes", min=1, max=64 * 1024**3),
    ] = DEFAULT_MAX_DATABASE_BYTES,
    projection_max_bytes: Annotated[
        int,
        typer.Option("--projection-max-bytes", min=1, max=4 * 1024**3),
    ] = MAX_M4_PROJECTION_BYTES,
) -> None:
    """Advance one explicit Case using offline three-role fake authority."""

    controlled_run_id, parsed, bundle = _prepare_command(
        operation="HEARING_PROCESS",
        run_id=run_id,
        config_path=config,
        fixture_path=fixture_bundle,
        json_output=json_output,
    )
    try:
        controlled_case_id = require_reference_token(case_id, "M4 process case reference")
    except (TypeError, ValueError):
        _operation_boundary_error(json_output, "HEARING_PROCESS", "CASE_ID_INVALID")
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        with open_m4_operations_service(
            config=parsed,
            run_id=controlled_run_id,
            workspace_root=workspace_root,
            database_path=database,
            fixture_bundle=bundle,
        ) as service:
            authority_report = service.process_case(controlled_case_id)
    except M4OperationsBoundaryError as error:
        _operation_boundary_error(
            json_output,
            "HEARING_PROCESS",
            error.code.value,
        )
    except (ContractViolation, LabCourtError, sqlite3.Error, OSError, TypeError, ValueError):
        _operation_boundary_error(
            json_output,
            "HEARING_PROCESS",
            "AUTHORITY_BOUNDARY_ERROR",
        )

    projection = _rebuild_projection(
        run_id=controlled_run_id,
        database_path=database,
        workspace_root=workspace_root,
        max_database_bytes=projection_max_database_bytes,
        max_projection_bytes=projection_max_bytes,
    )
    report = M4ProcessCommandReport(
        run_id=controlled_run_id,
        authority_report=authority_report,
        projection=projection,
    )
    _emit_process(report, json_output)
    if projection.disposition == M4ProjectionDisposition.PENDING_REBUILD:
        raise typer.Exit(code=1)


@hearing_backlog_app.command("retry")
def backlog_retry(
    run_id: Annotated[str, typer.Option("--run-id")],
    worker_id: Annotated[str, typer.Option("--worker-id")],
    fixture_bundle: Annotated[
        Path,
        typer.Option("--fixture-bundle", dir_okay=False),
    ],
    lease_duration_seconds: Annotated[
        int | None,
        typer.Option("--lease-duration-seconds", min=1, max=14_400),
    ] = None,
    reclaim_limit: Annotated[
        int,
        typer.Option("--reclaim-limit", min=1, max=10_000),
    ] = 100,
    config: Annotated[Path, typer.Option("--config", "-c", dir_okay=False)] = DEFAULT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    projection_max_database_bytes: Annotated[
        int,
        typer.Option("--projection-max-database-bytes", min=1, max=64 * 1024**3),
    ] = DEFAULT_MAX_DATABASE_BYTES,
    projection_max_bytes: Annotated[
        int,
        typer.Option("--projection-max-bytes", min=1, max=4 * 1024**3),
    ] = MAX_M4_PROJECTION_BYTES,
) -> None:
    """Retry one exact HEARING lease through local SQLite authority."""

    controlled_run_id, parsed, bundle = _prepare_command(
        operation="HEARING_BACKLOG_RETRY",
        run_id=run_id,
        config_path=config,
        fixture_path=fixture_bundle,
        json_output=json_output,
    )
    try:
        controlled_worker_id = require_reference_token(
            worker_id,
            "M4 backlog worker reference",
        )
    except (TypeError, ValueError):
        _operation_boundary_error(
            json_output,
            "HEARING_BACKLOG_RETRY",
            "WORKER_ID_INVALID",
        )
    workspace_root = (Path.cwd() / Path(parsed.run.workspace)).absolute()
    database = workspace_root / parsed.storage.database_filename
    try:
        with open_m4_operations_service(
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
    except M4OperationsBoundaryError as error:
        _operation_boundary_error(
            json_output,
            "HEARING_BACKLOG_RETRY",
            error.code.value,
        )
    except HearingBacklogRetryRecoveryRequired as error:
        _operation_boundary_error(
            json_output,
            "HEARING_BACKLOG_RETRY",
            error.code.value,
        )
    except (ContractViolation, LabCourtError, sqlite3.Error, OSError, TypeError, ValueError):
        _operation_boundary_error(
            json_output,
            "HEARING_BACKLOG_RETRY",
            "AUTHORITY_BOUNDARY_ERROR",
        )

    projection = _rebuild_projection(
        run_id=controlled_run_id,
        database_path=database,
        workspace_root=workspace_root,
        max_database_bytes=projection_max_database_bytes,
        max_projection_bytes=projection_max_bytes,
    )
    report = M4BacklogRetryCommandReport(
        run_id=controlled_run_id,
        authority_report=authority_report,
        projection=projection,
    )
    _emit_backlog(report, json_output)
    if projection.disposition == M4ProjectionDisposition.PENDING_REBUILD:
        raise typer.Exit(code=1)


def _rebuild_projection(
    *,
    run_id: str,
    database_path: Path,
    workspace_root: Path,
    max_database_bytes: int,
    max_projection_bytes: int,
) -> M4ProjectionOutcome:
    try:
        result = rebuild_m4_projection(
            run_id=run_id,
            database_path=database_path,
            workspace_root=workspace_root,
            max_database_bytes=max_database_bytes,
            max_projection_bytes=max_projection_bytes,
        )
    except (M4ProjectionFailure, ContractViolation, sqlite3.Error, OSError, ValueError):
        return M4ProjectionOutcome(
            disposition=M4ProjectionDisposition.PENDING_REBUILD,
            reason_code="PROJECTION_REBUILD_FAILED",
        )
    return M4ProjectionOutcome(
        disposition=M4ProjectionDisposition.REBUILT,
        generation_id=result.generation_id,
    )


def _emit_process(report: M4ProcessCommandReport, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
        return
    reason = report.projection.reason_code or "NONE"
    typer.echo(
        "SIMULATED PERCEPTION / FAKE VLM / CONTROLLED FAKE | "
        f"hearing process run={report.run_id}; authority=COMPLETE; "
        f"projection={report.projection.disposition.value}; "
        f"projection_reason={reason}; "
        f"acquisition_fixtures={report.authority_report.acquisition_fixture_count}; "
        f"selected={report.authority_report.counts.selected_cases}; "
        f"processed={report.authority_report.counts.processed_cases}; "
        f"backlogged={report.authority_report.counts.deferred_to_backlog_cases}; "
        f"human={report.authority_report.counts.transferred_to_human_cases}"
    )


def _emit_backlog(report: M4BacklogRetryCommandReport, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_json(report.model_dump(mode="json")))
        return
    reason = report.projection.reason_code or "NONE"
    typer.echo(
        "SIMULATED PERCEPTION / FAKE VLM / CONTROLLED FAKE | "
        f"hearing backlog retry run={report.run_id}; authority=COMPLETE; "
        f"disposition={report.authority_report.disposition.value}; "
        f"acquisition_fixtures={report.authority_report.acquisition_fixture_count}; "
        f"projection={report.projection.disposition.value}; "
        f"projection_reason={reason}"
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
                    "error": "M4_OPERATION_BOUNDARY_ERROR",
                    "model_mode": "FAKE VLM",
                    "operation": operation,
                    "perception_mode": "SIMULATED PERCEPTION",
                    "precedent_mode": "CONTROLLED FAKE",
                    "reason_code": reason_code,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        typer.echo(
            "SIMULATED PERCEPTION / FAKE VLM / CONTROLLED FAKE | "
            f"{operation.lower()} boundary error: {reason_code}",
            err=True,
        )
    raise typer.Exit(code=2)


def _response_recovery_boundary_error(
    json_output: bool,
    reason_code: str,
) -> NoReturn:
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "error": "M4_HEARING_RESPONSE_RECOVERY_BOUNDARY_ERROR",
                    "model_mode": "NO PROVIDER",
                    "operation_mode": "RECOVERY ONLY",
                    "perception_mode": "SIMULATED PERCEPTION",
                    "reason_code": reason_code,
                    "recovered": False,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        typer.echo(
            "SIMULATED PERCEPTION / NO PROVIDER / RECOVERY ONLY | "
            f"hearing response recovery boundary error: {reason_code}",
            err=True,
        )
    raise typer.Exit(code=2)


__all__ = [
    "backlog_retry",
    "hearing_app",
    "hearing_backlog_app",
    "process",
    "recover_responses",
    "register_m4_commands",
]
