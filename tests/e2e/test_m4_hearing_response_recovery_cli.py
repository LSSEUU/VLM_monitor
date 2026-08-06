from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

import labcourt.application.hearing_role_call as hearing_role_call
from labcourt.adapters.acquisition_fake import DeterministicFakeHearingAcquisitionExecutor
from labcourt.adapters.storage.hearing_model_response_store import (
    SecureHearingModelResponseStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.vlm.hearing_fake import DeterministicFakeHearingVLMClient
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.cli import app
from labcourt.contracts.hearing import (
    HearingModelRequest,
    HearingModelResponse,
    HearingModelResponseRecoveryReport,
)
from labcourt.contracts.hearing_recovery import HearingModelResponseRecoveryReason
from tests.integration.test_m4_hearing_model_response_recovery_sqlite import (
    RAW,
    _database_counts,
    _setup,
)
from tests.integration.test_m4_sqlite_repository import RUN_ID

ROOT = Path(__file__).parents[2]
CONFIG = ROOT / "configs" / "demo.yaml"
RUNNER = CliRunner()


def _forbid_non_recovery_capabilities(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("provider/parser/tool/Case capability reached recovery-only CLI")


def _patch_forbidden_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        DeterministicFakeHearingVLMClient,
        "complete",
        _forbid_non_recovery_capabilities,
    )
    monkeypatch.setattr(
        hearing_role_call,
        "inspect_hearing_response",
        _forbid_non_recovery_capabilities,
    )
    monkeypatch.setattr(
        DeterministicFakeHearingAcquisitionExecutor,
        "execute",
        _forbid_non_recovery_capabilities,
    )
    monkeypatch.setattr(
        HearingCoordinator,
        "process_case",
        _forbid_non_recovery_capabilities,
    )


def _prepare_journal(
    tmp_path: Path,
) -> tuple[Path, Path, HearingModelRequest, HearingModelResponse]:
    runs, database, storage, request = _setup(tmp_path, workspace_name="runs")
    storage.claim_hearing_model_call(RUN_ID, request, "cli-recovery-owner-" + "r" * 44)
    with SecureWorkspace(runs, 256 * 1024) as secure:
        response = SecureHearingModelResponseStore(secure).publish(
            request,
            RAW,
            input_tokens=11,
            output_tokens=7,
            latency_ms=13,
        )
    return runs, database, request, response


def _command(*, run_id: str = RUN_ID, json_output: bool = True) -> list[str]:
    arguments = [
        "hearing",
        "recover-responses",
        "--run-id",
        run_id,
        "--config",
        str(CONFIG),
        "--limit",
        "10",
    ]
    if json_output:
        arguments.append("--json")
    return arguments


def _non_recovery_authority(database: Path) -> tuple[object, ...]:
    with sqlite3.connect(database) as connection:
        case = connection.execute(
            "SELECT status, current_revision FROM cases WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        counts = tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "audit_entries",
                "case_versions",
                "m4_hearing_checkpoints",
                "m4_model_parse_receipts",
                "m4_parsed_hearing_outputs",
                "m4_acquisition_requests",
                "m4_acquisition_execution_claims",
                "m4_acquisition_execution_publications",
            )
        )
    return (case, *counts)


def test_recover_responses_cli_converges_journal_without_other_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs, database, request, response = _prepare_journal(tmp_path)
    before = _non_recovery_authority(database)
    _patch_forbidden_capabilities(monkeypatch)
    monkeypatch.chdir(tmp_path)

    first = RUNNER.invoke(app, _command())

    assert first.exit_code == 0, first.output
    report = HearingModelResponseRecoveryReport.model_validate_json(first.stdout)
    assert report.passed
    assert report.items[0].reason_code == (HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED)
    assert _database_counts(database) == (1, 1, 1, 1)
    assert _non_recovery_authority(database) == before
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT output_tokens FROM m4_hearing_usage_receipts WHERE request_id = ?",
            (request.request_id,),
        ).fetchone() == (response.output_tokens,)
    journal = (
        runs / ".staging" / RUN_ID / f"hearing-model-request-{request.request_id}" / "receipt.json"
    )
    assert not journal.exists()
    assert (runs / response.raw_response_ref).is_file()

    repeated = RUNNER.invoke(app, _command(json_output=False))
    assert repeated.exit_code == 0, repeated.output
    assert "SIMULATED PERCEPTION / NO PROVIDER / RECOVERY ONLY" in repeated.stdout
    assert "verified=1" in repeated.stdout
    assert _database_counts(database) == (1, 1, 1, 1)
    assert _non_recovery_authority(database) == before


def test_recover_responses_cli_returns_one_for_tampered_raw_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs, database, _request, response = _prepare_journal(tmp_path)
    tampered = bytearray(RAW)
    tampered[-2] = ord("X")
    (runs / response.raw_response_ref).write_bytes(bytes(tampered))
    before = _non_recovery_authority(database)
    _patch_forbidden_capabilities(monkeypatch)
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, _command())

    assert result.exit_code == 1, result.output
    report = HearingModelResponseRecoveryReport.model_validate_json(result.stdout)
    assert report.requires_attention
    assert report.items[0].reason_code == (
        HearingModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE
    )
    assert _database_counts(database) == (0, 0, 0, 1)
    assert _non_recovery_authority(database) == before


@pytest.mark.parametrize(
    ("arguments", "reason_code"),
    [
        (
            [
                "hearing",
                "recover-responses",
                "--run-id",
                "../invalid",
                "--config",
                str(CONFIG),
                "--json",
            ],
            "RUN_ID_INVALID",
        ),
        (
            [
                "hearing",
                "recover-responses",
                "--run-id",
                RUN_ID,
                "--config",
                "missing-config.yaml",
                "--json",
            ],
            "CONFIG_INVALID",
        ),
    ],
)
def test_recover_responses_cli_boundary_errors_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    reason_code: str,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, arguments)

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["error"] == "M4_HEARING_RESPONSE_RECOVERY_BOUNDARY_ERROR"
    assert payload["reason_code"] == reason_code
    assert payload["model_mode"] == "NO PROVIDER"
    assert payload["operation_mode"] == "RECOVERY ONLY"


def test_recover_responses_cli_rejects_unknown_valid_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_journal(tmp_path)
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, _command(run_id="unknown-m4-run"))

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["reason_code"] == "RUN_NOT_FOUND"


def test_recover_responses_cli_rejects_limit_above_public_boundary() -> None:
    result = RUNNER.invoke(
        app,
        [
            "hearing",
            "recover-responses",
            "--run-id",
            RUN_ID,
            "--limit",
            "10001",
        ],
    )
    assert result.exit_code == 2
