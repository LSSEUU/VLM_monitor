from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.cli import app
from labcourt.contracts.m8_access_cases import M8OperationalCaseStatus

RUNNER = CliRunner()
BUSY_TIMEOUT_MS = 5_000


def test_bootstrap_is_idempotent_and_persists_pending_case_projection(tmp_path: Path) -> None:
    database = tmp_path / "demo" / "labcourt.sqlite3"

    first = bootstrap_m8_personal_demo(database)
    replay = bootstrap_m8_personal_demo(database)

    assert replay == first
    assert first.receipt.case_status == M8OperationalCaseStatus.PENDING_VERIFICATION
    assert first.projection.overview.location_count == 4
    assert first.projection.overview.observed_sensor_count == 1
    assert first.projection.overview.pending_verification_case_count == 1
    repository = SQLiteM8OperationsRepository(
        database,
        BUSY_TIMEOUT_MS,
        first.projection.topology_receipt.repository_manifest_id,
    )
    case = repository.get_current_operational_case(first.receipt.case_id)
    assert case.status == M8OperationalCaseStatus.PENDING_VERIFICATION
    assert len(repository.list_operational_case_audit(first.receipt.case_id)) == 1


def test_bootstrap_cli_writes_replayable_local_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "local-demo"

    result = RUNNER.invoke(app, ["demo", "bootstrap", "--output", str(output), "--json"])
    replay = RUNNER.invoke(app, ["demo", "bootstrap", "--output", str(output), "--json"])

    assert result.exit_code == 0
    assert replay.exit_code == 0
    assert json.loads(result.stdout) == json.loads(replay.stdout)
    summary = json.loads(result.stdout)
    assert summary["case_status"] == "PENDING_VERIFICATION"
    assert summary["risk_level"] == "EMERGENCY"
    assert summary["simulated"] is True
    assert (output / "labcourt.sqlite3").is_file()
    assert (output / "bootstrap-receipt.json").is_file()
    assert (output / "operations-projection.json").is_file()
