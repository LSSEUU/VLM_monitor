from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from labcourt.adapters.m5_precedent_jsonl import (
    MAX_M5_IMPORT_ENTRIES,
    MAX_M5_IMPORT_FILE_BYTES,
    MAX_M5_IMPORT_LINE_BYTES,
)
from labcourt.cli import app
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import EvidenceClass, VerdictDecision, ViolationType
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m5_sqlite_alert_repository import _prepare_ready_case
from tests.integration.test_m5_sqlite_precedents import (
    _authority as _preset_authority,
)
from tests.integration.test_m5_sqlite_precedents import _install as _install_precedent_run

ROOT = Path(__file__).parents[2]


def test_m5_cli_finalizes_dispatches_and_replays_offline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "runs"
    workspace.mkdir()
    _prepare_ready_case(workspace)
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    config = str(ROOT / "configs/demo.yaml")

    finalized = runner.invoke(
        app,
        ["finalize", "--run-id", RUN_ID, "--config", config, "--json"],
    )
    assert finalized.exit_code == 0, finalized.output
    finalized_report = json.loads(finalized.stdout)
    assert finalized_report["selected_count"] == 1
    assert len(finalized_report["outcomes"]) == 1

    dispatched = runner.invoke(
        app,
        [
            "alert",
            "dispatch",
            "--run-id",
            RUN_ID,
            "--config",
            config,
            "--json",
        ],
    )
    assert dispatched.exit_code == 0, dispatched.output
    dispatch_report = json.loads(dispatched.stdout)
    assert dispatch_report["selected_count"] == 1
    assert dispatch_report["succeeded_count"] == 1

    repeated = runner.invoke(
        app,
        ["finalize", "--run-id", RUN_ID, "--config", config, "--json"],
    )
    repeated_dispatch = runner.invoke(
        app,
        [
            "alert",
            "dispatch",
            "--run-id",
            RUN_ID,
            "--config",
            config,
            "--json",
        ],
    )
    assert repeated.exit_code == 0
    assert json.loads(repeated.stdout)["selected_count"] == 0
    assert repeated_dispatch.exit_code == 0
    assert json.loads(repeated_dispatch.stdout)["selected_count"] == 0


def test_m5_cli_returns_typed_json_error_without_exposing_the_database_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "runs").mkdir()
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "finalize",
            "--run-id",
            "missing-run",
            "--config",
            str(ROOT / "configs/demo.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "M5_OPERATION_BOUNDARY_ERROR"
    assert "labcourt.sqlite3" not in result.output


def test_m5_precedent_cli_imports_reconciles_and_rejects_ambiguous_jsonl(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "runs"
    workspace.mkdir()
    _, _, manifest = _install_precedent_run(workspace)
    established = _preset_authority(
        manifest,
        "precedent-established",
        direction=VerdictDecision.ESTABLISHED,
    )
    rejected = _preset_authority(
        manifest,
        "precedent-rejected",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    unrelated = _preset_authority(
        manifest,
        "precedent-unrelated",
        evidence_class=EvidenceClass.ABSENCE,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
    )
    source = tmp_path / "precedents.jsonl"
    source.write_text(
        "\n".join(
            canonical_json(item.model_dump(mode="json"))
            for item in (rejected, unrelated, established)
        )
        + "\n",
        encoding="utf-8",
    )
    ambiguous = tmp_path / "ambiguous.jsonl"
    ambiguous.write_bytes(b'{"run_id":"one","run_id":"two"}\n')
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    config = str(ROOT / "configs/demo.yaml")

    imported = runner.invoke(
        app,
        [
            "precedent",
            "import",
            str(source),
            "--run-id",
            RUN_ID,
            "--config",
            config,
            "--json",
        ],
    )
    assert imported.exit_code == 0, imported.output
    assert json.loads(imported.stdout)["accepted_count"] == 3

    incomplete_budget = runner.invoke(
        app,
        [
            "precedent",
            "conflicts",
            "--run-id",
            RUN_ID,
            "--config",
            config,
            "--limit",
            "2",
            "--json",
        ],
    )
    assert incomplete_budget.exit_code == 2
    assert json.loads(incomplete_budget.stdout) == {
        "error": "M5_OPERATION_BOUNDARY_ERROR",
        "operation": "precedent-conflicts",
        "reason_code": "REPOSITORY_BOUNDARY_ERROR",
    }

    conflicts = runner.invoke(
        app,
        [
            "precedent",
            "conflicts",
            "--run-id",
            RUN_ID,
            "--config",
            config,
            "--json",
        ],
    )
    assert conflicts.exit_code == 0, conflicts.output
    report = json.loads(conflicts.stdout)
    assert len(report["applied_receipts"]) == 1
    assert report["current_conflict_precedent_ids"] == [
        "precedent-established",
        "precedent-rejected",
    ]

    human_conflicts = runner.invoke(
        app,
        [
            "precedent",
            "conflicts",
            "--run-id",
            RUN_ID,
            "--config",
            config,
        ],
    )
    assert human_conflicts.exit_code == 0, human_conflicts.output
    human_fields = dict(
        field.split("=", maxsplit=1) for field in human_conflicts.stdout.strip().split("; ")
    )
    assert len(human_fields["cut"]) == 64
    assert len(human_fields["batch"]) == 64
    assert len(human_fields["receipt"]) == 64

    rejected_input = runner.invoke(
        app,
        [
            "precedent",
            "import",
            str(ambiguous),
            "--run-id",
            RUN_ID,
            "--config",
            config,
            "--json",
        ],
    )
    assert rejected_input.exit_code == 2
    error = json.loads(rejected_input.stdout)
    assert error["reason_code"] == "JSON_INVALID"


def test_m5_precedent_conflict_limit_help_defines_a_complete_snapshot_budget() -> None:
    result = CliRunner().invoke(app, ["precedent", "conflicts", "--help"])

    assert result.exit_code == 0, result.output
    help_text = result.output.lower()
    assert "complete active-candidate" in help_text
    assert "snapshot budget" in help_text


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--max-file-bytes", MAX_M5_IMPORT_FILE_BYTES + 1),
        ("--max-line-bytes", MAX_M5_IMPORT_LINE_BYTES + 1),
        ("--max-entries", MAX_M5_IMPORT_ENTRIES + 1),
    ],
)
def test_m5_precedent_import_cli_rejects_budget_expansion(
    tmp_path: Path,
    option: str,
    value: int,
) -> None:
    source = tmp_path / "precedents.jsonl"
    source.write_text("", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "precedent",
            "import",
            str(source),
            "--run-id",
            RUN_ID,
            option,
            str(value),
        ],
    )

    assert result.exit_code == 2
    assert "invalid value" in result.output.lower()
