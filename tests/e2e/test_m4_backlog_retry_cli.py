"""True CLI coverage for the production SQLite HEARING backlog worker."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.enums import BacklogStatus, CaseStatus, VlmRole
from labcourt.contracts.m4_operations import (
    M4BacklogRetryCommandReport,
    M4BacklogRetryDisposition,
    M4FakeVLMFixtureBundle,
    M4ProcessCommandReport,
)
from tests.e2e.test_m4_operations_cli import _args, _escalate, _m4_bundle
from tests.integration.test_m3_operations_service import (
    ROOT,
    RUN_ID,
    _setup_ready_runtime,
)

RUNNER = CliRunner()


def _backlog_args(
    fixture: Path,
    *,
    run_id: str = RUN_ID,
    worker_id: str = "m4-backlog-worker",
) -> list[str]:
    return [
        "hearing",
        "backlog",
        "retry",
        "--run-id",
        run_id,
        "--worker-id",
        worker_id,
        "--fixture-bundle",
        str(fixture),
        "--config",
        str(ROOT / "configs" / "demo.yaml"),
        "--json",
    ]


def _seed_backlogged_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    seeded = _setup_ready_runtime(tmp_path)
    workspace = tmp_path / "runs"
    seeded.workspace_root.rename(workspace)
    runtime = replace(
        seeded,
        workspace_root=workspace,
        database=workspace / seeded.config.storage.database_filename,
    )
    monkeypatch.chdir(tmp_path)
    _escalate(runtime, tmp_path)
    success_fixture = _m4_bundle(runtime, tmp_path)
    empty_bundle = M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(),
    )
    outage_fixture = tmp_path / "m4-provider-missing.json"
    outage_fixture.write_text(empty_bundle.model_dump_json(), encoding="utf-8")
    seeded_backlog = RUNNER.invoke(app, _args(runtime, outage_fixture))
    assert seeded_backlog.exit_code == 0, seeded_backlog.output
    seeded_report = M4ProcessCommandReport.model_validate_json(seeded_backlog.stdout)
    assert seeded_report.authority_report.outcomes[0].status == CaseStatus.BACKLOGGED
    return runtime, outage_fixture, success_fixture


def _authority_counts(database: Path) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        tables = (
            "backlog_item_versions",
            "m4_hearing_backlog_retry_outcomes",
            "m4_backlog_completion_receipts",
            "m4_model_call_claims",
            "m4_model_responses",
            "m4_parsed_hearing_outputs",
            "case_versions",
            "audit_entries",
        )
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        )


def test_hearing_backlog_retry_completes_exact_role_then_replays_as_no_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _outage_fixture, success_fixture = _seed_backlogged_runtime(
        tmp_path,
        monkeypatch,
    )

    completed = RUNNER.invoke(app, _backlog_args(success_fixture))

    assert completed.exit_code == 0, completed.output
    report = M4BacklogRetryCommandReport.model_validate_json(completed.stdout)
    authority = report.authority_report
    assert authority.disposition == M4BacklogRetryDisposition.COMPLETED
    assert authority.role == VlmRole.PROSECUTOR
    assert authority.backlog_status == BacklogStatus.COMPLETED
    assert authority.resulting_case_status == CaseStatus.DELIBERATING
    assert authority.resulting_retry_generation == 0
    assert authority.source_checkpoint_id != authority.resulting_checkpoint_id
    assert authority.human_review_receipt_id is None

    before_replay = _authority_counts(runtime.database)
    replay = RUNNER.invoke(app, _backlog_args(success_fixture))

    assert replay.exit_code == 0, replay.output
    replayed = M4BacklogRetryCommandReport.model_validate_json(replay.stdout)
    assert replayed.authority_report.disposition == M4BacklogRetryDisposition.NO_WORK
    assert _authority_counts(runtime.database) == before_replay

    unknown = RUNNER.invoke(
        app,
        _backlog_args(success_fixture, run_id="unknown-m4-backlog-run"),
    )
    assert unknown.exit_code == 2
    assert json.loads(unknown.stdout)["reason_code"] == "AUTHORITY_BOUNDARY_ERROR"
    assert _authority_counts(runtime.database) == before_replay


def test_hearing_backlog_retry_requeues_then_exhausts_without_generation_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, outage_fixture, _success_fixture = _seed_backlogged_runtime(
        tmp_path,
        monkeypatch,
    )

    reports: list[M4BacklogRetryCommandReport] = []
    for attempt in range(1, 4):
        result = RUNNER.invoke(
            app,
            _backlog_args(outage_fixture, worker_id=f"m4-outage-worker-{attempt}"),
        )
        assert result.exit_code == 0, result.output
        reports.append(M4BacklogRetryCommandReport.model_validate_json(result.stdout))

    assert [item.authority_report.disposition for item in reports] == [
        M4BacklogRetryDisposition.REQUEUED,
        M4BacklogRetryDisposition.REQUEUED,
        M4BacklogRetryDisposition.EXHAUSTED,
    ]
    assert [item.authority_report.lease.attempt_count for item in reports] == [1, 2, 3]  # type: ignore[union-attr]
    assert all(
        item.authority_report.role == VlmRole.PROSECUTOR
        and item.authority_report.resulting_retry_generation == 0
        for item in reports
    )
    exhausted = reports[-1].authority_report
    assert exhausted.backlog_status == BacklogStatus.EXHAUSTED
    assert exhausted.resulting_case_status == CaseStatus.HUMAN_REVIEW
    assert exhausted.human_review_receipt_id is not None
    assert exhausted.source_checkpoint_id == exhausted.resulting_checkpoint_id

    before_no_work = _authority_counts(runtime.database)
    no_work = RUNNER.invoke(app, _backlog_args(outage_fixture))
    assert no_work.exit_code == 0, no_work.output
    assert (
        M4BacklogRetryCommandReport.model_validate_json(no_work.stdout).authority_report.disposition
        == M4BacklogRetryDisposition.NO_WORK
    )
    assert _authority_counts(runtime.database) == before_no_work
