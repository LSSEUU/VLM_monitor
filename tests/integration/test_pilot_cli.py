from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.enums import VerdictDecision
from labcourt.contracts.m3_operations import M3ProcessCounts
from labcourt.contracts.pilot import (
    PilotA3Report,
    PilotPerceptionReport,
    PilotRunRequest,
)

PROJECT_ROOT = Path(__file__).parents[2]
RUNNER = CliRunner()


def test_pilot_group_exposes_all_staged_commands() -> None:
    result = RUNNER.invoke(app, ["pilot", "--help"])
    assert result.exit_code == 0
    for command in ("run", "perceive", "screen", "report", "review", "ui"):
        assert command in result.stdout


@pytest.mark.parametrize("command", ("run", "perceive", "screen", "report", "review", "ui"))
def test_pilot_command_help_is_available(command: str) -> None:
    result = RUNNER.invoke(app, ["pilot", command, "--help"])
    assert result.exit_code == 0


def test_pilot_run_binds_the_verified_video_and_emits_the_full_run_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    payload = b"bounded-pilot-mp4-fixture"
    (tmp_path / "inputs" / "demo.mp4").write_bytes(payload)
    monkeypatch.chdir(tmp_path)
    expected: dict[str, object] | None = None

    class _Report:
        state = "COMPLETE"
        evidence = SimpleNamespace(candidate_event_count=0)
        publication = SimpleNamespace(
            metrics=SimpleNamespace(case_count=0),
            index_path="runs/pilot-001/report/index.html",
        )
        report_id = "d" * 64

        @staticmethod
        def model_dump(*, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {
                "report_id": "d" * 64,
                "run_id": "pilot-001",
                "schema_version": "pilot-a5-run-report-v1",
                "state": "COMPLETE",
            }

    def _run_a5(**kwargs: object) -> _Report:
        nonlocal expected
        request = cast(PilotRunRequest, kwargs["request"])
        assert request.video_sha256 == hashlib.sha256(payload).hexdigest()
        expected = _Report.model_dump(mode="json")
        return _Report()

    monkeypatch.setattr("labcourt.pilot_cli.run_pilot_a5", _run_a5)

    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "run",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--video",
            "inputs/demo.mp4",
            "--run-id",
            "pilot-001",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert expected is not None
    assert json.loads(result.stdout) == expected
    assert not (tmp_path / "runs" / "pilot-001").exists()


def test_pilot_run_missing_video_fails_closed_without_echoing_the_path() -> None:
    missing = "inputs/secret-person-name.mp4"
    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "run",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--video",
            missing,
            "--run-id",
            "pilot-missing",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr) == {
        "operation": "RUN",
        "reason_code": "VIDEO_MISSING",
        "status": "FAILED",
    }
    assert missing not in result.output


def test_pilot_run_returns_attention_exit_with_its_typed_json_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    (tmp_path / "inputs" / "demo.mp4").write_bytes(b"bounded-pilot-mp4-fixture")

    class _Report:
        state = "ATTENTION_REQUIRED"

        @staticmethod
        def model_dump(*, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {
                "run_id": "pilot-attention",
                "schema_version": "pilot-a5-run-report-v1",
                "state": "ATTENTION_REQUIRED",
            }

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("labcourt.pilot_cli.run_pilot_a5", lambda **_: _Report())
    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "run",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--video",
            "inputs/demo.mp4",
            "--run-id",
            "pilot-attention",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["state"] == "ATTENTION_REQUIRED"


def test_pilot_run_rejects_absolute_video_paths_before_opening(tmp_path: Path) -> None:
    video = tmp_path / "outside.mp4"
    video.write_bytes(b"must-not-be-read")
    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "run",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--video",
            str(video),
            "--run-id",
            "pilot-absolute",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["reason_code"] == "VIDEO_PATH_INVALID"


def test_pilot_perceive_emits_the_a1_report_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    (tmp_path / "inputs" / "demo.mp4").write_bytes(b"bounded-pilot-mp4-fixture")
    monkeypatch.chdir(tmp_path)
    expected = PilotPerceptionReport(
        run_id="pilot-001",
        frames_processed=4,
        detection_count=7,
        person_count=4,
        goggles_count=3,
        track_count=1,
        provider_failures=0,
        manifest_id="a" * 64,
        preview_path="runs/pilot-001/debug/perception-preview.mp4",
    )
    monkeypatch.setattr(
        "labcourt.pilot_cli.run_pilot_perception",
        lambda **_: expected,
    )

    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "perceive",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--video",
            "inputs/demo.mp4",
            "--run-id",
            "pilot-001",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == expected.model_dump(mode="json")


def test_pilot_screen_opens_the_run_scoped_real_provider_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "runs" / "pilot-001").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    expected = PilotA3Report(
        run_id="pilot-001",
        manifest_id="1" * 64,
        provider_profile="pilot-screening",
        provider="openai-compatible",
        model="vision-model",
        revision="2026-08-01",
        model_manifest_id="2" * 64,
        execution_location="EXTERNAL",
        transport="HTTP",
        requested_case_id=None,
        selection_limit=10,
        available_case_count=0,
        selection_truncated=False,
        outcomes=(),
        counts=M3ProcessCounts(
            selected_cases=0,
            pipeline_invocations=0,
            processed_cases=0,
            deferred_to_backlog_cases=0,
            observed_existing_cases=0,
            skipped_not_ready_cases=0,
            cache_hits=0,
            recovered_responses=0,
            repair_attempts=0,
        ),
    )
    captured: dict[str, object] = {}

    class _Service:
        def __enter__(self) -> _Service:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def process_run(self, **kwargs: object) -> PilotA3Report:
            captured["process"] = kwargs
            return expected

    def _open(**kwargs: object) -> _Service:
        captured["open"] = kwargs
        return _Service()

    monkeypatch.setattr("labcourt.pilot_cli.open_pilot_a3_operations_service", _open)

    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "screen",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--run-id",
            "pilot-001",
            "--max-cases",
            "10",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == expected.model_dump(mode="json")
    opened = cast(dict[str, object], captured["open"])
    assert opened["workspace_root"] == tmp_path / "runs"
    assert opened["database_path"] == tmp_path / "runs" / "pilot-001" / "labcourt.sqlite3"
    assert captured["process"] == {"case_id": None, "max_cases": 10}


def test_pilot_report_uses_the_run_scoped_a4_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _Report:
        metrics = SimpleNamespace(
            case_count=1,
            closed_count=1,
            verified_local_alert_count=1,
            human_review_count=0,
            unresolved_count=0,
        )
        dispatch = SimpleNamespace(
            retryable_failure_count=0,
            unknown_delivery_count=0,
            attention_required_count=0,
        )
        index_path = "runs/pilot-001/report/index.html"
        publication_id = "1" * 64

        @staticmethod
        def model_dump(*, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"publication_id": "1" * 64, "schema_version": "pilot-a4-publication-report-v1"}

    def _publish(**kwargs: object) -> _Report:
        captured.update(kwargs)
        return _Report()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("labcourt.pilot_cli.publish_pilot_run", _publish)
    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "report",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--run-id",
            "pilot-001",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["publication_id"] == "1" * 64
    assert captured["runs_root"] == tmp_path / "runs"
    assert captured["database_path"] == tmp_path / "runs" / "pilot-001" / "labcourt.sqlite3"


def test_pilot_report_returns_attention_exit_for_human_review_backlog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = SimpleNamespace(
        metrics=SimpleNamespace(
            case_count=1,
            closed_count=0,
            verified_local_alert_count=0,
            human_review_count=1,
            unresolved_count=1,
        ),
        dispatch=SimpleNamespace(
            retryable_failure_count=0,
            unknown_delivery_count=0,
            attention_required_count=0,
        ),
        index_path="runs/pilot-001/report/index.html",
        publication_id="1" * 64,
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("labcourt.pilot_cli.publish_pilot_run", lambda **_: report)

    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "report",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--run-id",
            "pilot-001",
        ],
    )

    assert result.exit_code == 1
    assert "pilot report published" in result.stdout


def test_pilot_review_reads_explicit_reason_and_uses_run_scoped_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reason = tmp_path / "review.md"
    reason.write_text("manual review reason", encoding="utf-8")
    captured: dict[str, object] = {}

    class _Report:
        @staticmethod
        def model_dump(*, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"review_id": "1" * 64, "schema_version": "pilot-a4-review-report-v1"}

    def _review(**kwargs: object) -> _Report:
        captured.update(kwargs)
        return _Report()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("labcourt.pilot_cli.review_pilot_case", _review)
    result = RUNNER.invoke(
        app,
        [
            "pilot",
            "review",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--run-id",
            "pilot-001",
            "--case-id",
            "case-001",
            "--decision",
            "ESTABLISHED",
            "--reason-file",
            str(reason),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["review_id"] == "1" * 64
    assert captured["runs_root"] == tmp_path / "runs"
    assert captured["database_path"] == tmp_path / "runs" / "pilot-001" / "labcourt.sqlite3"
    assert captured["reason"] == "manual review reason"
    assert captured["decision"] == VerdictDecision.ESTABLISHED


def test_artifact_validation_uses_pilot_run_scoped_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = tmp_path / "runs" / "pilot-001"
    run_root.mkdir(parents=True)
    (run_root / "labcourt.sqlite3").write_bytes(b"not-a-database")
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(
        app,
        [
            "artifacts",
            "validate",
            "--config",
            str(PROJECT_ROOT / "configs" / "pilot.yaml"),
            "--run-id",
            "pilot-001",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["reason_code"] == "DATABASE_BACKUP_FAILED"
