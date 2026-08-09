from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.m3_operations import M3ProcessCounts
from labcourt.contracts.pilot import (
    PilotA2Report,
    PilotA3Report,
    PilotPerceptionReport,
    PilotRunRequest,
)

PROJECT_ROOT = Path(__file__).parents[2]
RUNNER = CliRunner()


def test_pilot_group_exposes_all_staged_commands() -> None:
    result = RUNNER.invoke(app, ["pilot", "--help"])
    assert result.exit_code == 0
    for command in ("run", "perceive", "screen", "report", "review"):
        assert command in result.stdout


@pytest.mark.parametrize("command", ("run", "perceive", "screen", "report", "review"))
def test_pilot_command_help_is_available(command: str) -> None:
    result = RUNNER.invoke(app, ["pilot", command, "--help"])
    assert result.exit_code == 0


def test_pilot_run_binds_the_verified_video_and_emits_the_a2_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    payload = b"bounded-pilot-mp4-fixture"
    (tmp_path / "inputs" / "demo.mp4").write_bytes(payload)
    monkeypatch.chdir(tmp_path)
    expected: PilotA2Report | None = None

    def _run_a2(**kwargs: object) -> PilotA2Report:
        nonlocal expected
        request = cast(PilotRunRequest, kwargs["request"])
        assert request.video_sha256 == hashlib.sha256(payload).hexdigest()
        expected = PilotA2Report(
            run_id="pilot-001",
            state="NO_CANDIDATE",
            config_sha256=request.config_sha256,
            video_sha256=request.video_sha256,
            perception_manifest_id="a" * 64,
            perception_completion_id="b" * 64,
            run_manifest_id="c" * 64,
            selected_rules=("PPE_GOGGLES_MISSING",),
            frames_processed=4,
            association_count=4,
            l0_reminder_count=0,
            suppression_count=0,
            candidate_event_count=0,
            evidence_pack_count=0,
            evidence_packs=(),
        )
        return expected

    monkeypatch.setattr("labcourt.pilot_cli.run_pilot_a2", _run_a2)

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
    assert json.loads(result.stdout) == expected.model_dump(mode="json")
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


def test_later_pilot_stage_is_explicitly_unavailable_in_a0() -> None:
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

    assert result.exit_code == 2
    assert json.loads(result.stderr)["reason_code"] == "STAGE_NOT_AVAILABLE"
