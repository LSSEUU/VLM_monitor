from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from labcourt.cli import app

PROJECT_ROOT = Path(__file__).parents[2]
RUNNER = CliRunner()


def test_pilot_group_exposes_all_staged_commands() -> None:
    result = RUNNER.invoke(app, ["pilot", "--help"])
    assert result.exit_code == 0
    for command in ("run", "perceive", "report", "review"):
        assert command in result.stdout


@pytest.mark.parametrize("command", ("run", "perceive", "report", "review"))
def test_pilot_command_help_is_available(command: str) -> None:
    result = RUNNER.invoke(app, ["pilot", command, "--help"])
    assert result.exit_code == 0


def test_pilot_run_preflight_binds_the_verified_video_without_creating_a_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    payload = b"bounded-pilot-mp4-fixture"
    (tmp_path / "inputs" / "demo.mp4").write_bytes(payload)
    monkeypatch.chdir(tmp_path)

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
    report = json.loads(result.stdout)
    assert report == {
        "config_sha256": report["config_sha256"],
        "max_cases": 20,
        "resume": True,
        "run_id": "pilot-001",
        "selected_rules": ["PPE_GOGGLES_MISSING"],
        "video_relative_path": "inputs/demo.mp4",
        "video_sha256": hashlib.sha256(payload).hexdigest(),
    }
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
