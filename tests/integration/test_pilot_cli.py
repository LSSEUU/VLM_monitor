from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.pilot import PilotA2Report, PilotPerceptionReport, PilotRunRequest

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
