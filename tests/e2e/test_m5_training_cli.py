from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.enums import TrainingLabelQuality
from tests.integration.test_m3_sqlite_repository import ROOT, RUN_ID
from tests.integration.test_m5_training_operations_service import (
    _insert_training_labels,
    _prepare_training_run,
    _registration_state,
    _reviewed_label,
)


def test_m5_training_cli_publishes_and_replays_verified_coco_without_weak_labels(
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    source_config = ROOT / "configs" / "demo.yaml"
    local_config = tmp_path / "demo-workspace.yaml"
    local_config.write_text(
        source_config.read_text(encoding="utf-8").replace(
            'workspace: "runs"',
            'workspace: "workspace"',
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    args = [
        "training",
        "export",
        f"{RUN_ID}/datasets/reviewed.coco.json",
        "--run-id",
        RUN_ID,
        "--config",
        str(local_config),
        "--json",
    ]
    runner = CliRunner()

    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    first_report = json.loads(first.stdout)
    target = prepared.workspace_root / first_report["dataset"]["relative_path"]
    target_before = (target.read_bytes(), target.stat().st_mtime_ns)
    _insert_training_labels(
        prepared.database,
        (
            _reviewed_label(
                label_id="weak-tail",
                crop=prepared.crop,
                quality=TrainingLabelQuality.WEAK_AUTO,
            ),
        ),
    )
    committed_state = _registration_state(prepared.database)

    replay = runner.invoke(app, args)

    assert replay.exit_code == 0, replay.output
    assert json.loads(replay.stdout) == first_report
    assert _registration_state(prepared.database) == committed_state
    assert (target.read_bytes(), target.stat().st_mtime_ns) == target_before
    assert first_report["exported_label_ids"] == [prepared.strong_label_id]
    assert first_report["quarantined_label_ids"] == [
        "consensus-1",
        "excluded-1",
        "weak-1",
    ]
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert [item["labcourt_label_id"] for item in payload["annotations"]] == [
        prepared.strong_label_id
    ]
    assert tuple(prepared.workspace_root.rglob("*.png")) == (prepared.media_path,)


def test_m5_training_cli_returns_typed_error_for_unsafe_output_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _prepare_training_run(tmp_path)
    source_config = ROOT / "configs" / "demo.yaml"
    local_config = tmp_path / "demo-workspace.yaml"
    local_config.write_text(
        source_config.read_text(encoding="utf-8").replace(
            'workspace: "runs"',
            'workspace: "workspace"',
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "training",
            "export",
            "../escape.json",
            "--run-id",
            RUN_ID,
            "--config",
            str(local_config),
            "--json",
        ],
    )
    assert result.exit_code == 2
    error = json.loads(result.stdout)
    assert error["reason_code"] == "INVALID_ARGUMENT"


def test_m5_training_cli_maps_registered_dataset_loss_to_typed_replay_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    source_config = ROOT / "configs" / "demo.yaml"
    local_config = tmp_path / "demo-workspace.yaml"
    local_config.write_text(
        source_config.read_text(encoding="utf-8").replace(
            'workspace: "runs"',
            'workspace: "workspace"',
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    args = [
        "training",
        "export",
        f"{RUN_ID}/datasets/reviewed.coco.json",
        "--run-id",
        RUN_ID,
        "--config",
        str(local_config),
        "--json",
    ]
    runner = CliRunner()
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    report = json.loads(first.stdout)
    target = prepared.workspace_root / report["dataset"]["relative_path"]
    target.unlink()
    committed_state = _registration_state(prepared.database)

    replay = runner.invoke(app, args)

    assert replay.exit_code == 2
    assert json.loads(replay.stdout)["reason_code"] == "REGISTERED_DATASET_REPLAY_FAILED"
    assert _registration_state(prepared.database) == committed_state
    assert not target.exists()
