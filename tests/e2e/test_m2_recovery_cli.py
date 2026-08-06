from __future__ import annotations

import hashlib
import json
import os
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.vlm.fake import DeterministicFakeVLMClient
from labcourt.adapters.vlm.openai_compatible import OpenAICompatibleVLMClient
from labcourt.cli import app
from labcourt.config_loader import load_config
from labcourt.contracts.enums import RecoveryDisposition, RecoveryReasonCode
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.model_response_recovery import (
    ModelResponseArtifactPhase,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryReason,
)

PROJECT_ROOT = Path(__file__).parents[2]
CONFIG_PATH = PROJECT_ROOT / "configs" / "demo.yaml"
MANIFEST_PATH = PROJECT_ROOT / "tests" / "fixtures" / "m2" / "run-manifest-fake.json"
RUNNER = CliRunner()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _workspace_root(tmp_path: Path) -> Path:
    root = tmp_path / "runs"
    root.mkdir()
    return root


def _migrate_database(workspace_root: Path) -> tuple[Path, int]:
    config = load_config(CONFIG_PATH)
    database = workspace_root / config.storage.database_filename
    MigrationRunner(database, config.storage.busy_timeout_ms).apply_all()
    return database, config.storage.busy_timeout_ms


def _register_run(workspace_root: Path, run_id: str) -> Path:
    database, busy_timeout_ms = _migrate_database(workspace_root)
    manifest = RunManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))
    SQLiteEvidenceRepository(database, busy_timeout_ms).register_run(run_id, manifest)
    return database


def _create_file(
    workspace_root: Path,
    run_id: str,
    relative_name: str,
    data: bytes,
    *,
    make_old: bool = True,
) -> Path:
    config = load_config(CONFIG_PATH)
    relative_path = f"{run_id}/frames/{relative_name}"
    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        for directory in (
            ".staging",
            f".staging/{run_id}",
            run_id,
            f"{run_id}/frames",
        ):
            workspace.ensure_private_directory(directory)
        workspace.create_new(relative_path, data, _digest(data))
    path = workspace_root / Path(*relative_path.split("/"))
    if make_old:
        old = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
        os.utime(path, (old, old))
    return path


def _create_model_response_file(
    workspace_root: Path,
    run_id: str,
    response_id: str,
    data: bytes,
) -> Path:
    config = load_config(CONFIG_PATH)
    relative_path = f"{run_id}/model_responses/{response_id}.json"
    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        for directory in (run_id, f"{run_id}/model_responses"):
            workspace.ensure_private_directory(directory)
        workspace.create_new(relative_path, data, _digest(data))
    path = workspace_root / Path(*relative_path.split("/"))
    old = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
    os.utime(path, (old, old))
    return path


def _invoke_recovery(run_id: str) -> Result:
    return RUNNER.invoke(
        app,
        [
            "maintenance",
            "recover",
            "--run-id",
            run_id,
            "--config",
            str(CONFIG_PATH),
            "--json",
            "--max-items",
            "10",
            "--minimum-age-minutes",
            "60",
        ],
    )


def test_recovery_cli_quarantines_old_orphan_for_registered_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m2-recovery-cli-success"
    workspace_root = _workspace_root(tmp_path)
    _register_run(workspace_root, run_id)
    data = b"old-unreferenced-final-media"
    digest = _digest(data)
    source = _create_file(workspace_root, run_id, f"{digest}.png", data)
    quarantine = workspace_root / ".quarantine" / run_id / "frames" / f"{digest}.png"
    monkeypatch.chdir(tmp_path)

    result = _invoke_recovery(run_id)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["run_id"] == run_id
    assert payload["passed"] is True
    assert payload["requires_attention"] is False
    storage = payload["storage_report"]
    assert storage["retention_items"] == []
    assert storage["orphan_report"]["run_id"] == run_id
    assert len(storage["orphan_report"]["items"]) == 1
    item = storage["orphan_report"]["items"][0]
    assert item["content_sha256"] == digest
    assert item["disposition"] == RecoveryDisposition.QUARANTINED.value
    assert item["reason_code"] == RecoveryReasonCode.ORPHAN_QUARANTINED.value
    assert item["quarantine_relative_path"] == (f".quarantine/{run_id}/frames/{digest}.png")
    model_responses = payload["model_response_report"]
    assert model_responses["run_id"] == run_id
    assert model_responses["passed"] is True
    assert model_responses["items"] == []
    assert not source.exists()
    assert quarantine.read_bytes() == data
    assert str(workspace_root) not in result.stdout


def test_recovery_cli_rejects_unknown_run_before_moving_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m2-recovery-cli-unknown"
    workspace_root = _workspace_root(tmp_path)
    database, _ = _migrate_database(workspace_root)
    data = b"unknown-run-file-must-not-move"
    digest = _digest(data)
    source = _create_file(workspace_root, run_id, f"{digest}.png", data)
    monkeypatch.chdir(tmp_path)

    result = _invoke_recovery(run_id)

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["error"] == "STARTUP_RECOVERY_BOUNDARY_ERROR"
    assert payload["reason_code"] == "RUN_NOT_FOUND"
    assert payload["recovered"] is False
    assert source.read_bytes() == data
    assert not (workspace_root / ".quarantine").exists()
    assert database.is_file()


def test_recovery_cli_missing_database_does_not_create_or_move_any_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m2-recovery-cli-missing-db"
    workspace_root = _workspace_root(tmp_path)
    config = load_config(CONFIG_PATH)
    database = workspace_root / config.storage.database_filename
    data = b"missing-database-file-must-not-move"
    digest = _digest(data)
    source = _create_file(workspace_root, run_id, f"{digest}.png", data)
    monkeypatch.chdir(tmp_path)

    result = _invoke_recovery(run_id)

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["error"] == "STARTUP_RECOVERY_BOUNDARY_ERROR"
    assert isinstance(payload["reason_code"], str) and payload["reason_code"]
    assert payload["recovered"] is False
    assert source.read_bytes() == data
    assert not (workspace_root / ".quarantine").exists()
    assert not database.exists()
    assert tuple(workspace_root.glob(f"{database.name}*")) == ()


def test_recovery_cli_returns_exit_one_for_typed_filesystem_anomaly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m2-recovery-cli-attention"
    workspace_root = _workspace_root(tmp_path)
    _register_run(workspace_root, run_id)
    data = b"unknown-entry-shape"
    source = _create_file(workspace_root, run_id, "notes.txt", data)
    monkeypatch.chdir(tmp_path)

    result = _invoke_recovery(run_id)

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["run_id"] == run_id
    assert payload["passed"] is False
    assert payload["requires_attention"] is True
    storage = payload["storage_report"]
    assert storage["retention_items"] == []
    assert len(storage["orphan_report"]["items"]) == 1
    item = storage["orphan_report"]["items"][0]
    assert item["disposition"] == RecoveryDisposition.ANOMALY.value
    assert item["reason_code"] == RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE.value
    assert item["content_sha256"] is None
    assert item["quarantine_relative_path"] is None
    assert source.read_bytes() == data
    assert not (workspace_root / ".quarantine").exists()


def test_recovery_cli_runs_m3_orphan_recovery_without_constructing_any_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m3-recovery-cli-offline"
    workspace_root = _workspace_root(tmp_path)
    _register_run(workspace_root, run_id)
    response_id = "a" * 64
    data = b'{"provider_payload":"orphaned-but-never-logged"}'
    digest = _digest(data)
    source = _create_model_response_file(workspace_root, run_id, response_id, data)
    quarantine = (
        workspace_root
        / ".quarantine"
        / run_id
        / "model_responses"
        / "final"
        / f"{response_id}-{digest}.json"
    )

    def unexpected_provider(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("maintenance recovery must not construct a model provider")

    monkeypatch.setattr(DeterministicFakeVLMClient, "__init__", unexpected_provider)
    monkeypatch.setattr(OpenAICompatibleVLMClient, "__init__", unexpected_provider)
    monkeypatch.setattr(socket, "create_connection", unexpected_provider)
    monkeypatch.chdir(tmp_path)

    result = _invoke_recovery(run_id)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["storage_report"]["orphan_report"]["items"] == []
    model = payload["model_response_report"]
    assert model["artifact_phase"] == ModelResponseArtifactPhase.COMPLETED.value
    assert model["claim_scan_complete"] is True
    assert model["artifact_scan_complete"] is True
    assert len(model["items"]) == 1
    item = model["items"][0]
    assert item["area"] == ModelResponseRecoveryArea.FINAL_RESPONSE.value
    assert item["disposition"] == ModelResponseRecoveryDisposition.QUARANTINED.value
    assert item["reason_code"] == ModelResponseRecoveryReason.ORPHAN_FINAL_QUARANTINED.value
    assert item["content_sha256"] == digest
    assert item["quarantine_relative_path"] == (
        f".quarantine/{run_id}/model_responses/final/{response_id}-{digest}.json"
    )
    assert not source.exists()
    assert quarantine.read_bytes() == data
    assert "provider_payload" not in result.stdout
    assert str(workspace_root) not in result.stdout
