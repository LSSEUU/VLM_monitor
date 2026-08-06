from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m5_projection import (
    M5ProjectionCurrentPointer,
    M5ProjectionGenerationManifest,
)
from tests.integration.test_m5_sqlite_appeals import _prepare_overturn

ROOT = Path(__file__).parents[2]


def _fingerprint(root: Path) -> tuple[tuple[str, int, str], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            path.stat().st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    )


def test_m5_projection_and_validation_cli_replay_and_detect_tamper(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "runs"
    workspace.mkdir()
    _, repository, _, _, _, _, source, _, _, intent = _prepare_overturn(workspace)
    repository.commit_resolution(intent)
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    config = str(ROOT / "configs/demo.yaml")
    rebuild_args = [
        "projection",
        "rebuild-m5",
        "--run-id",
        source.run_id,
        "--config",
        config,
        "--json",
    ]

    first = runner.invoke(app, rebuild_args)
    assert first.exit_code == 0, first.output
    pointer = M5ProjectionCurrentPointer.model_validate(json.loads(first.stdout))
    replay = runner.invoke(app, rebuild_args)
    assert replay.exit_code == 0, replay.output
    assert M5ProjectionCurrentPointer.model_validate(json.loads(replay.stdout)) == pointer

    before_validation = _fingerprint(workspace)
    validated = runner.invoke(
        app,
        [
            "artifacts",
            "validate-m5",
            "--run-id",
            source.run_id,
            "--config",
            config,
            "--json",
        ],
    )
    assert validated.exit_code == 0, validated.output
    report = M5ArtifactValidationReport.model_validate(json.loads(validated.stdout))
    assert report.passed is True
    assert report.counts.authority_rows == report.counts.projection_records
    assert report.counts.projection_files == 6
    assert _fingerprint(workspace) == before_validation

    manifest_path = workspace / pointer.manifest_relative_path
    manifest = M5ProjectionGenerationManifest.model_validate_json(manifest_path.read_bytes())
    selected = manifest_path.parent / manifest.entries[0].relative_path
    selected.write_bytes(b"{}\n")
    damaged = selected.read_bytes()

    invalid = runner.invoke(
        app,
        [
            "artifacts",
            "validate-m5",
            "--run-id",
            source.run_id,
            "--config",
            config,
            "--json",
        ],
    )
    assert invalid.exit_code == 1, invalid.output
    invalid_report = M5ArtifactValidationReport.model_validate(json.loads(invalid.stdout))
    assert invalid_report.passed is False
    assert any(issue.reason_code == "EXPECTED_HASH_MISMATCH" for issue in invalid_report.issues)
    assert selected.read_bytes() == damaged

    refused_rebuild = runner.invoke(app, rebuild_args)
    assert refused_rebuild.exit_code == 2
    boundary = json.loads(refused_rebuild.stdout)
    assert boundary["error"] == "M5_OPERATION_BOUNDARY_ERROR"
    assert boundary["operation"] == "projection-rebuild-m5"
    assert str(workspace) not in refused_rebuild.output


def test_m5_projection_cli_missing_run_is_typed_and_path_free(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "runs").mkdir()
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "projection",
            "rebuild-m5",
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
    assert payload["operation"] == "projection-rebuild-m5"
    assert str(tmp_path) not in result.output
