"""Public read-only M4 artifact validation over a complete offline hearing."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from labcourt.cli import app
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.m4_artifact_validation import (
    M4ArtifactValidationIssueCode,
    M4ArtifactValidationReport,
)
from labcourt.contracts.m4_projection import (
    M4ProjectionCurrentPointer,
    M4ProjectionGenerationManifest,
)
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from tests.e2e.test_m4_operations_cli import _args, _escalate, _m4_bundle
from tests.integration.test_m3_operations_service import ROOT, RUN_ID, _setup_ready_runtime

RUNNER = CliRunner()


def _fingerprint(root: Path) -> tuple[tuple[str, str, int, int, str], ...]:
    entries: list[tuple[str, str, int, int, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        stat = path.stat()
        if path.is_file():
            entries.append(
                (
                    "FILE",
                    relative,
                    int(stat.st_size),
                    int(stat.st_mtime_ns),
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
        elif path.is_dir():
            entries.append(("DIRECTORY", relative, 0, int(stat.st_mtime_ns), ""))
        else:
            entries.append(("OTHER", relative, 0, int(stat.st_mtime_ns), ""))
    return tuple(entries)


def _invoke_readonly(
    workspace: Path,
    *options: str,
) -> tuple[object, M4ArtifactValidationReport]:
    before = _fingerprint(workspace)
    result = RUNNER.invoke(
        app,
        [
            "artifacts",
            "validate",
            "--run-id",
            RUN_ID,
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
            *options,
        ],
    )
    after = _fingerprint(workspace)
    assert before == after
    payload = json.loads(result.stdout)
    if payload.get("validator_version") == "m5-artifacts-v1":
        m5_report = M5ArtifactValidationReport.model_validate(payload)
        assert isinstance(m5_report.predecessor_report, M4ArtifactValidationReport)
        return result, m5_report.predecessor_report
    return result, M4ArtifactValidationReport.model_validate(payload)


def _codes(report: M4ArtifactValidationReport) -> set[M4ArtifactValidationIssueCode]:
    return {issue.code for issue in report.issues}


def test_public_m4_artifact_validation_is_complete_and_does_not_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    fixture = _m4_bundle(runtime, tmp_path)
    hearing = RUNNER.invoke(app, _args(runtime, fixture))
    assert hearing.exit_code == 0, hearing.output
    m5_projection = RUNNER.invoke(
        app,
        [
            "projection",
            "rebuild-m5",
            "--run-id",
            RUN_ID,
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
        ],
    )
    assert m5_projection.exit_code == 0, m5_projection.output

    result, report = _invoke_readonly(workspace)

    assert result.exit_code == 0, result.output
    assert report.passed
    assert report.authority_root_sha256 is not None
    assert report.counts.validated_authority_documents > 0
    assert report.counts.validated_media > 0
    assert report.counts.media_failures == 0
    assert report.counts.embedded_m3_superseded_issues > 0
    assert report.counts.embedded_m3_gating_issues == 0
    assert report.counts.projection_documents == report.counts.validated_authority_documents
    assert report.counts.projection_files == report.counts.projection_documents + 2

    projection_root = workspace / RUN_ID / "m4-projections"
    current_path = projection_root / "current.json"
    current_bytes = current_path.read_bytes()
    pointer = M4ProjectionCurrentPointer.model_validate_json(current_bytes)
    manifest_path = workspace / Path(pointer.manifest_relative_path)
    manifest_bytes = manifest_path.read_bytes()
    manifest = M4ProjectionGenerationManifest.model_validate_json(manifest_bytes)
    generation = manifest_path.parent
    first_entry = manifest.entries[0]
    document_path = generation / Path(first_entry.relative_path)

    missing_pointer = tmp_path / "missing-current.json"
    current_path.replace(missing_pointer)
    missing_result, missing_report = _invoke_readonly(workspace)
    assert missing_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.PROJECTION_MISSING in _codes(missing_report)
    missing_pointer.replace(current_path)

    current_path.write_bytes(b"{}")
    pointer_result, pointer_report = _invoke_readonly(workspace)
    assert pointer_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH in _codes(pointer_report)
    current_path.write_bytes(current_bytes)

    foreign_pointer = M4ProjectionCurrentPointer(
        run_id="foreign-run",
        authority_root_sha256=pointer.authority_root_sha256,
        generation_id=pointer.generation_id,
        manifest_relative_path=(
            f"foreign-run/m4-projections/generations/{pointer.generation_id}/"
            f"manifest-{pointer.manifest_sha256}.json"
        ),
        manifest_sha256=pointer.manifest_sha256,
        manifest_size_bytes=pointer.manifest_size_bytes,
    )
    current_path.write_bytes(canonical_bytes(foreign_pointer.model_dump(mode="json")))
    cross_run_result, cross_run_report = _invoke_readonly(workspace)
    assert cross_run_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.PROJECTION_ROOT_MISMATCH in _codes(cross_run_report)
    current_path.write_bytes(current_bytes)

    manifest_path.write_bytes(b"{}")
    manifest_result, manifest_report = _invoke_readonly(workspace)
    assert manifest_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH in _codes(manifest_report)
    manifest_path.write_bytes(manifest_bytes)

    document_bytes = document_path.read_bytes()
    document_path.write_bytes(b"{}")
    document_result, document_report = _invoke_readonly(workspace)
    assert document_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH in _codes(document_report)
    document_path.write_bytes(document_bytes)

    extra = generation / "extra.json"
    extra.write_bytes(b"{}")
    extra_result, extra_report = _invoke_readonly(workspace)
    assert extra_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.PROJECTION_INVENTORY_MISMATCH in _codes(extra_report)
    extra.unlink()

    partial = tmp_path / "partial-generation-document.json"
    document_path.replace(partial)
    partial_result, partial_report = _invoke_readonly(workspace)
    assert partial_result.exit_code == 1
    assert {
        M4ArtifactValidationIssueCode.PROJECTION_MISSING,
        M4ArtifactValidationIssueCode.PROJECTION_INVENTORY_MISMATCH,
    }.issubset(_codes(partial_report))
    partial.replace(document_path)

    budget_result, budget_report = _invoke_readonly(
        workspace,
        "--max-m4-projection-bytes",
        "1",
    )
    assert budget_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED in _codes(
        budget_report
    )

    media_path = next((workspace / RUN_ID / "frames").glob("*.png"))
    media_bytes = media_path.read_bytes()
    media_path.write_bytes(b"not-a-png")
    media_result, media_report = _invoke_readonly(workspace)
    assert media_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.AUTHORITY_MEDIA_INVALID in _codes(media_report)
    media_path.write_bytes(media_bytes)

    with sqlite3.connect(runtime.database) as connection:
        trigger_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'm4_hearings_no_update'"
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute("DROP TRIGGER m4_hearings_no_update")
        connection.execute(
            "UPDATE m4_hearings SET hearing_json = hearing_json || ' ' WHERE run_id = ?",
            (RUN_ID,),
        )
        connection.execute(str(trigger_row[0]))
    authority_result, authority_report = _invoke_readonly(workspace)
    assert authority_result.exit_code == 1
    assert M4ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID in _codes(authority_report)
