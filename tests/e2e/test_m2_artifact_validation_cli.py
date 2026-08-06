from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import pytest
from test_m2_evidence_pipeline import ROOT, _complete_request, _stack
from typer.testing import CliRunner

from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.json_projector import JsonProjector
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.cli import app
from labcourt.config_loader import load_config
from labcourt.contracts.artifact_validation import (
    ArtifactInventoryKind,
    ArtifactValidationIssueCode,
    ArtifactValidationReport,
    M3ArtifactValidationReport,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    ClosureDefectCode,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.projection_generation import ProjectionCurrentPointer

RUN_ID = "m2-cli-artifacts"
_M3_TABLES = (
    "model_call_failure_authorities",
    "backlog_completion_receipts",
    "backlog_heads",
    "backlog_item_versions",
    "backlog_items",
    "procedural_defects",
    "procedural_reviews",
    "verdicts",
    "screening_results",
    "model_call_usage_accounting",
    "model_parse_receipts",
    "parsed_screening_outputs",
    "model_cache",
    "model_responses",
    "model_call_claims",
)


@dataclass(frozen=True, slots=True)
class _Release:
    root: Path
    workspace: Path
    database: Path
    config: Path
    pack_id: str


class _CliResult(Protocol):
    @property
    def exit_code(self) -> int: ...

    @property
    def stdout(self) -> str: ...


def _generation_root(release: _Release) -> Path:
    pointer = ProjectionCurrentPointer.model_validate_json(
        (release.workspace / RUN_ID / "projections" / "current.json").read_bytes()
    )
    return release.workspace / RUN_ID / "projections" / "generations" / pointer.generation_id


def _pack_projection(release: _Release) -> Path:
    return _generation_root(release) / "packs" / f"{release.pack_id}.json"


def _fingerprint(root: Path) -> dict[str, tuple[int, int, int, str]]:
    return {
        path.relative_to(root).as_posix(): (
            int(path.stat().st_nlink),
            int(path.stat().st_size),
            int(path.stat().st_mtime_ns),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def _strip_m3_schema(database: Path) -> None:
    """Freeze the released fixture at the complete migration-3 M2 authority."""

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        m4_objects = connection.execute(
            """
            SELECT type, name
            FROM sqlite_master
            WHERE name GLOB 'm4_*'
               OR name GLOB 'idx_m4_*'
               OR name GLOB 'uq_m4_*'
            ORDER BY CASE type WHEN 'trigger' THEN 0 WHEN 'index' THEN 1 ELSE 2 END,
                     name
            """
        ).fetchall()
        for object_type, name in m4_objects:
            if object_type in {"trigger", "index", "table"}:
                connection.execute(f'DROP {str(object_type).upper()} "{name!s}"')
        connection.execute("DROP TRIGGER backlog_item_versions_validate_transition")
        connection.execute("DROP TRIGGER runs_portable_filesystem_identity_insert")
        connection.execute("DROP INDEX uq_runs_filesystem_identity_nocase")
        for table in _M3_TABLES:
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DROP TRIGGER schema_migrations_no_delete")
        connection.execute("DELETE FROM schema_migrations WHERE version > 3")
        connection.execute(
            """
            CREATE TRIGGER schema_migrations_no_delete
            BEFORE DELETE ON schema_migrations
            BEGIN
                SELECT RAISE(ABORT, 'schema_migrations is append-only');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()


def _invoke_json(*options: str) -> tuple[_CliResult, ArtifactValidationReport]:
    result = CliRunner().invoke(
        app,
        ["artifacts", "validate", "--run-id", RUN_ID, "--json", *options],
    )
    report = M3ArtifactValidationReport.model_validate_json(result.stdout)
    return result, report.m2_report


@pytest.fixture(scope="module")
def released_artifacts(tmp_path_factory: pytest.TempPathFactory) -> _Release:
    root = tmp_path_factory.mktemp("m2-cli-release")
    config_dir = root / "configs"
    config_dir.mkdir()
    config_path = config_dir / "default.yaml"
    config_path.write_text(
        (ROOT / "configs" / "demo.yaml")
        .read_text(encoding="utf-8")
        .replace('workspace: "runs"', 'workspace: "workspace"'),
        encoding="utf-8",
    )
    config = load_config(config_path)
    with _stack(root, run_id=RUN_ID, config=config) as stack:
        publication = stack.builder.build_and_publish(_complete_request(stack)).publication
        JsonProjector(stack.repository, stack.workspace_root).project_run(RUN_ID)
        pack_id = publication.pack.pack_id
    _strip_m3_schema(root / "workspace" / config.storage.database_filename)
    return _Release(
        root=root,
        workspace=root / "workspace",
        database=root / "workspace" / config.storage.database_filename,
        config=config_path,
        pack_id=pack_id,
    )


@pytest.fixture
def release_copy(
    released_artifacts: _Release,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _Release:
    shutil.copytree(released_artifacts.workspace, tmp_path / "workspace")
    shutil.copytree(released_artifacts.root / "configs", tmp_path / "configs")
    monkeypatch.chdir(tmp_path)
    return _Release(
        root=tmp_path,
        workspace=tmp_path / "workspace",
        database=tmp_path / "workspace" / released_artifacts.database.name,
        config=tmp_path / "configs" / "default.yaml",
        pack_id=released_artifacts.pack_id,
    )


def test_artifacts_validate_release_succeeds_stably_without_state_writes(
    release_copy: _Release,
) -> None:
    before = _fingerprint(release_copy.workspace)
    runner = CliRunner()
    human = runner.invoke(app, ["artifacts", "validate", "--run-id", RUN_ID])
    first = runner.invoke(
        app,
        ["artifacts", "validate", "--run-id", RUN_ID, "--json"],
    )
    second = runner.invoke(
        app,
        ["artifacts", "validate", "--run-id", RUN_ID, "--json"],
    )

    assert human.exit_code == 0, human.stdout
    assert "valid artifacts" in human.stdout
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    report = M3ArtifactValidationReport.model_validate_json(first.stdout)
    assert report.validator_version == "m3-artifacts-v1"
    assert report.passed is True
    assert report.issues == ()
    assert report.counts.documents == 0
    m2_report = report.m2_report
    assert m2_report.validator_version == "m2-artifacts-v1"
    assert m2_report.passed is True
    assert m2_report.counts.events == m2_report.counts.cases == 1
    assert m2_report.counts.max_document_bytes > 0
    assert m2_report.counts.packs == 1
    assert m2_report.counts.media > 1
    assert m2_report.counts.projections == 4
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_detects_unreferenced_authority_media_inventory(
    release_copy: _Release,
) -> None:
    orphan_media_sha256 = "f" * 64
    orphan_path = f"{RUN_ID}/frames/{orphan_media_sha256}.png"
    connection = sqlite3.connect(release_copy.database)
    try:
        inserted = connection.execute(
            """
            INSERT INTO media_assets(
                run_id, media_sha256, manifest_id, local_path, availability,
                pixel_sha256, width, height, size_bytes, media_type,
                encoding_version, ttl_expires_at, purged_at
            )
            SELECT
                run_id, ?, manifest_id, ?, availability,
                pixel_sha256, width, height, size_bytes, media_type,
                encoding_version, ttl_expires_at, NULL
            FROM media_assets
            WHERE run_id = ?
            ORDER BY media_sha256
            LIMIT 1
            """,
            (orphan_media_sha256, orphan_path, RUN_ID),
        )
        assert inserted.rowcount == 1
        connection.commit()
    finally:
        connection.close()
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()
    human = CliRunner().invoke(app, ["artifacts", "validate", "--run-id", RUN_ID])

    assert result.exit_code == human.exit_code == 1
    mismatches = tuple(
        issue
        for issue in report.issues
        if issue.code == ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH
    )
    assert len(mismatches) == 1
    mismatch = mismatches[0]
    assert mismatch.inventory_kind == ArtifactInventoryKind.MEDIA
    assert mismatch.authoritative_count == report.counts.media
    assert mismatch.traversed_count is not None
    assert mismatch.authoritative_count == mismatch.traversed_count + 1
    assert "inventory=MEDIA" in human.stdout
    assert (
        f"authority={mismatch.authoritative_count};traversed={mismatch.traversed_count}"
        in human.stdout
    )
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_detects_orphan_authority_pack_inventory(
    release_copy: _Release,
) -> None:
    orphan_pack_id = "e" * 64
    orphan_input_sha256 = "d" * 64
    connection = sqlite3.connect(release_copy.database)
    try:
        inserted = connection.execute(
            """
            INSERT INTO evidence_packs(
                run_id, pack_id, case_id, manifest_id, version, complete,
                pack_input_sha256, closure_input_sha256, pack_json,
                document_sha256, created_audit_sequence
            )
            SELECT
                source.run_id, ?, source.case_id, source.manifest_id,
                (
                    SELECT MAX(existing.version) + 1
                    FROM evidence_packs AS existing
                    WHERE existing.run_id = source.run_id
                      AND existing.case_id = source.case_id
                ),
                source.complete, ?, source.closure_input_sha256, source.pack_json,
                source.document_sha256, source.created_audit_sequence
            FROM evidence_packs AS source
            WHERE source.run_id = ?
            ORDER BY source.version
            LIMIT 1
            """,
            (orphan_pack_id, orphan_input_sha256, RUN_ID),
        )
        assert inserted.rowcount == 1
        connection.commit()
    finally:
        connection.close()
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    mismatches = tuple(
        issue
        for issue in report.issues
        if issue.code == ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH
    )
    assert len(mismatches) == 1
    mismatch = mismatches[0]
    assert mismatch.inventory_kind == ArtifactInventoryKind.PACK
    assert mismatch.authoritative_count == report.counts.packs
    assert mismatch.traversed_count is not None
    assert mismatch.authoritative_count == mismatch.traversed_count + 1
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_detects_tampered_png_without_repair(
    release_copy: _Release,
) -> None:
    pack_path = _pack_projection(release_copy)
    pack = EvidencePack.model_validate_json(pack_path.read_bytes())
    crop = pack.temporal_crops[0]
    assert crop.local_path is not None
    target = release_copy.workspace / Path(crop.local_path)
    target.write_bytes(
        encode_rgb_png(
            crop.output_width,
            crop.output_height,
            bytes([255]) * crop.output_width * crop.output_height * 3,
        )
    )
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()
    repeated_result, repeated_report = _invoke_json()

    assert result.exit_code == repeated_result.exit_code == 1
    assert result.stdout == repeated_result.stdout
    assert report == repeated_report
    assert any(
        issue.code == ArtifactValidationIssueCode.CURRENT_CLOSURE_DEFECT
        and issue.closure_defect_code == ClosureDefectCode.PIXEL_HASH_MISMATCH
        for issue in report.issues
    )
    assert _fingerprint(release_copy.workspace) == before


def test_stored_png_verifier_types_legal_retention_states_without_source_replay(
    release_copy: _Release,
) -> None:
    pack_path = _pack_projection(release_copy)
    crop = EvidencePack.model_validate_json(pack_path.read_bytes()).crops[0]
    before = _fingerprint(release_copy.workspace)
    config = load_config(release_copy.config)

    with SecureWorkspace(
        release_copy.workspace,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        current = verifier.verify_crop(crop)
        wrong_size = verifier.verify_crop(
            crop.model_copy(update={"size_bytes": crop.size_bytes + 1})
        )
        purging = verifier.verify_crop(
            crop.model_copy(update={"availability": MediaAvailability.PURGING})
        )
        purged = verifier.verify_crop(
            crop.model_copy(
                update={
                    "availability": MediaAvailability.PURGED_BY_RETENTION,
                    "local_path": None,
                }
            )
        )

    assert current.status == VerificationStatus.CURRENT_MEDIA_VERIFIED
    assert current.actual_source_pixel_sha256 is None
    assert current.actual_output_pixel_sha256 == crop.pixel_sha256
    assert current.actual_media_sha256 == crop.media_sha256
    assert wrong_size.status == VerificationStatus.SIZE_MISMATCH
    assert wrong_size.actual_source_pixel_sha256 is None
    assert wrong_size.actual_media_sha256 == crop.media_sha256
    assert wrong_size.actual_size_bytes == crop.size_bytes
    assert purging.status == VerificationStatus.MISSING
    assert purging.reason_code == "MEDIA_PURGING"
    assert purged.status == VerificationStatus.PURGED_BY_RETENTION
    assert purged.reason_code == "PURGED_BY_RETENTION"
    assert _fingerprint(release_copy.workspace) == before


@pytest.mark.parametrize("mode", ["missing", "mismatch"])
def test_artifacts_validate_detects_projection_damage_without_repair(
    release_copy: _Release,
    mode: str,
) -> None:
    target = _generation_root(release_copy) / "events.jsonl"
    if mode == "missing":
        target.unlink()
        expected_code = ArtifactValidationIssueCode.PROJECTION_MISSING
    else:
        target.write_bytes(b"{}\n")
        expected_code = ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert expected_code in {issue.code for issue in report.issues}
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_rejects_extra_current_generation_member(
    release_copy: _Release,
) -> None:
    extra = _generation_root(release_copy) / "unreferenced.json"
    extra.write_bytes(b"{}")
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert any(
        issue.code == ArtifactValidationIssueCode.PROJECTION_UNSAFE
        and issue.reason_code == "GENERATION_INVENTORY_MISMATCH"
        for issue in report.issues
    )
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_rejects_tampered_current_pointer(
    release_copy: _Release,
) -> None:
    target = release_copy.workspace / RUN_ID / "projections" / "current.json"
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["pointer_id"] = "f" * 64
    target.write_bytes(canonical_bytes(payload))
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert any(
        issue.code == ArtifactValidationIssueCode.PROJECTION_UNSAFE
        and issue.reason_code == "CURRENT_POINTER_INVALID"
        for issue in report.issues
    )
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_rejects_tampered_generation_manifest(
    release_copy: _Release,
) -> None:
    pointer_path = release_copy.workspace / RUN_ID / "projections" / "current.json"
    pointer = ProjectionCurrentPointer.model_validate_json(pointer_path.read_bytes())
    manifest_path = release_copy.workspace / Path(pointer.manifest_relative_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["generation_id"] = "f" * 64
    manifest_path.write_bytes(canonical_bytes(payload))
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert ArtifactValidationIssueCode.PROJECTION_UNSAFE in {issue.code for issue in report.issues}
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_detects_audit_document_corruption(
    release_copy: _Release,
) -> None:
    connection = sqlite3.connect(release_copy.database)
    try:
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute(
            "UPDATE audit_entries SET entry_json = '{}' WHERE run_id = ? AND sequence = 0",
            (RUN_ID,),
        )
        connection.commit()
    finally:
        connection.close()
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert ArtifactValidationIssueCode.AUDIT_DOCUMENT_INVALID in {
        issue.code for issue in report.issues
    }
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_detects_audit_head_corruption(
    release_copy: _Release,
) -> None:
    connection = sqlite3.connect(release_copy.database)
    try:
        connection.execute("DROP TRIGGER runs_monotonic_head_update")
        connection.execute("DROP TRIGGER runs_m6_audit_head_matches_entry")
        connection.execute(
            "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
            ("f" * 64, RUN_ID),
        )
        connection.commit()
    finally:
        connection.close()
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert ArtifactValidationIssueCode.AUDIT_CHAIN_INVALID in {
        issue.code for issue in report.issues
    }
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_rejects_hardlinked_projection(
    release_copy: _Release,
) -> None:
    target = _generation_root(release_copy) / "events.jsonl"
    alias = release_copy.workspace / RUN_ID / "events-hardlink-alias.jsonl"
    os.link(target, alias)
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert any(
        issue.code == ArtifactValidationIssueCode.PROJECTION_UNSAFE
        and issue.reason_code is not None
        and "LINK" in issue.reason_code
        for issue in report.issues
    )
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_rejects_hardlinked_media(
    release_copy: _Release,
) -> None:
    pack_path = _pack_projection(release_copy)
    pack = EvidencePack.model_validate_json(pack_path.read_bytes())
    crop = pack.crops[0]
    assert crop.local_path is not None
    target = release_copy.workspace / Path(crop.local_path)
    alias = target.with_name(f"{target.stem}-hardlink-alias.png")
    os.link(target, alias)
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json()

    assert result.exit_code == 1
    assert any(
        issue.code == ArtifactValidationIssueCode.CURRENT_CLOSURE_DEFECT
        and issue.closure_defect_code == ClosureDefectCode.UNSAFE_LINK
        for issue in report.issues
    )
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_budget_preflight_is_typed_and_read_only(
    release_copy: _Release,
) -> None:
    before = _fingerprint(release_copy.workspace)

    result, report = _invoke_json("--max-media", "1")

    assert result.exit_code == 1
    assert {issue.code for issue in report.issues} == {
        ArtifactValidationIssueCode.MEDIA_BUDGET_EXCEEDED
    }
    assert report.counts.media > 1
    assert report.counts.projections == 0

    audit_result, audit_report = _invoke_json("--max-audit-entries", "1")
    assert audit_result.exit_code == 1
    assert {issue.code for issue in audit_report.issues} == {
        ArtifactValidationIssueCode.AUDIT_BUDGET_EXCEEDED
    }
    assert audit_report.counts.audit_entries > 1
    assert audit_report.counts.projections == 0

    document_result, document_report = _invoke_json("--max-document-bytes", "1")
    assert document_result.exit_code == 1
    assert {issue.code for issue in document_report.issues} == {
        ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED
    }
    assert document_report.counts.max_document_bytes > 1
    assert document_report.counts.projections == 0
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_database_byte_budget_is_exit_2_and_read_only(
    release_copy: _Release,
) -> None:
    before = _fingerprint(release_copy.workspace)

    result = CliRunner().invoke(
        app,
        [
            "artifacts",
            "validate",
            "--run-id",
            RUN_ID,
            "--json",
            "--max-database-bytes",
            "1",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout) == {
        "error": "ARTIFACT_VALIDATION_BOUNDARY_ERROR",
        "reason_code": "DATABASE_BYTES_BUDGET_EXCEEDED",
        "valid": False,
    }
    assert _fingerprint(release_copy.workspace) == before


def test_artifacts_validate_missing_database_is_exit_2_and_not_created(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    shutil.copy2(ROOT / "configs" / "default.yaml", config_dir / "default.yaml")
    workspace = tmp_path / "runs"
    workspace.mkdir()
    monkeypatch.chdir(tmp_path)
    before = _fingerprint(tmp_path)

    result = CliRunner().invoke(
        app,
        ["artifacts", "validate", "--run-id", RUN_ID, "--json"],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout) == {
        "error": "ARTIFACT_VALIDATION_BOUNDARY_ERROR",
        "reason_code": "DATABASE_MISSING",
        "valid": False,
    }
    assert not (workspace / "labcourt.sqlite3").exists()
    assert _fingerprint(tmp_path) == before
