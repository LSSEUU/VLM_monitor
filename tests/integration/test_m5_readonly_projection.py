from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage.m5_jsonl_projector import M5JsonlProjector, M5ProjectionFailure
from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import TrainingLabelQuality
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
)
from labcourt.contracts.training import TrainingLabel
from labcourt.services.m5_artifact_validation import validate_m5_artifacts
from labcourt.services.m5_projection import rebuild_m5_projection
from tests.integration.test_m5_sqlite_appeals import _prepare_overturn
from tests.integration.test_m5_sqlite_precedents import _config


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


def _resolved(tmp_path: Path) -> tuple[Path, str]:
    database, repository, _, _, _, _, source, _, _, intent = _prepare_overturn(tmp_path)
    repository.commit_resolution(intent)
    return database, source.run_id


def _drop_update_restore(
    database: Path,
    trigger_name: str,
    statement: str,
) -> None:
    _mutate_without_triggers(
        database,
        (trigger_name,),
        lambda connection: connection.execute(statement),
    )


def _mutate_without_triggers(
    database: Path,
    trigger_names: tuple[str, ...],
    operation: Callable[[sqlite3.Connection], object],
) -> None:
    with sqlite3.connect(database) as connection:
        trigger_sql: list[str] = []
        for trigger_name in trigger_names:
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (trigger_name,),
            ).fetchone()
            assert row is not None and isinstance(row[0], str)
            trigger_sql.append(row[0])
            connection.execute(f'DROP TRIGGER "{trigger_name}"')
        operation(connection)
        for statement in trigger_sql:
            connection.execute(statement)


def _rewrite_provenance_terminal_root(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT provenance_json FROM strong_training_label_provenance_receipts"
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    receipt = M5StrongTrainingLabelProvenanceReceipt.model_validate_json(row[0])
    payload = receipt.model_dump(mode="json", exclude={"provenance_id"})
    payload["terminal_authority_sha256"] = "f" * 64
    forged = M5StrongTrainingLabelProvenanceReceipt.model_validate(payload)
    raw = canonical_json(forged.model_dump(mode="json"))
    connection.execute(
        """
        UPDATE strong_training_label_provenance_receipts
        SET provenance_id = ?, terminal_authority_sha256 = ?,
            provenance_json = ?, document_sha256 = ?
        WHERE provenance_id = ?
        """,
        (
            forged.provenance_id,
            forged.terminal_authority_sha256,
            raw,
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            receipt.provenance_id,
        ),
    )
    connection.execute(
        "UPDATE training_labels SET strong_provenance_id = ? WHERE label_id = ?",
        (forged.provenance_id, forged.label_id),
    )


def _insert_orphan_provenance(connection: sqlite3.Connection) -> str:
    row = connection.execute(
        "SELECT provenance_json FROM strong_training_label_provenance_receipts"
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    receipt = M5StrongTrainingLabelProvenanceReceipt.model_validate_json(row[0])
    authored_payload = receipt.authored_input.model_dump(mode="json", exclude={"input_id"})
    authored_payload["label_name"] = "orphan_training_fact"
    authored = M5AppealTrainingLabelInput.model_validate(authored_payload)
    payload = receipt.model_dump(mode="json", exclude={"provenance_id"})
    payload.update(
        authored_input=authored.model_dump(mode="json"),
        label_id=sha256_hex(
            [
                "m5-appeal-training-label",
                1,
                receipt.review_authority_sha256,
                receipt.terminal_status,
                receipt.reviewer_id,
                authored.input_id,
            ]
        ),
        label_document_sha256="f" * 64,
    )
    orphan = M5StrongTrainingLabelProvenanceReceipt.model_validate(payload)
    raw = canonical_json(orphan.model_dump(mode="json"))
    connection.execute(
        """
        INSERT INTO strong_training_label_provenance_receipts(
            run_id, provenance_id, case_id, appeal_id, label_id,
            label_document_sha256, crop_id, reviewer_id, quality,
            authored_input_id, review_authority_sha256,
            terminal_authority_sha256, terminal_status, resolution_intent_id,
            resolution_document_sha256, resolution_commit_receipt_id,
            resolution_commit_effect_root_sha256, manifest_id, rule_version,
            detector_manifest_id, provenance_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            orphan.run_id,
            orphan.provenance_id,
            orphan.case_id,
            orphan.appeal_id,
            orphan.label_id,
            orphan.label_document_sha256,
            orphan.crop_id,
            orphan.reviewer_id,
            orphan.quality.value,
            orphan.authored_input.input_id,
            orphan.review_authority_sha256,
            orphan.terminal_authority_sha256,
            orphan.terminal_status.value,
            orphan.resolution_intent_id,
            orphan.resolution_document_sha256,
            orphan.resolution_commit_receipt_id,
            orphan.resolution_commit_effect_root_sha256,
            orphan.manifest_id,
            orphan.rule_version,
            orphan.detector_manifest_id,
            raw,
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        ),
    )
    return orphan.provenance_id


def _rewrite_strong_label_as_weak(connection: sqlite3.Connection) -> None:
    row = connection.execute("SELECT label_json FROM training_labels").fetchone()
    assert row is not None and isinstance(row[0], str)
    label = TrainingLabel.model_validate_json(row[0])
    payload = label.model_dump(mode="json")
    payload.update(
        quality=TrainingLabelQuality.WEAK_AUTO,
        source="tampered-weak-label",
        reviewer_id=None,
        excluded_reason="not-human-confirmed",
    )
    weak = TrainingLabel.model_validate(payload)
    raw = canonical_json(weak.model_dump(mode="json"))
    connection.execute("PRAGMA ignore_check_constraints = ON")
    connection.execute(
        """
        UPDATE training_labels
        SET quality = ?, source = ?, reviewer_id = ?, label_json = ?, document_sha256 = ?
        WHERE label_id = ?
        """,
        (
            weak.quality.value,
            weak.source,
            weak.reviewer_id,
            raw,
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            weak.label_id,
        ),
    )


def test_resolved_m5_authority_projects_named_jsonl_and_validates_without_mutation(
    tmp_path: Path,
) -> None:
    database, run_id = _resolved(tmp_path)
    output = tmp_path / "projection"
    result = rebuild_m5_projection(
        config=_config(),
        run_id=run_id,
        database_path=database,
        workspace_root=output,
    )
    before_database = _fingerprint(database.parent)
    before_projection = _fingerprint(output)
    report = validate_m5_artifacts(
        config=_config(),
        run_id=run_id,
        database_path=database,
        workspace_root=output,
    )

    assert report.passed is True
    assert report.counts.authority_rows == report.counts.projection_records == 29
    inventory = {
        item.authority_kind: item.authoritative_count for item in report.counts.inventories
    }
    assert inventory[M5AuthorityKind.APPEAL_RESOLUTION_COMMIT] == 1
    assert inventory[M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE] == 1
    assert {path.name for path in result.jsonl_paths} == {
        "alerts.jsonl",
        "precedents.jsonl",
        "appeals.jsonl",
        "train_buffer.jsonl",
    }
    appeals_path = next(path for path in result.jsonl_paths if path.name == "appeals.jsonl")
    appeal_records = tuple(
        json.loads(line) for line in appeals_path.read_text(encoding="utf-8").splitlines()
    )
    commit_records = tuple(
        item
        for item in appeal_records
        if item["authority_kind"] == M5AuthorityKind.APPEAL_RESOLUTION_COMMIT
    )
    assert len(commit_records) == 1
    assert commit_records[0]["artifact_id"] == commit_records[0]["document"]["receipt_id"]
    train_buffer_path = next(
        path for path in result.jsonl_paths if path.name == "train_buffer.jsonl"
    )
    train_buffer_records = tuple(
        json.loads(line) for line in train_buffer_path.read_text(encoding="utf-8").splitlines()
    )
    provenance_records = tuple(
        item
        for item in train_buffer_records
        if item["authority_kind"] == M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE
    )
    assert len(provenance_records) == 1
    assert (
        provenance_records[0]["artifact_id"] == provenance_records[0]["document"]["provenance_id"]
    )
    assert _fingerprint(database.parent) == before_database
    assert _fingerprint(output) == before_projection
    replay = rebuild_m5_projection(
        config=_config(),
        run_id=run_id,
        database_path=database,
        workspace_root=output,
    )
    assert replay.generation_id == result.generation_id


def test_m5_projection_fault_never_selects_partial_generation(tmp_path: Path) -> None:
    database, repository, _, _, _, _, source, _, _, intent = _prepare_overturn(tmp_path)
    output = tmp_path / "projection"
    first = rebuild_m5_projection(
        config=_config(),
        run_id=source.run_id,
        database_path=database,
        workspace_root=output,
    )
    original_pointer = first.current_pointer_path.read_bytes()
    repository.commit_resolution(intent)

    def fault(phase: str) -> None:
        if phase == "before_current":
            raise RuntimeError("simulated crash")

    with pytest.raises(M5ProjectionFailure):
        rebuild_m5_projection(
            config=_config(),
            run_id=source.run_id,
            database_path=database,
            workspace_root=output,
            fault_injector=fault,
        )
    assert first.current_pointer_path.read_bytes() == original_pointer
    committed = rebuild_m5_projection(
        config=_config(),
        run_id=source.run_id,
        database_path=database,
        workspace_root=output,
    )
    assert committed.generation_id != first.generation_id


def test_m5_readonly_requires_strong_label_provenance_and_projection_fails_closed(
    tmp_path: Path,
) -> None:
    database, run_id = _resolved(tmp_path)
    _drop_update_restore(
        database,
        "strong_training_label_provenance_receipts_no_delete",
        "DELETE FROM strong_training_label_provenance_receipts",
    )

    authority = ReadonlyM5ArtifactRepository(database, config=_config()).scan(run_id)

    assert any(
        item.reason_code == "TRAINING_LABEL_PROVENANCE_MISSING"
        and item.authority_kind is M5AuthorityKind.TRAINING_LABEL
        for item in authority.failures
    )
    with pytest.raises(M5ProjectionFailure, match="failed closed"):
        M5JsonlProjector(tmp_path / "projection").publish(authority)


def test_m5_readonly_rejects_self_consistent_forged_provenance_root(
    tmp_path: Path,
) -> None:
    database, run_id = _resolved(tmp_path)
    _mutate_without_triggers(
        database,
        (
            "strong_training_label_provenance_receipts_no_update",
            "training_labels_no_update",
        ),
        _rewrite_provenance_terminal_root,
    )

    authority = ReadonlyM5ArtifactRepository(database, config=_config()).scan(run_id)
    reasons = {item.reason_code for item in authority.failures}

    assert "TRAINING_LABEL_TERMINAL_AUTHORITY_INVALID" in reasons
    assert "INDEX_BINDING_MISMATCH" not in reasons
    assert "CANONICAL_DOCUMENT_INVALID" not in reasons


def test_m5_readonly_rejects_extra_orphan_strong_provenance_receipt(
    tmp_path: Path,
) -> None:
    database, run_id = _resolved(tmp_path)
    _mutate_without_triggers(
        database,
        ("strong_training_label_provenance_receipts_validate_source",),
        _insert_orphan_provenance,
    )

    authority = ReadonlyM5ArtifactRepository(database, config=_config()).scan(run_id)

    assert any(
        item.reason_code == "TRAINING_LABEL_PROVENANCE_ORPHAN"
        and item.authority_kind is M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE
        for item in authority.failures
    )


def test_m5_readonly_rejects_weak_label_with_strong_provenance(tmp_path: Path) -> None:
    database, run_id = _resolved(tmp_path)
    _mutate_without_triggers(
        database,
        ("training_labels_no_update",),
        _rewrite_strong_label_as_weak,
    )

    authority = ReadonlyM5ArtifactRepository(database, config=_config()).scan(run_id)

    assert any(
        item.reason_code == "TRAINING_LABEL_WEAK_PROVENANCE_FORBIDDEN"
        for item in authority.failures
    )


@pytest.mark.parametrize(
    ("trigger_name", "statement", "reason_code"),
    (
        (
            "appeals_no_delete",
            "DELETE FROM appeals WHERE version = 2",
            "TRAINING_LABEL_REVIEW_AUTHORITY_INVALID",
        ),
        (
            "appeals_no_delete",
            "DELETE FROM appeals WHERE version = 3",
            "TRAINING_LABEL_TERMINAL_AUTHORITY_INVALID",
        ),
        (
            "appeal_resolution_receipts_no_delete",
            "DELETE FROM appeal_resolution_receipts",
            "TRAINING_LABEL_RESOLUTION_INTENT_INVALID",
        ),
        (
            "appeal_resolution_commit_receipts_no_delete",
            "DELETE FROM appeal_resolution_commit_receipts",
            "TRAINING_LABEL_RESOLUTION_COMMIT_INVALID",
        ),
        (
            "m5_precedent_causal_events_no_delete",
            "DELETE FROM m5_precedent_causal_events "
            "WHERE event_kind = 'APPEAL_RESOLUTION_COMMITTED'",
            "TRAINING_LABEL_RESOLUTION_MARKER_INVALID",
        ),
    ),
)
def test_m5_readonly_strong_provenance_requires_actual_resolution_roots(
    tmp_path: Path,
    trigger_name: str,
    statement: str,
    reason_code: str,
) -> None:
    database, run_id = _resolved(tmp_path)
    _drop_update_restore(database, trigger_name, statement)

    authority = ReadonlyM5ArtifactRepository(database, config=_config()).scan(run_id)

    assert any(item.reason_code == reason_code for item in authority.failures)


def test_m5_readonly_scan_reports_canonical_index_tamper_and_projection_fails_closed(
    tmp_path: Path,
) -> None:
    database, run_id = _resolved(tmp_path)
    _drop_update_restore(
        database,
        "precedents_no_update",
        "UPDATE precedents SET source = 'HUMAN_REVIEW' WHERE revision = 1",
    )
    authority = ReadonlyM5ArtifactRepository(database, config=_config()).scan(run_id)
    assert any(item.reason_code == "INDEX_BINDING_MISMATCH" for item in authority.failures)
    with pytest.raises(M5ProjectionFailure, match="failed closed"):
        M5JsonlProjector(tmp_path / "projection").publish(authority)


def test_m5_validation_and_rebuild_detect_tampered_selected_generation(tmp_path: Path) -> None:
    database, run_id = _resolved(tmp_path)
    output = tmp_path / "projection"
    result = rebuild_m5_projection(
        config=_config(),
        run_id=run_id,
        database_path=database,
        workspace_root=output,
    )
    result.jsonl_paths[0].write_bytes(b"{}\n")

    report = validate_m5_artifacts(
        config=_config(),
        run_id=run_id,
        database_path=database,
        workspace_root=output,
    )
    assert report.passed is False
    assert any(issue.reason_code == "EXPECTED_HASH_MISMATCH" for issue in report.issues)
    with pytest.raises(M5ProjectionFailure):
        rebuild_m5_projection(
            config=_config(),
            run_id=run_id,
            database_path=database,
            workspace_root=output,
        )


def test_m5_validation_rejects_extra_generation_inventory(tmp_path: Path) -> None:
    database, run_id = _resolved(tmp_path)
    output = tmp_path / "projection"
    result = rebuild_m5_projection(
        config=_config(),
        run_id=run_id,
        database_path=database,
        workspace_root=output,
    )
    (result.generation_directory / "unexpected.jsonl").write_bytes(b"")

    report = validate_m5_artifacts(
        config=_config(),
        run_id=run_id,
        database_path=database,
        workspace_root=output,
    )
    assert report.passed is False
    assert any(issue.reason_code == "GENERATION_INVENTORY_MISMATCH" for issue in report.issues)
