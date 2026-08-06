from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.m5_dataset_retention import m5_dataset_retention_holds
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import ArtifactKind, RetentionHoldKind, TrainingLabelQuality
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationBudget,
    M5ArtifactValidationIssueCode,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.storage import ArtifactRef, RetentionHold, ScopedArtifactRef
from labcourt.services.m5_artifact_validation import validate_m5_artifacts, validate_m5_snapshot
from labcourt.services.m5_projection import rebuild_m5_projection
from labcourt.services.m5_training_operations import export_m5_training_dataset
from tests.integration.test_m3_sqlite_repository import ROOT, RUN_ID
from tests.integration.test_m5_training_operations_service import (
    _direct_build,
    _export,
    _insert_training_labels,
    _prepare_training_run,
    _publish_direct_dataset,
    _reviewed_label,
    _stored_verifier,
)


def _config():
    return load_config(ROOT / "configs" / "demo.yaml")


def _validate(workspace_root: Path, database: Path, *, budget=None):
    return validate_m5_artifacts(
        config=_config(),
        run_id=RUN_ID,
        database_path=database,
        workspace_root=workspace_root,
        budget=budget,
    )


def _project(workspace_root: Path, database: Path) -> None:
    rebuild_m5_projection(
        config=_config(),
        run_id=RUN_ID,
        database_path=database,
        workspace_root=workspace_root,
    )


def _tamper_with_disabled_trigger(
    connection: sqlite3.Connection,
    trigger_name: str,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
        (trigger_name,),
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    connection.execute(f'DROP TRIGGER "{trigger_name}"')
    connection.execute(statement, parameters)
    connection.execute(row[0])


def test_readonly_validator_rebuilds_registered_dataset_bytes_and_retention_closure(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    exported = _export(prepared)
    _project(prepared.workspace_root, prepared.database)

    report = _validate(prepared.workspace_root, prepared.database)

    assert report.passed is True
    assert report.issues == ()
    assert report.counts.dataset_registrations == 1
    assert report.counts.verified_dataset_files == 1
    assert report.counts.dataset_bytes == exported.content_size_bytes
    assert report.counts.dataset_retention_holds == len(exported.crop_receipts)
    assert report.counts.orphan_retention_holds == 0


def test_readonly_dataset_rejects_exported_strong_label_with_orphaned_provenance(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    _project(prepared.workspace_root, prepared.database)
    with sqlite3.connect(prepared.database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'strong_training_label_provenance_receipts_no_delete'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute("DROP TRIGGER strong_training_label_provenance_receipts_no_delete")
        connection.execute("DELETE FROM strong_training_label_provenance_receipts")
        connection.execute(trigger_row[0])

    report = _validate(prepared.workspace_root, prepared.database)

    assert report.passed is False
    assert any(
        issue.reason_code == "DATASET_LABEL_PROVENANCE_INVALID"
        and issue.authority_kind is M5AuthorityKind.DATASET_ARTIFACT
        for issue in report.issues
    )
    assert any(
        issue.reason_code == "TRAINING_LABEL_PROVENANCE_MISSING"
        and issue.authority_kind is M5AuthorityKind.TRAINING_LABEL
        for issue in report.issues
    )


@pytest.mark.parametrize(
    ("tamper", "expected_code"),
    [
        ("dataset-bytes", M5ArtifactValidationIssueCode.DATASET_CONTENT_HASH_MISMATCH),
        ("dataset-missing", M5ArtifactValidationIssueCode.DATASET_CONTENT_MISSING),
        ("dataset-size", M5ArtifactValidationIssueCode.DATASET_CONTENT_SIZE_MISMATCH),
        ("dataset-link", M5ArtifactValidationIssueCode.DATASET_PATH_UNSAFE),
        ("crop-bytes", M5ArtifactValidationIssueCode.DATASET_CROP_AUTHORITY_INVALID),
    ],
)
def test_readonly_validator_reports_physical_and_durable_rebuild_divergence(
    tmp_path: Path,
    tamper: str,
    expected_code: M5ArtifactValidationIssueCode,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    exported = _export(prepared)
    _project(prepared.workspace_root, prepared.database)
    target = prepared.workspace_root / Path(exported.dataset.relative_path)
    if tamper == "dataset-bytes":
        changed = bytearray(target.read_bytes())
        changed[-2] ^= 1
        target.write_bytes(changed)
    elif tamper == "dataset-missing":
        target.unlink()
    elif tamper == "dataset-size":
        target.write_bytes(target.read_bytes() + b"x")
    elif tamper == "dataset-link":
        os.link(target, tmp_path / "dataset-hardlink.json")
    elif tamper == "crop-bytes":
        prepared.media_path.write_bytes(b"not-a-canonical-png")
    report = _validate(prepared.workspace_root, prepared.database)

    codes = {item.code for item in report.issues}
    assert expected_code in codes
    if tamper == "dataset-link":
        assert M5ArtifactValidationIssueCode.DATASET_DIRECTORY_UNSAFE in codes


def test_readonly_dataset_ignores_valid_label_appended_after_registration_cut(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    _insert_training_labels(
        prepared.database,
        (
            _reviewed_label(
                label_id="weak-tail-readonly",
                crop=prepared.crop,
                quality=TrainingLabelQuality.WEAK_AUTO,
            ),
        ),
    )
    _project(prepared.workspace_root, prepared.database)

    report = _validate(prepared.workspace_root, prepared.database)

    assert report.passed is True


def test_readonly_dataset_rejects_missing_registration_snapshot(tmp_path: Path) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    _project(prepared.workspace_root, prepared.database)
    with sqlite3.connect(prepared.database) as connection:
        _tamper_with_disabled_trigger(
            connection,
            "dataset_registration_snapshots_no_delete",
            "DELETE FROM dataset_registration_snapshots",
        )

    report = _validate(prepared.workspace_root, prepared.database)

    assert any(
        issue.reason_code == "DATASET_REGISTRATION_SNAPSHOT_MISSING"
        and issue.authority_kind is M5AuthorityKind.DATASET_ARTIFACT
        for issue in report.issues
    )


def test_readonly_dataset_rejects_forged_registration_snapshot_index(tmp_path: Path) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    _project(prepared.workspace_root, prepared.database)
    with sqlite3.connect(prepared.database) as connection:
        _tamper_with_disabled_trigger(
            connection,
            "dataset_registration_snapshots_no_update",
            "UPDATE dataset_registration_snapshots SET label_inventory_root_sha256 = ?",
            ("f" * 64,),
        )

    report = _validate(prepared.workspace_root, prepared.database)

    assert any(
        issue.code == M5ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH
        and issue.authority_kind is M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT
        for issue in report.issues
    )


def test_readonly_dataset_rejects_missing_training_label_event(tmp_path: Path) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    _project(prepared.workspace_root, prepared.database)
    with sqlite3.connect(prepared.database) as connection:
        _tamper_with_disabled_trigger(
            connection,
            "m5_training_causal_events_no_delete",
            "DELETE FROM m5_training_causal_events WHERE label_id = ?",
            ("weak-1",),
        )

    report = _validate(prepared.workspace_root, prepared.database)

    assert any(
        issue.code == M5ArtifactValidationIssueCode.TRAINING_CAUSAL_LEDGER_INVALID
        and issue.reason_code == "TRAINING_CAUSAL_EVENT_MISSING"
        for issue in report.issues
    )


def test_readonly_dataset_rejects_orphan_training_label_event(tmp_path: Path) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    _project(prepared.workspace_root, prepared.database)
    with sqlite3.connect(prepared.database) as connection:
        _tamper_with_disabled_trigger(
            connection,
            "training_labels_no_delete",
            "DELETE FROM training_labels WHERE label_id = ?",
            ("weak-1",),
        )

    report = _validate(prepared.workspace_root, prepared.database)

    assert any(
        issue.code == M5ArtifactValidationIssueCode.TRAINING_CAUSAL_LEDGER_INVALID
        and issue.reason_code == "TRAINING_CAUSAL_EVENT_ORPHAN"
        for issue in report.issues
    )


def test_readonly_dataset_rejects_forged_historical_pack(tmp_path: Path) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    _project(prepared.workspace_root, prepared.database)
    with sqlite3.connect(prepared.database) as connection:
        _tamper_with_disabled_trigger(
            connection,
            "evidence_packs_no_update",
            "UPDATE evidence_packs SET pack_json = ?",
            ("{}",),
        )

    report = _validate(prepared.workspace_root, prepared.database)

    assert any(
        issue.code == M5ArtifactValidationIssueCode.DATASET_SNAPSHOT_CLOSURE_INVALID
        and issue.reason_code == "DATASET_HISTORICAL_PACK_INVALID"
        for issue in report.issues
    )


def test_readonly_validator_rejects_registered_dataset_outside_canonical_run_directory(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    export_m5_training_dataset(
        config=_config(),
        workspace_root=prepared.workspace_root,
        database_path=prepared.database,
        run_id=RUN_ID,
        relative_path="datasets/noncanonical.coco.json",
    )
    _project(prepared.workspace_root, prepared.database)

    report = _validate(prepared.workspace_root, prepared.database)

    assert M5ArtifactValidationIssueCode.DATASET_PATH_UNSAFE in {
        item.code for item in report.issues
    }


@pytest.mark.parametrize(
    ("tamper", "expected_code"),
    [
        ("missing", M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_MISSING),
        ("released", M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_RELEASED),
        ("extra", M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_EXTRA),
        (
            "wrong-owner",
            M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_OWNER_MISMATCH,
        ),
        (
            "missing-link",
            M5ArtifactValidationIssueCode.DATASET_RETENTION_AUDIT_LINK_INVALID,
        ),
    ],
)
def test_readonly_validator_replays_exact_dataset_hold_and_audit_closure(
    tmp_path: Path,
    tamper: str,
    expected_code: M5ArtifactValidationIssueCode,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    exported = _export(prepared)
    expected = m5_dataset_retention_holds(exported)[0]
    with sqlite3.connect(prepared.database) as connection:
        if tamper == "missing":
            connection.execute("DROP TRIGGER retention_hold_audit_links_no_delete")
            connection.execute("DROP TRIGGER retention_holds_no_delete")
            connection.execute(
                "DELETE FROM retention_hold_audit_links WHERE run_id = ? AND hold_id = ?",
                (RUN_ID, expected.hold_id),
            )
            connection.execute(
                "DELETE FROM retention_holds WHERE run_id = ? AND hold_id = ?",
                (RUN_ID, expected.hold_id),
            )
        elif tamper == "released":
            connection.execute("DROP TRIGGER retention_holds_controlled_release")
            connection.execute(
                "UPDATE retention_holds SET active = 0 WHERE run_id = ? AND hold_id = ?",
                (RUN_ID, expected.hold_id),
            )
        elif tamper == "extra":
            _insert_hold_row(
                connection,
                expected.model_copy(
                    update={"hold_id": sha256_hex(["readonly-extra-hold", expected.hold_id])}
                ),
            )
        elif tamper == "wrong-owner":
            forged = RetentionHold(
                run_id=expected.run_id,
                hold_id=expected.hold_id,
                target_ref=expected.target_ref,
                kind=expected.kind,
                owner_ref=ScopedArtifactRef(
                    run_id=RUN_ID,
                    ref=ArtifactRef(kind=ArtifactKind.DATASET, artifact_id="wrong-dataset"),
                ),
                manifest_id=expected.manifest_id,
                policy_version=expected.policy_version,
                reason_code=expected.reason_code,
            )
            raw = canonical_json(forged.model_dump(mode="json"))
            connection.execute("DROP TRIGGER retention_holds_controlled_release")
            connection.execute(
                """
                UPDATE retention_holds
                SET owner_id = ?, hold_json = ?, document_sha256 = ?
                WHERE run_id = ? AND hold_id = ?
                """,
                (
                    forged.owner_ref.ref.artifact_id,
                    raw,
                    hashlib.sha256(raw.encode()).hexdigest(),
                    RUN_ID,
                    expected.hold_id,
                ),
            )
        else:
            connection.execute("DROP TRIGGER retention_hold_audit_links_no_delete")
            connection.execute(
                "DELETE FROM retention_hold_audit_links WHERE run_id = ? AND hold_id = ?",
                (RUN_ID, expected.hold_id),
            )
        connection.commit()
    _project(prepared.workspace_root, prepared.database)

    report = _validate(prepared.workspace_root, prepared.database)

    codes = {item.code for item in report.issues}
    assert expected_code in codes
    if tamper == "released":
        assert M5ArtifactValidationIssueCode.DATASET_RETENTION_HOLD_DOCUMENT_MISMATCH not in codes


def test_readonly_validator_reports_file_first_database_rollback_orphan_without_deleting(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = _config()
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        built = _direct_build(prepared, _stored_verifier(workspace))
        _publish_direct_dataset(workspace, built)
    orphan_path = prepared.workspace_root / Path(built.report.dataset.relative_path)
    _project(prepared.workspace_root, prepared.database)

    report = _validate(prepared.workspace_root, prepared.database)

    assert M5ArtifactValidationIssueCode.DATASET_UNREGISTERED_FILE in {
        item.code for item in report.issues
    }
    assert report.counts.unregistered_dataset_files == 1
    assert orphan_path.is_file()


def test_main_validation_applicability_includes_physical_orphan_without_any_m5_row(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = _config()
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        built = _direct_build(prepared, _stored_verifier(workspace))
        _publish_direct_dataset(workspace, built)
    with sqlite3.connect(prepared.database) as connection:
        trigger_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            ("training_labels_no_delete",),
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute("DROP TRIGGER training_labels_no_delete")
        connection.execute("DELETE FROM training_labels WHERE run_id = ?", (RUN_ID,))
        connection.execute(trigger_row[0])
        connection.commit()

    with readonly_sqlite_snapshot(prepared.database) as snapshot:
        report = validate_m5_snapshot(
            config=config,
            run_id=RUN_ID,
            snapshot_path=snapshot,
            workspace_root=prepared.workspace_root,
            only_if_authority=True,
        )

    assert report is not None
    assert M5ArtifactValidationIssueCode.DATASET_UNREGISTERED_FILE in {
        item.code for item in report.issues
    }


def test_dataset_directory_total_bytes_budget_includes_unregistered_files(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = _config()
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        built = _direct_build(prepared, _stored_verifier(workspace))
        _publish_direct_dataset(workspace, built)
    _project(prepared.workspace_root, prepared.database)

    report = _validate(
        prepared.workspace_root,
        prepared.database,
        budget=M5ArtifactValidationBudget(
            max_dataset_total_bytes=max(1, len(built.content) - 1),
        ),
    )

    assert M5ArtifactValidationIssueCode.DATASET_TOTAL_BYTES_BUDGET_EXCEEDED in {
        item.code for item in report.issues
    }


def test_dataset_directory_item_budget_preflights_before_orphan_reads(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    config = _config()
    with SecureWorkspace(
        prepared.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        built = _direct_build(prepared, _stored_verifier(workspace))
        _publish_direct_dataset(workspace, built)
        second = b"{}"
        workspace.create_new(
            f"{RUN_ID}/datasets/second-orphan.json",
            second,
            hashlib.sha256(second).hexdigest(),
        )
    _project(prepared.workspace_root, prepared.database)

    report = _validate(
        prepared.workspace_root,
        prepared.database,
        budget=M5ArtifactValidationBudget(max_dataset_files=1),
    )

    assert M5ArtifactValidationIssueCode.DATASET_FILE_COUNT_BUDGET_EXCEEDED in {
        item.code for item in report.issues
    }


def test_readonly_validation_never_creates_a_missing_dataset_directory(tmp_path: Path) -> None:
    prepared = _prepare_training_run(tmp_path)
    dataset_directory = prepared.workspace_root / RUN_ID / "datasets"
    assert not dataset_directory.exists()
    _project(prepared.workspace_root, prepared.database)

    _validate(prepared.workspace_root, prepared.database)

    assert not dataset_directory.exists()


@pytest.mark.parametrize(
    ("owner_kind", "hold_kind", "expected_code"),
    [
        (
            ArtifactKind.DATASET,
            RetentionHoldKind.GOLD_SET,
            M5ArtifactValidationIssueCode.ORPHAN_DATASET_RETENTION_HOLD,
        ),
        (
            ArtifactKind.APPEAL,
            RetentionHoldKind.APPEAL,
            M5ArtifactValidationIssueCode.ORPHAN_APPEAL_RETENTION_HOLD,
        ),
    ],
)
def test_readonly_validator_classifies_orphan_appeal_and_dataset_holds(
    tmp_path: Path,
    owner_kind: ArtifactKind,
    hold_kind: RetentionHoldKind,
    expected_code: M5ArtifactValidationIssueCode,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    hold = RetentionHold(
        run_id=RUN_ID,
        hold_id=sha256_hex(["readonly-orphan-hold", owner_kind.value]),
        target_ref=ScopedArtifactRef(
            run_id=RUN_ID,
            ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=prepared.crop.crop_id),
        ),
        kind=hold_kind,
        owner_ref=ScopedArtifactRef(
            run_id=RUN_ID,
            ref=ArtifactRef(kind=owner_kind, artifact_id=f"missing-{owner_kind.value.lower()}"),
        ),
        manifest_id=prepared.manifest.manifest_id,
        policy_version="readonly-orphan-policy-v1",
        reason_code="readonly-orphan-test",
    )
    with sqlite3.connect(prepared.database) as connection:
        _insert_hold_row(connection, hold)
        connection.commit()
    _project(prepared.workspace_root, prepared.database)

    report = _validate(prepared.workspace_root, prepared.database)

    assert expected_code in {item.code for item in report.issues}
    assert report.counts.orphan_retention_holds == 1


def test_retention_sql_preflight_rejects_before_document_decoder(
    tmp_path: Path,
) -> None:
    prepared = _prepare_training_run(tmp_path)
    _export(prepared)
    calls = 0

    def decoder_spy(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("retention decoder must not run after SQL budget failure")

    with patch(
        "labcourt.adapters.storage._readonly_m5_artifact_relations.RetentionHold.model_validate_json",
        side_effect=decoder_spy,
    ):
        report = _validate(
            prepared.workspace_root,
            prepared.database,
            budget=M5ArtifactValidationBudget(max_retention_record_bytes=64),
        )

    assert calls == 0
    assert {item.code for item in report.issues} == {
        M5ArtifactValidationIssueCode.RETENTION_RECORD_BYTES_BUDGET_EXCEEDED
    }


def _insert_hold_row(connection: sqlite3.Connection, hold: RetentionHold) -> None:
    raw = canonical_json(hold.model_dump(mode="json"))
    connection.execute(
        """
        INSERT INTO retention_holds(
            run_id, hold_id, target_kind, target_id, hold_kind, owner_kind,
            owner_id, active, manifest_id, policy_version, reason_code,
            hold_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
        """,
        (
            hold.run_id,
            hold.hold_id,
            hold.target_ref.ref.kind.value,
            hold.target_ref.ref.artifact_id,
            hold.kind.value,
            hold.owner_ref.ref.kind.value,
            hold.owner_ref.ref.artifact_id,
            hold.manifest_id,
            hold.policy_version,
            hold.reason_code,
            raw,
            hashlib.sha256(raw.encode()).hexdigest(),
        ),
    )
