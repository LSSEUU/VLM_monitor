from __future__ import annotations

import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.storage.sqlite_schema import (
    M6_UPGRADE_LEDGER_INDEXES,
    M6_UPGRADE_LEDGER_OBJECTS,
    M6_UPGRADE_LEDGER_TABLES,
    M6_UPGRADE_LEDGER_TRIGGERS,
    m6_upgrade_ledger_installed,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory

MIGRATIONS = Path(__file__).parents[2] / "src" / "labcourt" / "adapters" / "storage" / "migrations"
BUSY_TIMEOUT_MS = 5_000
AUDIT_GENESIS_HASH = "0" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_document(value: object) -> tuple[str, str, int]:
    raw = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    return raw, _sha(raw), len(raw.encode("utf-8"))


def _install(tmp_path: Path) -> Path:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, MIGRATIONS).apply_all() == tuple(range(1, 19))
    return database


def _copy_migrations(destination: Path, *, through: int) -> None:
    destination.mkdir()
    for version in range(1, through + 1):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, destination / source.name)


def _register_scope(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority | None = None,
) -> M6UpgradeExecutionScopeAuthority:
    scope = scope or _inventory().execution_ledger.execution_scope
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    repository.register_run(scope.candidate_run_id, scope.candidate_manifest)
    raw, document_sha256, size_bytes = _canonical_document(scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO m6_upgrade_execution_scopes(
                run_id, execution_scope_authority_id, command_id,
                execution_dataset_snapshot_id, candidate_manifest_id,
                candidate_manifest_document_sha256, candidate_config_sha256,
                execution_component_authority_id, expected_sample_count,
                execution_start_audit_head_sequence,
                execution_start_audit_head_hash, scope_json,
                document_sha256, size_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
                scope.command.command_id,
                scope.execution_dataset.execution_dataset_snapshot_id,
                scope.candidate_manifest.manifest_id,
                scope.candidate_manifest_content_sha256,
                scope.candidate_config.config_sha256,
                scope.execution_component.component_authority_id,
                len(scope.execution_dataset.entries),
                scope.execution_start_audit_head_sequence,
                scope.execution_start_audit_head_hash,
                raw,
                document_sha256,
                size_bytes,
            ),
        )
    return scope


def _single_no_case_execution() -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecord,
]:
    ledger = _inventory().execution_ledger
    scope = ledger.execution_scope
    record = next(
        item
        for item in ledger.sample_executions
        if item.outcome == M6ReplayExecutionOutcome.NO_CASE
    )
    dataset = scope.execution_dataset.model_copy(update={"entries": (record.execution_entry,)})
    command = scope.command.model_copy(
        update={"execution_dataset_snapshot_id": dataset.execution_dataset_snapshot_id}
    )
    _command_raw, command_sha256, command_size = _canonical_document(command)
    _dataset_raw, dataset_sha256, dataset_size = _canonical_document(dataset)
    reduced_scope = scope.model_copy(
        update={
            "command": command,
            "command_content_sha256": command_sha256,
            "command_size_bytes": command_size,
            "execution_dataset": dataset,
            "execution_dataset_content_sha256": dataset_sha256,
            "execution_dataset_size_bytes": dataset_size,
        }
    )
    reduced_record = record.model_copy(
        update={
            "execution_scope_authority_id": reduced_scope.execution_scope_authority_id,
            "command_id": command.command_id,
            "execution_dataset_snapshot_id": dataset.execution_dataset_snapshot_id,
            "ledger_sequence": 0,
            "previous_ledger_entry_hash": M6_UPGRADE_LEDGER_GENESIS_HASH,
        }
    )
    return reduced_scope, reduced_record


def _insert_ref(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    link: M6UpgradeSampleArtifactLink,
) -> None:
    _insert_physical_ref(connection, scope, link.artifact)


def _insert_physical_ref(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    ref: M6UpgradePhysicalArtifactRef,
) -> None:
    raw, document_sha256, size_bytes = _canonical_document(ref)
    connection.execute(
        """
        INSERT INTO m6_upgrade_physical_artifact_refs(
            run_id, execution_scope_authority_id, artifact_ref_id,
            source, kind, artifact_id, container_id,
            artifact_document_sha256, artifact_content_sha256,
            artifact_size_bytes, ref_json, ref_document_sha256,
            ref_size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            ref.artifact_ref_id,
            ref.source.value,
            ref.kind.value,
            ref.artifact_id,
            ref.container_id,
            ref.document_sha256,
            ref.content_sha256,
            ref.size_bytes,
            raw,
            document_sha256,
            size_bytes,
        ),
    )


def _insert_link(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecord,
    link: M6UpgradeSampleArtifactLink,
) -> None:
    raw, document_sha256, size_bytes = _canonical_document(link)
    connection.execute(
        """
        INSERT INTO m6_upgrade_sample_artifact_links(
            run_id, execution_entry_id, ordinal, usage, artifact_ref_id,
            artifact_link_id, link_json, link_document_sha256, link_size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scope.candidate_run_id,
            record.execution_entry_id,
            link.ordinal,
            link.usage.value,
            link.artifact.artifact_ref_id,
            link.artifact_link_id,
            raw,
            document_sha256,
            size_bytes,
        ),
    )


def _insert_sample(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecord,
) -> None:
    raw, document_sha256, size_bytes = _canonical_document(record)
    connection.execute(
        """
        INSERT INTO m6_upgrade_sample_executions(
            run_id, execution_scope_authority_id, ledger_sequence,
            previous_ledger_entry_hash, command_id,
            execution_dataset_snapshot_id, execution_entry_id, sample_id,
            outcome, case_id, case_revision, case_document_sha256,
            case_audit_sequence, case_audit_entry_hash, artifact_link_count,
            artifact_link_inventory_root_sha256, sample_execution_record_id,
            record_json, record_document_sha256, record_size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL,
                  ?, ?, ?, ?, ?, ?)
        """,
        (
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            record.ledger_sequence,
            record.previous_ledger_entry_hash,
            record.command_id,
            record.execution_dataset_snapshot_id,
            record.execution_entry_id,
            record.sample_id,
            record.outcome.value,
            record.artifact_link_count,
            record.artifact_link_inventory_root_sha256,
            record.sample_execution_record_id,
            raw,
            document_sha256,
            size_bytes,
        ),
    )


def _insert_seal(
    connection: sqlite3.Connection,
    seal: M6UpgradeExecutionLedgerSeal,
    *,
    raw_override: str | None = None,
) -> None:
    raw, document_sha256, size_bytes = _canonical_document(seal)
    if raw_override is not None:
        raw = raw_override
        document_sha256 = _sha(raw)
        size_bytes = len(raw.encode("utf-8"))
    connection.execute(
        """
        INSERT INTO m6_upgrade_execution_ledger_seals(
            run_id, execution_scope_authority_id,
            execution_scope_document_sha256, execution_scope_size_bytes,
            source_audit_head_sequence, source_audit_head_hash,
            sample_execution_count, sample_execution_inventory_root_sha256,
            artifact_link_count, artifact_link_inventory_root_sha256,
            candidate_case_count, candidate_case_inventory_root_sha256,
            ledger_preseal_sequence, ledger_preseal_hash,
            ledger_head_sequence, ledger_seal_authority_id,
            seal_json, document_sha256, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            seal.candidate_run_id,
            seal.execution_scope.execution_scope_authority_id,
            seal.execution_scope_content_sha256,
            seal.execution_scope_size_bytes,
            seal.source_audit_head_sequence,
            seal.source_audit_head_hash,
            seal.sample_execution_count,
            seal.sample_execution_inventory_root_sha256,
            seal.artifact_link_count,
            seal.artifact_link_inventory_root_sha256,
            seal.candidate_case_count,
            seal.candidate_case_inventory_root_sha256,
            seal.ledger_preseal_sequence,
            seal.ledger_preseal_hash,
            seal.ledger_head_sequence,
            seal.ledger_seal_authority_id,
            raw,
            document_sha256,
            size_bytes,
        ),
    )


def test_migrations_0010_through_0014_install_the_complete_m6_ledger_authority(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    with sqlite3.connect(database) as connection:
        observed = {
            (str(row[0]), str(row[1]))
            for row in connection.execute("SELECT type, name FROM sqlite_master")
        }
        assert m6_upgrade_ledger_installed(connection)
        assert {("table", name) for name in M6_UPGRADE_LEDGER_TABLES} <= observed
        assert {("index", name) for name in M6_UPGRADE_LEDGER_INDEXES} <= observed
        assert {("trigger", name) for name in M6_UPGRADE_LEDGER_TRIGGERS} <= observed
        assert len(M6_UPGRADE_LEDGER_OBJECTS) == 75


@pytest.mark.parametrize(
    ("object_type", "object_name"),
    [
        ("table", "m6_upgrade_execution_scopes"),
        ("table", "m6_upgrade_execution_ledger_protocols"),
        ("table", "m6_upgrade_physical_artifact_refs"),
        ("table", "m6_upgrade_pending_sample_commitments"),
        ("table", "m6_upgrade_execution_ledger_seals"),
        ("index", "uq_runs_m6_audit_cut"),
        ("index", "uq_m6_upgrade_physical_artifact_key"),
        ("index", "uq_m6_upgrade_pending_commitment_record"),
        ("trigger", "runs_m6_require_genesis_insert"),
        ("trigger", "audit_entries_m6_require_next"),
        ("trigger", "runs_m6_audit_head_matches_entry"),
        ("trigger", "m6_upgrade_execution_scopes_require_complete_json"),
        ("trigger", "m6_upgrade_physical_artifact_refs_require_complete_json"),
        ("trigger", "m6_upgrade_sample_artifact_links_validate"),
        ("trigger", "m6_upgrade_sample_artifact_links_require_complete_json"),
        ("trigger", "m6_upgrade_sample_executions_validate_observation_backing"),
        ("trigger", "m6_upgrade_execution_ledger_seals_no_delete"),
    ],
)
def test_m6_installation_check_rejects_a_missing_security_object(
    tmp_path: Path,
    object_type: str,
    object_name: str,
) -> None:
    database = _install(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(f'DROP {object_type.upper()} "{object_name}"')
        assert not m6_upgrade_ledger_installed(connection)


def test_migration_0010_preflight_rejects_a_legacy_run_with_a_ghost_head(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=9)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 10))
    manifest_id = _sha("legacy-manifest")
    ghost_head = _sha("ghost-head")
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO run_manifests(
                manifest_id, schema_version, document_json,
                document_sha256, registered_at
            ) VALUES (?, '2.0.0', '{}', ?, '2026-08-03T00:00:00.000000Z')
            """,
            (manifest_id, _sha("{}")),
        )
        connection.execute(
            """
            INSERT INTO runs(
                run_id, manifest_id, revision, audit_head_sequence,
                audit_head_hash, registered_at
            ) VALUES ('legacy-ghost-run', ?, 1, 0, ?, '2026-08-03T00:00:00.000000Z')
            """,
            (manifest_id, ghost_head),
        )
    shutil.copy2(next(MIGRATIONS.glob("0010_*.sql")), copied)

    with pytest.raises(MigrationIntegrityError, match=r"migration 0010.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 10").fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'm6_upgrade_execution_scopes'"
            ).fetchone()
            is None
        )


def test_m6_audit_hardening_rejects_non_genesis_runs_and_unbacked_heads(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    scope = _inventory().execution_ledger.execution_scope
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    repository.register_run(scope.candidate_run_id, scope.candidate_manifest)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="new runs must start"):
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, manifest_id, revision, audit_head_sequence,
                    audit_head_hash, registered_at
                ) VALUES ('forged-run', ?, 1, 0, ?, '2026-08-03T00:00:00.000000Z')
                """,
                (scope.candidate_manifest.manifest_id, _sha("forged-head")),
            )
        with pytest.raises(sqlite3.IntegrityError, match="exact immutable audit entry"):
            connection.execute(
                """
                UPDATE runs
                SET revision = 1, audit_head_sequence = 0, audit_head_hash = ?
                WHERE run_id = ?
                """,
                (_sha("missing-audit-entry"), scope.candidate_run_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="extend the exact current run head"):
            connection.execute(
                """
                INSERT INTO audit_entries(
                    run_id, sequence, manifest_id, actor, action,
                    object_kind, object_id, before_sha256, after_sha256,
                    recorded_at, prev_entry_hash, entry_hash,
                    entry_json, document_sha256
                ) VALUES (?, 1, ?, 'ATTACKER', 'CREATE', 'CASE', 'ghost-case',
                          NULL, NULL, '2026-08-03T00:00:00.000000Z', ?, ?, '{}', ?)
                """,
                (
                    scope.candidate_run_id,
                    scope.candidate_manifest.manifest_id,
                    AUDIT_GENESIS_HASH,
                    _sha("out-of-order-entry"),
                    _sha("{}"),
                ),
            )


def test_m6_scope_rejects_a_detached_audit_entry_committed_before_scope(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    scope = _inventory().execution_ledger.execution_scope
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    repository.register_run(scope.candidate_run_id, scope.candidate_manifest)
    detached_hash = _sha("detached-before-scope")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO audit_entries(
                run_id, sequence, manifest_id, actor, action,
                object_kind, object_id, before_sha256, after_sha256,
                recorded_at, prev_entry_hash, entry_hash,
                entry_json, document_sha256
            ) VALUES (?, 0, ?, 'ATTACKER', 'CREATE', 'CASE', 'detached-case',
                      NULL, ?, '2026-08-03T00:00:00.000000Z', ?, ?, '{}', ?)
            """,
            (
                scope.candidate_run_id,
                scope.candidate_manifest.manifest_id,
                _sha("detached-case"),
                AUDIT_GENESIS_HASH,
                detached_hash,
                _sha("{}"),
            ),
        )
        connection.commit()

    with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade execution scope"):
        _register_scope(database, scope)

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM m6_upgrade_execution_scopes WHERE run_id = ?",
                (scope.candidate_run_id,),
            ).fetchone()
            is None
        )
        connection.execute(
            """
            UPDATE runs
            SET revision = 1, audit_head_sequence = 0, audit_head_hash = ?
            WHERE run_id = ?
            """,
            (detached_hash, scope.candidate_run_id),
        )


def test_m6_scope_is_exact_append_only_and_rejects_invalid_physical_routes(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    scope = _register_scope(database)
    frame = _inventory().execution_ledger.sample_executions[0].artifact_links[0].artifact
    raw_ref = canonical_json(frame.model_dump(mode="json"))
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m6_upgrade_execution_scopes SET size_bytes = size_bytes WHERE run_id = ?",
                (scope.candidate_run_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM m6_upgrade_execution_scopes WHERE run_id = ?",
                (scope.candidate_run_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade physical artifact"):
            connection.execute(
                """
                INSERT INTO m6_upgrade_physical_artifact_refs(
                    run_id, execution_scope_authority_id, artifact_ref_id,
                    source, kind, artifact_id, container_id,
                    artifact_document_sha256, artifact_content_sha256,
                    artifact_size_bytes, ref_json, ref_document_sha256,
                    ref_size_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope.candidate_run_id,
                    scope.execution_scope_authority_id,
                    frame.artifact_ref_id,
                    M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL.value,
                    frame.kind.value,
                    frame.artifact_id,
                    frame.container_id,
                    frame.document_sha256,
                    frame.content_sha256,
                    frame.size_bytes,
                    raw_ref,
                    _sha(raw_ref),
                    len(raw_ref.encode("utf-8")),
                ),
            )
        grafted_payload = frame.model_dump(mode="python", exclude_computed_fields=True)
        grafted_payload["container_id"] = "camera-graft:stream:0"
        grafted_frame = M6UpgradePhysicalArtifactRef.model_construct(**grafted_payload)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_physical_ref(connection, scope, grafted_frame)

        detection_link = next(
            link
            for record in _inventory().execution_ledger.sample_executions
            for link in record.artifact_links
            if link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
        )
        mismatched_payload = detection_link.artifact.model_dump(
            mode="python",
            exclude_computed_fields=True,
        )
        mismatched_payload["content_sha256"] = _sha("canonical-content-mismatch")
        mismatched_detection = M6UpgradePhysicalArtifactRef.model_construct(**mismatched_payload)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_physical_ref(connection, scope, mismatched_detection)


def test_m6_no_case_sample_rejects_case_scoped_artifact_even_with_exact_forged_ids(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    scope, source_record = _single_no_case_execution()
    _register_scope(database, scope)
    case_record = next(
        record
        for record in _inventory().execution_ledger.sample_executions
        if record.candidate_case is not None
    )
    case_scoped_link = next(
        link
        for link in case_record.artifact_links
        if link.artifact.kind
        not in {
            M6UpgradePhysicalArtifactKind.FRAME,
            M6UpgradePhysicalArtifactKind.DETECTION,
        }
    )
    ordered = tuple(
        sorted(
            (
                *((link.artifact, link.usage) for link in source_record.artifact_links),
                (case_scoped_link.artifact, case_scoped_link.usage),
            ),
            key=lambda item: item[0].physical_key,
        )
    )
    links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=ordinal,
            usage=usage,
            artifact=artifact,
        )
        for ordinal, (artifact, usage) in enumerate(ordered)
    )
    forged = M6UpgradeSampleExecutionRecord.model_construct(
        schema_version=source_record.schema_version,
        execution_scope_authority_id=source_record.execution_scope_authority_id,
        candidate_run_id=source_record.candidate_run_id,
        command_id=source_record.command_id,
        execution_dataset_snapshot_id=source_record.execution_dataset_snapshot_id,
        execution_entry=source_record.execution_entry,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifact_links=links,
        ledger_sequence=source_record.ledger_sequence,
        previous_ledger_entry_hash=source_record.previous_ledger_entry_hash,
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for link in forged.artifact_links:
            _insert_ref(connection, scope, link)
            _insert_link(connection, scope, forged, link)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution",
        ):
            _insert_sample(connection, scope, forged)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_sample_executions"
        ).fetchone() == (0,)
        connection.rollback()


def test_migration_0011_does_not_retroactively_change_legacy_v1_sample_semantics(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    scope, source_record = _single_no_case_execution()
    _register_scope(database, scope)
    frame_link = next(
        link
        for link in source_record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    oversized_frame = frame_link.artifact.model_copy(
        update={"size_bytes": MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES + 1}
    )
    links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=ordinal,
            usage=link.usage,
            artifact=(
                oversized_frame
                if link.artifact.artifact_ref_id == frame_link.artifact.artifact_ref_id
                else link.artifact
            ),
        )
        for ordinal, link in enumerate(source_record.artifact_links)
    )
    forged = M6UpgradeSampleExecutionRecord.model_construct(
        schema_version=source_record.schema_version,
        execution_scope_authority_id=source_record.execution_scope_authority_id,
        candidate_run_id=source_record.candidate_run_id,
        command_id=source_record.command_id,
        execution_dataset_snapshot_id=source_record.execution_dataset_snapshot_id,
        execution_entry=source_record.execution_entry,
        outcome=source_record.outcome,
        candidate_case=source_record.candidate_case,
        artifact_links=links,
        ledger_sequence=source_record.ledger_sequence,
        previous_ledger_entry_hash=source_record.previous_ledger_entry_hash,
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for link in forged.artifact_links:
            _insert_ref(connection, scope, link)
            _insert_link(connection, scope, forged, link)
        _insert_sample(connection, scope, forged)
        assert connection.execute(
            "SELECT sample_execution_record_id FROM m6_upgrade_sample_executions WHERE run_id = ?",
            (scope.candidate_run_id,),
        ).fetchone() == (forged.sample_execution_record_id,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_sample_executions"
        ).fetchone() == (1,)
        connection.rollback()


def test_m6_links_and_sample_accept_one_canonical_execution_then_freeze(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    scope, record = _single_no_case_execution()
    _register_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for link in record.artifact_links:
            _insert_ref(connection, scope, link)
            _insert_link(connection, scope, record, link)
        _insert_sample(connection, scope, record)
        connection.commit()

        stored = connection.execute(
            """
            SELECT sample_execution_record_id, artifact_link_count
            FROM m6_upgrade_sample_executions
            WHERE run_id = ? AND ledger_sequence = 0
            """,
            (scope.candidate_run_id,),
        ).fetchone()
        assert stored == (record.sample_execution_record_id, record.artifact_link_count)

        late_link = record.artifact_links[0].model_copy(
            update={"ordinal": record.artifact_link_count}
        )
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade sample artifact link"):
            _insert_link(connection, scope, record, late_link)
        connection.rollback()

        _scope_raw, scope_document_sha256, scope_size_bytes = _canonical_document(scope)
        seal = M6UpgradeExecutionLedgerSeal(
            execution_scope=scope,
            execution_scope_content_sha256=scope_document_sha256,
            execution_scope_size_bytes=scope_size_bytes,
            source_audit_head_sequence=-1,
            source_audit_head_hash=AUDIT_GENESIS_HASH,
            sample_executions=(record,),
        )
        tampered_payload = seal.model_dump(mode="json")
        tampered_payload["sample_executions"][0]["sample_id"] = "forged-sample"
        with pytest.raises(
            sqlite3.IntegrityError,
            match=r"invalid M6 upgrade (?:execution ledger seal|ledger schema-version closure)",
        ):
            _insert_seal(
                connection,
                seal,
                raw_override=canonical_json(tampered_payload),
            )
        connection.rollback()

        _insert_seal(connection, seal)
        connection.commit()
        assert connection.execute(
            "SELECT ledger_seal_authority_id FROM m6_upgrade_execution_ledger_seals"
        ).fetchone() == (seal.ledger_seal_authority_id,)
