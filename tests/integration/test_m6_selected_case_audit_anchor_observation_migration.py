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
from labcourt.contracts.audit import AuditAction
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.storage import ArtifactRef
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
    MIGRATIONS,
    _canonical_document,
    _register_scope,
    _single_no_case_execution,
)
from tests.integration.test_m6_upgrade_execution_observation_repository import (
    _insert_children,
)
from tests.integration.test_m6_upgrade_observation_backed_ledger_migration import (
    _candidate_case_binding,
    _commitment,
    _insert_commitment,
    _insert_observation,
    _insert_v2_protocol_and_scope,
    _observation_for,
    _v2_record,
)


def _sha(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _copy_migrations(destination: Path, *, through: int) -> None:
    destination.mkdir()
    for version in range(1, through + 1):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, destination / source.name)


def _register_scope_with_protocol(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
    protocol_version: str,
) -> None:
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    raw, document_sha256, size_bytes = _canonical_document(scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO m6_upgrade_execution_ledger_protocols(
                run_id, execution_scope_authority_id, protocol_version
            ) VALUES (?, ?, ?)
            """,
            (
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
                protocol_version,
            ),
        )
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


def _v2_no_case_observation(
    scope: M6UpgradeExecutionScopeAuthority,
    source: M6UpgradeSampleExecutionRecord,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    legacy = _observation_for(scope, source)
    return M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=legacy.execution_scope_authority_id,
        candidate_run_id=legacy.candidate_run_id,
        command_id=legacy.command_id,
        execution_dataset_snapshot_id=legacy.execution_dataset_snapshot_id,
        execution_entry=legacy.execution_entry,
        ledger_sequence=legacy.ledger_sequence,
        outcome=legacy.outcome,
        candidate_case=None,
        artifacts=legacy.artifacts,
        model_calls=legacy.model_calls,
        selected_case_audit_anchor=None,
    )


def _v2_case_observation(
    scope: M6UpgradeExecutionScopeAuthority,
    source: M6UpgradeSampleExecutionRecord,
    binding: M6UpgradeCandidateCaseBinding,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    legacy = _observation_for(scope, source, candidate_case=binding)
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=AuditAction.CASE_CREATED,
        object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=binding.case_id),
    )
    return M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=legacy.execution_scope_authority_id,
        candidate_run_id=legacy.candidate_run_id,
        command_id=legacy.command_id,
        execution_dataset_snapshot_id=legacy.execution_dataset_snapshot_id,
        execution_entry=legacy.execution_entry,
        ledger_sequence=legacy.ledger_sequence,
        outcome=legacy.outcome,
        candidate_case=binding,
        artifacts=legacy.artifacts,
        model_calls=legacy.model_calls,
        selected_case_audit_anchor=anchor,
    )


def _insert_versioned_parent(
    connection: sqlite3.Connection,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    *,
    observation_schema_version: str,
    raw: str | None = None,
    anchor_id: str | None = None,
    action: str | None = None,
    object_kind: str | None = None,
    object_id: str | None = None,
) -> None:
    document = raw or canonical_json(observation.model_dump(mode="json"))
    candidate_case = observation.candidate_case
    anchor = getattr(observation, "selected_case_audit_anchor", None)
    connection.execute(
        """
        INSERT INTO m6_upgrade_sample_execution_observations(
            run_id, execution_scope_authority_id, ledger_sequence,
            observation_authority_id, command_id,
            execution_dataset_snapshot_id, execution_entry_id,
            sample_id, outcome, case_id, case_revision,
            case_document_sha256, case_audit_sequence,
            case_audit_entry_hash, artifact_count, model_call_count,
            observation_json, document_sha256, size_bytes,
            observation_schema_version, selected_case_audit_anchor_id,
            case_audit_action, case_audit_object_kind, case_audit_object_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            observation.candidate_run_id,
            observation.execution_scope_authority_id,
            observation.ledger_sequence,
            observation.observation_authority_id,
            observation.command_id,
            observation.execution_dataset_snapshot_id,
            observation.execution_entry.execution_entry_id,
            observation.execution_entry.sample_id,
            observation.outcome.value,
            candidate_case.case_id if candidate_case is not None else None,
            candidate_case.case_revision if candidate_case is not None else None,
            candidate_case.case_document_sha256 if candidate_case is not None else None,
            candidate_case.case_audit_sequence if candidate_case is not None else None,
            candidate_case.case_audit_entry_hash if candidate_case is not None else None,
            len(observation.artifacts),
            len(observation.model_calls),
            document,
            _sha(document),
            len(document.encode("utf-8")),
            observation_schema_version,
            anchor_id
            if anchor_id is not None
            else (anchor.selected_case_audit_anchor_id if anchor is not None else None),
            action if action is not None else (anchor.action.value if anchor is not None else None),
            object_kind
            if object_kind is not None
            else (anchor.object_ref.kind.value if anchor is not None else None),
            object_id
            if object_id is not None
            else (anchor.object_ref.artifact_id if anchor is not None else None),
        ),
    )


def _prepare_case_observation(
    database: Path,
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
]:
    scope, source = _single_no_case_execution()
    _register_scope_with_protocol(database, scope, "v3")
    binding = _candidate_case_binding(database, scope)
    return scope, _v2_case_observation(scope, source, binding)


def test_0013_preserves_preexisting_v1_and_v2_protocol_rows(tmp_path: Path) -> None:
    scope, source = _single_no_case_execution()

    v1_migrations = tmp_path / "v1-migrations"
    _copy_migrations(v1_migrations, through=12)
    v1_database = tmp_path / "v1" / "labcourt.sqlite3"
    v1_database.parent.mkdir()
    assert MigrationRunner(v1_database, BUSY_TIMEOUT_MS, v1_migrations).apply_all() == tuple(
        range(1, 13)
    )
    _register_scope(v1_database, scope)

    v2_migrations = tmp_path / "v2-migrations"
    _copy_migrations(v2_migrations, through=12)
    v2_database = tmp_path / "v2" / "labcourt.sqlite3"
    v2_database.parent.mkdir()
    assert MigrationRunner(v2_database, BUSY_TIMEOUT_MS, v2_migrations).apply_all() == tuple(
        range(1, 13)
    )
    SQLiteEvidenceRepository(v2_database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    observation = _observation_for(scope, source)
    with sqlite3.connect(v2_database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_v2_protocol_and_scope(connection, scope)
        _insert_observation(connection, observation)
    raw_before = canonical_json(observation.model_dump(mode="json"))

    for migrations, database in (
        (v1_migrations, v1_database),
        (v2_migrations, v2_database),
    ):
        migration = next(MIGRATIONS.glob("0013_*.sql"))
        shutil.copy2(migration, migrations / migration.name)
        assert MigrationRunner(database, BUSY_TIMEOUT_MS, migrations).apply_all() == (13,)

    with sqlite3.connect(v1_database) as connection:
        assert connection.execute(
            "SELECT protocol_version FROM m6_upgrade_execution_ledger_protocols"
        ).fetchone() == ("v1",)
    with sqlite3.connect(v2_database) as connection:
        assert connection.execute(
            "SELECT protocol_version FROM m6_upgrade_execution_ledger_protocols"
        ).fetchone() == ("v2",)
        assert connection.execute(
            """
            SELECT observation_schema_version, selected_case_audit_anchor_id,
                   case_audit_action, case_audit_object_kind,
                   case_audit_object_id, observation_json
            FROM m6_upgrade_sample_execution_observations
            """
        ).fetchone() == ("v1", None, None, None, None, raw_before)


def test_0013_preflight_rejects_non_v1_historical_observation_atomically(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=12)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 13))
    scope, source = _single_no_case_execution()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    observation = _observation_for(scope, source)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_v2_protocol_and_scope(connection, scope)
        _insert_observation(connection, observation)
        payload = observation.model_dump(mode="json")
        payload["schema_version"] = "m6-upgrade-sample-execution-observation-authority-v2"
        raw = canonical_json(payload)
        connection.execute("DROP TRIGGER m6_upgrade_sample_execution_observations_no_update")
        connection.execute(
            """
            UPDATE m6_upgrade_sample_execution_observations
            SET observation_json = ?, document_sha256 = ?, size_bytes = ?
            """,
            (raw, _sha(raw), len(raw.encode("utf-8"))),
        )

    migration = next(MIGRATIONS.glob("0013_*.sql"))
    shutil.copy2(migration, copied / migration.name)
    with pytest.raises(MigrationIntegrityError, match=r"migration 0013.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 13").fetchone()
            is None
        )
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(m6_upgrade_sample_execution_observations)"
            )
        }
        assert "observation_schema_version" not in columns
        protocol_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'm6_upgrade_execution_ledger_protocols'
            """
        ).fetchone()
        assert protocol_sql is not None and "'v3'" not in str(protocol_sql[0])


def test_protocol_v3_accepts_only_observation_v2_and_v2_rejects_it(
    tmp_path: Path,
) -> None:
    scope, source = _single_no_case_execution()

    v3_database = tmp_path / "v3" / "labcourt.sqlite3"
    v3_database.parent.mkdir()
    MigrationRunner(v3_database, BUSY_TIMEOUT_MS).apply_all()
    _register_scope_with_protocol(v3_database, scope, "v3")
    legacy = _observation_for(scope, source)
    with sqlite3.connect(v3_database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, legacy)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_versioned_parent(
                connection,
                legacy,
                observation_schema_version="v1",
            )
        connection.rollback()

    v2_database = tmp_path / "v2" / "labcourt.sqlite3"
    v2_database.parent.mkdir()
    MigrationRunner(v2_database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(v2_database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    observation_v2 = _v2_no_case_observation(scope, source)
    with sqlite3.connect(v2_database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_v2_protocol_and_scope(connection, scope)
        _insert_children(connection, observation_v2)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_versioned_parent(
                connection,
                observation_v2,
                observation_schema_version="v2",
            )
        connection.rollback()


def test_protocol_v3_persists_one_no_case_observation_but_cannot_advance_pending(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, source = _single_no_case_execution()
    _register_scope_with_protocol(database, scope, "v3")
    observation = _v2_no_case_observation(scope, source)
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )
        connection.commit()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT observation_schema_version, selected_case_audit_anchor_id,
                   case_audit_action, case_audit_object_kind, case_audit_object_id
            FROM m6_upgrade_sample_execution_observations
            """
        ).fetchone() == ("v2", None, None, None, None)
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ):
            _insert_commitment(connection, commitment)

        for trigger_name in (
            "m6_upgrade_pending_sample_commitments_validate",
            "m6_upgrade_sample_executions_validate_observation_backing",
            "m6_upgrade_execution_ledger_seals_validate_schema_version",
        ):
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (trigger_name,),
            ).fetchone()
            assert row is not None
            trigger_sql = str(row[0])
            assert "protocol.protocol_version = 'v2'" in trigger_sql
            assert "protocol.protocol_version = 'v3'" not in trigger_sql


def test_protocol_v3_persists_a_case_anchor_exactly_joined_to_audit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    _scope, observation = _prepare_case_observation(database)
    anchor = observation.selected_case_audit_anchor
    assert anchor is not None

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT selected_case_audit_anchor_id, case_audit_action,
                   case_audit_object_kind, case_audit_object_id
            FROM m6_upgrade_sample_execution_observations
            """
        ).fetchone() == (
            anchor.selected_case_audit_anchor_id,
            AuditAction.CASE_CREATED.value,
            ArtifactKind.CASE.value,
            observation.candidate_case.case_id if observation.candidate_case else None,
        )


def test_protocol_v3_rejects_normalized_anchor_json_drift(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    _scope, observation = _prepare_case_observation(database)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_versioned_parent(
                connection,
                observation,
                observation_schema_version="v2",
                action=AuditAction.CASE_STATE_CHANGED.value,
            )
        connection.rollback()


def test_protocol_v3_rejects_an_anchor_not_exactly_joined_to_the_audit_row(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation = _prepare_case_observation(database)
    candidate_case = observation.candidate_case
    assert candidate_case is not None

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute(
            """
            UPDATE audit_entries
            SET object_id = 'case-audit-object-drift'
            WHERE run_id = ? AND sequence = ?
            """,
            (scope.candidate_run_id, candidate_case.case_audit_sequence),
        )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_versioned_parent(
                connection,
                observation,
                observation_schema_version="v2",
            )
        connection.rollback()


def test_protocol_v3_no_case_rejects_any_normalized_anchor_state(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    _register_scope_with_protocol(database, scope, "v3")
    observation = _v2_no_case_observation(scope, source)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_versioned_parent(
                connection,
                observation,
                observation_schema_version="v2",
                anchor_id="f" * 64,
            )
        connection.rollback()


def test_protocol_v3_rows_remain_append_only_after_protocol_table_rebuild(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, _source = _single_no_case_execution()
    _register_scope_with_protocol(database, scope, "v3")

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m6_upgrade_execution_ledger_protocols SET protocol_version = 'v2'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m6_upgrade_execution_ledger_protocols")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT INTO m6_upgrade_execution_ledger_protocols(
                    run_id, execution_scope_authority_id, protocol_version
                ) VALUES (?, ?, 'v3')
                """,
                (scope.candidate_run_id, scope.execution_scope_authority_id),
            )
