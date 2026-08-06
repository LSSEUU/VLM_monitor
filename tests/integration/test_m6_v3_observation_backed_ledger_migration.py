from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage import _sqlite_migration_contract_functions
from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
)
from labcourt.adapters.storage.sqlite_schema import m6_upgrade_ledger_installed
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
)
from tests.integration.test_m6_selected_case_audit_anchor_observation_migration import (
    _insert_versioned_parent,
    _prepare_case_observation,
    _register_scope_with_protocol,
    _v2_no_case_observation,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    AUDIT_GENESIS_HASH,
    BUSY_TIMEOUT_MS,
    MIGRATIONS,
    _canonical_document,
    _insert_sample,
    _insert_seal,
    _register_scope,
    _single_no_case_execution,
)
from tests.integration.test_m6_upgrade_execution_observation_repository import (
    _insert_children,
)
from tests.integration.test_m6_upgrade_observation_backed_ledger_migration import (
    _commitment,
    _insert_commitment,
    _insert_observation,
    _insert_refs_and_links,
    _insert_v2_sample,
    _insert_v2_seal,
    _no_case_bundle,
    _observation_for,
    _register_v2_scope,
    _v2_record,
)

_FORGED = "f" * 64


def _copy_migrations(destination: Path, *, through: int) -> None:
    destination.mkdir()
    for version in range(1, through + 1):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, destination / source.name)


def _ledger_counts(connection: sqlite3.Connection) -> tuple[int, int, int, int]:
    tables = (
        "m6_upgrade_sample_executions",
        "m6_upgrade_sample_execution_observations",
        "m6_upgrade_pending_sample_commitments",
        "m6_upgrade_execution_ledger_seals",
    )
    return tuple(
        int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in tables
    )


def _install_0014_with_inventory_cap(copied: Path, max_bytes: int) -> None:
    source = next(MIGRATIONS.glob("0014_*.sql"))
    destination = copied / source.name
    sql = source.read_text(encoding="utf-8")
    marker = "268435456 AS max_inventory_bytes"
    assert sql.count(marker) == 1
    destination.write_text(
        sql.replace(marker, f"{max_bytes} AS max_inventory_bytes"),
        encoding="utf-8",
    )


def _assert_0014_rolled_back(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 14").fetchone()
            is None
        )
        assert connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_sample_executions_validate'
            """
        ).fetchone() == (1,)
        assert (
            connection.execute(
                """
            SELECT 1 FROM sqlite_master
            WHERE name = 'm6_v3_observation_backed_ledger_preflight'
            """
            ).fetchone()
            is None
        )


def test_0014_fresh_install_recreates_all_v3_ledger_barriers(tmp_path: Path) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=14)
    database = tmp_path / "labcourt.sqlite3"

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 15))

    trigger_names = (
        "m6_upgrade_sample_executions_validate",
        "m6_upgrade_pending_sample_commitments_validate",
        "m6_upgrade_sample_executions_validate_observation_backing",
        "m6_upgrade_execution_ledger_seals_validate_schema_version",
    )
    with sqlite3.connect(database) as connection:
        assert m6_upgrade_ledger_installed(connection)
        rows = connection.execute(
            f"""
            SELECT name, sql
            FROM sqlite_master
            WHERE type = 'trigger'
              AND name IN ({", ".join("?" for _name in trigger_names)})
            """,
            trigger_names,
        ).fetchall()
        persisted_udf_reference = connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE sql LIKE '%labcourt_migration_%'
            """
        ).fetchone()

    assert {str(row[0]) for row in rows} == set(trigger_names)
    assert all("'v3'" in str(row[1]) for row in rows)
    assert persisted_udf_reference is None


def test_0014_continues_0013_v3_observation_through_five_ledger_states(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 14))

    scope, source = _single_no_case_execution()
    observation = _v2_no_case_observation(scope, source)
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)
    _scope_raw, scope_sha256, scope_size = _canonical_document(scope)
    seal = M6UpgradeExecutionLedgerSealV2(
        execution_scope=scope,
        execution_scope_content_sha256=scope_sha256,
        execution_scope_size_bytes=scope_size,
        source_audit_head_sequence=-1,
        source_audit_head_hash=AUDIT_GENESIS_HASH,
        sample_executions=(record,),
    )
    _register_scope_with_protocol(database, scope, "v3")

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        assert _ledger_counts(connection) == (0, 0, 0, 0)
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )
        assert _ledger_counts(connection) == (0, 1, 0, 0)
        before = connection.execute(
            """
            SELECT observation_json, document_sha256, size_bytes,
                   observation_schema_version, selected_case_audit_anchor_id,
                   case_audit_action, case_audit_object_kind, case_audit_object_id
            FROM m6_upgrade_sample_execution_observations
            """
        ).fetchone()

    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (14,)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        assert (
            connection.execute(
                """
            SELECT observation_json, document_sha256, size_bytes,
                   observation_schema_version, selected_case_audit_anchor_id,
                   case_audit_action, case_audit_object_kind, case_audit_object_id
            FROM m6_upgrade_sample_execution_observations
            """
            ).fetchone()
            == before
        )

        _insert_commitment(connection, commitment)
        assert _ledger_counts(connection) == (0, 1, 1, 0)
        with pytest.raises(
            sqlite3.IntegrityError,
            match=r"invalid M6 upgrade (?:execution ledger seal|ledger schema-version closure)",
        ):
            _insert_v2_seal(connection, seal)

        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)
        assert _ledger_counts(connection) == (1, 1, 1, 0)

        _insert_v2_seal(connection, seal)
        assert _ledger_counts(connection) == (1, 1, 1, 1)
        assert connection.execute(
            """
            SELECT record_schema_version, observation_authority_id
            FROM m6_upgrade_sample_executions
            """
        ).fetchone() == ("v2", observation.observation_authority_id)
        assert connection.execute(
            "SELECT seal_schema_version FROM m6_upgrade_execution_ledger_seals"
        ).fetchone() == ("v2",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_0014_preflight_rejects_forged_v3_commitment_atomically(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 14))

    scope, source = _single_no_case_execution()
    observation = _v2_no_case_observation(scope, source)
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)
    _register_scope_with_protocol(database, scope, "v3")

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )
        connection.execute("DROP TRIGGER m6_upgrade_pending_sample_commitments_validate")
        _insert_commitment(connection, commitment)

    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    with pytest.raises(MigrationIntegrityError, match=r"migration 0014.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 14").fetchone()
            is None
        )
        assert connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_sample_executions_validate'
            """
        ).fetchone() == (1,)
        assert (
            connection.execute(
                """
            SELECT 1
            FROM sqlite_master
            WHERE name = 'm6_v3_observation_backed_ledger_preflight'
            """
            ).fetchone()
            is None
        )


def test_0014_preflight_rejects_unknown_observation_padding_with_old_digest(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, source = _single_no_case_execution()
    observation = _v2_no_case_observation(scope, source)
    _register_scope_with_protocol(database, scope, "v3")

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )
        original_digest = str(
            connection.execute(
                """
                SELECT document_sha256
                FROM m6_upgrade_sample_execution_observations
                """
            ).fetchone()[0]
        )
        original_raw = str(
            connection.execute(
                """
                SELECT observation_json
                FROM m6_upgrade_sample_execution_observations
                """
            ).fetchone()[0]
        )
        padded_payload = json.loads(original_raw)
        assert isinstance(padded_payload, dict)
        padded_payload["unrecognized_padding"] = "padding"
        padded_raw = canonical_json(padded_payload)
        assert (
            _sqlite_migration_contract_functions.migration_sha256_utf8(padded_raw)
            != original_digest
        )
        assert (
            _sqlite_migration_contract_functions.migration_contract_is_canonical(
                "sample-execution-observation-v2",
                padded_raw,
            )
            == 0
        )
        connection.execute("DROP TRIGGER m6_upgrade_sample_execution_observations_no_update")
        connection.execute(
            """
            UPDATE m6_upgrade_sample_execution_observations
            SET observation_json = ?, size_bytes = ?
            """,
            (padded_raw, len(padded_raw.encode("utf-8"))),
        )
        assert connection.execute(
            """
            SELECT document_sha256
            FROM m6_upgrade_sample_execution_observations
            """
        ).fetchone() == (original_digest,)

    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    with pytest.raises(MigrationIntegrityError, match=r"migration 0014.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    _assert_0014_rolled_back(database)


def test_0014_preflight_rejects_equivalent_noncanonical_json_with_new_digest(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, _source = _single_no_case_execution()
    _register_scope_with_protocol(database, scope, "v3")

    with sqlite3.connect(database) as connection:
        raw = str(
            connection.execute("SELECT scope_json FROM m6_upgrade_execution_scopes").fetchone()[0]
        )
        noncanonical = f"\n{raw}"
        connection.execute("DROP TRIGGER m6_upgrade_execution_scopes_no_update")
        connection.execute(
            """
            UPDATE m6_upgrade_execution_scopes
            SET scope_json = ?, document_sha256 = ?, size_bytes = ?
            """,
            (
                noncanonical,
                hashlib.sha256(noncanonical.encode("utf-8")).hexdigest(),
                len(noncanonical.encode("utf-8")),
            ),
        )
        assert connection.execute(
            "SELECT json(scope_json) = json(?) FROM m6_upgrade_execution_scopes",
            (raw,),
        ).fetchone() == (1,)

    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    with pytest.raises(MigrationIntegrityError, match=r"migration 0014.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    _assert_0014_rolled_back(database)


def test_0014_rejects_oversize_before_either_contract_udf_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, _source = _single_no_case_execution()
    _register_scope_with_protocol(database, scope, "v3")
    scope_size = _canonical_document(scope)[2]
    _install_0014_with_inventory_cap(copied, scope_size - 1)

    udf_calls: list[str] = []

    def sha256_trap(_raw: object) -> None:
        udf_calls.append("sha256")

    def canonical_trap(_kind: object, _raw: object) -> int:
        udf_calls.append("canonical")
        return 0

    monkeypatch.setattr(
        _sqlite_migration_contract_functions,
        "migration_sha256_utf8",
        sha256_trap,
    )
    monkeypatch.setattr(
        _sqlite_migration_contract_functions,
        "migration_contract_is_canonical",
        canonical_trap,
    )

    with pytest.raises(MigrationIntegrityError, match=r"migration 0014.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    assert udf_calls == []
    _assert_0014_rolled_back(database)


def test_0014_rejects_aggregate_prefix_overrun_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, observation, record, commitment, _seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)

    scope_size = _canonical_document(scope)[2]
    record_size = _canonical_document(record)[2]
    aggregate_cap = scope_size + record_size - 1
    assert (
        max(
            scope_size,
            record_size,
            _canonical_document(observation)[2],
            _canonical_document(commitment)[2],
        )
        < aggregate_cap
    )
    _install_0014_with_inventory_cap(copied, aggregate_cap)

    udf_calls: list[str] = []

    def sha256_trap(_raw: object) -> None:
        udf_calls.append("sha256")

    def canonical_trap(_kind: object, _raw: object) -> int:
        udf_calls.append("canonical")
        return 0

    monkeypatch.setattr(
        _sqlite_migration_contract_functions,
        "migration_sha256_utf8",
        sha256_trap,
    )
    monkeypatch.setattr(
        _sqlite_migration_contract_functions,
        "migration_contract_is_canonical",
        canonical_trap,
    )

    with pytest.raises(MigrationIntegrityError, match=r"migration 0014.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    assert udf_calls == []
    _assert_0014_rolled_back(database)


def test_0014_continues_an_exact_v3_case_anchor_to_a_sealed_record(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, observation = _prepare_case_observation(database)
    _unused_scope, source = _single_no_case_execution()
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)
    _scope_raw, scope_sha256, scope_size = _canonical_document(scope)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )
        source_audit_sequence, source_audit_hash = connection.execute(
            "SELECT audit_head_sequence, audit_head_hash FROM runs WHERE run_id = ?",
            (scope.candidate_run_id,),
        ).fetchone()

    seal = M6UpgradeExecutionLedgerSealV2(
        execution_scope=scope,
        execution_scope_content_sha256=scope_sha256,
        execution_scope_size_bytes=scope_size,
        source_audit_head_sequence=int(source_audit_sequence),
        source_audit_head_hash=str(source_audit_hash),
        sample_executions=(record,),
    )
    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (14,)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)
        _insert_v2_seal(connection, seal)
        anchor = observation.selected_case_audit_anchor
        assert anchor is not None
        assert connection.execute(
            """
            SELECT observation_schema_version, selected_case_audit_anchor_id,
                   case_audit_action, case_audit_object_kind,
                   record_schema_version, seal_schema_version
            FROM m6_upgrade_sample_execution_observations AS observation
            JOIN m6_upgrade_sample_executions AS sample
              ON sample.run_id = observation.run_id
             AND sample.ledger_sequence = observation.ledger_sequence
            JOIN m6_upgrade_execution_ledger_seals AS seal
              ON seal.run_id = sample.run_id
            """
        ).fetchone() == (
            "v2",
            anchor.selected_case_audit_anchor_id,
            anchor.action.value,
            anchor.object_ref.kind.value,
            "v2",
            "v2",
        )


def test_0014_preserves_v1_and_v2_authority_rows_byte_for_byte(
    tmp_path: Path,
) -> None:
    v1_migrations = tmp_path / "v1-migrations"
    _copy_migrations(v1_migrations, through=13)
    v1_workspace = tmp_path / "v1-workspace"
    v1_workspace.mkdir()
    v1_database = v1_workspace / "labcourt.sqlite3"
    assert MigrationRunner(v1_database, BUSY_TIMEOUT_MS, v1_migrations).apply_all() == tuple(
        range(1, 14)
    )
    v1_scope, v1_record = _single_no_case_execution()
    _register_scope(v1_database, v1_scope)
    _scope_raw, v1_scope_sha, v1_scope_size = _canonical_document(v1_scope)
    v1_seal = M6UpgradeExecutionLedgerSeal(
        execution_scope=v1_scope,
        execution_scope_content_sha256=v1_scope_sha,
        execution_scope_size_bytes=v1_scope_size,
        source_audit_head_sequence=-1,
        source_audit_head_hash=AUDIT_GENESIS_HASH,
        sample_executions=(v1_record,),
    )
    with sqlite3.connect(v1_database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_refs_and_links(connection, v1_scope, v1_record)
        _insert_sample(connection, v1_scope, v1_record)
        _insert_seal(connection, v1_seal)

    v2_migrations = tmp_path / "v2-migrations"
    _copy_migrations(v2_migrations, through=13)
    v2_workspace = tmp_path / "v2-workspace"
    v2_workspace.mkdir()
    v2_database = v2_workspace / "labcourt.sqlite3"
    assert MigrationRunner(v2_database, BUSY_TIMEOUT_MS, v2_migrations).apply_all() == tuple(
        range(1, 14)
    )
    v2_scope, v2_observation, v2_record, v2_commitment, v2_seal = _no_case_bundle()
    _register_v2_scope(v2_database, v2_scope)
    with sqlite3.connect(v2_database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, v2_observation)
        _insert_commitment(connection, v2_commitment)
        _insert_refs_and_links(connection, v2_scope, v2_record)
        _insert_v2_sample(connection, v2_record)
        _insert_v2_seal(connection, v2_seal)

    tables = (
        "m6_upgrade_execution_scopes",
        "m6_upgrade_execution_ledger_protocols",
        "m6_upgrade_sample_execution_observations",
        "m6_upgrade_pending_sample_commitments",
        "m6_upgrade_physical_artifact_refs",
        "m6_upgrade_sample_artifact_links",
        "m6_upgrade_sample_executions",
        "m6_upgrade_execution_ledger_seals",
    )

    def snapshot(database: Path) -> dict[str, list[tuple[object, ...]]]:
        with sqlite3.connect(database) as connection:
            return {
                table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                for table in tables
            }

    v1_before = snapshot(v1_database)
    v2_before = snapshot(v2_database)
    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), v1_migrations)
    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), v2_migrations)
    assert MigrationRunner(v1_database, BUSY_TIMEOUT_MS, v1_migrations).apply_all() == (14,)
    assert MigrationRunner(v2_database, BUSY_TIMEOUT_MS, v2_migrations).apply_all() == (14,)
    assert snapshot(v1_database) == v1_before
    assert snapshot(v2_database) == v2_before


def test_0014_preserves_append_only_errors_after_recreating_validators(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=14)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, observation, record, commitment, seal = _no_case_bundle()
    _register_v2_scope(database, scope)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)
        _insert_v2_seal(connection, seal)

        with pytest.raises(
            sqlite3.IntegrityError,
            match="M6 upgrade pending sample commitments are append-only",
        ):
            _insert_commitment(connection, commitment)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="M6 upgrade sample executions are append-only",
        ):
            _insert_v2_sample(connection, record)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="M6 upgrade execution ledger seals are append-only",
        ):
            _insert_v2_seal(connection, seal)


@pytest.mark.parametrize("stage", ["observation", "pending", "record"])
def test_0014_preflight_accepts_each_legal_unsealed_v2_prefix(
    tmp_path: Path,
    stage: str,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, observation, record, commitment, _seal = _no_case_bundle()
    _register_v2_scope(database, scope)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        if stage in {"pending", "record"}:
            _insert_commitment(connection, commitment)
        if stage == "record":
            _insert_refs_and_links(connection, scope, record)
            _insert_v2_sample(connection, record)
        before = _ledger_counts(connection)

    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (14,)
    with sqlite3.connect(database) as connection:
        assert _ledger_counts(connection) == before


@pytest.mark.parametrize("protocol_version", ["v2", "v3"])
def test_0014_pending_rejects_cross_protocol_observation_wire(
    tmp_path: Path,
    protocol_version: str,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=14)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, source = _single_no_case_execution()
    _register_scope_with_protocol(database, scope, protocol_version)

    if protocol_version == "v2":
        observation = _v2_no_case_observation(scope, source)
        observation_schema_version = "v2"
    else:
        observation = _observation_for(scope, source)
        observation_schema_version = "v1"
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DROP TRIGGER m6_upgrade_sample_execution_observations_validate")
        if observation_schema_version == "v2":
            _insert_children(connection, observation)
            _insert_versioned_parent(
                connection,
                observation,
                observation_schema_version="v2",
            )
        else:
            _insert_observation(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ):
            _insert_commitment(connection, commitment)


def test_0014_pending_rechecks_v3_anchor_against_the_exact_audit_row(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=14)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, observation = _prepare_case_observation(database)
    _unused_scope, source = _single_no_case_execution()
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
        connection.execute("DROP TRIGGER m6_upgrade_sample_execution_observations_no_update")
        connection.execute(
            """
            UPDATE m6_upgrade_sample_execution_observations
            SET case_audit_object_id = ?
            WHERE observation_authority_id = ?
            """,
            (_FORGED, observation.observation_authority_id),
        )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ):
            _insert_commitment(connection, commitment)


@pytest.mark.parametrize("stage", ["record", "seal"])
def test_0014_record_and_seal_recheck_the_exact_v3_anchor(
    tmp_path: Path,
    stage: str,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=14)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, observation = _prepare_case_observation(database)
    _unused_scope, source = _single_no_case_execution()
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)
    _scope_raw, scope_sha256, scope_size = _canonical_document(scope)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        source_audit_sequence, source_audit_hash = connection.execute(
            "SELECT audit_head_sequence, audit_head_hash FROM runs WHERE run_id = ?",
            (scope.candidate_run_id,),
        ).fetchone()
        if stage == "seal":
            _insert_v2_sample(connection, record)

        connection.execute("DROP TRIGGER m6_upgrade_sample_execution_observations_no_update")
        connection.execute(
            """
            UPDATE m6_upgrade_sample_execution_observations
            SET case_audit_object_id = ?
            WHERE observation_authority_id = ?
            """,
            (_FORGED, observation.observation_authority_id),
        )

        if stage == "record":
            with pytest.raises(
                sqlite3.IntegrityError,
                match=(
                    r"invalid M6 (?:upgrade sample execution|"
                    r"observation-backed sample execution)"
                ),
            ):
                _insert_v2_sample(connection, record)
            connection.rollback()
        else:
            seal = M6UpgradeExecutionLedgerSealV2(
                execution_scope=scope,
                execution_scope_content_sha256=scope_sha256,
                execution_scope_size_bytes=scope_size,
                source_audit_head_sequence=int(source_audit_sequence),
                source_audit_head_hash=str(source_audit_hash),
                sample_executions=(record,),
            )
            with pytest.raises(
                sqlite3.IntegrityError,
                match=r"invalid M6 upgrade (?:execution ledger seal|ledger schema-version closure)",
            ):
                _insert_v2_seal(connection, seal)


def test_0014_preflight_rejects_v3_anchor_drift_before_trigger_replacement(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    _scope, observation = _prepare_case_observation(database)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        _insert_versioned_parent(
            connection,
            observation,
            observation_schema_version="v2",
        )
        connection.execute("DROP TRIGGER m6_upgrade_sample_execution_observations_no_update")
        connection.execute(
            """
            UPDATE m6_upgrade_sample_execution_observations
            SET case_audit_action = 'CASE_CLOSED'
            WHERE observation_authority_id = ?
            """,
            (observation.observation_authority_id,),
        )

    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    with pytest.raises(MigrationIntegrityError, match=r"migration 0014.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 14").fetchone()
            is None
        )
        assert connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_pending_sample_commitments_validate'
            """
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    ("append_only_trigger", "mutation_sql", "parameter_count"),
    (
        pytest.param(
            "m6_upgrade_sample_executions_no_update",
            "UPDATE m6_upgrade_sample_executions SET command_id = ?",
            1,
            id="record-normalized-drift",
        ),
        pytest.param(
            "m6_upgrade_sample_executions_no_update",
            """
            UPDATE m6_upgrade_sample_executions
            SET record_json = json_set(record_json, '$.command_id', ?),
                record_size_bytes = length(CAST(
                    json_set(record_json, '$.command_id', ?) AS BLOB
                ))
            """,
            2,
            id="record-raw-drift",
        ),
        pytest.param(
            "m6_upgrade_sample_executions_no_update",
            "UPDATE m6_upgrade_sample_executions SET record_document_sha256 = ?",
            1,
            id="record-linked-document-hash-drift",
        ),
        pytest.param(
            "m6_upgrade_sample_executions_no_update",
            "UPDATE m6_upgrade_sample_executions SET record_size_bytes = record_size_bytes + 1",
            0,
            id="record-size-drift",
        ),
        pytest.param(
            "m6_upgrade_pending_sample_commitments_no_update",
            """
            UPDATE m6_upgrade_pending_sample_commitments
            SET sample_execution_record_document_sha256 = ?
            """,
            1,
            id="pending-record-hash-drift",
        ),
        pytest.param(
            "m6_upgrade_pending_sample_commitments_no_update",
            """
            UPDATE m6_upgrade_pending_sample_commitments
            SET commitment_json = json_set(commitment_json, '$.command_id', ?),
                size_bytes = length(CAST(
                    json_set(commitment_json, '$.command_id', ?) AS BLOB
                ))
            """,
            2,
            id="pending-raw-drift",
        ),
        pytest.param(
            "m6_upgrade_pending_sample_commitments_no_update",
            """
            UPDATE m6_upgrade_pending_sample_commitments
            SET size_bytes = size_bytes + 1
            """,
            0,
            id="pending-size-drift",
        ),
        pytest.param(
            "m6_upgrade_execution_ledger_seals_no_update",
            "UPDATE m6_upgrade_execution_ledger_seals SET ledger_preseal_hash = ?",
            1,
            id="seal-ledger-hash-drift",
        ),
        pytest.param(
            "m6_upgrade_execution_ledger_seals_no_update",
            """
            UPDATE m6_upgrade_execution_ledger_seals
            SET seal_json = json_set(seal_json, '$.ledger_head_sequence', 99),
                size_bytes = length(CAST(
                    json_set(seal_json, '$.ledger_head_sequence', 99) AS BLOB
                ))
            """,
            0,
            id="seal-raw-drift",
        ),
        pytest.param(
            "m6_upgrade_execution_ledger_seals_no_update",
            "UPDATE m6_upgrade_execution_ledger_seals SET size_bytes = size_bytes + 1",
            0,
            id="seal-size-drift",
        ),
    ),
)
def test_0014_preflight_rejects_historical_v2_authority_corruption(
    tmp_path: Path,
    append_only_trigger: str,
    mutation_sql: str,
    parameter_count: int,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=13)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, observation, record, commitment, seal = _no_case_bundle()
    _register_v2_scope(database, scope)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)
        _insert_v2_seal(connection, seal)
        connection.execute(f'DROP TRIGGER "{append_only_trigger}"')
        connection.execute(mutation_sql, (_FORGED,) * parameter_count)

    shutil.copy2(next(MIGRATIONS.glob("0014_*.sql")), copied)
    with pytest.raises(MigrationIntegrityError, match=r"migration 0014.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 14").fetchone()
            is None
        )
        assert connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_pending_sample_commitments_validate'
            """
        ).fetchone() == (1,)
        assert connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_sample_executions_validate'
            """
        ).fetchone() == (1,)
        assert (
            connection.execute(
                """
            SELECT 1
            FROM sqlite_master
            WHERE name = 'm6_v3_observation_backed_ledger_preflight'
            """
            ).fetchone()
            is None
        )
