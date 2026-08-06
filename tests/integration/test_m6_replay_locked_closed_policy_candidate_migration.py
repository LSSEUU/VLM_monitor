from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind, AuditAction, AuditActorRole
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.alert_policy import plan_case_alert
from tests.integration.test_m6_replay_locked_candidate_repository import (
    _runtime as _m3_runtime,
)
from tests.integration.test_m6_replay_locked_m4_candidate_repository import (
    _runtime as _m4_runtime,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
    MIGRATIONS,
)
from tests.unit.test_m5_alert_policy import _manifest_with_stream, _ready_case
from tests.unit.test_m5_finalization import _closed_case

ROOT = Path(__file__).parents[2]

_TABLE = "m6_replay_locked_closed_policy_candidate_cases"
_COLUMNS = (
    "candidate_run_id",
    "execution_scope_authority_id",
    "pre_policy_execution_scope_authority_id",
    "ledger_sequence",
    "sample_id",
    "execution_entry_id",
    "source_catalog_entry_id",
    "pending_commitment_authority_id",
    "pre_policy_pending_commitment_authority_id",
    "source_binding_authority_id",
    "policy_causal_cut_authority_id",
    "locked_config_sha256",
    "route",
    "pre_policy_route",
    "case_id",
    "event_id",
    "case_revision",
    "manifest_id",
    "status",
    "case_json",
    "case_document_sha256",
    "case_document_size_bytes",
    "candidate_alert_policy_authority_id",
    "alert_policy_json",
    "alert_policy_document_sha256",
    "alert_policy_document_size_bytes",
    "case_audit_sequence",
    "case_audit_entry_hash",
)
_INSERT_SQL = f"""
    INSERT INTO {_TABLE}(
        candidate_run_id, execution_scope_authority_id,
        pre_policy_execution_scope_authority_id, ledger_sequence,
        sample_id, execution_entry_id, source_catalog_entry_id,
        pending_commitment_authority_id,
        pre_policy_pending_commitment_authority_id,
        source_binding_authority_id, policy_causal_cut_authority_id,
        locked_config_sha256, route, pre_policy_route, case_id, event_id,
        case_revision, manifest_id, status, case_json,
        case_document_sha256, case_document_size_bytes,
        candidate_alert_policy_authority_id, alert_policy_json,
        alert_policy_document_sha256, alert_policy_document_size_bytes,
        case_audit_sequence, case_audit_entry_hash
    ) VALUES (
        :candidate_run_id, :execution_scope_authority_id,
        :pre_policy_execution_scope_authority_id, :ledger_sequence,
        :sample_id, :execution_entry_id, :source_catalog_entry_id,
        :pending_commitment_authority_id,
        :pre_policy_pending_commitment_authority_id,
        :source_binding_authority_id, :policy_causal_cut_authority_id,
        :locked_config_sha256, :route, :pre_policy_route, :case_id, :event_id,
        :case_revision, :manifest_id, :status, :case_json,
        :case_document_sha256, :case_document_size_bytes,
        :candidate_alert_policy_authority_id, :alert_policy_json,
        :alert_policy_document_sha256, :alert_policy_document_size_bytes,
        :case_audit_sequence, :case_audit_entry_hash
    )
"""


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _copy_migrations(destination: Path, *, through: int) -> None:
    destination.mkdir()
    for version in range(1, through + 1):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, destination / source.name)


def _candidate_row() -> tuple[object, dict[str, Any]]:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = _manifest_with_stream()
    ready = _ready_case(manifest)
    policy = plan_case_alert(ready, config, manifest)
    closed = _closed_case(ready, policy)
    case_document = canonical_json(closed.model_dump(mode="json"))
    policy_document = canonical_json(policy.model_dump(mode="json"))
    return manifest, {
        "candidate_run_id": closed.run_id,
        "execution_scope_authority_id": _sha("closed-policy-v2-scope"),
        "pre_policy_execution_scope_authority_id": _sha("pre-policy-v1-scope"),
        "ledger_sequence": 0,
        "sample_id": "closed-policy-sample",
        "execution_entry_id": _sha("closed-policy-entry"),
        "source_catalog_entry_id": _sha("closed-policy-source-entry"),
        "pending_commitment_authority_id": _sha("closed-policy-v2-pending"),
        "pre_policy_pending_commitment_authority_id": _sha("closed-policy-v1-pending"),
        "source_binding_authority_id": _sha("closed-policy-source-binding"),
        "policy_causal_cut_authority_id": _sha("closed-policy-causal-cut"),
        "locked_config_sha256": config.config_sha256,
        "route": "ALERT_POLICY_CLOSED",
        "pre_policy_route": "M3_FAST_TERMINAL_POST_PARSE",
        "case_id": closed.case_id,
        "event_id": closed.event.event_id,
        "case_revision": 1,
        "manifest_id": closed.manifest_id,
        "status": "CLOSED",
        "case_json": case_document,
        "case_document_sha256": _sha(case_document),
        "case_document_size_bytes": len(case_document.encode("utf-8")),
        "candidate_alert_policy_authority_id": policy.authority_id,
        "alert_policy_json": policy_document,
        "alert_policy_document_sha256": _sha(policy_document),
        "alert_policy_document_size_bytes": len(policy_document.encode("utf-8")),
        "case_audit_sequence": 0,
        "case_audit_entry_hash": "0" * 64,
    }


def _install_and_register(database: Path) -> tuple[object, dict[str, Any]]:
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    manifest, row = _candidate_row()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        row["candidate_run_id"],
        manifest,  # type: ignore[arg-type]
    )
    return manifest, row


def _insert_with_case_audit(database: Path, row: dict[str, Any]) -> None:
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    with repository._immediate() as connection:
        head = repository._validated_head(connection, row["candidate_run_id"])
        audit, _ = repository._append_audit(
            connection,
            head,
            action=AuditAction.CASE_CREATED,
            object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=row["case_id"]),
            before_sha256=None,
            after_sha256=row["case_document_sha256"],
            actor=AuditActorRole.SYSTEM,
        )
        controlled = {
            **row,
            "case_audit_sequence": audit.sequence,
            "case_audit_entry_hash": audit.entry_hash,
        }
        connection.execute(_INSERT_SQL, controlled)


def test_0018_fresh_install_creates_strict_closed_only_authority_at_path(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))

    with sqlite3.connect(database) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        columns = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({_TABLE})"))
        strict = connection.execute(
            "SELECT strict FROM pragma_table_list WHERE name = ?",
            (_TABLE,),
        ).fetchone()
        table_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                (_TABLE,),
            ).fetchone()[0]
        )
        triggers = {
            str(name): str(sql)
            for name, sql in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND tbl_name IN (
                      'm6_replay_locked_candidate_cases',
                      'm6_replay_locked_m4_candidate_cases',
                      'm6_replay_locked_closed_policy_candidate_cases'
                  )
                """
            )
        }

    assert versions == [(version,) for version in range(1, 19)]
    assert columns == _COLUMNS
    assert strict == (1,)
    assert "status TEXT NOT NULL CHECK (status = 'CLOSED')" in table_sql
    assert "case_revision INTEGER NOT NULL CHECK (case_revision = 1)" in table_sql
    assert "candidate_alert_policy_authority_id" in table_sql
    assert "alert_policy_json" in table_sql
    assert {
        "m6_replay_locked_closed_policy_candidate_cases_validate",
        "m6_replay_locked_closed_policy_candidate_cases_no_replace",
        "m6_replay_locked_closed_policy_candidate_cases_no_update",
        "m6_replay_locked_closed_policy_candidate_cases_no_delete",
        "m6_replay_locked_closed_policy_candidate_cases_cross_route_no_replace",
        "m6_replay_locked_candidate_cases_closed_policy_no_replace",
        "m6_replay_locked_m4_candidate_cases_closed_policy_no_replace",
        "m6_replay_locked_candidate_cases_closed_policy_budget",
        "m6_replay_locked_m4_candidate_cases_closed_policy_budget",
    }.issubset(triggers)
    for trigger_name in (
        "m6_replay_locked_closed_policy_candidate_cases_validate",
        "m6_replay_locked_candidate_cases_closed_policy_budget",
        "m6_replay_locked_m4_candidate_cases_closed_policy_budget",
    ):
        sql = triggers[trigger_name]
        assert "m6_replay_locked_candidate_cases" in sql
        assert "m6_replay_locked_m4_candidate_cases" in sql
        assert "m6_replay_locked_closed_policy_candidate_cases" in sql
        assert "268435456" in sql


def test_0018_upgrades_0017_without_rewriting_frozen_tables_or_checksums(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=17)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 18))

    with sqlite3.connect(database) as connection:
        frozen_tables = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'table'
              AND name IN (
                  'm6_replay_locked_candidate_cases',
                  'm6_replay_locked_m4_candidate_cases'
              )
            ORDER BY name
            """
        ).fetchall()
        frozen_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations WHERE version <= 17 ORDER BY version
            """
        ).fetchall()

    migration = next(MIGRATIONS.glob("0018_*.sql"))
    shutil.copy2(migration, copied / migration.name)
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (18,)

    with sqlite3.connect(database) as connection:
        upgraded_frozen_tables = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'table'
              AND name IN (
                  'm6_replay_locked_candidate_cases',
                  'm6_replay_locked_m4_candidate_cases'
              )
            ORDER BY name
            """
        ).fetchall()
        upgraded_frozen_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations WHERE version <= 17 ORDER BY version
            """
        ).fetchall()
        count = connection.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
        foreign_key_failures = connection.execute("PRAGMA foreign_key_check").fetchall()

    assert upgraded_frozen_tables == frozen_tables
    assert upgraded_frozen_migrations == frozen_migrations
    assert count == (0,)
    assert foreign_key_failures == []


def test_0018_commits_only_one_closed_revision_and_policy_for_recovery(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _, row = _install_and_register(database)

    _insert_with_case_audit(database, row)

    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            f"""
            SELECT status, case_revision, case_json, alert_policy_json,
                   case_audit_sequence, ledger_sequence
            FROM {_TABLE}
            """
        ).fetchone()
        counts = connection.execute(
            f"""
            SELECT
                (SELECT COUNT(*) FROM m6_replay_locked_candidate_cases),
                (SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases),
                (SELECT COUNT(*) FROM {_TABLE}),
                (SELECT COUNT(*) FROM audit_entries)
            """
        ).fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                f"UPDATE {_TABLE} SET source_binding_authority_id = ?",
                (_sha("replacement"),),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(f"DELETE FROM {_TABLE}")

    assert stored == (
        "CLOSED",
        1,
        row["case_json"],
        row["alert_policy_json"],
        0,
        0,
    )
    assert json.loads(str(stored[2]))["status"] == "CLOSED"
    assert "transient_ready_case" not in _COLUMNS
    assert counts == (0, 0, 1, 1)


@pytest.mark.parametrize(
    "corruption",
    ("ready_case", "noncanonical_policy", "non_atomic_policy"),
)
def test_0018_rejects_nonclosed_or_noncanonical_recovery_payload_atomically(
    tmp_path: Path,
    corruption: str,
) -> None:
    database_root = tmp_path / corruption
    database_root.mkdir()
    database = database_root / "labcourt.sqlite3"
    _, row = _install_and_register(database)
    if corruption == "ready_case":
        payload = json.loads(row["case_json"])
        payload["status"] = "READY_FOR_ALERT_POLICY"
        document = canonical_json(payload)
        row.update(
            {
                "case_json": document,
                "case_document_sha256": _sha(document),
                "case_document_size_bytes": len(document.encode("utf-8")),
            }
        )
    elif corruption == "noncanonical_policy":
        document = " " + str(row["alert_policy_json"])
        row.update(
            {
                "alert_policy_json": document,
                "alert_policy_document_sha256": _sha(document),
                "alert_policy_document_size_bytes": len(document.encode("utf-8")),
            }
        )
    else:
        payload = json.loads(row["alert_policy_json"])
        payload["outbox_item"] = None
        document = canonical_json(payload)
        row.update(
            {
                "alert_policy_json": document,
                "alert_policy_document_sha256": _sha(document),
                "alert_policy_document_size_bytes": len(document.encode("utf-8")),
            }
        )

    with pytest.raises(sqlite3.IntegrityError, match="invalid M6 replay-locked CLOSED"):
        _insert_with_case_audit(database, row)

    with sqlite3.connect(database) as connection:
        assert connection.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone() == (0,)
        assert connection.execute("SELECT revision, audit_head_sequence FROM runs").fetchone() == (
            0,
            -1,
        )


@pytest.mark.parametrize("legacy_route", ("m3", "m4"))
def test_0018_rejects_legacy_candidate_collisions_when_closed_is_inserted_later(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_route: str,
) -> None:
    runtime = (
        _m3_runtime(tmp_path)
        if legacy_route == "m3"
        else _m4_runtime(tmp_path, monkeypatch=monkeypatch)
    )
    if legacy_route == "m3":
        runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)
    else:
        runtime.repository.publish_m4_candidate(runtime.scope, runtime.pending, runtime.write)
    _, row = _candidate_row()
    table = (
        "m6_replay_locked_candidate_cases"
        if legacy_route == "m3"
        else "m6_replay_locked_m4_candidate_cases"
    )
    with sqlite3.connect(runtime.database) as connection:
        legacy = connection.execute(
            f"""
            SELECT candidate_run_id, execution_scope_authority_id,
                   ledger_sequence, sample_id, execution_entry_id,
                   source_catalog_entry_id, pending_commitment_authority_id,
                   case_id, event_id, manifest_id
            FROM {table}
            """
        ).fetchone()
        assert legacy is not None
        (
            row["candidate_run_id"],
            row["pre_policy_execution_scope_authority_id"],
            row["ledger_sequence"],
            row["sample_id"],
            row["execution_entry_id"],
            row["source_catalog_entry_id"],
            row["pre_policy_pending_commitment_authority_id"],
            row["case_id"],
            row["event_id"],
            row["manifest_id"],
        ) = legacy
        row["pre_policy_route"] = (
            "M3_FAST_TERMINAL_POST_PARSE"
            if legacy_route == "m3"
            else "M4_HEARING_GATE_TERMINAL_POST_PARSE"
        )
        # The V2 CLOSED generation cannot join a partially populated V1 run,
        # even when every per-sample identity and sequence is otherwise fresh.
        row.update(
            {
                "pre_policy_execution_scope_authority_id": _sha(f"different-{legacy_route}-scope"),
                "ledger_sequence": 1,
                "sample_id": f"different-{legacy_route}-sample",
                "execution_entry_id": _sha(f"different-{legacy_route}-entry"),
                "pending_commitment_authority_id": _sha(f"different-{legacy_route}-v2-pending"),
                "pre_policy_pending_commitment_authority_id": _sha(
                    f"different-{legacy_route}-v1-pending"
                ),
                "case_id": "11111111-1111-1111-1111-111111111111",
                "event_id": "22222222-2222-2222-2222-222222222222",
            }
        )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="candidate generations are append-only",
        ):
            connection.execute(_INSERT_SQL, row)


@pytest.mark.parametrize(
    ("legacy_table", "legacy_route"),
    (
        ("m6_replay_locked_candidate_cases", "M3_FAST_TERMINAL_POST_PARSE"),
        (
            "m6_replay_locked_m4_candidate_cases",
            "M4_HEARING_GATE_TERMINAL_POST_PARSE",
        ),
    ),
)
def test_0018_rejects_closed_candidate_collisions_from_both_legacy_insert_directions(
    tmp_path: Path,
    legacy_table: str,
    legacy_route: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _, row = _install_and_register(database)
    _insert_with_case_audit(database, row)

    with (
        sqlite3.connect(database) as connection,
        pytest.raises(
            sqlite3.IntegrityError,
            match="candidate generations are append-only",
        ),
    ):
        connection.execute(
            f"""
            INSERT INTO {legacy_table}(
                candidate_run_id, execution_scope_authority_id,
                ledger_sequence, sample_id, execution_entry_id,
                source_catalog_entry_id, pending_commitment_authority_id,
                route, case_id, event_id, case_revision, manifest_id,
                status, case_json, case_document_sha256,
                case_document_size_bytes, case_audit_sequence,
                case_audit_entry_hash
            )
            SELECT
                candidate_run_id, pre_policy_execution_scope_authority_id,
                ledger_sequence, sample_id, execution_entry_id,
                source_catalog_entry_id,
                pre_policy_pending_commitment_authority_id,
                ?, case_id, event_id, case_revision, manifest_id,
                'READY_FOR_ALERT_POLICY', case_json, case_document_sha256,
                case_document_size_bytes, case_audit_sequence,
                case_audit_entry_hash
            FROM {_TABLE}
            """,
            (legacy_route,),
        )


def test_0018_legacy_insert_guards_count_closed_policy_bytes_in_shared_budget(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _, row = _install_and_register(database)
    _insert_with_case_audit(database, row)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER m6_replay_locked_closed_policy_candidate_cases_no_update")
        connection.execute("DROP TRIGGER m6_replay_locked_candidate_cases_closed_policy_no_replace")
        connection.execute(
            f"""
            UPDATE {_TABLE}
            SET case_document_size_bytes = 268435455,
                alert_policy_document_size_bytes = 1
            """
        )
        connection.commit()

        with pytest.raises(
            sqlite3.IntegrityError,
            match="candidate byte budget exceeded",
        ):
            connection.execute(
                """
                INSERT INTO m6_replay_locked_candidate_cases(
                    candidate_run_id, execution_scope_authority_id,
                    ledger_sequence, sample_id, execution_entry_id,
                    source_catalog_entry_id, pending_commitment_authority_id,
                    route, case_id, event_id, case_revision, manifest_id,
                    status, case_json, case_document_sha256,
                    case_document_size_bytes, case_audit_sequence,
                    case_audit_entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["candidate_run_id"],
                    row["pre_policy_execution_scope_authority_id"],
                    1,
                    "another-sample",
                    _sha("another-entry"),
                    _sha("another-source-entry"),
                    _sha("another-pending"),
                    "M3_FAST_TERMINAL_POST_PARSE",
                    "11111111-1111-1111-1111-111111111111",
                    "22222222-2222-2222-2222-222222222222",
                    1,
                    row["manifest_id"],
                    "READY_FOR_ALERT_POLICY",
                    "{}",
                    _sha("{}"),
                    1,
                    1,
                    _sha("another-audit"),
                ),
            )
