from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind, AuditAction, AuditActorRole
from labcourt.contracts.storage import ArtifactRef
from tests.integration.test_m6_replay_locked_candidate_repository import (
    _runtime as _m3_runtime,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
    MIGRATIONS,
)
from tests.unit.test_m6_replay_locked_m4_terminal import _execution as _m4_execution

_CANDIDATE_COLUMNS = (
    "candidate_run_id",
    "execution_scope_authority_id",
    "ledger_sequence",
    "sample_id",
    "execution_entry_id",
    "source_catalog_entry_id",
    "pending_commitment_authority_id",
    "route",
    "case_id",
    "event_id",
    "case_revision",
    "manifest_id",
    "status",
    "case_json",
    "case_document_sha256",
    "case_document_size_bytes",
    "case_audit_sequence",
    "case_audit_entry_hash",
)

_M3_CANDIDATE_TRIGGERS = {
    "m6_replay_locked_candidate_cases_validate",
    "m6_replay_locked_candidate_cases_no_replace",
    "m6_replay_locked_candidate_cases_no_update",
    "m6_replay_locked_candidate_cases_no_delete",
    "m6_replay_locked_candidate_cases_cross_route_no_replace",
}
_M4_CANDIDATE_TRIGGERS = {
    "m6_replay_locked_m4_candidate_cases_validate",
    "m6_replay_locked_m4_candidate_cases_no_replace",
    "m6_replay_locked_m4_candidate_cases_no_update",
    "m6_replay_locked_m4_candidate_cases_no_delete",
    "m6_replay_locked_m4_candidate_cases_cross_route_no_replace",
}


def _copy_migrations(destination: Path, *, through: int) -> None:
    destination.mkdir()
    for version in range(1, through + 1):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, destination / source.name)


def _insert_m4_candidate_document(
    repository: SQLiteEvidenceRepository,
    *,
    scope: object,
    pending: object,
    candidate: object,
    document: str,
) -> None:
    case = candidate.case  # type: ignore[attr-defined]
    document_bytes = document.encode("utf-8")
    document_sha256 = hashlib.sha256(document_bytes).hexdigest()
    with repository._immediate() as connection:
        head = repository._validated_head(  # type: ignore[attr-defined]
            connection,
            scope.candidate_run_id,  # type: ignore[attr-defined]
        )
        audit, _ = repository._append_audit(
            connection,
            head,
            action=AuditAction.CASE_CREATED,
            object_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case.case_id),
            before_sha256=None,
            after_sha256=document_sha256,
            actor=AuditActorRole.SYSTEM,
        )
        connection.execute(
            """
            INSERT INTO m6_replay_locked_m4_candidate_cases(
                candidate_run_id, execution_scope_authority_id, ledger_sequence,
                sample_id, execution_entry_id, source_catalog_entry_id,
                pending_commitment_authority_id, route, case_id, event_id,
                case_revision, manifest_id, status, case_json,
                case_document_sha256, case_document_size_bytes,
                case_audit_sequence, case_audit_entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scope.candidate_run_id,  # type: ignore[attr-defined]
                scope.execution_scope_authority_id,  # type: ignore[attr-defined]
                pending.ledger_sequence,  # type: ignore[attr-defined]
                pending.sample_id,  # type: ignore[attr-defined]
                pending.execution_entry_id,  # type: ignore[attr-defined]
                pending.source_catalog_entry_id,  # type: ignore[attr-defined]
                pending.pending_commitment_authority_id,  # type: ignore[attr-defined]
                pending.route.value,  # type: ignore[attr-defined]
                case.case_id,
                case.event.event_id,
                1,
                case.manifest_id,
                case.status.value,
                document,
                document_sha256,
                len(document_bytes),
                audit.sequence,
                audit.entry_hash,
            ),
        )


def test_0016_fresh_install_creates_one_strict_empty_candidate_case_authority(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=16)
    database = tmp_path / "labcourt.sqlite3"

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 17))

    with sqlite3.connect(database) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_info(m6_replay_locked_candidate_cases)")
        )
        strict = connection.execute(
            "SELECT strict FROM pragma_table_list WHERE name = ?",
            ("m6_replay_locked_candidate_cases",),
        ).fetchone()
        triggers = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'trigger'
                  AND tbl_name = 'm6_replay_locked_candidate_cases'
                """
            )
        }
        count = connection.execute(
            "SELECT COUNT(*) FROM m6_replay_locked_candidate_cases"
        ).fetchone()

    assert versions == [(version,) for version in range(1, 17)]
    assert columns == _CANDIDATE_COLUMNS
    assert strict == (1,)
    assert triggers == {
        "m6_replay_locked_candidate_cases_validate",
        "m6_replay_locked_candidate_cases_no_replace",
        "m6_replay_locked_candidate_cases_no_update",
        "m6_replay_locked_candidate_cases_no_delete",
    }
    assert count == (0,)


def test_0016_upgrades_0015_without_rewriting_old_tables_or_checksums(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=15)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 16))

    with sqlite3.connect(database) as connection:
        old_tables = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        old_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations ORDER BY version
            """
        ).fetchall()

    migration = next(MIGRATIONS.glob("0016_*.sql"))
    shutil.copy2(migration, copied / migration.name)
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (16,)

    with sqlite3.connect(database) as connection:
        upgraded_old_tables = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'table'
              AND name <> 'm6_replay_locked_candidate_cases'
            ORDER BY name
            """
        ).fetchall()
        upgraded_old_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations WHERE version <= 15 ORDER BY version
            """
        ).fetchall()
        candidate_count = connection.execute(
            "SELECT COUNT(*) FROM m6_replay_locked_candidate_cases"
        ).fetchone()
        foreign_key_failures = connection.execute("PRAGMA foreign_key_check").fetchall()

    assert upgraded_old_tables == old_tables
    assert upgraded_old_migrations == old_migrations
    assert candidate_count == (0,)
    assert foreign_key_failures == []


def test_0017_fresh_install_creates_strict_m4_candidate_authority_and_shared_ledger(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=17)
    database = tmp_path / "labcourt.sqlite3"

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 18))

    with sqlite3.connect(database) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_info(m6_replay_locked_m4_candidate_cases)")
        )
        strict = connection.execute(
            "SELECT strict FROM pragma_table_list WHERE name = ?",
            ("m6_replay_locked_m4_candidate_cases",),
        ).fetchone()
        table_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                ("m6_replay_locked_m4_candidate_cases",),
            ).fetchone()[0]
        )
        trigger_sql = {
            str(name): str(sql)
            for name, sql in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND tbl_name IN (
                      'm6_replay_locked_candidate_cases',
                      'm6_replay_locked_m4_candidate_cases'
                  )
                """
            )
        }
        count = connection.execute(
            "SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases"
        ).fetchone()

    assert versions == [(version,) for version in range(1, 18)]
    assert columns == _CANDIDATE_COLUMNS
    assert strict == (1,)
    assert "M4_HEARING_GATE_TERMINAL_POST_PARSE" in table_sql
    assert set(trigger_sql) == _M3_CANDIDATE_TRIGGERS | _M4_CANDIDATE_TRIGGERS
    assert (
        "m6_replay_locked_m4_candidate_cases"
        in trigger_sql["m6_replay_locked_candidate_cases_validate"]
    )
    assert (
        "m6_replay_locked_candidate_cases"
        in trigger_sql["m6_replay_locked_m4_candidate_cases_validate"]
    )
    assert "decision') = 'ESCALATE'" in trigger_sql["m6_replay_locked_m4_candidate_cases_validate"]
    assert count == (0,)


def test_0017_upgrades_0016_without_rewriting_0016_or_old_tables(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=16)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 17))

    with sqlite3.connect(database) as connection:
        old_tables = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        old_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations ORDER BY version
            """
        ).fetchall()

    migration = next(MIGRATIONS.glob("0017_*.sql"))
    shutil.copy2(migration, copied / migration.name)
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (17,)

    with sqlite3.connect(database) as connection:
        upgraded_old_tables = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'table'
              AND name <> 'm6_replay_locked_m4_candidate_cases'
            ORDER BY name
            """
        ).fetchall()
        upgraded_old_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations WHERE version <= 16 ORDER BY version
            """
        ).fetchall()
        counts = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM m6_replay_locked_candidate_cases),
                (SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases)
            """
        ).fetchone()
        foreign_key_failures = connection.execute("PRAGMA foreign_key_check").fetchall()

    assert upgraded_old_tables == old_tables
    assert upgraded_old_migrations == old_migrations
    assert counts == (0, 0)
    assert foreign_key_failures == []


def test_0017_rejects_raw_m4_pack_v2_and_rolls_back_its_case_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    scope, pending, source = _m4_execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    repository.register_run(scope.candidate_run_id, scope.locked_manifest)
    payload = json.loads(candidate.canonical_case_document)
    payload["evidence_packs"][0]["version"] = 2
    payload["screening_results"][0]["evidence_pack_version"] = 2
    payload["screening_results"][0]["parsed_output"]["evidence_pack_version"] = 2
    payload["verdicts"][0]["evidence_pack_version"] = 2
    payload["procedural_reviews"][0]["evidence_pack_version"] = 2
    pack_v2_document = canonical_json(payload)

    with pytest.raises(sqlite3.IntegrityError, match="invalid M6 replay-locked M4"):
        _insert_m4_candidate_document(
            repository,
            scope=scope,
            pending=pending,
            candidate=candidate,
            document=pack_v2_document,
        )

    with sqlite3.connect(database) as connection:
        rejected_counts = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases),
                (SELECT COUNT(*) FROM audit_entries),
                revision,
                audit_head_sequence
            FROM runs WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()
    assert rejected_counts == (0, 0, 0, -1)

    _insert_m4_candidate_document(
        repository,
        scope=scope,
        pending=pending,
        candidate=candidate,
        document=candidate.canonical_case_document,
    )
    with sqlite3.connect(database) as connection:
        committed_counts = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases),
                (SELECT COUNT(*) FROM audit_entries),
                revision,
                audit_head_sequence
            FROM runs WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()
    assert committed_counts == (1, 1, 1, 0)

    with pytest.raises(
        sqlite3.IntegrityError,
        match="M6 replay-locked M4 candidate Cases are append-only",
    ):
        _insert_m4_candidate_document(
            repository,
            scope=scope,
            pending=pending,
            candidate=candidate,
            document=candidate.canonical_case_document,
        )
    with sqlite3.connect(database) as connection:
        retry_counts = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases),
                (SELECT COUNT(*) FROM audit_entries),
                revision,
                audit_head_sequence
            FROM runs WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()
    assert retry_counts == committed_counts

    with (
        sqlite3.connect(database) as connection,
        pytest.raises(
            sqlite3.IntegrityError,
            match="M6 replay-locked candidate routes are append-only",
        ),
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
            )
            SELECT
                candidate_run_id, execution_scope_authority_id,
                ledger_sequence, sample_id, execution_entry_id,
                source_catalog_entry_id, pending_commitment_authority_id,
                'M3_FAST_TERMINAL_POST_PARSE', case_id, event_id,
                case_revision, manifest_id, status, case_json,
                case_document_sha256, case_document_size_bytes,
                case_audit_sequence, case_audit_entry_hash
            FROM m6_replay_locked_m4_candidate_cases
            """
        )


def test_0017_rejects_an_m3_candidate_copied_into_the_m4_route(
    tmp_path: Path,
) -> None:
    runtime = _m3_runtime(tmp_path)
    runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)

    with sqlite3.connect(runtime.database) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="M6 replay-locked candidate routes are append-only",
        ):
            connection.execute(
                """
                INSERT INTO m6_replay_locked_m4_candidate_cases(
                    candidate_run_id, execution_scope_authority_id,
                    ledger_sequence, sample_id, execution_entry_id,
                    source_catalog_entry_id, pending_commitment_authority_id,
                    route, case_id, event_id, case_revision, manifest_id,
                    status, case_json, case_document_sha256,
                    case_document_size_bytes, case_audit_sequence,
                    case_audit_entry_hash
                )
                SELECT
                    candidate_run_id, execution_scope_authority_id,
                    ledger_sequence, sample_id, execution_entry_id,
                    source_catalog_entry_id, pending_commitment_authority_id,
                    'M4_HEARING_GATE_TERMINAL_POST_PARSE', case_id, event_id,
                    case_revision, manifest_id, status, case_json,
                    case_document_sha256, case_document_size_bytes,
                    case_audit_sequence, case_audit_entry_hash
                FROM m6_replay_locked_candidate_cases
                """
            )
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases"
        ).fetchone() == (0,)
