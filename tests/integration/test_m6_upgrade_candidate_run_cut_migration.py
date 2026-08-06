from __future__ import annotations

import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v2_inventory,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
    MIGRATIONS,
)
from tests.integration.test_m6_upgrade_execution_ledger_v2_repository import (
    MutableExactSampleArtifactVerifier,
)
from tests.integration.test_m6_upgrade_execution_ledger_v3_repository import (
    _v3_pipeline,
)

_MAX_DOCUMENT_BYTES = 256 * 1024 * 1024
_RUN_CUT_COLUMNS = (
    "run_id",
    "execution_scope_authority_id",
    "ledger_seal_authority_id",
    "candidate_manifest_id",
    "candidate_manifest_content_sha256",
    "candidate_config_sha256",
    "candidate_config_content_sha256",
    "execution_component_manifest_id",
    "audit_head_sequence",
    "audit_head_hash",
    "validation_report_id",
    "validation_report_content_sha256",
    "validation_report_size_bytes",
    "candidate_run_cut_authority_id",
    "run_cut_json",
    "document_sha256",
    "size_bytes",
)


def _sha256_utf8(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _canonical_document(value: object) -> tuple[str, str, int]:
    raw = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    return raw, _sha256_utf8(raw), len(raw.encode("utf-8"))


def _copy_migrations(destination: Path, *, through: int) -> None:
    destination.mkdir()
    for version in range(1, through + 1):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, destination / source.name)


def _seal_v3_run(
    database: Path,
) -> tuple[M6UpgradeExecutionScopeAuthority, M6UpgradeExecutionLedgerSealV2]:
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    scope, observations, records, commitments = _v3_pipeline()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
    )
    observations_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitments_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    ledger.begin_execution(scope)
    for observation, commitment in zip(observations, commitments, strict=True):
        observations_repository.append(observation)
        commitments_repository.append(commitment)
        ledger.append_committed_sample(commitment)
    return scope, ledger.seal(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )


def _run_cut_for_seal(
    scope: M6UpgradeExecutionScopeAuthority,
    seal: M6UpgradeExecutionLedgerSealV2,
) -> M6UpgradeCandidateRunCutAuthority:
    source = _v2_inventory().candidate_run_cut
    report = source.validation_report
    m4_report = report.predecessor_report
    assert m4_report is not None
    m3_report = m4_report.m3_report
    m2_report = m3_report.m2_report.model_copy(
        update={
            "audit_head_sequence": seal.source_audit_head_sequence,
            "audit_head_hash": seal.source_audit_head_hash,
        }
    )
    rebuilt_m3 = m3_report.model_copy(update={"m2_report": m2_report})
    rebuilt_m4 = m4_report.model_copy(update={"m3_report": rebuilt_m3})
    rebuilt_counts = report.counts.model_copy(update={"case_roots": seal.candidate_case_count})
    rebuilt_report = report.model_copy(
        update={
            "predecessor_report": rebuilt_m4,
            "counts": rebuilt_counts,
        }
    )
    _report_raw, report_sha256, _report_size = _canonical_document(rebuilt_report)
    return M6UpgradeCandidateRunCutAuthority(
        candidate_run_id=scope.candidate_run_id,
        candidate_manifest=scope.candidate_manifest,
        candidate_manifest_content_sha256=scope.candidate_manifest_content_sha256,
        candidate_config=scope.candidate_config,
        candidate_config_content_sha256=scope.candidate_config_content_sha256,
        execution_component_manifest_id=(scope.execution_component.component_authority_id),
        audit_head_sequence=seal.source_audit_head_sequence,
        audit_head_hash=seal.source_audit_head_hash,
        validation_report=rebuilt_report,
        validation_report_content_sha256=report_sha256,
    )


def _run_cut_row(
    scope: M6UpgradeExecutionScopeAuthority,
    seal: M6UpgradeExecutionLedgerSealV2,
    cut: M6UpgradeCandidateRunCutAuthority,
) -> dict[str, object]:
    raw, document_sha256, size_bytes = _canonical_document(cut)
    report_raw, _report_sha256, report_size_bytes = _canonical_document(cut.validation_report)
    assert _sha256_utf8(report_raw) == cut.validation_report_content_sha256
    return {
        "run_id": scope.candidate_run_id,
        "execution_scope_authority_id": scope.execution_scope_authority_id,
        "ledger_seal_authority_id": seal.ledger_seal_authority_id,
        "candidate_manifest_id": cut.candidate_manifest.manifest_id,
        "candidate_manifest_content_sha256": cut.candidate_manifest_content_sha256,
        "candidate_config_sha256": cut.candidate_config.config_sha256,
        "candidate_config_content_sha256": cut.candidate_config_content_sha256,
        "execution_component_manifest_id": cut.execution_component_manifest_id,
        "audit_head_sequence": cut.audit_head_sequence,
        "audit_head_hash": cut.audit_head_hash,
        "validation_report_id": cut.validation_report.report_id,
        "validation_report_content_sha256": cut.validation_report_content_sha256,
        "validation_report_size_bytes": report_size_bytes,
        "candidate_run_cut_authority_id": cut.candidate_run_cut_authority_id,
        "run_cut_json": raw,
        "document_sha256": document_sha256,
        "size_bytes": size_bytes,
    }


def _insert_run_cut(
    connection: sqlite3.Connection,
    row: dict[str, object],
    *,
    replace: bool = False,
) -> None:
    command = "INSERT OR REPLACE" if replace else "INSERT"
    connection.execute(
        f"""
        {command} INTO m6_upgrade_candidate_run_cuts(
            {", ".join(_RUN_CUT_COLUMNS)}
        ) VALUES ({", ".join("?" for _column in _RUN_CUT_COLUMNS)})
        """,
        tuple(row[column] for column in _RUN_CUT_COLUMNS),
    )


def test_0015_fresh_install_creates_one_strict_empty_run_cut_authority(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=15)
    database = tmp_path / "labcourt.sqlite3"

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 16))

    with sqlite3.connect(database) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        table = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            ("m6_upgrade_candidate_run_cuts",),
        ).fetchone()
        columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_info(m6_upgrade_candidate_run_cuts)")
        )
        strict = connection.execute(
            "SELECT strict FROM pragma_table_list WHERE name = ?",
            ("m6_upgrade_candidate_run_cuts",),
        ).fetchone()
        triggers = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'trigger'
                  AND tbl_name = 'm6_upgrade_candidate_run_cuts'
                """
            )
        }
        count = connection.execute("SELECT COUNT(*) FROM m6_upgrade_candidate_run_cuts").fetchone()

    assert versions == [(version,) for version in range(1, 16)]
    assert table is not None and str(table[0]).rstrip().endswith("STRICT")
    assert columns == _RUN_CUT_COLUMNS
    assert strict == (1,)
    assert triggers == {
        "m6_upgrade_candidate_run_cuts_validate",
        "m6_upgrade_candidate_run_cuts_no_replace",
        "m6_upgrade_candidate_run_cuts_no_update",
        "m6_upgrade_candidate_run_cuts_no_delete",
    }
    assert count == (0,)


def test_0015_upgrades_0014_without_rewriting_old_tables_or_checksums(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=14)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 15))

    with sqlite3.connect(database) as connection:
        old_tables = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
            """
        ).fetchall()
        old_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()

    migration = next(MIGRATIONS.glob("0015_*.sql"))
    shutil.copy2(migration, copied / migration.name)
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (15,)

    with sqlite3.connect(database) as connection:
        upgraded_old_tables = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'table'
              AND name <> 'm6_upgrade_candidate_run_cuts'
            ORDER BY name
            """
        ).fetchall()
        upgraded_old_migrations = connection.execute(
            """
            SELECT version, name, sql_sha256, applied_at
            FROM schema_migrations
            WHERE version <= 14
            ORDER BY version
            """
        ).fetchall()
        run_cut_count = connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_candidate_run_cuts"
        ).fetchone()
        foreign_key_failures = connection.execute("PRAGMA foreign_key_check").fetchall()

    assert upgraded_old_tables == old_tables
    assert upgraded_old_migrations == old_migrations
    assert run_cut_count == (0,)
    assert foreign_key_failures == []


def test_0015_rejects_cross_cut_projections_and_requires_v3_seal_v2(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, seal = _seal_v3_run(database)
    cut = _run_cut_for_seal(scope, seal)
    row = _run_cut_row(scope, seal, cut)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        wrong_manifest = dict(row)
        wrong_manifest["candidate_manifest_id"] = "f" * 64
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade candidate run cut"):
            _insert_run_cut(connection, wrong_manifest)

        wrong_seal = dict(row)
        wrong_seal["ledger_seal_authority_id"] = "e" * 64
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade candidate run cut"):
            _insert_run_cut(connection, wrong_seal)

        wrong_report_size = dict(row)
        wrong_report_size["validation_report_size_bytes"] = (
            int(row["validation_report_size_bytes"]) + 1
        )
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade candidate run cut"):
            _insert_run_cut(connection, wrong_report_size)

        oversized = dict(row)
        oversized["size_bytes"] = _MAX_DOCUMENT_BYTES + 1
        with pytest.raises(sqlite3.IntegrityError):
            _insert_run_cut(connection, oversized)

        connection.execute("DROP TRIGGER m6_upgrade_execution_ledger_protocols_no_update")
        connection.execute(
            "UPDATE m6_upgrade_execution_ledger_protocols SET protocol_version = 'v2'"
        )
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade candidate run cut"):
            _insert_run_cut(connection, row)
        connection.execute(
            "UPDATE m6_upgrade_execution_ledger_protocols SET protocol_version = 'v3'"
        )

        connection.execute("DROP TRIGGER m6_upgrade_execution_ledger_seals_no_update")
        connection.execute(
            "UPDATE m6_upgrade_execution_ledger_seals SET seal_schema_version = 'v1'"
        )
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade candidate run cut"):
            _insert_run_cut(connection, row)
        connection.execute(
            "UPDATE m6_upgrade_execution_ledger_seals SET seal_schema_version = 'v2'"
        )

        _insert_run_cut(connection, row)
        stored = connection.execute(
            f"""
            SELECT {", ".join(_RUN_CUT_COLUMNS)}
            FROM m6_upgrade_candidate_run_cuts
            """
        ).fetchone()

    assert stored == tuple(row[column] for column in _RUN_CUT_COLUMNS)


def test_0015_run_cut_is_append_only_and_cannot_be_replaced(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, seal = _seal_v3_run(database)
    row = _run_cut_row(scope, seal, _run_cut_for_seal(scope, seal))

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_run_cut(connection, row)

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            _insert_run_cut(connection, row)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            _insert_run_cut(connection, row, replace=True)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE m6_upgrade_candidate_run_cuts SET audit_head_sequence = 0")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m6_upgrade_candidate_run_cuts")

        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_candidate_run_cuts"
        ).fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
