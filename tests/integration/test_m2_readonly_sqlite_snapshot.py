from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_sqlite import (
    ReadOnlySnapshotError,
    readonly_sqlite_snapshot,
    snapshot_run_counts,
)
from labcourt.adapters.storage.secure_workspace import require_owner_only_directory


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _directory_fingerprint(root: Path) -> dict[str, tuple[int, int, int, int, int, str]]:
    return {
        path.name: (
            int(path.stat().st_dev),
            int(path.stat().st_ino),
            int(path.stat().st_nlink),
            int(path.stat().st_size),
            int(path.stat().st_mtime_ns),
            _sha256(path),
        )
        for path in root.iterdir()
        if path.is_file()
    }


def test_readonly_snapshot_includes_committed_wal_without_changing_source(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    writer = sqlite3.connect(database)
    try:
        assert writer.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        writer.execute("CREATE TABLE sample(value TEXT NOT NULL)")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("INSERT INTO sample(value) VALUES ('committed-only-in-wal')")
        writer.commit()

        wal = database.with_name(f"{database.name}-wal")
        assert wal.is_file() and wal.stat().st_size > 0
        shm = database.with_name(f"{database.name}-shm")
        assert shm.is_file() and shm.stat().st_size > 0
        before = _directory_fingerprint(tmp_path)
        assert set(before) == {database.name, wal.name, shm.name}

        with readonly_sqlite_snapshot(database) as snapshot:
            copy = sqlite3.connect(snapshot)
            try:
                assert copy.execute("SELECT value FROM sample").fetchone()[0] == (
                    "committed-only-in-wal"
                )
            finally:
                copy.close()
            assert _directory_fingerprint(tmp_path) == before

        assert _directory_fingerprint(tmp_path) == before
    finally:
        writer.close()


def test_readonly_snapshot_missing_database_does_not_create_it(tmp_path: Path) -> None:
    database = tmp_path / "missing.sqlite3"

    with (
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_MISSING"),
        readonly_sqlite_snapshot(database),
    ):
        raise AssertionError("unreachable")

    assert not database.exists()


def test_readonly_snapshot_rejects_hardlinked_database(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    sqlite3.connect(database).close()
    alias = tmp_path / "alias.sqlite3"
    os.link(database, alias)

    with (
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_FILE_UNSAFE"),
        readonly_sqlite_snapshot(database),
    ):
        raise AssertionError("unreachable")


def test_readonly_snapshot_rejects_sidecar_appearing_during_use(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE sample(value TEXT NOT NULL)")
    connection.commit()
    connection.close()

    with (
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_SOURCE_SET_CHANGED"),
        readonly_sqlite_snapshot(database),
    ):
        database.with_name(f"{database.name}-wal").write_bytes(b"new-sidecar")


def test_readonly_snapshot_rejects_total_source_bytes_before_copy(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE sample(value TEXT NOT NULL)")
    connection.commit()
    connection.close()
    before = _directory_fingerprint(tmp_path)

    with (
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_BYTES_BUDGET_EXCEEDED"),
        readonly_sqlite_snapshot(database, max_database_bytes=1),
    ):
        raise AssertionError("unreachable")

    assert _directory_fingerprint(tmp_path) == before


def test_snapshot_counts_keep_frozen_m2_database_compatible_without_m3_tables(
    tmp_path: Path,
) -> None:
    database = tmp_path / "m2-only.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE run_manifests(manifest_id TEXT, document_json TEXT);
            CREATE TABLE runs(run_id TEXT, manifest_id TEXT);
            CREATE TABLE cases(run_id TEXT, event_json TEXT);
            CREATE TABLE case_versions(run_id TEXT, case_json TEXT);
            CREATE TABLE evidence_packs(run_id TEXT, pack_json TEXT);
            CREATE TABLE audit_entries(run_id TEXT, entry_json TEXT);
            CREATE TABLE evidence_pack_crops(run_id TEXT, crop_json TEXT);
            CREATE TABLE frames(run_id TEXT, document_json TEXT);
            CREATE TABLE detections(run_id TEXT, document_json TEXT);
            CREATE TABLE media_assets(run_id TEXT);
            INSERT INTO run_manifests VALUES ('manifest', '{}');
            INSERT INTO runs VALUES ('m2-only-run', 'manifest');
            """
        )

    with readonly_sqlite_snapshot(database) as snapshot:
        counts = snapshot_run_counts(snapshot, "m2-only-run")

    assert counts.max_document_bytes == 2
    assert counts.model_call_claims == 0
    assert counts.model_responses == 0
    assert counts.backlog_completion_receipts == 0
    assert counts.raw_response_bytes == 0
    assert counts.m3_max_document_bytes == 0


def test_snapshot_counts_reject_m3_migrations_with_all_m3_tables_missing(
    tmp_path: Path,
) -> None:
    database = tmp_path / "missing-m3-tables.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_migrations(version INTEGER);
            INSERT INTO schema_migrations VALUES (4), (5);
            CREATE TABLE run_manifests(manifest_id TEXT, document_json TEXT);
            CREATE TABLE runs(run_id TEXT, manifest_id TEXT);
            CREATE TABLE cases(run_id TEXT, event_json TEXT);
            CREATE TABLE case_versions(run_id TEXT, case_json TEXT);
            CREATE TABLE evidence_packs(run_id TEXT, pack_json TEXT);
            CREATE TABLE audit_entries(run_id TEXT, entry_json TEXT);
            CREATE TABLE evidence_pack_crops(run_id TEXT, crop_json TEXT);
            CREATE TABLE frames(run_id TEXT, document_json TEXT);
            CREATE TABLE detections(run_id TEXT, document_json TEXT);
            CREATE TABLE media_assets(run_id TEXT);
            """
        )

    with (
        readonly_sqlite_snapshot(database) as snapshot,
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_SCHEMA_INVALID"),
    ):
        snapshot_run_counts(snapshot, "m3-corrupt-run")


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL verification")
def test_readonly_snapshot_uses_verified_owner_only_windows_directories(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE sample(value TEXT NOT NULL)")
    connection.commit()
    connection.close()

    with readonly_sqlite_snapshot(database) as snapshot:
        require_owner_only_directory(snapshot.parent)
        require_owner_only_directory(snapshot.parent / "raw")
