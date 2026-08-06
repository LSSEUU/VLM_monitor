from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from labcourt.adapters.storage.sqlite_authority import SQLiteAuthorityError
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, SQLiteEvidenceRepository

BUSY_TIMEOUT_MS = 1_000


def _create_symlink(link: Path, target: Path, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error.__class__.__name__}")


def _create_windows_junction(link: Path, target: Path) -> None:
    completed = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip("junction creation is unavailable for this test")


def _migrate(database: Path) -> None:
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))


def test_safe_existing_authority_opens_and_missing_repository_never_creates(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _migrate(database)

    settings = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).pragma_settings()

    assert settings["journal_mode"] == "wal"
    missing_parent = tmp_path / "missing"
    missing_parent.mkdir()
    missing = missing_parent / "labcourt.sqlite3"
    with pytest.raises(SQLiteAuthorityError) as raised:
        SQLiteEvidenceRepository(missing, BUSY_TIMEOUT_MS).pragma_settings()
    assert raised.value.reason_code == "DATABASE_MISSING"
    assert not missing.exists()


def test_authority_requires_the_canonical_basename_without_leaking_host_path(
    tmp_path: Path,
) -> None:
    database = tmp_path / "not-authority.sqlite3"

    with pytest.raises(SQLiteAuthorityError) as raised:
        MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()

    assert raised.value.reason_code == "DATABASE_NAME_INVALID"
    assert str(tmp_path) not in str(raised.value)
    assert not database.exists()


def test_migration_rejects_main_database_hardlink_before_any_external_write(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside-payload.bin"
    original = b"outside bytes must remain unchanged"
    outside.write_bytes(original)
    database = tmp_path / "labcourt.sqlite3"
    try:
        os.link(outside, database)
    except OSError as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")

    with pytest.raises(SQLiteAuthorityError) as raised:
        MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()

    assert raised.value.reason_code == "DATABASE_LINK_COUNT_UNSAFE"
    assert outside.read_bytes() == original
    assert database.read_bytes() == original


def test_repository_rejects_an_existing_authority_hardlinked_outside_workspace(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _migrate(database)
    outside_parent = tmp_path / "outside"
    outside_parent.mkdir()
    outside = outside_parent / "authority-copy.sqlite3"
    database.replace(outside)
    try:
        os.link(outside, database)
    except OSError as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")
    before = hashlib.sha256(outside.read_bytes()).hexdigest()

    with pytest.raises(SQLiteAuthorityError) as raised:
        SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).pragma_settings()

    assert raised.value.reason_code == "DATABASE_LINK_COUNT_UNSAFE"
    assert hashlib.sha256(outside.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_repository_rejects_hardlinked_sidecar_before_sqlite_can_open_it(
    tmp_path: Path,
    suffix: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _migrate(database)
    sidecar = database.with_name(f"{database.name}{suffix}")
    sidecar.unlink(missing_ok=True)
    outside = tmp_path / f"outside{suffix}"
    outside.write_bytes(b"external sidecar target")
    before = hashlib.sha256(outside.read_bytes()).hexdigest()
    try:
        os.link(outside, sidecar)
    except OSError as error:
        pytest.skip(f"hardlink creation is unavailable: {error.__class__.__name__}")

    with pytest.raises(SQLiteAuthorityError) as raised:
        SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).pragma_settings()

    assert raised.value.reason_code == "DATABASE_SIDECAR_LINK_COUNT_UNSAFE"
    assert hashlib.sha256(outside.read_bytes()).hexdigest() == before


def test_repository_fails_closed_when_a_rollback_journal_exists(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _migrate(database)
    journal = database.with_name(f"{database.name}-journal")
    journal.write_bytes(b"untrusted rollback journal")

    with pytest.raises(SQLiteAuthorityError) as raised:
        SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).pragma_settings()

    assert raised.value.reason_code == "DATABASE_ROLLBACK_JOURNAL_PRESENT"
    assert journal.read_bytes() == b"untrusted rollback journal"


def test_directory_and_posix_fifo_cannot_be_used_as_the_authority_leaf(tmp_path: Path) -> None:
    directory = tmp_path / "labcourt.sqlite3"
    directory.mkdir()
    with pytest.raises(SQLiteAuthorityError) as raised:
        MigrationRunner(directory, BUSY_TIMEOUT_MS).apply_all()
    assert raised.value.reason_code == "DATABASE_NOT_REGULAR"

    if os.name != "posix" or not hasattr(os, "mkfifo"):
        return
    fifo_parent = tmp_path / "fifo"
    fifo_parent.mkdir()
    fifo = fifo_parent / "labcourt.sqlite3"
    os.mkfifo(fifo)
    with pytest.raises(SQLiteAuthorityError) as fifo_raised:
        MigrationRunner(fifo, BUSY_TIMEOUT_MS).apply_all()
    assert fifo_raised.value.reason_code == "DATABASE_NOT_REGULAR"


def test_database_leaf_symlink_is_rejected_without_touching_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"do not touch")
    database = tmp_path / "labcourt.sqlite3"
    _create_symlink(database, outside, directory=False)

    with pytest.raises(SQLiteAuthorityError) as raised:
        MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()

    assert raised.value.reason_code in {"DATABASE_REPARSE_POINT", "DATABASE_NOT_REGULAR"}
    assert outside.read_bytes() == b"do not touch"


def test_database_parent_symlink_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-workspace"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-workspace"
    _create_symlink(linked_parent, real_parent, directory=True)

    with pytest.raises(SQLiteAuthorityError) as raised:
        MigrationRunner(linked_parent / "labcourt.sqlite3", BUSY_TIMEOUT_MS).apply_all()

    assert raised.value.reason_code in {"DATABASE_PARENT_REPARSE_POINT", "DATABASE_PARENT_UNSAFE"}
    assert not (real_parent / "labcourt.sqlite3").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_windows_database_parent_junction_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "junction-target"
    real_parent.mkdir()
    junction = tmp_path / "junction-workspace"
    _create_windows_junction(junction, real_parent)

    with pytest.raises(SQLiteAuthorityError) as raised:
        MigrationRunner(junction / "labcourt.sqlite3", BUSY_TIMEOUT_MS).apply_all()

    assert raised.value.reason_code == "DATABASE_PARENT_REPARSE_POINT"
    assert not (real_parent / "labcourt.sqlite3").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows delete-pending sidecar semantics")
def test_windows_concurrent_short_connections_reanchor_retired_wal_sidecars(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _migrate(database)
    first_open = Event()
    second_anchored = Event()
    first_closed = Event()

    def first_hook(phase: str) -> None:
        if phase == "sqlite_authority.after_sqlite_open":
            first_open.set()
            assert second_anchored.wait(5)

    def second_hook(phase: str) -> None:
        if phase == "sqlite_authority.before_sqlite_open":
            second_anchored.set()
            assert first_closed.wait(5)

    first = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=first_hook,
    )
    second = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=second_hook,
    )

    def query_first() -> dict[str, int | str]:
        try:
            return first.pragma_settings()
        finally:
            first_closed.set()

    def query_second() -> dict[str, int | str]:
        assert first_open.wait(5)
        return second.pragma_settings()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(query_first)
        second_future = executor.submit(query_second)
        settings = (first_future.result(), second_future.result())

    assert [item["journal_mode"] for item in settings] == ["wal", "wal"]
    assert (
        SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).pragma_settings()["journal_mode"]
        == "wal"
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode and rename semantics")
def test_migration_creates_0600_and_detects_pre_open_swap_without_writing_target(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    original = tmp_path / "guard-created.sqlite3"
    outside = tmp_path / "outside-target.bin"
    outside.write_bytes(b"external bytes")

    def swap_at_checkpoint(phase: str) -> None:
        if phase != "sqlite_authority.before_sqlite_open":
            return
        database.rename(original)
        os.link(outside, database)

    with pytest.raises(SQLiteAuthorityError) as raised:
        MigrationRunner(
            database,
            BUSY_TIMEOUT_MS,
            authority_fault_hook=swap_at_checkpoint,
        ).apply_all()

    assert raised.value.reason_code == "DATABASE_IDENTITY_CHANGED"
    assert outside.read_bytes() == b"external bytes"
    assert stat.S_IMODE(original.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics")
def test_migration_exclusively_creates_an_owner_only_database(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"

    _migrate(database)

    info = database.stat()
    assert stat.S_ISREG(info.st_mode)
    assert info.st_nlink == 1
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid()
