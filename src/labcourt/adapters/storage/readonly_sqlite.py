"""Globally stable, read-only SQLite snapshots for validation-only workflows."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from labcourt.adapters.storage.secure_workspace import (
    create_owner_only_directory,
    require_owner_only_directory,
)
from labcourt.exceptions import ContractViolation, PathBoundaryViolation

from .sqlite_schema import (
    M3_REQUIRED_MIGRATION_VERSIONS,
    m3_authority_hardening_installed,
)

_O_BINARY = int(getattr(os, "O_BINARY", 0))
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))
_O_NOFOLLOW = int(getattr(os, "O_NOFOLLOW", 0))
_O_NOATIME = int(getattr(os, "O_NOATIME", 0))
_FILE_ATTRIBUTE_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_COPY_CHUNK_BYTES = 1024 * 1024
DEFAULT_MAX_DATABASE_BYTES = 4 * 1024 * 1024 * 1024


class ReadOnlySnapshotError(ContractViolation):
    """The authoritative database could not be safely snapshotted without writes."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"read-only SQLite snapshot failed: {reason_code}")


@dataclass(frozen=True, slots=True)
class SnapshotRunCounts:
    max_document_bytes: int
    audit_entries: int
    events: int
    cases: int
    packs: int
    media: int
    model_call_claims: int = 0
    model_call_failure_authorities: int = 0
    model_responses: int = 0
    parsed_screening_outputs: int = 0
    model_parse_receipts: int = 0
    model_cache_entries: int = 0
    model_call_usage: int = 0
    screening_results: int = 0
    verdicts: int = 0
    procedural_reviews: int = 0
    procedural_defects: int = 0
    backlog_items: int = 0
    backlog_item_versions: int = 0
    backlog_heads: int = 0
    backlog_completion_receipts: int = 0
    raw_response_bytes: int = 0
    max_raw_response_bytes: int = 0
    m3_max_document_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _Identity:
    device: int
    inode: int
    size_bytes: int
    modified_ns: int
    link_count: int


@dataclass(frozen=True, slots=True)
class _SourceFile:
    name: str
    path: Path
    descriptor: int
    identity: _Identity
    sha256: str


def _is_reparse(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _identity(info: os.stat_result) -> _Identity:
    return _Identity(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        size_bytes=int(info.st_size),
        modified_ns=int(info.st_mtime_ns),
        link_count=int(info.st_nlink),
    )


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_READ_FAILED") from None


def _candidate_paths(database: Path) -> tuple[Path, Path, Path]:
    return (
        database,
        database.with_name(f"{database.name}-wal"),
        database.with_name(f"{database.name}-shm"),
    )


def _present_source_paths(database: Path) -> tuple[Path, ...]:
    present: list[Path] = []
    for path in _candidate_paths(database):
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            raise ReadOnlySnapshotError("DATABASE_STAT_FAILED") from None
        present.append(path)
    return tuple(present)


def _journal_present(database: Path) -> bool:
    journal = database.with_name(f"{database.name}-journal")
    try:
        os.lstat(journal)
    except FileNotFoundError:
        return False
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_STAT_FAILED") from None
    return True


def _open_source_file(path: Path, parent_resolved: Path) -> _SourceFile:
    try:
        path_info = os.lstat(path)
    except FileNotFoundError:
        raise ReadOnlySnapshotError("DATABASE_SOURCE_SET_CHANGED") from None
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_STAT_FAILED") from None
    if (
        not stat.S_ISREG(path_info.st_mode)
        or stat.S_ISLNK(path_info.st_mode)
        or _is_reparse(path_info)
        or int(path_info.st_nlink) != 1
    ):
        raise ReadOnlySnapshotError("DATABASE_FILE_UNSAFE")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_RESOLUTION_FAILED") from None
    if resolved.parent != parent_resolved or resolved.name != path.name:
        raise ReadOnlySnapshotError("DATABASE_PATH_ESCAPE")

    flags = os.O_RDONLY | _O_BINARY | _O_CLOEXEC | _O_NOFOLLOW | _O_NOATIME
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_OPEN_FAILED") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(opened.st_nlink) != 1
            or _identity(opened) != _identity(path_info)
        ):
            raise ReadOnlySnapshotError("DATABASE_IDENTITY_MISMATCH")
    except BaseException:
        os.close(descriptor)
        raise
    return _SourceFile(path.name, path, descriptor, _identity(opened), "")


def _open_source_set(
    database: Path,
    max_database_bytes: int,
) -> tuple[_SourceFile, ...]:
    try:
        parent_info = os.lstat(database.parent)
    except FileNotFoundError:
        raise ReadOnlySnapshotError("DATABASE_MISSING") from None
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_STAT_FAILED") from None
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or _is_reparse(parent_info)
    ):
        raise ReadOnlySnapshotError("DATABASE_PARENT_UNSAFE")
    try:
        parent_resolved = database.parent.resolve(strict=True)
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_RESOLUTION_FAILED") from None
    if _journal_present(database):
        raise ReadOnlySnapshotError("DATABASE_ROLLBACK_JOURNAL_UNSUPPORTED")

    paths = _present_source_paths(database)
    if not paths or paths[0] != database:
        raise ReadOnlySnapshotError("DATABASE_MISSING")
    opened: list[_SourceFile] = []
    try:
        for path in paths:
            opened.append(_open_source_file(path, parent_resolved))
        if sum(source.identity.size_bytes for source in opened) > max_database_bytes:
            raise ReadOnlySnapshotError("DATABASE_BYTES_BUDGET_EXCEEDED")
        sources = tuple(
            _SourceFile(
                source.name,
                source.path,
                source.descriptor,
                source.identity,
                _hash_descriptor(source.descriptor),
            )
            for source in opened
        )
        _require_stable_source_set(database, sources)
        return sources
    except BaseException:
        for source in opened:
            os.close(source.descriptor)
        raise


def _require_stable_source_set(database: Path, sources: tuple[_SourceFile, ...]) -> None:
    try:
        observed_paths = _present_source_paths(database)
        journal_exists = _journal_present(database)
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_RESTAT_FAILED") from None
    if journal_exists or tuple(path.name for path in observed_paths) != tuple(
        source.name for source in sources
    ):
        raise ReadOnlySnapshotError("DATABASE_SOURCE_SET_CHANGED")
    for source in sources:
        try:
            path_info = os.lstat(source.path)
            opened = os.fstat(source.descriptor)
        except OSError:
            raise ReadOnlySnapshotError("DATABASE_RESTAT_FAILED") from None
        if (
            not stat.S_ISREG(path_info.st_mode)
            or stat.S_ISLNK(path_info.st_mode)
            or _is_reparse(path_info)
            or _identity(path_info) != source.identity
            or _identity(opened) != source.identity
            or _hash_descriptor(source.descriptor) != source.sha256
        ):
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_SNAPSHOT")


def _copy_source(source: _SourceFile, target: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_CLOEXEC
    try:
        target_descriptor = os.open(target, flags, 0o600)
    except OSError:
        raise ReadOnlySnapshotError("PRIVATE_SNAPSHOT_CREATE_FAILED") from None
    digest = hashlib.sha256()
    try:
        os.lseek(source.descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source.descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
        os.fsync(target_descriptor)
    except OSError:
        raise ReadOnlySnapshotError("PRIVATE_SNAPSHOT_COPY_FAILED") from None
    finally:
        os.close(target_descriptor)
    try:
        os.chmod(target, 0o600)
    except OSError:
        raise ReadOnlySnapshotError("PRIVATE_SNAPSHOT_PERMISSIONS_FAILED") from None
    if digest.hexdigest() != source.sha256:
        raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_SNAPSHOT")


def _sqlite_backup(source_database: Path, snapshot: Path) -> None:
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    try:
        source = sqlite3.connect(
            f"{source_database.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
        )
        source.execute("PRAGMA query_only = ON")
        source.execute("BEGIN")
        source.execute("SELECT schema_version FROM pragma_schema_version").fetchone()
        target = sqlite3.connect(snapshot)
        source.backup(target)
        target.commit()
    except sqlite3.Error:
        raise ReadOnlySnapshotError("DATABASE_BACKUP_FAILED") from None
    finally:
        if target is not None:
            target.close()
        if source is not None:
            source.close()
    try:
        os.chmod(snapshot, 0o600)
    except OSError:
        raise ReadOnlySnapshotError("PRIVATE_SNAPSHOT_PERMISSIONS_FAILED") from None


def _require_private_directory(path: Path) -> None:
    try:
        require_owner_only_directory(path)
    except PathBoundaryViolation as error:
        raise ReadOnlySnapshotError(error.reason_code) from None


@contextmanager
def readonly_sqlite_snapshot(
    database_path: str | Path,
    *,
    max_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
) -> Iterator[Path]:
    """Yield a private SQLite backup without ever opening the source through SQLite.

    SQLite may write WAL read marks even for ``mode=ro`` connections. The source files
    are therefore copied from validated read handles as one globally stable set; only
    that private copy is passed to SQLite. See ADR 0009 for the residual path-open ABA
    boundary that cannot be removed without a custom VFS.
    """

    if not isinstance(max_database_bytes, int) or isinstance(max_database_bytes, bool):
        raise TypeError("max_database_bytes must be an integer")
    if max_database_bytes <= 0:
        raise ValueError("max_database_bytes must be positive")
    database = Path(database_path).absolute()
    sources = _open_source_set(database, max_database_bytes)
    try:
        with tempfile.TemporaryDirectory(prefix="labcourt-artifact-validation-") as temporary:
            private_root = Path(temporary) / "private"
            try:
                create_owner_only_directory(private_root)
                raw = private_root / "raw"
                create_owner_only_directory(raw)
            except PathBoundaryViolation as error:
                raise ReadOnlySnapshotError(error.reason_code) from None
            for source in sources:
                _copy_source(source, raw / source.name)
            _require_private_directory(private_root)
            _require_private_directory(raw)
            _require_stable_source_set(database, sources)
            snapshot = private_root / "labcourt.sqlite3"
            _sqlite_backup(raw / database.name, snapshot)
            _require_private_directory(private_root)
            _require_private_directory(raw)
            _require_stable_source_set(database, sources)
            try:
                yield snapshot
            finally:
                _require_private_directory(private_root)
                _require_private_directory(raw)
                _require_stable_source_set(database, sources)
    finally:
        for source in sources:
            os.close(source.descriptor)


def snapshot_contains_run(snapshot: str | Path, run_id: str) -> bool:
    """Check run existence in the private snapshot without creating any database."""

    database = Path(snapshot).absolute()
    try:
        connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
        try:
            row = connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ? LIMIT 1",
                (run_id,),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID") from None
    return row is not None


def snapshot_run_counts(snapshot: str | Path, run_id: str) -> SnapshotRunCounts:
    """Count run-scoped rows with constant-memory queries before repository materialization."""

    database = Path(snapshot).absolute()
    try:
        connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
        try:
            row = connection.execute(
                """
                WITH document_lengths(bytes) AS (
                    SELECT length(CAST(rm.document_json AS BLOB))
                    FROM run_manifests AS rm
                    JOIN runs AS r ON r.manifest_id = rm.manifest_id
                    WHERE r.run_id = ?
                    UNION ALL
                    SELECT length(CAST(c.event_json AS BLOB))
                    FROM cases AS c WHERE c.run_id = ?
                    UNION ALL
                    SELECT length(CAST(cv.case_json AS BLOB))
                    FROM case_versions AS cv WHERE cv.run_id = ?
                    UNION ALL
                    SELECT length(CAST(ep.pack_json AS BLOB))
                    FROM evidence_packs AS ep WHERE ep.run_id = ?
                    UNION ALL
                    SELECT length(CAST(ae.entry_json AS BLOB))
                    FROM audit_entries AS ae WHERE ae.run_id = ?
                    UNION ALL
                    SELECT length(CAST(epc.crop_json AS BLOB))
                    FROM evidence_pack_crops AS epc WHERE epc.run_id = ?
                    UNION ALL
                    SELECT length(CAST(f.document_json AS BLOB))
                    FROM frames AS f WHERE f.run_id = ?
                    UNION ALL
                    SELECT length(CAST(d.document_json AS BLOB))
                    FROM detections AS d WHERE d.run_id = ?
                )
                SELECT
                    (SELECT COUNT(*) FROM audit_entries WHERE run_id = ?),
                    (SELECT COUNT(*) FROM cases WHERE run_id = ?),
                    (SELECT COUNT(*) FROM evidence_packs WHERE run_id = ?),
                    (SELECT COUNT(*) FROM media_assets WHERE run_id = ?),
                    COALESCE((SELECT MAX(bytes) FROM document_lengths), 0)
                """,
                (run_id,) * 12,
            ).fetchone()
            m3_row = _snapshot_m3_run_counts(connection, run_id)
        finally:
            connection.close()
    except sqlite3.Error:
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID") from None
    if row is None or len(row) != 5:
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
    audit_entries, cases, packs, media, m2_max_document_bytes = (int(value) for value in row)
    (
        model_call_claims,
        model_call_failure_authorities,
        model_responses,
        parsed_screening_outputs,
        model_parse_receipts,
        model_cache_entries,
        model_call_usage,
        screening_results,
        verdicts,
        procedural_reviews,
        procedural_defects,
        backlog_items,
        backlog_item_versions,
        backlog_heads,
        backlog_completion_receipts,
        raw_response_bytes,
        max_raw_response_bytes,
        m3_max_document_bytes,
    ) = m3_row
    return SnapshotRunCounts(
        # Frozen M2 callers consume this field directly.  M3 document sizes have
        # their own field so adding M3 tables cannot retroactively change an M2
        # validation result.
        max_document_bytes=m2_max_document_bytes,
        audit_entries=audit_entries,
        events=cases,
        cases=cases,
        packs=packs,
        media=media,
        model_call_claims=model_call_claims,
        model_call_failure_authorities=model_call_failure_authorities,
        model_responses=model_responses,
        parsed_screening_outputs=parsed_screening_outputs,
        model_parse_receipts=model_parse_receipts,
        model_cache_entries=model_cache_entries,
        model_call_usage=model_call_usage,
        screening_results=screening_results,
        verdicts=verdicts,
        procedural_reviews=procedural_reviews,
        procedural_defects=procedural_defects,
        backlog_items=backlog_items,
        backlog_item_versions=backlog_item_versions,
        backlog_heads=backlog_heads,
        backlog_completion_receipts=backlog_completion_receipts,
        raw_response_bytes=raw_response_bytes,
        max_raw_response_bytes=max_raw_response_bytes,
        m3_max_document_bytes=m3_max_document_bytes,
    )


_M3_TABLES = frozenset(
    {
        "model_call_claims",
        "model_call_failure_authorities",
        "model_responses",
        "parsed_screening_outputs",
        "model_parse_receipts",
        "model_cache",
        "model_call_usage_accounting",
        "screening_results",
        "verdicts",
        "procedural_reviews",
        "procedural_defects",
        "backlog_items",
        "backlog_item_versions",
        "backlog_heads",
        "backlog_completion_receipts",
    }
)


def _snapshot_m3_run_counts(
    connection: sqlite3.Connection,
    run_id: str,
) -> tuple[int, ...]:
    """Return zeroes for a complete frozen M2 schema, or exact M3 counts.

    A partially migrated M3 schema is not interpreted.  Treating missing tables
    as empty would let a damaged authority snapshot pass validation.
    """

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    all_tables = {str(row[0]) for row in table_rows if isinstance(row[0], str)}
    tables = all_tables & _M3_TABLES
    if not tables:
        if "schema_migrations" in all_tables:
            migrations = {
                int(row[0])
                for row in connection.execute(
                    "SELECT version FROM schema_migrations WHERE version IN (4, 5, 6, 7)"
                ).fetchall()
                if isinstance(row[0], int) and not isinstance(row[0], bool)
            }
            if migrations:
                raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
        return (0,) * 18
    if tables != _M3_TABLES:
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
    migrations = {
        int(row[0])
        for row in connection.execute(
            "SELECT version FROM schema_migrations WHERE version IN (4, 5, 6, 7)"
        ).fetchall()
        if isinstance(row[0], int) and not isinstance(row[0], bool)
    }
    if migrations != M3_REQUIRED_MIGRATION_VERSIONS or not m3_authority_hardening_installed(
        connection
    ):
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")

    row = connection.execute(
        """
        WITH document_lengths(bytes) AS (
            SELECT length(CAST(request_json AS BLOB))
            FROM model_call_claims WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(authority_json AS BLOB))
            FROM model_call_failure_authorities WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(response_json AS BLOB))
            FROM model_responses WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(output_json AS BLOB))
            FROM parsed_screening_outputs WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(receipt_json AS BLOB))
            FROM model_parse_receipts WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(request_json AS BLOB))
            FROM model_cache WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(entry_json AS BLOB))
            FROM model_cache WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(usage_json AS BLOB))
            FROM model_call_usage_accounting WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(result_json AS BLOB))
            FROM screening_results WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(verdict_json AS BLOB))
            FROM verdicts WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(review_json AS BLOB))
            FROM procedural_reviews WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(defect_json AS BLOB))
            FROM procedural_defects WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(initial_json AS BLOB))
            FROM backlog_items WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(item_json AS BLOB))
            FROM backlog_item_versions WHERE run_id = ?
            UNION ALL
            SELECT length(CAST(receipt_json AS BLOB))
            FROM backlog_completion_receipts WHERE run_id = ?
        )
        SELECT
            (SELECT COUNT(*) FROM model_call_claims WHERE run_id = ?),
            (SELECT COUNT(*) FROM model_call_failure_authorities WHERE run_id = ?),
            (SELECT COUNT(*) FROM model_responses WHERE run_id = ?),
            (SELECT COUNT(*) FROM parsed_screening_outputs WHERE run_id = ?),
            (SELECT COUNT(*) FROM model_parse_receipts WHERE run_id = ?),
            (SELECT COUNT(*) FROM model_cache WHERE run_id = ?),
            (SELECT COUNT(*) FROM model_call_usage_accounting WHERE run_id = ?),
            (SELECT COUNT(*) FROM screening_results WHERE run_id = ?),
            (SELECT COUNT(*) FROM verdicts WHERE run_id = ?),
            (SELECT COUNT(*) FROM procedural_reviews WHERE run_id = ?),
            (SELECT COUNT(*) FROM procedural_defects WHERE run_id = ?),
            (SELECT COUNT(*) FROM backlog_items WHERE run_id = ?),
            (SELECT COUNT(*) FROM backlog_item_versions WHERE run_id = ?),
            (SELECT COUNT(*) FROM backlog_heads WHERE run_id = ?),
            (SELECT COUNT(*) FROM backlog_completion_receipts WHERE run_id = ?),
            COALESCE((SELECT SUM(size_bytes) FROM model_responses WHERE run_id = ?), 0),
            COALESCE((SELECT MAX(size_bytes) FROM model_responses WHERE run_id = ?), 0),
            COALESCE((SELECT MAX(bytes) FROM document_lengths), 0)
        """,
        (run_id,) * 32,
    ).fetchone()
    if (
        row is None
        or len(row) != 18
        or any(not isinstance(value, (int, float)) or isinstance(value, bool) for value in row)
    ):
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID")
    return tuple(int(value) for value in row)


__all__ = [
    "DEFAULT_MAX_DATABASE_BYTES",
    "ReadOnlySnapshotError",
    "SnapshotRunCounts",
    "readonly_sqlite_snapshot",
    "snapshot_contains_run",
    "snapshot_run_counts",
]
