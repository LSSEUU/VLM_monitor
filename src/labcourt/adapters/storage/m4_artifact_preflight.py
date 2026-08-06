"""Bounded M4 presence and byte preflight over an existing private snapshot."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from labcourt.contracts.references import require_reference_token

from .readonly_sqlite import ReadOnlySnapshotError
from .sqlite_schema import M4_AUTHORITY_TABLES


@dataclass(frozen=True, slots=True)
class M4ArtifactPreflight:
    """Cheap observations used before materializing M4 authority documents."""

    has_authority: bool
    authority_rows: int
    max_document_bytes: int


def m4_artifact_preflight(snapshot: str | Path, run_id: str) -> M4ArtifactPreflight:
    """Inspect only run-scoped M4 rows in the supplied read-only snapshot."""

    controlled_run_id = require_reference_token(run_id, "M4 artifact preflight run_id")
    database = Path(snapshot).absolute()
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{database.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
        )
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            if isinstance(row[0], str)
        }
        authority_rows = 0
        max_document_bytes = 0
        for table in sorted(M4_AUTHORITY_TABLES & tables):
            columns = tuple(
                str(row[1])
                for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                if isinstance(row[1], str)
            )
            if "run_id" not in columns:
                continue
            row = connection.execute(
                f'SELECT COUNT(*) FROM "{table}" WHERE run_id = ?',
                (controlled_run_id,),
            ).fetchone()
            if row is None or not isinstance(row[0], int) or isinstance(row[0], bool):
                raise sqlite3.DatabaseError
            authority_rows += row[0]
            for column in columns:
                if not column.endswith("_json"):
                    continue
                size = connection.execute(
                    f'SELECT MAX(length(CAST("{column}" AS BLOB))) FROM "{table}" WHERE run_id = ?',
                    (controlled_run_id,),
                ).fetchone()
                if size is not None and isinstance(size[0], int) and not isinstance(size[0], bool):
                    max_document_bytes = max(max_document_bytes, size[0])
        connection.commit()
        return M4ArtifactPreflight(
            has_authority=authority_rows > 0,
            authority_rows=authority_rows,
            max_document_bytes=max_document_bytes,
        )
    except sqlite3.Error:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        raise ReadOnlySnapshotError("DATABASE_SCHEMA_INVALID") from None
    finally:
        if connection is not None:
            connection.close()


__all__ = ["M4ArtifactPreflight", "m4_artifact_preflight"]
