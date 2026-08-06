"""Composition boundary for one-snapshot M4 validation and JSON projection."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.m4_json_projector import (
    MAX_M4_PROJECTION_BYTES,
    M4JsonProjector,
    M4ProjectionFailure,
    M4ProjectionFaultInjector,
    M4ProjectionResult,
)
from labcourt.adapters.storage.readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import (
    DEFAULT_MAX_DATABASE_BYTES,
    readonly_sqlite_snapshot,
    snapshot_contains_run,
)
from labcourt.contracts.references import require_reference_token


def rebuild_m4_projection(
    *,
    run_id: str,
    database_path: str | Path,
    workspace_root: str | Path,
    max_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
    max_projection_bytes: int = MAX_M4_PROJECTION_BYTES,
    fault_injector: M4ProjectionFaultInjector | None = None,
) -> M4ProjectionResult:
    """Validate and project exactly one private SQLite snapshot."""

    controlled_run_id = require_reference_token(run_id, "M4 projection run reference")
    database = Path(database_path).absolute()
    with readonly_sqlite_snapshot(
        database,
        max_database_bytes=max_database_bytes,
    ) as snapshot_path:
        if not snapshot_contains_run(snapshot_path, controlled_run_id):
            raise M4ProjectionFailure("M4 projection run does not exist")
        authority = ReadonlyM4ArtifactRepository(snapshot_path).scan(controlled_run_id)
        return M4JsonProjector(
            workspace_root,
            fault_injector=fault_injector,
            max_projection_bytes=max_projection_bytes,
        ).publish(authority)


__all__ = ["rebuild_m4_projection"]
