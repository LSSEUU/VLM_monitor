"""One-snapshot composition boundary for M5 validation and projection."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.m5_jsonl_projector import (
    MAX_M5_PROJECTION_BYTES,
    M5JsonlProjector,
    M5ProjectionFaultInjector,
    M5ProjectionResult,
)
from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import (
    DEFAULT_MAX_DATABASE_BYTES,
    readonly_sqlite_snapshot,
    snapshot_contains_run,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.references import require_reference_token


def rebuild_m5_projection(
    *,
    config: AppConfig,
    run_id: str,
    database_path: str | Path,
    workspace_root: str | Path,
    max_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
    max_projection_bytes: int = MAX_M5_PROJECTION_BYTES,
    fault_injector: M5ProjectionFaultInjector | None = None,
) -> M5ProjectionResult:
    controlled = require_reference_token(run_id, "M5 projection run reference")
    database = Path(database_path).absolute()
    with readonly_sqlite_snapshot(database, max_database_bytes=max_database_bytes) as snapshot:
        if not snapshot_contains_run(snapshot, controlled):
            from labcourt.adapters.storage.m5_jsonl_projector import M5ProjectionFailure

            raise M5ProjectionFailure("M5 projection run does not exist")
        authority = ReadonlyM5ArtifactRepository(snapshot, config=config).scan(controlled)
        return M5JsonlProjector(
            workspace_root,
            fault_injector=fault_injector,
            max_projection_bytes=max_projection_bytes,
        ).publish(authority)


__all__ = ["rebuild_m5_projection"]
