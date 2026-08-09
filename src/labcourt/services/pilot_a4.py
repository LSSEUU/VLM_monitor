"""Run-scoped A4 composition root for safe local pilot closure."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from labcourt.contracts.config import AppConfig
from labcourt.contracts.pilot import PilotA4CloseReport
from labcourt.contracts.references import require_portable_run_id
from labcourt.services.m5_operations import finalize_m5_run


def close_pilot_run(
    *,
    config: AppConfig,
    runs_root: str | Path,
    database_path: str | Path,
    run_id: str,
    limit: int = 256,
    clock: Callable[[], datetime] | None = None,
) -> PilotA4CloseReport:
    """Close READY cases inside one pilot run without dispatching its local outbox."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    controlled_run_id = require_portable_run_id(run_id, "pilot A4 run_id")
    supplied_root = Path(runs_root)
    supplied_database = Path(database_path)
    if ".." in supplied_root.parts or ".." in supplied_database.parts:
        raise ValueError("pilot A4 paths cannot contain parent traversal")
    root = supplied_root.absolute()
    run_root = root / controlled_run_id
    database = supplied_database.absolute()
    expected_database = run_root / config.storage.database_filename
    if database != expected_database or database.parent != run_root:
        raise ValueError("database_path must be the selected pilot run authority")

    finalization = finalize_m5_run(
        config=config,
        workspace_root=run_root,
        database_path=database,
        run_id=controlled_run_id,
        limit=limit,
        clock=clock,
    )
    return PilotA4CloseReport(
        run_id=finalization.run_id,
        manifest_id=finalization.manifest_id,
        config_sha256=finalization.config_sha256,
        selected_count=finalization.selected_count,
        outcomes=finalization.outcomes,
    )


__all__ = ["close_pilot_run"]
