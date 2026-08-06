"""Composition boundary for explicit M5 appeal commands."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.application.m5_appeal_operations import M5AppealOperationsCoordinator
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_appeal_operations import (
    M5AppealResolutionCommandReport,
    M5AppealReviewCommandReport,
    M5AppealSubmissionCommandReport,
)
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealReviewCommand,
    AppealSubmissionCommand,
)


def _open_coordinator(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
) -> M5AppealOperationsCoordinator:
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    supplied_root = Path(workspace_root)
    supplied_database = Path(database_path)
    if ".." in supplied_root.parts or ".." in supplied_database.parts:
        raise ValueError("M5 appeal operation paths cannot contain parent traversal")
    root = supplied_root.absolute()
    database = supplied_database.absolute()
    expected = root / config.storage.database_filename
    if database != expected or database.parent != root:
        raise ValueError(
            "database_path must be the configured appeal authority inside workspace_root"
        )
    return M5AppealOperationsCoordinator(
        SQLiteM5Repository(database, config.storage.busy_timeout_ms)
    )


def submit_m5_appeal(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    command: AppealSubmissionCommand,
) -> M5AppealSubmissionCommandReport:
    """Submit one fully explicit human-authored appeal command."""

    return _open_coordinator(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    ).submit(command)


def begin_m5_appeal_review(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    command: AppealReviewCommand,
) -> M5AppealReviewCommandReport:
    """Assign the explicit reviewer and begin review exactly once."""

    return _open_coordinator(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    ).begin_review(command)


def resolve_m5_appeal(
    *,
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
    command: AppealResolutionCommand,
) -> M5AppealResolutionCommandReport:
    """Commit one explicit terminal human decision and its atomic effects."""

    return _open_coordinator(
        config=config,
        workspace_root=workspace_root,
        database_path=database_path,
    ).resolve(command)


__all__ = [
    "begin_m5_appeal_review",
    "resolve_m5_appeal",
    "submit_m5_appeal",
]
