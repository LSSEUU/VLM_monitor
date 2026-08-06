"""Offline composition for provider-free M4 hearing response recovery."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from labcourt.adapters.storage.hearing_model_response_store import (
    SecureHearingModelResponseStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_hearing_recovery import (
    SQLiteHearingModelCallRecoveryRepository,
)
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.application.hearing_model_response_recovery import (
    HearingModelCallRecoveryService,
)
from labcourt.contracts.hearing_recovery import MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS


def build_m4_hearing_model_response_recovery(
    *,
    database_path: str | Path,
    busy_timeout_ms: int,
    workspace: SecureWorkspace,
    limit: int = MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS,
    clock: Callable[[], datetime] | None = None,
) -> HearingModelCallRecoveryService:
    """Build a recovery-only service with no provider, parser, or Case writer.

    The returned service can inspect durable claims, verify an already
    journaled/final response, and complete the exact expired claim.  Its
    composition contains no VLM client or acquisition executor.
    """

    if not isinstance(workspace, SecureWorkspace):
        raise TypeError("workspace must be a SecureWorkspace")
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS
    ):
        raise ValueError("M4 hearing recovery limit is invalid")
    response_store = SecureHearingModelResponseStore(workspace)
    host = SQLiteEvidenceRepository(
        database_path,
        busy_timeout_ms,
        clock=clock,
    )
    repository = SQLiteHearingModelCallRecoveryRepository(host, response_store)
    return HearingModelCallRecoveryService(
        repository=repository,
        responses=response_store,
        limit=limit,
    )


__all__ = ["build_m4_hearing_model_response_recovery"]
