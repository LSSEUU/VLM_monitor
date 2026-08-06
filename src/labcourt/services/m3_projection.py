"""Bounded post-authority rebuild of M3 JSON projections."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.json_projector import (
    JsonProjector,
    ProjectionFaultInjector,
)
from labcourt.adapters.storage.readonly_sqlite import (
    ReadOnlySnapshotError,
    readonly_sqlite_snapshot,
    snapshot_contains_run,
    snapshot_run_counts,
)
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m3_command_reports import (
    M3ProjectionBudget,
    M3ProjectionCounts,
    M3ProjectionDisposition,
    M3ProjectionOutcome,
    M3ProjectionReasonCode,
)
from labcourt.contracts.references import require_reference_token


def rebuild_m3_projection(
    *,
    config: AppConfig,
    run_id: str,
    workspace_root: str | Path,
    database_path: str | Path,
    budget: M3ProjectionBudget,
    fault_injector: ProjectionFaultInjector | None = None,
) -> M3ProjectionOutcome:
    """Rebuild from one bounded private snapshot, returning only typed failures."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    controlled_run_id = require_reference_token(run_id, "M3 projection run reference")
    if not isinstance(budget, M3ProjectionBudget):
        raise TypeError("budget must be an M3ProjectionBudget")
    if fault_injector is not None and not callable(fault_injector):
        raise TypeError("fault_injector must be callable")

    root = Path(workspace_root).absolute()
    database = Path(database_path).absolute()
    if database != root / config.storage.database_filename:
        raise ValueError("database_path must match the configured projection authority")

    counts: M3ProjectionCounts | None = None
    try:
        with readonly_sqlite_snapshot(
            database,
            max_database_bytes=budget.max_database_bytes,
        ) as snapshot:
            if not snapshot_contains_run(snapshot, controlled_run_id):
                return _pending(
                    budget,
                    M3ProjectionReasonCode.RUN_NOT_FOUND,
                    counts=None,
                )
            observed = snapshot_run_counts(snapshot, controlled_run_id)
            counts = M3ProjectionCounts(
                snapshot_database_bytes=snapshot.stat().st_size,
                audit_entries=observed.audit_entries,
                cases=observed.cases,
                packs=observed.packs,
                max_document_bytes=observed.max_document_bytes,
            )
            reason = _preflight_reason(counts, budget)
            if reason is not None:
                return _pending(budget, reason, counts=counts)

            repository = SQLiteEvidenceRepository(
                snapshot,
                config.storage.busy_timeout_ms,
            )
            JsonProjector(
                repository,
                root,
                fault_injector=fault_injector,
                max_projection_bytes=budget.max_projection_file_bytes,
            ).project_run(controlled_run_id)
    except ReadOnlySnapshotError as error:
        reason = (
            M3ProjectionReasonCode.DATABASE_BYTES_BUDGET_EXCEEDED
            if error.reason_code == "DATABASE_BYTES_BUDGET_EXCEEDED"
            else M3ProjectionReasonCode.SNAPSHOT_UNAVAILABLE
        )
        return _pending(budget, reason, counts=counts)
    # This is deliberately the post-commit failure boundary.  Any ordinary
    # projector exception becomes a typed pending outcome so it cannot erase
    # the authoritative report that the caller already holds.  Process-control
    # exceptions (KeyboardInterrupt/SystemExit) remain outside Exception.
    except Exception:
        return _pending(
            budget,
            M3ProjectionReasonCode.PROJECTION_REBUILD_FAILED,
            counts=counts,
        )

    return M3ProjectionOutcome(
        disposition=M3ProjectionDisposition.REBUILT,
        reason_code=None,
        budget=budget,
        counts=counts,
    )


def _preflight_reason(
    counts: M3ProjectionCounts,
    budget: M3ProjectionBudget,
) -> M3ProjectionReasonCode | None:
    if counts.snapshot_database_bytes > budget.max_database_bytes:
        return M3ProjectionReasonCode.DATABASE_BYTES_BUDGET_EXCEEDED
    if counts.audit_entries > budget.max_audit_entries:
        return M3ProjectionReasonCode.AUDIT_ENTRY_BUDGET_EXCEEDED
    if counts.cases > budget.max_cases:
        return M3ProjectionReasonCode.CASE_BUDGET_EXCEEDED
    if counts.packs > budget.max_packs:
        return M3ProjectionReasonCode.PACK_BUDGET_EXCEEDED
    if counts.max_document_bytes > budget.max_document_bytes:
        return M3ProjectionReasonCode.DOCUMENT_BYTES_BUDGET_EXCEEDED
    if (
        counts.max_document_bytes > budget.max_projection_file_bytes
        or counts.largest_jsonl_upper_bound_bytes > budget.max_projection_file_bytes
    ):
        return M3ProjectionReasonCode.PROJECTION_FILE_BUDGET_EXCEEDED
    if counts.materialization_upper_bound_bytes > budget.max_materialization_bytes:
        return M3ProjectionReasonCode.MATERIALIZATION_BUDGET_EXCEEDED
    return None


def _pending(
    budget: M3ProjectionBudget,
    reason: M3ProjectionReasonCode,
    *,
    counts: M3ProjectionCounts | None,
) -> M3ProjectionOutcome:
    return M3ProjectionOutcome(
        disposition=M3ProjectionDisposition.PENDING_REBUILD,
        reason_code=reason,
        budget=budget,
        counts=counts,
    )


__all__ = ["rebuild_m3_projection"]
