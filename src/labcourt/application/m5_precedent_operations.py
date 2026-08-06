"""Bounded restart-safe orchestration for M5 precedent administration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from labcourt.application.m5_precedents import (
    evaluate_m5_automatic_activation,
    resolve_m5_precedent_conflict_batch,
)
from labcourt.contracts.m5_operations import (
    M5PrecedentActivationCommandReport,
    M5PrecedentConflictCommandReport,
    M5PrecedentImportReport,
)
from labcourt.contracts.m5_precedents import (
    MAX_M5_PRECEDENTS,
    M5PrecedentAuthority,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m5_precedents import M5PrecedentRepository


class M5PrecedentOperationsRepository(M5PrecedentRepository, Protocol):
    pass


def _require_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_M5_PRECEDENTS:
        raise ContractViolation(
            f"M5 precedent operation limit must be an integer in [1, {MAX_M5_PRECEDENTS}]"
        )
    return limit


def _require_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise ContractViolation("M5 precedent operation clock must use timezone-aware UTC")
    return value


def import_m5_precedent_authorities(
    *,
    repository: M5PrecedentRepository,
    run_id: str,
    authorities: tuple[M5PrecedentAuthority, ...],
) -> M5PrecedentImportReport:
    """Accept one validated authored batch through the repository's atomic boundary."""

    if not isinstance(authorities, tuple):
        raise TypeError("authorities must be a tuple")
    if len(authorities) > MAX_M5_PRECEDENTS:
        raise ContractViolation("M5 precedent import exceeds its hard authority bound")
    if any(not isinstance(item, M5PrecedentAuthority) for item in authorities):
        raise TypeError("authorities must contain M5PrecedentAuthority values")
    ordered = tuple(sorted(authorities, key=lambda item: item.precedent.precedent_id))
    precedent_ids = tuple(item.precedent.precedent_id for item in ordered)
    if len(precedent_ids) != len(set(precedent_ids)):
        raise ContractViolation("M5 precedent import contains duplicate precedent IDs")
    if any(item.run_id != run_id for item in ordered):
        raise ContractViolation("M5 precedent import contains an authority from another run")

    accepted = repository.append_authorities(run_id, ordered)
    if accepted != ordered:
        raise ContractViolation("M5 precedent repository returned another imported authority")
    return M5PrecedentImportReport(
        run_id=run_id,
        accepted_count=len(accepted),
        precedent_ids=precedent_ids,
        authority_ids=tuple(item.authority_id for item in accepted),
    )


def activate_m5_precedents(
    *,
    repository: M5PrecedentRepository,
    run_id: str,
    evaluated_at: datetime,
    limit: int = MAX_M5_PRECEDENTS,
) -> M5PrecedentActivationCommandReport:
    """Evaluate one stable due batch against a fresh appeal snapshot per source Case."""

    _require_limit(limit)
    _require_utc(evaluated_at)
    selected = repository.list_activation_candidates(run_id, evaluated_at, limit)
    ordered = tuple(sorted(selected, key=lambda item: item.precedent.precedent_id))
    receipts = []
    for authority in ordered:
        source_case_id = authority.precedent.source_case_id
        if source_case_id is None:
            raise ContractViolation("automatic activation candidate has no source Case")
        snapshot = repository.load_appeal_window_snapshot(
            run_id,
            source_case_id,
            evaluated_at,
        )
        result = evaluate_m5_automatic_activation(
            authority=authority,
            appeal_snapshot=snapshot,
            evaluated_at=evaluated_at,
        )
        committed = repository.commit_activation(result)
        if committed != result:
            raise ContractViolation("M5 repository returned another activation result")
        receipts.append(committed.receipt)
    return M5PrecedentActivationCommandReport(
        run_id=run_id,
        evaluated_at=evaluated_at,
        selected_count=len(ordered),
        receipts=tuple(receipts),
    )


def reconcile_m5_precedent_conflicts(
    *,
    repository: M5PrecedentOperationsRepository,
    run_id: str,
    policy: M5PrecedentPolicy,
    limit: int = MAX_M5_PRECEDENTS,
) -> M5PrecedentConflictCommandReport:
    """Exact-compare one complete budgeted active snapshot and persist real conflicts."""

    _require_limit(limit)
    snapshot = repository.load_conflict_snapshot(run_id, limit)
    if not isinstance(snapshot, M5PrecedentConflictSnapshot):
        raise ContractViolation("M5 repository returned an invalid conflict snapshot")
    ordered = snapshot.authorities
    candidate_ids = tuple(item.precedent.precedent_id for item in ordered)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ContractViolation("M5 conflict candidate inventory contains duplicate IDs")
    if snapshot.causal_cut.run_id != run_id or snapshot.causal_cut.policy_id != policy.policy_id:
        raise ContractViolation("M5 conflict candidate inventory is outside the active run scope")

    resolution = resolve_m5_precedent_conflict_batch(
        snapshot=snapshot,
        policy=policy,
        scan_limit=limit,
    )
    committed = repository.commit_conflict_batch(resolution)
    if committed != resolution:
        raise ContractViolation("M5 repository returned another conflict batch resolution")

    current_conflicts = repository.list_conflicts(run_id, MAX_M5_PRECEDENTS)
    current_ids = tuple(sorted(item.precedent.precedent_id for item in current_conflicts))
    return M5PrecedentConflictCommandReport(
        run_id=run_id,
        candidate_count=len(ordered),
        evaluated_pair_count=committed.batch_authority.evaluated_pair_count,
        conflict_edge_count=len(committed.batch_authority.edges),
        causal_cut_id=committed.batch_authority.causal_cut.cut_id,
        batch_authority_id=committed.batch_authority.batch_authority_id,
        batch_receipt_id=committed.receipt.receipt_id,
        applied_receipts=(committed.receipt,),
        current_conflict_precedent_ids=current_ids,
    )


__all__ = [
    "M5PrecedentOperationsRepository",
    "activate_m5_precedents",
    "import_m5_precedent_authorities",
    "reconcile_m5_precedent_conflicts",
]
