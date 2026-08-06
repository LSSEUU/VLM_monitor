"""Pure M5 precedent-conflict classification policy."""

from __future__ import annotations

from labcourt.contracts.enums import VerdictDecision
from labcourt.contracts.m5_precedents import M5PrecedentConflictOutcome


def precedent_directions_are_opposed(
    first: VerdictDecision,
    second: VerdictDecision,
) -> bool:
    """Return whether two terminal precedent directions actually contradict."""

    return {first, second} == {
        VerdictDecision.ESTABLISHED,
        VerdictDecision.NOT_ESTABLISHED,
    }


def classify_precedent_conflict(
    *,
    same_authority_scope: bool,
    existing_direction: VerdictDecision,
    new_direction: VerdictDecision,
    similarity: float | None,
    threshold: float,
    existing_priority: int,
    new_priority: int,
) -> M5PrecedentConflictOutcome:
    """Classify one exact pair without mutating either authority."""

    if not same_authority_scope:
        return M5PrecedentConflictOutcome.NO_CONFLICT
    if not precedent_directions_are_opposed(existing_direction, new_direction):
        return M5PrecedentConflictOutcome.NO_CONFLICT
    if similarity is None:
        return M5PrecedentConflictOutcome.NO_CONFLICT
    if similarity < threshold:
        return M5PrecedentConflictOutcome.NO_CONFLICT
    if existing_priority > new_priority:
        return M5PrecedentConflictOutcome.NEW_INVALIDATED
    if new_priority > existing_priority:
        return M5PrecedentConflictOutcome.EXISTING_INVALIDATED
    return M5PrecedentConflictOutcome.PEER_CONFLICT


__all__ = [
    "classify_precedent_conflict",
    "precedent_directions_are_opposed",
]
