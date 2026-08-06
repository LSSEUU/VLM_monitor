from __future__ import annotations

import pytest

from labcourt.contracts.enums import VerdictDecision
from labcourt.contracts.m5_precedents import M5PrecedentConflictOutcome
from labcourt.domain.precedent_conflict_policy import classify_precedent_conflict


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"same_authority_scope": False}, M5PrecedentConflictOutcome.NO_CONFLICT),
        (
            {"new_direction": VerdictDecision.ESTABLISHED},
            M5PrecedentConflictOutcome.NO_CONFLICT,
        ),
        ({"similarity": None}, M5PrecedentConflictOutcome.NO_CONFLICT),
        ({"similarity": 0.79}, M5PrecedentConflictOutcome.NO_CONFLICT),
        (
            {"existing_priority": 2, "new_priority": 1},
            M5PrecedentConflictOutcome.NEW_INVALIDATED,
        ),
        (
            {"existing_priority": 1, "new_priority": 2},
            M5PrecedentConflictOutcome.EXISTING_INVALIDATED,
        ),
        ({}, M5PrecedentConflictOutcome.PEER_CONFLICT),
    ],
)
def test_conflict_policy_covers_every_decision_branch(
    updates: dict[str, object],
    expected: M5PrecedentConflictOutcome,
) -> None:
    inputs: dict[str, object] = {
        "same_authority_scope": True,
        "existing_direction": VerdictDecision.ESTABLISHED,
        "new_direction": VerdictDecision.NOT_ESTABLISHED,
        "similarity": 0.8,
        "threshold": 0.8,
        "existing_priority": 1,
        "new_priority": 1,
    }
    inputs.update(updates)
    assert classify_precedent_conflict(**inputs) == expected  # type: ignore[arg-type]
