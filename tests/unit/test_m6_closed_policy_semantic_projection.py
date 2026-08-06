from __future__ import annotations

import pytest

from labcourt.domain.m6_semantic_projection import (
    build_m6_closed_policy_case_replay_snapshot,
)
from tests.contract.test_m6_replay_locked_closed_policy_execution_contracts import (
    _closed_terminal,
)
from tests.unit.test_m6_semantic_projection import _snapshot


def test_closed_policy_projection_reuses_five_roots_and_rebuilds_policy_root() -> None:
    record = _closed_terminal().sample_executions[0]
    candidate = record.closed_candidate_binding
    ready_snapshot = _snapshot(candidate.transient_ready_case, revision=1).model_copy(
        update={"sample_id": record.sample_id}
    )

    rebuilt = build_m6_closed_policy_case_replay_snapshot(
        pre_policy_snapshot=ready_snapshot,
        transient_ready_case=candidate.transient_ready_case,
        candidate_alert_policy=candidate.candidate_alert_policy,
        closed_candidate_case=candidate.closed_candidate_case,
    )

    assert rebuilt == record.candidate_snapshot
    assert rebuilt.stage_roots[:-1] == ready_snapshot.stage_roots[:-1]
    assert rebuilt.stage_roots[-1] != ready_snapshot.stage_roots[-1]


def test_closed_policy_projection_rejects_a_policy_from_another_ready_case() -> None:
    record = _closed_terminal().sample_executions[0]
    candidate = record.closed_candidate_binding
    foreign_ready = record.policy_causal_cut.source_ready_case
    ready_snapshot = _snapshot(foreign_ready, revision=1).model_copy(
        update={"sample_id": record.sample_id}
    )

    with pytest.raises(ValueError, match="exact READY successor"):
        build_m6_closed_policy_case_replay_snapshot(
            pre_policy_snapshot=ready_snapshot,
            transient_ready_case=foreign_ready,
            candidate_alert_policy=candidate.candidate_alert_policy,
            closed_candidate_case=candidate.closed_candidate_case,
        )
