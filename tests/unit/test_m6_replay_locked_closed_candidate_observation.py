from __future__ import annotations

import dataclasses

import pytest

from labcourt.application.m6_replay_locked_closed_candidate_observation import (
    build_m6_replay_locked_closed_candidate_observation,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateError,
    M6ReplayLockedClosedCandidateFailureCode,
)
from tests.contract.test_m6_replay_locked_closed_policy_execution_contracts import (
    _closed_terminal,
)
from tests.unit.test_m6_replay_locked_closed_policy_candidate_port import (
    _authorities,
)
from tests.unit.test_m6_semantic_projection import _snapshot


def test_observation_recovers_ready_witness_and_snapshot_without_storing_ready() -> None:
    seal = _closed_terminal()
    record = seal.sample_executions[0]
    _, stored, _ = _authorities()
    pre_policy_snapshot = _snapshot(
        record.closed_candidate_binding.transient_ready_case,
        revision=1,
    ).model_copy(update={"sample_id": record.sample_id})

    observed = build_m6_replay_locked_closed_candidate_observation(
        execution_scope=seal.execution_scope,
        pending_commitment=record.pending_commitment,
        stored_candidate=stored,
        pre_policy_candidate_snapshot=pre_policy_snapshot,
    )

    assert observed.closed_candidate_binding == record.closed_candidate_binding
    assert observed.candidate_snapshot == record.candidate_snapshot


def test_observation_rejects_a_stored_candidate_from_another_pending() -> None:
    seal = _closed_terminal()
    record = seal.sample_executions[0]
    _, stored, _ = _authorities()
    foreign = dataclasses.replace(
        stored,
        pending_commitment_authority_id="f" * 64,
    )
    pre_policy_snapshot = _snapshot(
        record.closed_candidate_binding.transient_ready_case,
        revision=1,
    ).model_copy(update={"sample_id": record.sample_id})

    with pytest.raises(M6ReplayLockedClosedCandidateError) as captured:
        build_m6_replay_locked_closed_candidate_observation(
            execution_scope=seal.execution_scope,
            pending_commitment=record.pending_commitment,
            stored_candidate=foreign,
            pre_policy_candidate_snapshot=pre_policy_snapshot,
        )

    assert captured.value.reason_code == (
        M6ReplayLockedClosedCandidateFailureCode.CANDIDATE_CONFLICT
    )
