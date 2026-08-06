from __future__ import annotations

import pytest

from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_seal,
    build_m6_replay_locked_closed_policy_sample_record,
)
from labcourt.ports.m6_replay_locked_closed_policy_ledger import (
    M6ReplayLockedClosedPolicyExecutionResumeV2,
    M6ReplayLockedClosedPolicyLedgerStatus,
)
from tests.unit.test_m6_replay_locked_closed_policy_execution import (
    _terminal_facts,
)


def _chain():  # type: ignore[no-untyped-def]
    scope, stored, cut, pending, proof, observation, head = _terminal_facts()
    record = build_m6_replay_locked_closed_policy_sample_record(
        execution_scope=scope,
        stored_source_catalog=stored,
        pending_commitment=pending,
        source_determinism=proof,
        policy_causal_cut=cut,
        candidate_observation=observation,
    )
    seal = build_m6_replay_locked_closed_policy_execution_seal(
        execution_scope=scope,
        sample_records=(record,),
        candidate_audit_head=head,
    )
    return scope, pending, record, seal


def test_resume_derives_every_durable_ledger_phase() -> None:
    scope, pending, record, seal = _chain()

    fresh = M6ReplayLockedClosedPolicyExecutionResumeV2(scope, (), ())
    pending_state = M6ReplayLockedClosedPolicyExecutionResumeV2(
        scope,
        (pending,),
        (),
    )
    terminal = M6ReplayLockedClosedPolicyExecutionResumeV2(
        scope,
        (pending,),
        (record,),
    )
    sealed = M6ReplayLockedClosedPolicyExecutionResumeV2(
        scope,
        (pending,),
        (record,),
        seal,
    )

    assert fresh.status == M6ReplayLockedClosedPolicyLedgerStatus.READY_FOR_PENDING
    assert pending_state.status == M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    assert terminal.status == M6ReplayLockedClosedPolicyLedgerStatus.READY_TO_SEAL
    assert sealed.status == M6ReplayLockedClosedPolicyLedgerStatus.SEALED
    assert fresh.next_ledger_sequence == 0
    assert terminal.next_ledger_sequence == 1
    assert terminal.ledger_head_hash == record.sample_execution_record_id


def test_resume_rejects_a_record_without_its_exact_pending() -> None:
    scope, _pending, record, _seal = _chain()

    with pytest.raises(ValueError, match="cardinality"):
        M6ReplayLockedClosedPolicyExecutionResumeV2(
            scope,
            (),
            (record,),
        )


def test_resume_revalidates_models_copied_without_pydantic_validation() -> None:
    scope, pending, _record, _seal = _chain()
    grafted = pending.model_copy(update={"execution_scope_authority_id": "f" * 64})

    with pytest.raises(ValueError, match="differs from its scope"):
        M6ReplayLockedClosedPolicyExecutionResumeV2(
            scope,
            (grafted,),
            (),
        )
