from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from labcourt.application.m6_replay_locked_fast_terminal import (
    build_m6_replay_locked_fast_terminal_candidate,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import TimelineEntry, UsageSummary
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateWrite,
    M6ReplayLockedM4CandidateWrite,
    M6ReplayLockedStoredCandidateCase,
)
from tests.unit.test_m6_replay_locked_fast_terminal import _execution as _fast_execution
from tests.unit.test_m6_replay_locked_m4_terminal import _execution as _m4_execution


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_m4_candidate_write_accepts_one_atomic_hearing_and_gate_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _m4_execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )

    write = M6ReplayLockedM4CandidateWrite(
        case=candidate.case,
        canonical_document=candidate.canonical_case_document,
    )

    assert write.case == candidate.case
    assert write.canonical_document == candidate.canonical_case_document


@pytest.mark.parametrize(
    "update",
    (
        {"usage": UsageSummary(input_tokens=1)},
        {
            "timeline": (
                TimelineEntry(
                    sequence=0,
                    action="M6_TEST_ONLY",
                    stage="HEARING",
                    object_ref="candidate",
                ),
            )
        },
    ),
)
def test_m4_candidate_write_rejects_nonzero_operational_state(
    monkeypatch: pytest.MonkeyPatch,
    update: dict[str, object],
) -> None:
    scope, pending, source = _m4_execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    forged = candidate.case.model_copy(update=update)

    with pytest.raises(ValueError, match="bindings differ"):
        M6ReplayLockedM4CandidateWrite(
            case=forged,
            canonical_document=canonical_json(forged.model_dump(mode="json")),
        )


def test_m4_candidate_write_rejects_policy_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _m4_execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    forged = candidate.case.model_copy(
        update={"final_decision": candidate.case.verdicts[0].decision}
    )

    with pytest.raises(ValueError, match="bindings differ"):
        M6ReplayLockedM4CandidateWrite(
            case=forged,
            canonical_document=canonical_json(forged.model_dump(mode="json")),
        )


def test_fast_and_m4_candidate_writes_are_route_disjoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fast_scope, fast_pending, fast_source = _fast_execution()
    fast_candidate = build_m6_replay_locked_fast_terminal_candidate(
        execution_scope=fast_scope,
        pending_commitment=fast_pending,
        source=fast_source,
    )
    m4_scope, m4_pending, m4_source = _m4_execution(monkeypatch)
    m4_candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=m4_scope,
        pending_commitment=m4_pending,
        source=m4_source,
    )

    with pytest.raises(ValueError, match="bindings differ"):
        M6ReplayLockedM4CandidateWrite(
            case=fast_candidate.case,
            canonical_document=fast_candidate.canonical_case_document,
        )
    with pytest.raises(ValueError, match="bindings differ"):
        M6ReplayLockedCandidateWrite(
            case=m4_candidate.case,
            canonical_document=m4_candidate.canonical_case_document,
        )


def test_stored_candidate_dispatches_validation_by_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _m4_execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    document = candidate.canonical_case_document
    payload = document.encode("utf-8")
    stored = M6ReplayLockedStoredCandidateCase(
        candidate_run_id=scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
        ledger_sequence=pending.ledger_sequence,
        sample_id=pending.sample_id,
        execution_entry_id=pending.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        route=M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        case=candidate.case,
        canonical_document=document,
        case_document_sha256=hashlib.sha256(payload).hexdigest(),
        case_document_size_bytes=len(payload),
        case_audit_sequence=pending.ledger_sequence,
        case_audit_entry_hash=_sha("m4-candidate-audit-entry"),
    )

    assert stored.route == M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    with pytest.raises(ValueError, match="bindings differ"):
        replace(stored, route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE)
