from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from labcourt.application.m6_replay_locked_candidate_observation import (
    M6ReplayLockedRoutedCandidateObservationService,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidateObservation,
    M6ReplayLockedStoredCandidateCase,
)
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime as _fast_runtime
from tests.unit.test_m6_replay_locked_m4_terminal import _execution as _m4_execution


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class _StoredProvider:
    value: M6ReplayLockedStoredCandidateCase
    calls: int = 0

    def load_stored_candidate_case(
        self,
        _candidate_run_id: str,
        _sample_id: str,
    ) -> M6ReplayLockedStoredCandidateCase:
        self.calls += 1
        return self.value


@dataclass(slots=True)
class _ObservationProvider:
    value: M6ReplayLockedCandidateObservation
    calls: int = 0

    def load_candidate_observation(
        self,
        _candidate_run_id: str,
        _sample_id: str,
    ) -> M6ReplayLockedCandidateObservation:
        self.calls += 1
        return self.value


def _m4_authorities(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[M6ReplayLockedStoredCandidateCase, M6ReplayLockedCandidateObservation]:
    scope, pending, source = _m4_execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    document = candidate.canonical_case_document
    payload = document.encode("utf-8")
    audit_hash = _sha("routed-M4-candidate-audit")
    stored = M6ReplayLockedStoredCandidateCase(
        candidate_run_id=scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
        ledger_sequence=0,
        sample_id=pending.sample_id,
        execution_entry_id=pending.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        route=pending.route,
        case=candidate.case,
        canonical_document=document,
        case_document_sha256=hashlib.sha256(payload).hexdigest(),
        case_document_size_bytes=len(payload),
        case_audit_sequence=0,
        case_audit_entry_hash=audit_hash,
    )
    observation = M6ReplayLockedCandidateObservation(
        case=candidate.case,
        canonical_document=document,
        case_revision=1,
        case_audit_sequence=0,
        case_audit_entry_hash=audit_hash,
        candidate_snapshot=candidate.candidate_snapshot,
    )
    return stored, observation


def test_routed_observation_selects_only_fast_from_the_stored_route() -> None:
    runtime = _fast_runtime()
    observation = runtime.service.load_candidate_observation(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )
    fast = _ObservationProvider(observation)
    m4 = _ObservationProvider(observation)
    routed = M6ReplayLockedRoutedCandidateObservationService(
        stored_candidate_provider=_StoredProvider(runtime.stored),
        fast_observation_provider=fast,
        m4_observation_provider=m4,
    )

    observed = routed.load_candidate_observation(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )

    assert observed == observation
    assert (fast.calls, m4.calls) == (1, 0)


def test_routed_observation_selects_only_m4_from_the_stored_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored, observation = _m4_authorities(monkeypatch)
    fast = _ObservationProvider(observation)
    m4 = _ObservationProvider(observation)
    routed = M6ReplayLockedRoutedCandidateObservationService(
        stored_candidate_provider=_StoredProvider(stored),
        fast_observation_provider=fast,
        m4_observation_provider=m4,
    )

    observed = routed.load_candidate_observation(
        stored.candidate_run_id,
        stored.sample_id,
    )

    assert observed == observation
    assert (fast.calls, m4.calls) == (0, 1)


def test_routed_observation_rejects_selected_provider_case_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored, observation = _m4_authorities(monkeypatch)
    foreign = M6ReplayLockedCandidateObservation(
        case=observation.case,
        canonical_document=observation.canonical_document,
        case_revision=observation.case_revision,
        case_audit_sequence=observation.case_audit_sequence,
        case_audit_entry_hash=_sha("foreign-routed-observation-audit"),
        candidate_snapshot=observation.candidate_snapshot,
    )
    routed = M6ReplayLockedRoutedCandidateObservationService(
        stored_candidate_provider=_StoredProvider(stored),
        fast_observation_provider=_ObservationProvider(observation),
        m4_observation_provider=_ObservationProvider(foreign),
    )

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        routed.load_candidate_observation(stored.candidate_run_id, stored.sample_id)

    assert raised.value.reason_code == M6ReplayLockedCandidateFailureCode.CANDIDATE_CONFLICT
