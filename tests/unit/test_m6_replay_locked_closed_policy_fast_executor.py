from __future__ import annotations

from dataclasses import dataclass

import pytest

import labcourt.application.m6_replay_locked_closed_policy_fast_executor as subject
from labcourt.application.m6_replay_locked_alert_policy import (
    M6ReplayLockedClosedPolicyCandidate,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateWrite,
)
from labcourt.ports.m6_replay_locked_closed_policy_sample_executor import (
    M6ReplayLockedClosedPolicySampleExecutorError,
    M6ReplayLockedClosedPolicySampleExecutorFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
)
from tests.unit.test_m6_replay_locked_closed_policy_fast_terminal import _execution
from tests.unit.test_m6_replay_locked_closed_pre_policy_source_application import (
    _policy_for_ready,
)
from tests.unit.test_m6_replay_locked_policy_source import _closed_case, _sha


@dataclass
class _SourceProvider:
    value: M6ReplayLockedClosedPolicyFastPrePolicySource
    calls: list[tuple[M6ReplayInputClosureAuthority, str]]

    def load_closed_policy_pre_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
        source_binding: M6ReplayLockedClosedPolicySourceBindingAuthority,
    ) -> M6ReplayLockedClosedPolicyFastPrePolicySource:
        self.calls.append((closure, source_binding.source_binding_authority_id))
        return self.value


@dataclass
class _Publisher:
    observed: list[
        tuple[
            M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
            M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
            M6ReplayLockedClosedCandidateWrite,
        ]
    ]

    def publish_closed_candidate(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        candidate: M6ReplayLockedClosedCandidateWrite,
    ) -> None:
        self.observed.append((execution_scope, pending_commitment, candidate))


def _offline_policy_candidate(**kwargs: object) -> M6ReplayLockedClosedPolicyCandidate:
    ready = kwargs["ready_case"]
    binding = kwargs["source_binding"]
    assert hasattr(ready, "model_dump")
    assert type(binding) is M6ReplayLockedClosedPolicySourceBindingAuthority
    policy = _policy_for_ready(ready)
    closed = _closed_case(ready, policy)
    return M6ReplayLockedClosedPolicyCandidate(
        ready_case=ready,
        alert_policy=policy,
        closed_case=closed,
        source_binding_authority_id=binding.source_binding_authority_id,
        policy_causal_cut_authority_id=binding.policy_causal_cut_authority_id,
    )


def test_fast_executor_publishes_one_atomic_policy_and_closed_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source, closure, scope, pending, safe_source = _execution()
    sources = _SourceProvider(safe_source, [])
    publisher = _Publisher([])
    monkeypatch.setattr(
        subject,
        "build_m6_replay_locked_closed_policy_candidate",
        _offline_policy_candidate,
    )
    service = subject.M6ReplayLockedClosedPolicyFastSampleExecutorService(
        pre_policy_source_provider=sources,
        candidate_publisher=publisher,
    )

    service.execute_sample(scope, pending, closure)

    assert sources.calls == [(closure, pending.source_binding_authority_id)]
    assert len(publisher.observed) == 1
    observed_scope, observed_pending, write = publisher.observed[0]
    assert observed_scope == scope
    assert observed_pending == pending
    assert write.transient_ready_case.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert write.closed_candidate_case.status is CaseStatus.CLOSED
    assert write.canonical_alert_policy_document == canonical_json(
        write.candidate_alert_policy.model_dump(mode="json")
    )
    assert write.canonical_closed_case_document == canonical_json(
        write.closed_candidate_case.model_dump(mode="json")
    )


def test_fast_executor_rejects_a_catalog_closure_outside_pending_before_loading() -> None:
    _source, closure, scope, pending, safe_source = _execution()
    sources = _SourceProvider(safe_source, [])
    publisher = _Publisher([])
    service = subject.M6ReplayLockedClosedPolicyFastSampleExecutorService(
        pre_policy_source_provider=sources,
        candidate_publisher=publisher,
    )
    foreign = M6ReplayInputClosureAuthority.model_validate(
        {
            **closure.model_dump(mode="json", exclude_computed_fields=True),
            "sample_id": _sha("foreign-closed-policy-sample"),
        }
    )

    with pytest.raises(M6ReplayLockedClosedPolicySampleExecutorError) as raised:
        service.execute_sample(scope, pending, foreign)

    assert raised.value.reason_code is (
        M6ReplayLockedClosedPolicySampleExecutorFailureCode.SOURCE_INPUT_REJECTED
    )
    assert sources.calls == []
    assert publisher.observed == []
