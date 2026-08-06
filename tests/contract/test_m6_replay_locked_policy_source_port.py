from __future__ import annotations

import inspect

from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
    M6ReplayLockedAlertPolicySourceProvider,
    M6ReplayLockedCooldownHistoryRowObservation,
)
from tests.unit.test_m6_replay_locked_policy_source import _observation


class _StructuralPolicySourceProvider:
    def load_alert_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedAlertPolicySourceObservation:
        del closure
        raise AssertionError("structural port checks must not invoke the provider")


class _MissingPolicySourceProvider:
    pass


def test_policy_source_provider_signature_is_stable_and_typed() -> None:
    method = M6ReplayLockedAlertPolicySourceProvider.load_alert_policy_source
    assert tuple(inspect.signature(method).parameters) == ("self", "closure")
    assert inspect.get_annotations(method, eval_str=True) == {
        "closure": M6ReplayInputClosureAuthority,
        "return": M6ReplayLockedAlertPolicySourceObservation,
    }


def test_policy_source_provider_is_runtime_checkable_by_structure() -> None:
    assert isinstance(
        _StructuralPolicySourceProvider(),
        M6ReplayLockedAlertPolicySourceProvider,
    )
    assert not isinstance(
        _MissingPolicySourceProvider(),
        M6ReplayLockedAlertPolicySourceProvider,
    )


def test_policy_source_observation_is_typed_and_carries_exact_documents() -> None:
    observation = _observation(history_count=1)

    assert type(observation.replay_input_closure) is M6ReplayInputClosureAuthority
    assert observation.source_validation_report.passed
    assert observation.source_validation_report.authority_root_sha256 == (
        observation.source_m5_authority_root_sha256
    )
    assert observation.source_ready_case_revision + 1 == (observation.source_closed_case_revision)
    assert len(observation.cooldown_eligible_history_rows) == 1
    assert all(
        type(row) is M6ReplayLockedCooldownHistoryRowObservation
        and row.source_identity_sha256 == observation.source_identity_sha256
        for row in observation.cooldown_eligible_history_rows
    )
    assert not hasattr(observation, "__dict__")
