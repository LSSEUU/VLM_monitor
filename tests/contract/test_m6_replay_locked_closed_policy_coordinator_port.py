from __future__ import annotations

import inspect

from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_closed_policy_coordinator import (
    M6ReplayLockedClosedPolicyCoordinator,
    M6ReplayLockedClosedPolicyCoordinatorError,
    M6ReplayLockedClosedPolicyCoordinatorFailureCode,
)


class _StructuralCoordinator:
    def run_to_terminal(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        stored_source_catalog: M6StoredRegressionExecutionSourceCatalog,
    ) -> M6ReplayLockedClosedPolicyExecutionSealAuthorityV2:
        del execution_scope, stored_source_catalog
        raise AssertionError("structural checks must not invoke the coordinator")


class _MissingCoordinator:
    pass


def test_closed_policy_coordinator_signature_is_stable_and_typed() -> None:
    method = M6ReplayLockedClosedPolicyCoordinator.run_to_terminal

    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "execution_scope",
        "stored_source_catalog",
    )
    assert inspect.get_annotations(method, eval_str=True) == {
        "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        "stored_source_catalog": M6StoredRegressionExecutionSourceCatalog,
        "return": M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
    }


def test_closed_policy_coordinator_is_runtime_checkable_by_structure() -> None:
    assert isinstance(_StructuralCoordinator(), M6ReplayLockedClosedPolicyCoordinator)
    assert not isinstance(_MissingCoordinator(), M6ReplayLockedClosedPolicyCoordinator)


def test_closed_policy_coordinator_failure_is_payload_free() -> None:
    error = M6ReplayLockedClosedPolicyCoordinatorError(
        M6ReplayLockedClosedPolicyCoordinatorFailureCode.PENDING_REJECTED
    )

    assert error.reason_code == (M6ReplayLockedClosedPolicyCoordinatorFailureCode.PENDING_REJECTED)
    assert vars(error) == {"reason_code": error.reason_code}
