from __future__ import annotations

from dataclasses import dataclass

import pytest

from labcourt.application.m6_replay_locked_closed_policy_routed_executor import (
    M6ReplayLockedClosedPolicyRoutedSampleExecutorService,
)
from labcourt.ports.m6_replay_locked_closed_policy_sample_executor import (
    M6ReplayLockedClosedPolicySampleExecutorError,
    M6ReplayLockedClosedPolicySampleExecutorFailureCode,
)
from tests.unit.test_m6_replay_locked_closed_policy_fast_terminal import (
    _execution as _fast_execution,
)
from tests.unit.test_m6_replay_locked_closed_policy_m4_terminal import (
    _closed_execution as _m4_execution,
)


@dataclass(slots=True)
class _Executor:
    calls: int = 0
    reason: M6ReplayLockedClosedPolicySampleExecutorFailureCode | None = None
    raw_failure: bool = False

    def execute_sample(self, _scope, _pending, _closure):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.reason is not None:
            raise M6ReplayLockedClosedPolicySampleExecutorError(self.reason)
        if self.raw_failure:
            raise RuntimeError("private CLOSED routed executor payload")


def _dispatcher(fast: _Executor, m4: _Executor):  # type: ignore[no-untyped-def]
    return M6ReplayLockedClosedPolicyRoutedSampleExecutorService(
        fast_executor=fast,
        m4_executor=m4,
    )


def test_closed_dispatcher_selects_only_fast_for_an_m3_pending() -> None:
    _source, closure, scope, pending, _safe = _fast_execution()
    fast = _Executor()
    m4 = _Executor()

    _dispatcher(fast, m4).execute_sample(scope, pending, closure)

    assert (fast.calls, m4.calls) == (1, 0)


def test_closed_dispatcher_selects_only_m4_for_a_hearing_gate_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _m4_execution(monkeypatch)
    fast = _Executor()
    m4 = _Executor()

    _dispatcher(fast, m4).execute_sample(scope, pending, source.catalog_closure)

    assert (fast.calls, m4.calls) == (0, 1)


def test_closed_dispatcher_preserves_typed_failure_and_redacts_raw_failure() -> None:
    _source, closure, scope, pending, _safe = _fast_execution()
    typed = _Executor(
        reason=M6ReplayLockedClosedPolicySampleExecutorFailureCode.CANDIDATE_STATE_CONFLICT
    )

    with pytest.raises(M6ReplayLockedClosedPolicySampleExecutorError) as selected:
        _dispatcher(typed, _Executor()).execute_sample(scope, pending, closure)

    assert selected.value.reason_code is (
        M6ReplayLockedClosedPolicySampleExecutorFailureCode.CANDIDATE_STATE_CONFLICT
    )

    with pytest.raises(M6ReplayLockedClosedPolicySampleExecutorError) as raw:
        _dispatcher(_Executor(raw_failure=True), _Executor()).execute_sample(
            scope,
            pending,
            closure,
        )

    assert raw.value.reason_code is (
        M6ReplayLockedClosedPolicySampleExecutorFailureCode.STORAGE_REJECTED
    )
    assert "private CLOSED routed executor payload" not in str(raw.value)
    assert raw.value.__suppress_context__ is True
