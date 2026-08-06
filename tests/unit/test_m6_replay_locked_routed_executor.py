from __future__ import annotations

from dataclasses import dataclass

import pytest

from labcourt.application.m6_replay_locked_routed_executor import (
    M6ReplayLockedRoutedSampleExecutorService,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
    M6ReplayLockedSampleExecutorError,
    M6ReplayLockedSampleExecutorFailureCode,
)
from tests.unit.test_m6_replay_locked_fast_terminal import _execution as _fast_execution
from tests.unit.test_m6_replay_locked_m4_terminal import _execution as _m4_execution


@dataclass(slots=True)
class _Executor:
    calls: int = 0
    reason: M6ReplayLockedSampleExecutorFailureCode | None = None
    raw_failure: bool = False

    def execute_sample(self, _scope, _pending, _closure):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.reason is not None:
            raise M6ReplayLockedSampleExecutorError(self.reason)
        if self.raw_failure:
            raise RuntimeError("private routed executor payload")


def test_dispatcher_selects_only_fast_for_an_m3_pending() -> None:
    scope, pending, source = _fast_execution()
    fast = _Executor()
    m4 = _Executor()
    dispatcher = M6ReplayLockedRoutedSampleExecutorService(
        fast_executor=fast,  # type: ignore[arg-type]
        m4_executor=m4,  # type: ignore[arg-type]
    )

    dispatcher.execute_sample(scope, pending, source.closure)

    assert (fast.calls, m4.calls) == (1, 0)


def test_dispatcher_selects_only_m4_for_a_hearing_gate_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _m4_execution(monkeypatch)
    fast = _Executor()
    m4 = _Executor()
    dispatcher = M6ReplayLockedRoutedSampleExecutorService(
        fast_executor=fast,  # type: ignore[arg-type]
        m4_executor=m4,  # type: ignore[arg-type]
    )

    dispatcher.execute_sample(scope, pending, source.closure)

    assert (fast.calls, m4.calls) == (0, 1)


def test_dispatcher_preserves_selected_executor_typed_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _m4_execution(monkeypatch)
    fast = _Executor()
    m4 = _Executor(reason=M6ReplayLockedSampleExecutorFailureCode.CANDIDATE_STATE_CONFLICT)
    dispatcher = M6ReplayLockedRoutedSampleExecutorService(
        fast_executor=fast,  # type: ignore[arg-type]
        m4_executor=m4,  # type: ignore[arg-type]
    )

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        dispatcher.execute_sample(scope, pending, source.closure)

    assert raised.value.reason_code == (
        M6ReplayLockedSampleExecutorFailureCode.CANDIDATE_STATE_CONFLICT
    )
    assert (fast.calls, m4.calls) == (0, 1)


def test_dispatcher_redacts_an_untyped_executor_failure() -> None:
    scope, pending, source = _fast_execution()
    fast = _Executor(raw_failure=True)
    dispatcher = M6ReplayLockedRoutedSampleExecutorService(
        fast_executor=fast,  # type: ignore[arg-type]
        m4_executor=_Executor(),  # type: ignore[arg-type]
    )

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        dispatcher.execute_sample(scope, pending, source.closure)

    assert raised.value.reason_code == M6ReplayLockedSampleExecutorFailureCode.STORAGE_REJECTED
    assert "private routed executor payload" not in str(raised.value)
    assert raised.value.__suppress_context__ is True
