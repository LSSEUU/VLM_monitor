"""Route one locked Pending to its isolated offline sample executor."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
    M6ReplayLockedSampleExecutor,
    M6ReplayLockedSampleExecutorError,
    M6ReplayLockedSampleExecutorFailureCode,
)

_FailureCode = M6ReplayLockedSampleExecutorFailureCode
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(code: _FailureCode) -> M6ReplayLockedSampleExecutorError:
    return M6ReplayLockedSampleExecutorError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(_FailureCode.INVALID_ARGUMENT)
    return controlled


class M6ReplayLockedRoutedSampleExecutorService:
    """Dispatch only the two explicitly supported M6 replay routes."""

    __slots__ = ("_fast", "_m4")

    def __init__(
        self,
        *,
        fast_executor: M6ReplayLockedSampleExecutor,
        m4_executor: M6ReplayLockedSampleExecutor,
    ) -> None:
        if not callable(getattr(fast_executor, "execute_sample", None)) or not callable(
            getattr(m4_executor, "execute_sample", None)
        ):
            raise TypeError("invalid M6 locked routed executor dependency")
        self._fast = fast_executor
        self._m4 = m4_executor

    def _attempt_execute(
        self,
        execution_scope: object,
        pending_commitment: object,
        replay_input_closure: object,
    ) -> None:
        scope = _canonical(execution_scope, M6ReplayLockedExecutionScopeAuthority)
        pending = _canonical(
            pending_commitment,
            M6ReplayLockedPendingSampleCommitmentAuthority,
        )
        closure = _canonical(replay_input_closure, M6ReplayInputClosureAuthority)
        if pending.route == M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE:
            executor = self._fast
        elif pending.route == M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
            executor = self._m4
        else:
            _fail(_FailureCode.UNSUPPORTED_ROUTE)
        try:
            executor.execute_sample(scope, pending, closure)
        except M6ReplayLockedSampleExecutorError:
            raise
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None:
        """Select a route without exposing either executor's private dependencies."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            self._attempt_execute(
                execution_scope,
                pending_commitment,
                replay_input_closure,
            )
            return
        except M6ReplayLockedSampleExecutorError as error:
            failure = error.reason_code
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, execution_scope, pending_commitment, replay_input_closure
        raise _error(failure) from None


__all__ = ["M6ReplayLockedRoutedSampleExecutorService"]
