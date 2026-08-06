"""Isolated coordinator-facing executor for the first M6 locked replay route."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_fast_source import (
    M6ReplayLockedFastSourceError,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    M6ReplayLockedFastTerminalError,
    M6ReplayLockedFastTerminalErrorCode,
    build_m6_replay_locked_fast_terminal_candidate,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidatePublisher,
    M6ReplayLockedCandidateWrite,
)
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
    M6ReplayLockedFastTerminalSourceProvider,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
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


def _controlled_source(value: object) -> M6ReplayLockedFastTerminalSource:
    if type(value) is not M6ReplayLockedFastTerminalSource:
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)
    try:
        return M6ReplayLockedFastTerminalSource(
            source_identity_sha256=value.source_identity_sha256,
            closure=value.closure,
            projection_context=value.projection_context,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)


def _builder_failure(code: M6ReplayLockedFastTerminalErrorCode) -> _FailureCode:
    if code == M6ReplayLockedFastTerminalErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedFastTerminalErrorCode.ROUTE_REJECTED:
        return _FailureCode.UNSUPPORTED_ROUTE
    if code in {
        M6ReplayLockedFastTerminalErrorCode.SCOPE_MISMATCH,
        M6ReplayLockedFastTerminalErrorCode.SOURCE_INPUT_REJECTED,
    }:
        return _FailureCode.SOURCE_INPUT_REJECTED
    return _FailureCode.CANDIDATE_STATE_CONFLICT


def _candidate_failure(code: M6ReplayLockedCandidateFailureCode) -> _FailureCode:
    if code == M6ReplayLockedCandidateFailureCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code in {
        M6ReplayLockedCandidateFailureCode.CANDIDATE_CONFLICT,
        M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID,
    }:
        return _FailureCode.CANDIDATE_STATE_CONFLICT
    return _FailureCode.STORAGE_REJECTED


class M6ReplayLockedFastSampleExecutorService:
    """Load sealed source facts, re-execute M3, then atomically publish Case bytes."""

    __slots__ = ("_candidates", "_sources")

    def __init__(
        self,
        *,
        fast_source_provider: M6ReplayLockedFastTerminalSourceProvider,
        candidate_publisher: M6ReplayLockedCandidatePublisher,
    ) -> None:
        if not callable(
            getattr(fast_source_provider, "load_fast_terminal_source", None)
        ) or not callable(getattr(candidate_publisher, "publish_candidate", None)):
            raise TypeError("invalid M6 locked fast executor dependency")
        self._sources = fast_source_provider
        self._candidates = candidate_publisher

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
        if pending.route != M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE:
            _fail(_FailureCode.UNSUPPORTED_ROUTE)
        try:
            observed_source = self._sources.load_fast_terminal_source(closure)
        except M6ReplayLockedFastSourceError:
            _fail(_FailureCode.SOURCE_INPUT_REJECTED)
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        source = _controlled_source(observed_source)
        if source.closure != closure:
            _fail(_FailureCode.SOURCE_INPUT_REJECTED)
        try:
            candidate = build_m6_replay_locked_fast_terminal_candidate(
                execution_scope=scope,
                pending_commitment=pending,
                source=source,
            )
        except M6ReplayLockedFastTerminalError as error:
            _fail(_builder_failure(error.code))
        write = M6ReplayLockedCandidateWrite(
            case=candidate.case,
            canonical_document=candidate.canonical_case_document,
        )
        try:
            self._candidates.publish_candidate(scope, pending, write)
        except M6ReplayLockedCandidateError as error:
            _fail(_candidate_failure(error.reason_code))
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None:
        """Execute without returning candidate claims to the coordinator."""

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


__all__ = ["M6ReplayLockedFastSampleExecutorService"]
