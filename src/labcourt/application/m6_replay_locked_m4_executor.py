"""Coordinator-facing executor for the atomic M6 M4 hearing-plus-Gate route."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_m4_source import (
    M6ReplayLockedM4SourceError,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    M6ReplayLockedM4TerminalError,
    M6ReplayLockedM4TerminalErrorCode,
    build_m6_replay_locked_m4_gate_terminal_candidate,
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
    M6ReplayLockedM4CandidatePublisher,
    M6ReplayLockedM4CandidateWrite,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
    M6ReplayLockedM4GateTerminalSourceProvider,
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


def _controlled_source(value: object) -> M6ReplayLockedM4GateTerminalSource:
    if type(value) is not M6ReplayLockedM4GateTerminalSource:
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)
    try:
        controlled = M6ReplayLockedM4GateTerminalSource(
            source_identity_sha256=value.source_identity_sha256,
            closure=value.closure,
            projection_context=value.projection_context,
            hearing_record=value.hearing_record,
            hearing_verdict_binding=value.hearing_verdict_binding,
            gate_current_closure_receipt=value.gate_current_closure_receipt,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)
    if controlled != value:
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)
    return controlled


def _builder_failure(code: M6ReplayLockedM4TerminalErrorCode) -> _FailureCode:
    if code == M6ReplayLockedM4TerminalErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedM4TerminalErrorCode.ROUTE_REJECTED:
        return _FailureCode.UNSUPPORTED_ROUTE
    if code in {
        M6ReplayLockedM4TerminalErrorCode.SCOPE_MISMATCH,
        M6ReplayLockedM4TerminalErrorCode.SOURCE_INPUT_REJECTED,
        M6ReplayLockedM4TerminalErrorCode.HEARING_REBUILD_REJECTED,
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


class M6ReplayLockedM4SampleExecutorService:
    """Load sealed facts, rebuild M4 plus Gate, then atomically publish Case bytes."""

    __slots__ = ("_candidates", "_sources")

    def __init__(
        self,
        *,
        m4_source_provider: M6ReplayLockedM4GateTerminalSourceProvider,
        candidate_publisher: M6ReplayLockedM4CandidatePublisher,
    ) -> None:
        if not callable(
            getattr(m4_source_provider, "load_m4_gate_terminal_source", None)
        ) or not callable(getattr(candidate_publisher, "publish_m4_candidate", None)):
            raise TypeError("invalid M6 locked M4 executor dependency")
        self._sources = m4_source_provider
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
        if pending.route != M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
            _fail(_FailureCode.UNSUPPORTED_ROUTE)
        try:
            observed_source = self._sources.load_m4_gate_terminal_source(closure)
        except M6ReplayLockedM4SourceError:
            _fail(_FailureCode.SOURCE_INPUT_REJECTED)
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        source = _controlled_source(observed_source)
        if source.closure != closure:
            _fail(_FailureCode.SOURCE_INPUT_REJECTED)
        try:
            candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
                execution_scope=scope,
                pending_commitment=pending,
                source=source,
            )
        except M6ReplayLockedM4TerminalError as error:
            _fail(_builder_failure(error.code))
        write = M6ReplayLockedM4CandidateWrite(
            case=candidate.case,
            canonical_document=candidate.canonical_case_document,
        )
        try:
            self._candidates.publish_m4_candidate(scope, pending, write)
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


__all__ = ["M6ReplayLockedM4SampleExecutorService"]
