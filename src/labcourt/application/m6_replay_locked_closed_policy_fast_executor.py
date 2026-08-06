"""Isolated Fast executor for additive M6 CLOSED-policy replay."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_alert_policy import (
    M6ReplayLockedAlertPolicyError,
    M6ReplayLockedAlertPolicyErrorCode,
    build_m6_replay_locked_closed_policy_candidate,
)
from labcourt.application.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPrePolicySourceError,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    M6ReplayLockedFastTerminalError,
    M6ReplayLockedFastTerminalErrorCode,
    build_m6_replay_locked_closed_policy_fast_pre_policy_candidate,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateError,
    M6ReplayLockedClosedCandidateFailureCode,
    M6ReplayLockedClosedCandidatePublisher,
    M6ReplayLockedClosedCandidateWrite,
)
from labcourt.ports.m6_replay_locked_closed_policy_sample_executor import (
    M6ReplayLockedClosedPolicySampleExecutorError,
    M6ReplayLockedClosedPolicySampleExecutorFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
    M6ReplayLockedClosedPolicyPrePolicySourceProvider,
)

_FailureCode = M6ReplayLockedClosedPolicySampleExecutorFailureCode
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(code: _FailureCode) -> M6ReplayLockedClosedPolicySampleExecutorError:
    return M6ReplayLockedClosedPolicySampleExecutorError(code)


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


def _controlled_source(value: object) -> M6ReplayLockedClosedPolicyFastPrePolicySource:
    if type(value) is not M6ReplayLockedClosedPolicyFastPrePolicySource:
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)
    try:
        controlled = M6ReplayLockedClosedPolicyFastPrePolicySource(
            source_identity_sha256=value.source_identity_sha256,
            source_binding=value.source_binding,
            catalog_closure=value.catalog_closure,
            source_ready_case_revision=value.source_ready_case_revision,
            projection_context=value.projection_context,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)
    if controlled != value:
        _fail(_FailureCode.SOURCE_INPUT_REJECTED)
    return controlled


def _require_input_cut(
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    closure: M6ReplayInputClosureAuthority,
) -> None:
    binding = pending.source_binding
    entry = pending.pre_policy_pending_commitment.execution_entry
    if (
        pending.execution_scope_authority_id != scope.execution_scope_authority_id
        or pending.execution_component_authority_id
        != scope.execution_component.component_authority_id
        or pending.locked_config_sha256 != scope.locked_config_sha256
        or pending.pre_policy_execution_scope_authority_id
        != scope.pre_policy_execution_scope_authority_id
        or pending.pre_policy_route != M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE
        or binding.sample_id != closure.sample_id
        or binding.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
        or binding.replay_input_closure_document_sha256
        != closure.replay_input_closure_document_sha256
        or entry.sample_id != closure.sample_id
        or entry.input_authority_id != closure.input_authority_id
        or entry.input_authority_document_sha256 != closure.input_authority_document_sha256
        or entry.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
        or entry.replay_input_closure_document_sha256
        != closure.replay_input_closure_document_sha256
    ):
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


def _policy_failure(code: M6ReplayLockedAlertPolicyErrorCode) -> _FailureCode:
    if code == M6ReplayLockedAlertPolicyErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedAlertPolicyErrorCode.SOURCE_BINDING_MISMATCH:
        return _FailureCode.SOURCE_INPUT_REJECTED
    if code == M6ReplayLockedAlertPolicyErrorCode.PRE_POLICY_CASE_REJECTED:
        return _FailureCode.CANDIDATE_STATE_CONFLICT
    if code == M6ReplayLockedAlertPolicyErrorCode.POLICY_REBUILD_REJECTED:
        return _FailureCode.POLICY_REJECTED
    return _FailureCode.CANDIDATE_STATE_CONFLICT


def _candidate_failure(code: M6ReplayLockedClosedCandidateFailureCode) -> _FailureCode:
    if code == M6ReplayLockedClosedCandidateFailureCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code in {
        M6ReplayLockedClosedCandidateFailureCode.CANDIDATE_CONFLICT,
        M6ReplayLockedClosedCandidateFailureCode.STORED_AUTHORITY_INVALID,
    }:
        return _FailureCode.CANDIDATE_STATE_CONFLICT
    return _FailureCode.STORAGE_REJECTED


class M6ReplayLockedClosedPolicyFastSampleExecutorService:
    """Re-execute Fast READY, rebuild policy, then publish one atomic CLOSED unit."""

    __slots__ = ("_candidates", "_sources")

    def __init__(
        self,
        *,
        pre_policy_source_provider: M6ReplayLockedClosedPolicyPrePolicySourceProvider,
        candidate_publisher: M6ReplayLockedClosedCandidatePublisher,
    ) -> None:
        if not callable(
            getattr(
                pre_policy_source_provider,
                "load_closed_policy_pre_policy_source",
                None,
            )
        ) or not callable(getattr(candidate_publisher, "publish_closed_candidate", None)):
            raise TypeError("invalid M6 CLOSED-policy Fast executor dependency")
        self._sources = pre_policy_source_provider
        self._candidates = candidate_publisher

    def _attempt_execute(
        self,
        execution_scope: object,
        pending_commitment: object,
        replay_input_closure: object,
    ) -> None:
        scope = _canonical(
            execution_scope,
            M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        )
        pending = _canonical(
            pending_commitment,
            M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        )
        closure = _canonical(replay_input_closure, M6ReplayInputClosureAuthority)
        _require_input_cut(scope, pending, closure)
        try:
            observed = self._sources.load_closed_policy_pre_policy_source(
                closure,
                pending.source_binding,
            )
        except M6ReplayLockedClosedPrePolicySourceError:
            _fail(_FailureCode.SOURCE_INPUT_REJECTED)
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        source = _controlled_source(observed)
        if source.catalog_closure != closure or source.source_binding != pending.source_binding:
            _fail(_FailureCode.SOURCE_INPUT_REJECTED)
        try:
            pre_policy_candidate = build_m6_replay_locked_closed_policy_fast_pre_policy_candidate(
                execution_scope=scope,
                pending_commitment=pending,
                source=source,
            )
        except M6ReplayLockedFastTerminalError as error:
            _fail(_builder_failure(error.code))
        try:
            candidate = build_m6_replay_locked_closed_policy_candidate(
                ready_case=pre_policy_candidate.case,
                source_binding=pending.source_binding,
                locked_config=scope.pre_policy_execution_scope.locked_config,
                locked_manifest=scope.pre_policy_execution_scope.locked_manifest,
            )
        except M6ReplayLockedAlertPolicyError as error:
            _fail(_policy_failure(error.code))
        try:
            write = M6ReplayLockedClosedCandidateWrite(
                transient_ready_case=candidate.ready_case,
                candidate_alert_policy=candidate.alert_policy,
                closed_candidate_case=candidate.closed_case,
                canonical_alert_policy_document=canonical_json(
                    candidate.alert_policy.model_dump(mode="json")
                ),
                canonical_closed_case_document=candidate.canonical_closed_case_document,
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            _fail(_FailureCode.CANDIDATE_STATE_CONFLICT)
        try:
            self._candidates.publish_closed_candidate(scope, pending, write)
        except M6ReplayLockedClosedCandidateError as error:
            _fail(_candidate_failure(error.reason_code))
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None:
        """Execute without returning candidate or evaluator claims to the coordinator."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            self._attempt_execute(
                execution_scope,
                pending_commitment,
                replay_input_closure,
            )
            return
        except M6ReplayLockedClosedPolicySampleExecutorError as error:
            failure = error.reason_code
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, execution_scope, pending_commitment, replay_input_closure
        raise _error(failure) from None


__all__ = ["M6ReplayLockedClosedPolicyFastSampleExecutorService"]
