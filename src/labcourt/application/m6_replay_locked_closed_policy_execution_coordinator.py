"""Crash-recoverable coordinator for additive M6 CLOSED-policy replay."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_closed_candidate_observation import (
    build_m6_replay_locked_closed_candidate_observation,
)
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionError,
    M6ReplayLockedClosedPolicyExecutionErrorCode,
    build_m6_replay_locked_closed_policy_execution_seal,
    build_m6_replay_locked_closed_policy_pending_commitment,
    build_m6_replay_locked_closed_policy_sample_record,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    M6ReplayLockedFastTerminalError,
    M6ReplayLockedFastTerminalErrorCode,
    build_m6_replay_locked_closed_policy_fast_pre_policy_candidate,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    M6ReplayLockedM4TerminalError,
    M6ReplayLockedM4TerminalErrorCode,
    build_m6_replay_locked_closed_policy_m4_pre_policy_candidate,
)
from labcourt.application.m6_replay_locked_policy_source import (
    M6ReplayLockedPolicySourceBuildError,
    M6ReplayLockedPolicySourceBuildErrorCode,
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.application.m6_replay_locked_source_determinism import (
    M6ReplayLockedSourceDeterminismError,
    M6ReplayLockedSourceDeterminismErrorCode,
    prove_m6_replay_locked_closed_policy_source_determinism,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedAlertPolicyCausalCutAuthority,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateAuditHeadProvider,
    M6ReplayLockedClosedCandidateError,
    M6ReplayLockedClosedCandidateFailureCode,
    M6ReplayLockedStoredClosedCandidate,
    M6ReplayLockedStoredClosedCandidateProvider,
)
from labcourt.ports.m6_replay_locked_closed_policy_coordinator import (
    M6ReplayLockedClosedPolicyCoordinatorError,
    M6ReplayLockedClosedPolicyCoordinatorFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_policy_ledger import (
    M6ReplayLockedClosedPolicyExecutionResumeV2,
    M6ReplayLockedClosedPolicyLedgerError,
    M6ReplayLockedClosedPolicyLedgerFailureCode,
    M6ReplayLockedClosedPolicyLedgerRepository,
    M6ReplayLockedClosedPolicyLedgerStatus,
)
from labcourt.ports.m6_replay_locked_closed_policy_sample_executor import (
    M6ReplayLockedClosedPolicySampleExecutor,
    M6ReplayLockedClosedPolicySampleExecutorError,
    M6ReplayLockedClosedPolicySampleExecutorFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyPrePolicySourceProvider,
)
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceProvider,
)

_FailureCode = M6ReplayLockedClosedPolicyCoordinatorFailureCode
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(code: _FailureCode) -> M6ReplayLockedClosedPolicyCoordinatorError:
    return M6ReplayLockedClosedPolicyCoordinatorError(code)


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


def _controlled_catalog(value: object) -> M6StoredRegressionExecutionSourceCatalog:
    if type(value) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(_FailureCode.INVALID_ARGUMENT)
    try:
        return M6StoredRegressionExecutionSourceCatalog(
            source_catalog=value.source_catalog,
            canonical_document=value.canonical_document,
            content_sha256=value.content_sha256,
            size_bytes=value.size_bytes,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)


def _canonical_document(value: BaseModel) -> str:
    try:
        return canonical_json(value.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.INVALID_ARGUMENT)


def _ledger_failure(code: M6ReplayLockedClosedPolicyLedgerFailureCode) -> _FailureCode:
    direct = {
        M6ReplayLockedClosedPolicyLedgerFailureCode.INVALID_ARGUMENT: (
            _FailureCode.INVALID_ARGUMENT
        ),
        M6ReplayLockedClosedPolicyLedgerFailureCode.SCOPE_NOT_FOUND: (_FailureCode.SCOPE_NOT_FOUND),
        M6ReplayLockedClosedPolicyLedgerFailureCode.SCOPE_CONFLICT: (_FailureCode.SCOPE_REJECTED),
        M6ReplayLockedClosedPolicyLedgerFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6ReplayLockedClosedPolicyLedgerFailureCode.PENDING_CONFLICT: (
            _FailureCode.PENDING_REJECTED
        ),
        M6ReplayLockedClosedPolicyLedgerFailureCode.RECORD_CONFLICT: (_FailureCode.RECORD_REJECTED),
        M6ReplayLockedClosedPolicyLedgerFailureCode.SEAL_CONFLICT: (_FailureCode.SEAL_REJECTED),
        M6ReplayLockedClosedPolicyLedgerFailureCode.COMMIT_OUTCOME_UNKNOWN: (
            _FailureCode.COMMIT_OUTCOME_UNKNOWN
        ),
        M6ReplayLockedClosedPolicyLedgerFailureCode.STORAGE_REJECTED: (
            _FailureCode.STORAGE_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.EXECUTION_STATE_INVALID)


def _execution_failure(
    code: M6ReplayLockedClosedPolicyExecutionErrorCode,
) -> _FailureCode:
    direct = {
        M6ReplayLockedClosedPolicyExecutionErrorCode.INVALID_ARGUMENT: (
            _FailureCode.INVALID_ARGUMENT
        ),
        M6ReplayLockedClosedPolicyExecutionErrorCode.SCOPE_REJECTED: (_FailureCode.SCOPE_REJECTED),
        M6ReplayLockedClosedPolicyExecutionErrorCode.SOURCE_CATALOG_MISMATCH: (
            _FailureCode.SOURCE_CATALOG_MISMATCH
        ),
        M6ReplayLockedClosedPolicyExecutionErrorCode.POLICY_CAUSAL_CUT_MISMATCH: (
            _FailureCode.POLICY_CAUSAL_CUT_REJECTED
        ),
        M6ReplayLockedClosedPolicyExecutionErrorCode.PENDING_REJECTED: (
            _FailureCode.PENDING_REJECTED
        ),
        M6ReplayLockedClosedPolicyExecutionErrorCode.CANDIDATE_OBSERVATION_REJECTED: (
            _FailureCode.CANDIDATE_OBSERVATION_REJECTED
        ),
        M6ReplayLockedClosedPolicyExecutionErrorCode.RECORD_REJECTED: (
            _FailureCode.RECORD_REJECTED
        ),
        M6ReplayLockedClosedPolicyExecutionErrorCode.AUDIT_HEAD_MISMATCH: (
            _FailureCode.AUDIT_HEAD_REJECTED
        ),
        M6ReplayLockedClosedPolicyExecutionErrorCode.SEAL_REJECTED: (_FailureCode.SEAL_REJECTED),
    }
    return direct.get(code, _FailureCode.EXECUTION_STATE_INVALID)


def _candidate_failure(code: M6ReplayLockedClosedCandidateFailureCode) -> _FailureCode:
    if code == M6ReplayLockedClosedCandidateFailureCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedClosedCandidateFailureCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code == M6ReplayLockedClosedCandidateFailureCode.STORAGE_REJECTED:
        return _FailureCode.STORAGE_REJECTED
    return _FailureCode.CANDIDATE_OBSERVATION_REJECTED


def _executor_failure(
    code: M6ReplayLockedClosedPolicySampleExecutorFailureCode,
) -> _FailureCode:
    if code == M6ReplayLockedClosedPolicySampleExecutorFailureCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedClosedPolicySampleExecutorFailureCode.UNSUPPORTED_ROUTE:
        return _FailureCode.UNSUPPORTED_ROUTE
    if code == M6ReplayLockedClosedPolicySampleExecutorFailureCode.SOURCE_INPUT_REJECTED:
        return _FailureCode.SOURCE_PROJECTION_REJECTED
    if code == M6ReplayLockedClosedPolicySampleExecutorFailureCode.STORAGE_REJECTED:
        return _FailureCode.STORAGE_REJECTED
    return _FailureCode.SAMPLE_EXECUTION_REJECTED


def _source_determinism_failure(
    code: M6ReplayLockedSourceDeterminismErrorCode,
) -> _FailureCode:
    if code == M6ReplayLockedSourceDeterminismErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedSourceDeterminismErrorCode.POLICY_CAUSAL_CUT_MISMATCH:
        return _FailureCode.POLICY_CAUSAL_CUT_REJECTED
    return _FailureCode.SOURCE_PROJECTION_REJECTED


def _fast_builder_failure(code: M6ReplayLockedFastTerminalErrorCode) -> _FailureCode:
    if code == M6ReplayLockedFastTerminalErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedFastTerminalErrorCode.ROUTE_REJECTED:
        return _FailureCode.UNSUPPORTED_ROUTE
    return _FailureCode.SOURCE_PROJECTION_REJECTED


def _m4_builder_failure(code: M6ReplayLockedM4TerminalErrorCode) -> _FailureCode:
    if code == M6ReplayLockedM4TerminalErrorCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedM4TerminalErrorCode.ROUTE_REJECTED:
        return _FailureCode.UNSUPPORTED_ROUTE
    return _FailureCode.SOURCE_PROJECTION_REJECTED


def _policy_cut_failure(code: M6ReplayLockedPolicySourceBuildErrorCode) -> _FailureCode:
    if code == M6ReplayLockedPolicySourceBuildErrorCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    return _FailureCode.POLICY_CAUSAL_CUT_REJECTED


class M6ReplayLockedClosedPolicyExecutionCoordinatorService:
    """Advance one routed CLOSED-policy run from durable five-state facts."""

    __slots__ = (
        "_audit_heads",
        "_candidates",
        "_executor",
        "_ledger",
        "_policy_sources",
        "_pre_policy_sources",
    )

    def __init__(
        self,
        *,
        ledger_repository: M6ReplayLockedClosedPolicyLedgerRepository,
        policy_source_provider: M6ReplayLockedAlertPolicySourceProvider,
        pre_policy_source_provider: M6ReplayLockedClosedPolicyPrePolicySourceProvider,
        sample_executor: M6ReplayLockedClosedPolicySampleExecutor,
        stored_candidate_provider: M6ReplayLockedStoredClosedCandidateProvider,
        candidate_audit_head_provider: M6ReplayLockedClosedCandidateAuditHeadProvider,
    ) -> None:
        requirements = (
            (ledger_repository, "resume"),
            (ledger_repository, "persist_pending"),
            (ledger_repository, "append_record"),
            (ledger_repository, "seal"),
            (policy_source_provider, "load_alert_policy_source"),
            (pre_policy_source_provider, "load_closed_policy_pre_policy_source"),
            (sample_executor, "execute_sample"),
            (stored_candidate_provider, "load_stored_closed_candidate"),
            (candidate_audit_head_provider, "load_closed_candidate_audit_head"),
        )
        if any(
            not callable(getattr(dependency, method, None)) for dependency, method in requirements
        ):
            raise TypeError("invalid M6 CLOSED-policy coordinator dependency")
        self._ledger = ledger_repository
        self._policy_sources = policy_source_provider
        self._pre_policy_sources = pre_policy_source_provider
        self._executor = sample_executor
        self._candidates = stored_candidate_provider
        self._audit_heads = candidate_audit_head_provider

    def _resume(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    ) -> M6ReplayLockedClosedPolicyExecutionResumeV2:
        try:
            observed = self._ledger.resume(scope)
        except M6ReplayLockedClosedPolicyLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if type(observed) is not M6ReplayLockedClosedPolicyExecutionResumeV2:
            _fail(_FailureCode.EXECUTION_STATE_INVALID)
        try:
            resume = M6ReplayLockedClosedPolicyExecutionResumeV2(
                execution_scope=observed.execution_scope,
                pending_commitments=observed.pending_commitments,
                sample_records=observed.sample_records,
                execution_seal=observed.execution_seal,
            )
        except (AttributeError, TypeError, ValueError):
            _fail(_FailureCode.EXECUTION_STATE_INVALID)
        if resume != observed or resume.execution_scope != scope:
            _fail(_FailureCode.EXECUTION_STATE_INVALID)
        return resume

    def _load_policy_cut(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedAlertPolicyCausalCutAuthority:
        try:
            observation = self._policy_sources.load_alert_policy_source(closure)
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        try:
            if observation.replay_input_closure != closure:
                _fail(_FailureCode.POLICY_CAUSAL_CUT_REJECTED)
            cut = build_m6_replay_locked_alert_policy_causal_cut(
                observation=observation,
            )
        except M6ReplayLockedClosedPolicyCoordinatorError:
            raise
        except M6ReplayLockedPolicySourceBuildError as error:
            _fail(_policy_cut_failure(error.code))
        except Exception:
            _fail(_FailureCode.POLICY_CAUSAL_CUT_REJECTED)
        if (
            cut.sample_id != closure.sample_id
            or cut.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
            or cut.replay_input_closure_document_sha256
            != closure.replay_input_closure_document_sha256
            or closure.source_case_id is None
            or closure.source_case_revision is None
            or closure.source_case_document_sha256 is None
            or cut.source_closed_case.run_id != closure.source_run_id
            or cut.source_closed_case.case_id != closure.source_case_id
            or cut.source_closed_case_revision != closure.source_case_revision
            or cut.source_closed_case_content_sha256 != closure.source_case_document_sha256
            or cut.source_closed_case.manifest_id != closure.source_manifest_id
        ):
            _fail(_FailureCode.POLICY_CAUSAL_CUT_REJECTED)
        return cut

    @staticmethod
    def _require_supported_pending(
        pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    ) -> None:
        if pending.pre_policy_route not in {
            M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        }:
            _fail(_FailureCode.UNSUPPORTED_ROUTE)

    def _persist_pending(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        stored: M6StoredRegressionExecutionSourceCatalog,
        resume: M6ReplayLockedClosedPolicyExecutionResumeV2,
    ) -> None:
        entries = stored.source_catalog.entries
        if resume.next_ledger_sequence >= len(entries):
            _fail(_FailureCode.SOURCE_CATALOG_MISMATCH)
        closure = entries[resume.next_ledger_sequence].replay_input_closure
        cut = self._load_policy_cut(closure)
        try:
            pending = build_m6_replay_locked_closed_policy_pending_commitment(
                execution_scope=scope,
                stored_source_catalog=stored,
                policy_causal_cut=cut,
                ledger_sequence=resume.next_ledger_sequence,
                previous_ledger_entry_hash=resume.ledger_head_hash,
            )
            self._require_supported_pending(pending)
            advanced = self._ledger.persist_pending(
                scope,
                pending,
                _canonical_document(pending),
            )
        except M6ReplayLockedClosedPolicyExecutionError as error:
            _fail(_execution_failure(error.code))
        except M6ReplayLockedClosedPolicyLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if (
            type(advanced) is not M6ReplayLockedClosedPolicyExecutionResumeV2
            or len(advanced.pending_commitments) <= pending.ledger_sequence
            or advanced.pending_commitments[pending.ledger_sequence] != pending
        ):
            _fail(_FailureCode.PENDING_REJECTED)

    def _load_stored_candidate(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        sample_id: str,
    ) -> M6ReplayLockedStoredClosedCandidate | None:
        try:
            observed = self._candidates.load_stored_closed_candidate(
                scope.candidate_run_id,
                sample_id,
            )
        except M6ReplayLockedClosedCandidateError as error:
            if error.reason_code == M6ReplayLockedClosedCandidateFailureCode.NOT_FOUND:
                return None
            _fail(_candidate_failure(error.reason_code))
        if type(observed) is not M6ReplayLockedStoredClosedCandidate:
            _fail(_FailureCode.CANDIDATE_OBSERVATION_REJECTED)
        return observed

    def _rebuild_pre_policy_candidate_snapshot(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6CaseReplaySnapshot:
        try:
            source = self._pre_policy_sources.load_closed_policy_pre_policy_source(
                closure,
                pending.source_binding,
            )
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        if pending.pre_policy_route == (M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE):
            try:
                snapshot = build_m6_replay_locked_closed_policy_fast_pre_policy_candidate(
                    execution_scope=scope,
                    pending_commitment=pending,
                    source=source,
                ).candidate_snapshot
            except M6ReplayLockedFastTerminalError as error:
                _fail(_fast_builder_failure(error.code))
        elif pending.pre_policy_route == (
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
        ):
            try:
                snapshot = build_m6_replay_locked_closed_policy_m4_pre_policy_candidate(
                    execution_scope=scope,
                    pending_commitment=pending,
                    source=source,
                ).candidate_snapshot
            except M6ReplayLockedM4TerminalError as error:
                _fail(_m4_builder_failure(error.code))
        else:
            _fail(_FailureCode.UNSUPPORTED_ROUTE)
        return snapshot

    def _execute_pending(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        stored: M6StoredRegressionExecutionSourceCatalog,
        resume: M6ReplayLockedClosedPolicyExecutionResumeV2,
    ) -> None:
        pending = resume.pending_commitments[-1]
        self._require_supported_pending(pending)
        entries = stored.source_catalog.entries
        if pending.ledger_sequence >= len(entries):
            _fail(_FailureCode.SOURCE_CATALOG_MISMATCH)
        closure = entries[pending.ledger_sequence].replay_input_closure
        cut = self._load_policy_cut(closure)
        try:
            expected = build_m6_replay_locked_closed_policy_pending_commitment(
                execution_scope=scope,
                stored_source_catalog=stored,
                policy_causal_cut=cut,
                ledger_sequence=pending.ledger_sequence,
                previous_ledger_entry_hash=pending.previous_ledger_entry_hash,
            )
        except M6ReplayLockedClosedPolicyExecutionError as error:
            _fail(_execution_failure(error.code))
        if expected != pending:
            _fail(_FailureCode.PENDING_REJECTED)

        stored_candidate = self._load_stored_candidate(scope, pending.sample_id)
        if stored_candidate is None:
            try:
                self._executor.execute_sample(scope, pending, closure)
            except M6ReplayLockedClosedPolicySampleExecutorError as error:
                _fail(_executor_failure(error.reason_code))
            stored_candidate = self._load_stored_candidate(scope, pending.sample_id)
            if stored_candidate is None:
                _fail(_FailureCode.CANDIDATE_OBSERVATION_MISSING)

        pre_policy_snapshot = self._rebuild_pre_policy_candidate_snapshot(
            scope,
            pending,
            closure,
        )
        try:
            observation = build_m6_replay_locked_closed_candidate_observation(
                execution_scope=scope,
                pending_commitment=pending,
                stored_candidate=stored_candidate,
                pre_policy_candidate_snapshot=pre_policy_snapshot,
            )
        except M6ReplayLockedClosedCandidateError as error:
            _fail(_candidate_failure(error.reason_code))
        try:
            proof = prove_m6_replay_locked_closed_policy_source_determinism(
                execution_scope=scope,
                pending_commitment=pending,
                closure=closure,
                policy_causal_cut=cut,
                projection_provider=self._pre_policy_sources,
            )
        except M6ReplayLockedSourceDeterminismError as error:
            _fail(_source_determinism_failure(error.code))
        try:
            record = build_m6_replay_locked_closed_policy_sample_record(
                execution_scope=scope,
                stored_source_catalog=stored,
                pending_commitment=pending,
                source_determinism=proof,
                policy_causal_cut=cut,
                candidate_observation=observation,
            )
            advanced = self._ledger.append_record(
                scope,
                record,
                _canonical_document(record),
            )
        except M6ReplayLockedClosedPolicyExecutionError as error:
            _fail(_execution_failure(error.code))
        except M6ReplayLockedClosedPolicyLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if (
            type(advanced) is not M6ReplayLockedClosedPolicyExecutionResumeV2
            or len(advanced.sample_records) <= record.ledger_sequence
            or advanced.sample_records[record.ledger_sequence] != record
        ):
            _fail(_FailureCode.RECORD_REJECTED)

    def _seal(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        resume: M6ReplayLockedClosedPolicyExecutionResumeV2,
    ) -> M6ReplayLockedClosedPolicyExecutionSealAuthorityV2:
        try:
            head = self._audit_heads.load_closed_candidate_audit_head(scope.candidate_run_id)
        except M6ReplayLockedClosedCandidateError as error:
            _fail(_candidate_failure(error.reason_code))
        try:
            seal = build_m6_replay_locked_closed_policy_execution_seal(
                execution_scope=scope,
                sample_records=resume.sample_records,
                candidate_audit_head=head,
            )
            advanced = self._ledger.seal(
                scope,
                seal,
                _canonical_document(seal),
            )
        except M6ReplayLockedClosedPolicyExecutionError as error:
            _fail(_execution_failure(error.code))
        except M6ReplayLockedClosedPolicyLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if (
            type(advanced) is not M6ReplayLockedClosedPolicyExecutionResumeV2
            or advanced.status != M6ReplayLockedClosedPolicyLedgerStatus.SEALED
            or advanced.execution_seal != seal
        ):
            _fail(_FailureCode.SEAL_REJECTED)
        return seal

    def _attempt_run_to_terminal(
        self,
        execution_scope: object,
        stored_source_catalog: object,
    ) -> M6ReplayLockedClosedPolicyExecutionSealAuthorityV2:
        scope = _canonical(
            execution_scope,
            M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        )
        stored = _controlled_catalog(stored_source_catalog)
        maximum_steps = 2 * len(scope.pre_policy_execution_scope.execution_dataset.entries) + 4
        for _step in range(maximum_steps):
            resume = self._resume(scope)
            if resume.status == M6ReplayLockedClosedPolicyLedgerStatus.READY_FOR_PENDING:
                self._persist_pending(scope, stored, resume)
                continue
            if resume.status == M6ReplayLockedClosedPolicyLedgerStatus.PENDING:
                self._execute_pending(scope, stored, resume)
                continue
            if resume.status == M6ReplayLockedClosedPolicyLedgerStatus.READY_TO_SEAL:
                return self._seal(scope, resume)
            if resume.status == M6ReplayLockedClosedPolicyLedgerStatus.SEALED:
                if resume.execution_seal is None:
                    _fail(_FailureCode.EXECUTION_STATE_INVALID)
                return resume.execution_seal
            _fail(_FailureCode.EXECUTION_STATE_INVALID)
        _fail(_FailureCode.COORDINATION_STALLED)

    def run_to_terminal(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        stored_source_catalog: M6StoredRegressionExecutionSourceCatalog,
    ) -> M6ReplayLockedClosedPolicyExecutionSealAuthorityV2:
        """Resume or complete one exact routed CLOSED-policy execution."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_run_to_terminal(
                execution_scope,
                stored_source_catalog,
            )
        except M6ReplayLockedClosedPolicyCoordinatorError as error:
            failure = error.reason_code
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, execution_scope, stored_source_catalog
        raise _error(failure) from None


__all__ = ["M6ReplayLockedClosedPolicyExecutionCoordinatorService"]
