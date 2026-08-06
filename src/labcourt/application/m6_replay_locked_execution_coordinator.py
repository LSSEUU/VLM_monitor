"""Crash-recoverable coordinator for the dedicated M6 locked replay ledger."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_replay_locked_execution import (
    M6ReplayLockedExecutionError,
    M6ReplayLockedExecutionErrorCode,
    build_m6_replay_locked_execution_seal,
    build_m6_replay_locked_pending_commitment,
    build_m6_replay_locked_sample_record,
)
from labcourt.application.m6_replay_locked_source_determinism import (
    M6ReplayLockedSourceDeterminismError,
    prove_m6_replay_locked_source_determinism,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateAuditHeadProvider,
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidateObservation,
    M6ReplayLockedCandidateObservationProvider,
)
from labcourt.ports.m6_replay_locked_coordinator import (
    M6ReplayLockedCoordinatorError,
    M6ReplayLockedCoordinatorFailureCode,
)
from labcourt.ports.m6_replay_locked_ledger import (
    M6ReplayLockedExecutionResume,
    M6ReplayLockedLedgerError,
    M6ReplayLockedLedgerFailureCode,
    M6ReplayLockedLedgerRepository,
    M6ReplayLockedLedgerStatus,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
    M6ReplayLockedSampleExecutor,
    M6ReplayLockedSampleExecutorError,
    M6ReplayLockedSampleExecutorFailureCode,
)
from labcourt.ports.m6_replay_locked_source import (
    M6ReplayLockedSourceProjectionProvider,
)

_FailureCode = M6ReplayLockedCoordinatorFailureCode
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(code: _FailureCode) -> M6ReplayLockedCoordinatorError:
    return M6ReplayLockedCoordinatorError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
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


def _ledger_failure(code: M6ReplayLockedLedgerFailureCode) -> _FailureCode:
    direct = {
        M6ReplayLockedLedgerFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6ReplayLockedLedgerFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6ReplayLockedLedgerFailureCode.SCOPE_CONFLICT: _FailureCode.SCOPE_REJECTED,
        M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE: _FailureCode.DOCUMENT_TOO_LARGE,
        M6ReplayLockedLedgerFailureCode.PENDING_CONFLICT: _FailureCode.PENDING_REJECTED,
        M6ReplayLockedLedgerFailureCode.RECORD_CONFLICT: _FailureCode.RECORD_REJECTED,
        M6ReplayLockedLedgerFailureCode.SEAL_CONFLICT: _FailureCode.SEAL_REJECTED,
        M6ReplayLockedLedgerFailureCode.COMMIT_OUTCOME_UNKNOWN: (
            _FailureCode.COMMIT_OUTCOME_UNKNOWN
        ),
        M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED: _FailureCode.STORAGE_REJECTED,
    }
    return direct.get(code, _FailureCode.EXECUTION_STATE_INVALID)


def _execution_failure(code: M6ReplayLockedExecutionErrorCode) -> _FailureCode:
    direct = {
        M6ReplayLockedExecutionErrorCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6ReplayLockedExecutionErrorCode.SCOPE_CATALOG_MISMATCH: (
            _FailureCode.SCOPE_CATALOG_MISMATCH
        ),
        M6ReplayLockedExecutionErrorCode.PENDING_REJECTED: _FailureCode.PENDING_REJECTED,
        M6ReplayLockedExecutionErrorCode.CANDIDATE_OBSERVATION_REJECTED: (
            _FailureCode.CANDIDATE_OBSERVATION_REJECTED
        ),
        M6ReplayLockedExecutionErrorCode.RECORD_REJECTED: _FailureCode.RECORD_REJECTED,
        M6ReplayLockedExecutionErrorCode.AUDIT_HEAD_MISMATCH: (_FailureCode.AUDIT_HEAD_REJECTED),
        M6ReplayLockedExecutionErrorCode.SEAL_REJECTED: _FailureCode.SEAL_REJECTED,
    }
    return direct.get(code, _FailureCode.SAMPLE_EXECUTION_REJECTED)


def _candidate_failure(code: M6ReplayLockedCandidateFailureCode) -> _FailureCode:
    if code == M6ReplayLockedCandidateFailureCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedCandidateFailureCode.STORAGE_REJECTED:
        return _FailureCode.STORAGE_REJECTED
    return _FailureCode.CANDIDATE_OBSERVATION_REJECTED


def _executor_failure(code: M6ReplayLockedSampleExecutorFailureCode) -> _FailureCode:
    if code == M6ReplayLockedSampleExecutorFailureCode.INVALID_ARGUMENT:
        return _FailureCode.INVALID_ARGUMENT
    if code == M6ReplayLockedSampleExecutorFailureCode.STORAGE_REJECTED:
        return _FailureCode.STORAGE_REJECTED
    return _FailureCode.SAMPLE_EXECUTION_REJECTED


class M6ReplayLockedExecutionCoordinatorService:
    """Advance Pending -> candidate -> Record -> Seal from durable state only."""

    __slots__ = (
        "_audit_heads",
        "_candidates",
        "_executor",
        "_ledger",
        "_source_projections",
    )

    def __init__(
        self,
        *,
        ledger_repository: M6ReplayLockedLedgerRepository,
        source_projection_provider: M6ReplayLockedSourceProjectionProvider,
        sample_executor: M6ReplayLockedSampleExecutor,
        candidate_observation_provider: M6ReplayLockedCandidateObservationProvider,
        candidate_audit_head_provider: M6ReplayLockedCandidateAuditHeadProvider,
    ) -> None:
        requirements = (
            (ledger_repository, "resume"),
            (ledger_repository, "persist_pending"),
            (ledger_repository, "append_record"),
            (ledger_repository, "seal"),
            (source_projection_provider, "load_source_projection"),
            (sample_executor, "execute_sample"),
            (candidate_observation_provider, "load_candidate_observation"),
            (candidate_audit_head_provider, "load_candidate_audit_head"),
        )
        if any(
            not callable(getattr(dependency, method, None)) for dependency, method in requirements
        ):
            raise TypeError("invalid M6 locked execution coordinator dependency")
        self._ledger = ledger_repository
        self._source_projections = source_projection_provider
        self._executor = sample_executor
        self._candidates = candidate_observation_provider
        self._audit_heads = candidate_audit_head_provider

    def _resume(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
    ) -> M6ReplayLockedExecutionResume:
        try:
            observed = self._ledger.resume(scope)
        except M6ReplayLockedLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if type(observed) is not M6ReplayLockedExecutionResume:
            _fail(_FailureCode.EXECUTION_STATE_INVALID)
        try:
            resume = M6ReplayLockedExecutionResume(
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

    def _persist_pending(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
        stored: M6StoredRegressionExecutionSourceCatalog,
        resume: M6ReplayLockedExecutionResume,
    ) -> None:
        try:
            pending = build_m6_replay_locked_pending_commitment(
                execution_scope=scope,
                stored_source_catalog=stored,
                ledger_sequence=resume.next_ledger_sequence,
                previous_ledger_entry_hash=resume.ledger_head_hash,
            )
            advanced = self._ledger.persist_pending(
                scope,
                pending,
                _canonical_document(pending),
            )
        except M6ReplayLockedExecutionError as error:
            _fail(_execution_failure(error.code))
        except M6ReplayLockedLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if (
            type(advanced) is not M6ReplayLockedExecutionResume
            or len(advanced.pending_commitments) <= pending.ledger_sequence
            or advanced.pending_commitments[pending.ledger_sequence] != pending
        ):
            _fail(_FailureCode.PENDING_REJECTED)

    def _load_candidate(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
        sample_id: str,
    ) -> M6ReplayLockedCandidateObservation | None:
        try:
            observed = self._candidates.load_candidate_observation(
                scope.candidate_run_id,
                sample_id,
            )
        except M6ReplayLockedCandidateError as error:
            if error.reason_code == M6ReplayLockedCandidateFailureCode.NOT_FOUND:
                return None
            _fail(_candidate_failure(error.reason_code))
        if type(observed) is not M6ReplayLockedCandidateObservation:
            _fail(_FailureCode.CANDIDATE_OBSERVATION_REJECTED)
        try:
            return M6ReplayLockedCandidateObservation(
                case=observed.case,
                canonical_document=observed.canonical_document,
                case_revision=observed.case_revision,
                case_audit_sequence=observed.case_audit_sequence,
                case_audit_entry_hash=observed.case_audit_entry_hash,
                candidate_snapshot=observed.candidate_snapshot,
            )
        except (AttributeError, TypeError, ValueError):
            _fail(_FailureCode.CANDIDATE_OBSERVATION_REJECTED)

    def _execute_pending(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
        stored: M6StoredRegressionExecutionSourceCatalog,
        resume: M6ReplayLockedExecutionResume,
    ) -> None:
        pending = resume.pending_commitments[-1]
        source_entry = stored.source_catalog.entries[pending.ledger_sequence]
        observation = self._load_candidate(scope, pending.sample_id)
        if observation is None:
            try:
                self._executor.execute_sample(
                    scope,
                    pending,
                    source_entry.replay_input_closure,
                )
            except M6ReplayLockedSampleExecutorError as error:
                _fail(_executor_failure(error.reason_code))
            observation = self._load_candidate(scope, pending.sample_id)
            if observation is None:
                _fail(_FailureCode.CANDIDATE_OBSERVATION_MISSING)
        try:
            source_determinism = prove_m6_replay_locked_source_determinism(
                command=scope.command,
                execution_entry=pending.execution_entry,
                closure=source_entry.replay_input_closure,
                candidate_run_id=scope.candidate_run_id,
                execution_component_manifest_id=(scope.execution_component.component_authority_id),
                projection_provider=self._source_projections,
            )
            record = build_m6_replay_locked_sample_record(
                execution_scope=scope,
                stored_source_catalog=stored,
                pending_commitment=pending,
                source_determinism=source_determinism,
                candidate_observation=observation,
            )
            advanced = self._ledger.append_record(
                scope,
                record,
                _canonical_document(record),
            )
        except M6ReplayLockedSourceDeterminismError:
            _fail(_FailureCode.SOURCE_PROJECTION_REJECTED)
        except M6ReplayLockedExecutionError as error:
            _fail(_execution_failure(error.code))
        except M6ReplayLockedLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if (
            type(advanced) is not M6ReplayLockedExecutionResume
            or len(advanced.sample_records) <= record.ledger_sequence
            or advanced.sample_records[record.ledger_sequence] != record
        ):
            _fail(_FailureCode.RECORD_REJECTED)

    def _seal(
        self,
        scope: M6ReplayLockedExecutionScopeAuthority,
        stored: M6StoredRegressionExecutionSourceCatalog,
        resume: M6ReplayLockedExecutionResume,
    ) -> M6ReplayLockedExecutionSealAuthority:
        try:
            head = self._audit_heads.load_candidate_audit_head(scope.candidate_run_id)
        except M6ReplayLockedCandidateError as error:
            _fail(_candidate_failure(error.reason_code))
        try:
            seal = build_m6_replay_locked_execution_seal(
                execution_scope=scope,
                stored_source_catalog=stored,
                sample_records=resume.sample_records,
                candidate_audit_head=head,
            )
            advanced = self._ledger.seal(scope, seal, _canonical_document(seal))
        except M6ReplayLockedExecutionError as error:
            _fail(_execution_failure(error.code))
        except M6ReplayLockedLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        if (
            type(advanced) is not M6ReplayLockedExecutionResume
            or advanced.status != M6ReplayLockedLedgerStatus.SEALED
            or advanced.execution_seal != seal
        ):
            _fail(_FailureCode.SEAL_REJECTED)
        return seal

    def _attempt_run_to_terminal(
        self,
        execution_scope: object,
        stored_source_catalog: object,
    ) -> M6ReplayLockedExecutionSealAuthority:
        scope = _canonical_model(execution_scope, M6ReplayLockedExecutionScopeAuthority)
        stored = _controlled_catalog(stored_source_catalog)
        maximum_steps = 2 * len(scope.execution_dataset.entries) + 4
        for _step in range(maximum_steps):
            resume = self._resume(scope)
            if resume.status == M6ReplayLockedLedgerStatus.READY_FOR_PENDING:
                self._persist_pending(scope, stored, resume)
                continue
            if resume.status == M6ReplayLockedLedgerStatus.PENDING:
                self._execute_pending(scope, stored, resume)
                continue
            if resume.status == M6ReplayLockedLedgerStatus.READY_TO_SEAL:
                return self._seal(scope, stored, resume)
            if resume.status == M6ReplayLockedLedgerStatus.SEALED:
                if resume.execution_seal is None:
                    _fail(_FailureCode.EXECUTION_STATE_INVALID)
                return resume.execution_seal
            _fail(_FailureCode.EXECUTION_STATE_INVALID)
        _fail(_FailureCode.COORDINATION_STALLED)

    def run_to_terminal(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        stored_source_catalog: M6StoredRegressionExecutionSourceCatalog,
    ) -> M6ReplayLockedExecutionSealAuthority:
        """Resume or complete one exact locked execution without caller-supplied claims."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_run_to_terminal(
                execution_scope,
                stored_source_catalog,
            )
        except M6ReplayLockedCoordinatorError as error:
            failure = error.reason_code
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, execution_scope, stored_source_catalog
        raise _error(failure) from None


__all__ = ["M6ReplayLockedExecutionCoordinatorService"]
