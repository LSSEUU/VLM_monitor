"""Independently rebuild one persisted M6 route candidate for ledger observation."""

from __future__ import annotations

from typing import NoReturn

from labcourt.application.m6_replay_locked_execution import (
    M6ReplayLockedExecutionError,
    build_m6_replay_locked_pending_commitment,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    M6ReplayLockedFastTerminalError,
    build_m6_replay_locked_fast_terminal_candidate,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    M6ReplayLockedM4TerminalError,
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.contracts.references import require_portable_run_id, require_reference_token
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogError,
    M6RegressionExecutionSourceCatalogFailureCode,
    M6RegressionExecutionSourceCatalogProvider,
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidateObservation,
    M6ReplayLockedCandidateObservationProvider,
    M6ReplayLockedStoredCandidateCase,
    M6ReplayLockedStoredCandidateProvider,
)
from labcourt.ports.m6_replay_locked_execution_scope import (
    M6ReplayLockedExecutionScopeFailureCode,
    M6ReplayLockedExecutionScopeProvider,
    M6ReplayLockedExecutionScopeStoreError,
    M6StoredReplayLockedExecutionScope,
)
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
    M6ReplayLockedFastTerminalSourceProvider,
)
from labcourt.ports.m6_replay_locked_ledger import (
    M6ReplayLockedExecutionResume,
    M6ReplayLockedLedgerError,
    M6ReplayLockedLedgerFailureCode,
    M6ReplayLockedLedgerRepository,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
    M6ReplayLockedM4GateTerminalSourceProvider,
)

_FailureCode = M6ReplayLockedCandidateFailureCode


def _error(code: _FailureCode) -> M6ReplayLockedCandidateError:
    return M6ReplayLockedCandidateError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _scope_failure(code: M6ReplayLockedExecutionScopeFailureCode) -> _FailureCode:
    if code == M6ReplayLockedExecutionScopeFailureCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code in {
        M6ReplayLockedExecutionScopeFailureCode.STORAGE_REJECTED,
        M6ReplayLockedExecutionScopeFailureCode.COMMIT_OUTCOME_UNKNOWN,
    }:
        return _FailureCode.STORAGE_REJECTED
    return _FailureCode.STORED_AUTHORITY_INVALID


def _catalog_failure(
    code: M6RegressionExecutionSourceCatalogFailureCode,
) -> _FailureCode:
    if code == M6RegressionExecutionSourceCatalogFailureCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code in {
        M6RegressionExecutionSourceCatalogFailureCode.STORAGE_REJECTED,
        M6RegressionExecutionSourceCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN,
    }:
        return _FailureCode.STORAGE_REJECTED
    return _FailureCode.STORED_AUTHORITY_INVALID


def _ledger_failure(code: M6ReplayLockedLedgerFailureCode) -> _FailureCode:
    if code == M6ReplayLockedLedgerFailureCode.DOCUMENT_TOO_LARGE:
        return _FailureCode.DOCUMENT_TOO_LARGE
    if code in {
        M6ReplayLockedLedgerFailureCode.STORAGE_REJECTED,
        M6ReplayLockedLedgerFailureCode.COMMIT_OUTCOME_UNKNOWN,
    }:
        return _FailureCode.STORAGE_REJECTED
    return _FailureCode.STORED_AUTHORITY_INVALID


def _controlled_stored(value: object) -> M6ReplayLockedStoredCandidateCase:
    if type(value) is not M6ReplayLockedStoredCandidateCase:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return M6ReplayLockedStoredCandidateCase(
            candidate_run_id=value.candidate_run_id,
            execution_scope_authority_id=value.execution_scope_authority_id,
            ledger_sequence=value.ledger_sequence,
            sample_id=value.sample_id,
            execution_entry_id=value.execution_entry_id,
            source_catalog_entry_id=value.source_catalog_entry_id,
            pending_commitment_authority_id=value.pending_commitment_authority_id,
            route=value.route,
            case=value.case,
            canonical_document=value.canonical_document,
            case_document_sha256=value.case_document_sha256,
            case_document_size_bytes=value.case_document_size_bytes,
            case_audit_sequence=value.case_audit_sequence,
            case_audit_entry_hash=value.case_audit_entry_hash,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def _controlled_scope(value: object) -> M6StoredReplayLockedExecutionScope:
    if type(value) is not M6StoredReplayLockedExecutionScope:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return M6StoredReplayLockedExecutionScope(
            scope=value.scope,
            canonical_document=value.canonical_document,
            content_sha256=value.content_sha256,
            size_bytes=value.size_bytes,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def _controlled_resume(value: object) -> M6ReplayLockedExecutionResume:
    if type(value) is not M6ReplayLockedExecutionResume:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return M6ReplayLockedExecutionResume(
            execution_scope=value.execution_scope,
            pending_commitments=value.pending_commitments,
            sample_records=value.sample_records,
            execution_seal=value.execution_seal,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def _controlled_catalog(value: object) -> M6StoredRegressionExecutionSourceCatalog:
    if type(value) is not M6StoredRegressionExecutionSourceCatalog:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return M6StoredRegressionExecutionSourceCatalog(
            source_catalog=value.source_catalog,
            canonical_document=value.canonical_document,
            content_sha256=value.content_sha256,
            size_bytes=value.size_bytes,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def _controlled_source(value: object) -> M6ReplayLockedFastTerminalSource:
    if type(value) is not M6ReplayLockedFastTerminalSource:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return M6ReplayLockedFastTerminalSource(
            source_identity_sha256=value.source_identity_sha256,
            closure=value.closure,
            projection_context=value.projection_context,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


def _controlled_m4_source(value: object) -> M6ReplayLockedM4GateTerminalSource:
    if type(value) is not M6ReplayLockedM4GateTerminalSource:
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)
    try:
        return M6ReplayLockedM4GateTerminalSource(
            source_identity_sha256=value.source_identity_sha256,
            closure=value.closure,
            projection_context=value.projection_context,
            hearing_record=value.hearing_record,
            hearing_verdict_binding=value.hearing_verdict_binding,
            gate_current_closure_receipt=value.gate_current_closure_receipt,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(_FailureCode.STORED_AUTHORITY_INVALID)


class M6ReplayLockedFastCandidateObservationService:
    """Observe SQLite bytes only after replaying all immutable source authorities."""

    __slots__ = ("_catalogs", "_ledger", "_scopes", "_sources", "_stored")

    def __init__(
        self,
        *,
        stored_candidate_provider: M6ReplayLockedStoredCandidateProvider,
        execution_scope_provider: M6ReplayLockedExecutionScopeProvider,
        ledger_repository: M6ReplayLockedLedgerRepository,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        fast_source_provider: M6ReplayLockedFastTerminalSourceProvider,
    ) -> None:
        requirements = (
            (stored_candidate_provider, "load_stored_candidate_case"),
            (execution_scope_provider, "load"),
            (ledger_repository, "resume"),
            (source_catalog_provider, "load"),
            (fast_source_provider, "load_fast_terminal_source"),
        )
        if any(
            not callable(getattr(dependency, method, None)) for dependency, method in requirements
        ):
            raise TypeError("invalid M6 locked candidate observation dependency")
        self._stored = stored_candidate_provider
        self._scopes = execution_scope_provider
        self._ledger = ledger_repository
        self._catalogs = source_catalog_provider
        self._sources = fast_source_provider

    @staticmethod
    def _public_identity(candidate_run_id: object, sample_id: object) -> tuple[str, str]:
        try:
            if not isinstance(candidate_run_id, str) or not isinstance(sample_id, str):
                raise TypeError
            return (
                require_portable_run_id(
                    candidate_run_id,
                    "M6 locked candidate observation run_id",
                ),
                require_reference_token(
                    sample_id,
                    "M6 locked candidate observation sample_id",
                ),
            )
        except (TypeError, ValueError):
            _fail(_FailureCode.INVALID_ARGUMENT)

    def _load_stored(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedStoredCandidateCase:
        try:
            observed = self._stored.load_stored_candidate_case(candidate_run_id, sample_id)
        except M6ReplayLockedCandidateError:
            raise
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        stored = _controlled_stored(observed)
        if stored.candidate_run_id != candidate_run_id or stored.sample_id != sample_id:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        return stored

    def _load_scope(
        self,
        stored: M6ReplayLockedStoredCandidateCase,
    ) -> M6StoredReplayLockedExecutionScope:
        try:
            observed = self._scopes.load(
                stored.candidate_run_id,
                stored.execution_scope_authority_id,
            )
        except M6ReplayLockedExecutionScopeStoreError as error:
            _fail(_scope_failure(error.reason_code))
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        controlled = _controlled_scope(observed)
        scope = controlled.scope
        if (
            scope.candidate_run_id != stored.candidate_run_id
            or scope.execution_scope_authority_id != stored.execution_scope_authority_id
        ):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        return controlled

    def _load_resume(
        self,
        stored_scope: M6StoredReplayLockedExecutionScope,
    ) -> M6ReplayLockedExecutionResume:
        try:
            observed = self._ledger.resume(stored_scope.scope)
        except M6ReplayLockedLedgerError as error:
            _fail(_ledger_failure(error.reason_code))
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        resume = _controlled_resume(observed)
        if resume.execution_scope != stored_scope.scope:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        return resume

    def _load_catalog(
        self,
        stored_scope: M6StoredReplayLockedExecutionScope,
    ) -> M6StoredRegressionExecutionSourceCatalog:
        scope = stored_scope.scope
        try:
            observed = self._catalogs.load(
                scope.execution_dataset.source_catalog_authority_id,
                scope.execution_dataset.source_catalog_document_sha256,
            )
        except M6RegressionExecutionSourceCatalogError as error:
            _fail(_catalog_failure(error.reason_code))
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        return _controlled_catalog(observed)

    def _attempt_load(
        self,
        candidate_run_id: object,
        sample_id: object,
    ) -> M6ReplayLockedCandidateObservation:
        run_id, controlled_sample = self._public_identity(candidate_run_id, sample_id)
        stored = self._load_stored(run_id, controlled_sample)
        stored_scope = self._load_scope(stored)
        scope = stored_scope.scope
        resume = self._load_resume(stored_scope)
        if stored.ledger_sequence >= len(resume.pending_commitments):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        pending = resume.pending_commitments[stored.ledger_sequence]
        if (
            pending.pending_commitment_authority_id != stored.pending_commitment_authority_id
            or pending.sample_id != stored.sample_id
            or pending.execution_entry_id != stored.execution_entry_id
            or pending.source_catalog_entry_id != stored.source_catalog_entry_id
            or pending.route != stored.route
        ):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        catalog = self._load_catalog(stored_scope)
        try:
            expected_pending = build_m6_replay_locked_pending_commitment(
                execution_scope=scope,
                stored_source_catalog=catalog,
                ledger_sequence=pending.ledger_sequence,
                previous_ledger_entry_hash=pending.previous_ledger_entry_hash,
            )
        except M6ReplayLockedExecutionError:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if expected_pending != pending:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if pending.ledger_sequence >= len(catalog.source_catalog.entries):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        source_entry = catalog.source_catalog.entries[pending.ledger_sequence]
        if source_entry.catalog_entry_id != stored.source_catalog_entry_id:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        try:
            source = self._sources.load_fast_terminal_source(source_entry.replay_input_closure)
        except Exception:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        controlled_source = _controlled_source(source)
        try:
            rebuilt = build_m6_replay_locked_fast_terminal_candidate(
                execution_scope=scope,
                pending_commitment=pending,
                source=controlled_source,
            )
        except M6ReplayLockedFastTerminalError:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if (
            rebuilt.case != stored.case
            or rebuilt.canonical_case_document != stored.canonical_document
            or rebuilt.candidate_snapshot.sample_id != stored.sample_id
        ):
            _fail(_FailureCode.CANDIDATE_CONFLICT)
        try:
            return M6ReplayLockedCandidateObservation(
                case=rebuilt.case,
                canonical_document=rebuilt.canonical_case_document,
                case_revision=1,
                case_audit_sequence=stored.case_audit_sequence,
                case_audit_entry_hash=stored.case_audit_entry_hash,
                candidate_snapshot=rebuilt.candidate_snapshot,
            )
        except (TypeError, ValueError):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)

    def load_candidate_observation(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedCandidateObservation:
        """Rebuild the candidate snapshot; never deserialize one from SQLite."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_load(candidate_run_id, sample_id)
        except M6ReplayLockedCandidateError as error:
            failure = error.reason_code
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, candidate_run_id, sample_id
        raise _error(failure) from None


class M6ReplayLockedM4CandidateObservationService(M6ReplayLockedFastCandidateObservationService):
    """Observe one persisted M4 hearing-plus-Gate candidate from sealed facts."""

    __slots__ = ("_m4_sources",)

    def __init__(
        self,
        *,
        stored_candidate_provider: M6ReplayLockedStoredCandidateProvider,
        execution_scope_provider: M6ReplayLockedExecutionScopeProvider,
        ledger_repository: M6ReplayLockedLedgerRepository,
        source_catalog_provider: M6RegressionExecutionSourceCatalogProvider,
        m4_source_provider: M6ReplayLockedM4GateTerminalSourceProvider,
    ) -> None:
        requirements = (
            (stored_candidate_provider, "load_stored_candidate_case"),
            (execution_scope_provider, "load"),
            (ledger_repository, "resume"),
            (source_catalog_provider, "load"),
            (m4_source_provider, "load_m4_gate_terminal_source"),
        )
        if any(
            not callable(getattr(dependency, method, None)) for dependency, method in requirements
        ):
            raise TypeError("invalid M6 locked M4 candidate observation dependency")
        self._stored = stored_candidate_provider
        self._scopes = execution_scope_provider
        self._ledger = ledger_repository
        self._catalogs = source_catalog_provider
        self._m4_sources = m4_source_provider

    def _attempt_load(
        self,
        candidate_run_id: object,
        sample_id: object,
    ) -> M6ReplayLockedCandidateObservation:
        run_id, controlled_sample = self._public_identity(candidate_run_id, sample_id)
        stored = self._load_stored(run_id, controlled_sample)
        if stored.route != M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        stored_scope = self._load_scope(stored)
        scope = stored_scope.scope
        resume = self._load_resume(stored_scope)
        if stored.ledger_sequence >= len(resume.pending_commitments):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        pending = resume.pending_commitments[stored.ledger_sequence]
        if (
            pending.pending_commitment_authority_id != stored.pending_commitment_authority_id
            or pending.sample_id != stored.sample_id
            or pending.execution_entry_id != stored.execution_entry_id
            or pending.source_catalog_entry_id != stored.source_catalog_entry_id
            or pending.route != stored.route
        ):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        catalog = self._load_catalog(stored_scope)
        try:
            expected_pending = build_m6_replay_locked_pending_commitment(
                execution_scope=scope,
                stored_source_catalog=catalog,
                ledger_sequence=pending.ledger_sequence,
                previous_ledger_entry_hash=pending.previous_ledger_entry_hash,
            )
        except M6ReplayLockedExecutionError:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if expected_pending != pending:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if pending.ledger_sequence >= len(catalog.source_catalog.entries):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        source_entry = catalog.source_catalog.entries[pending.ledger_sequence]
        if source_entry.catalog_entry_id != stored.source_catalog_entry_id:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        try:
            source = self._m4_sources.load_m4_gate_terminal_source(
                source_entry.replay_input_closure
            )
        except Exception:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        controlled_source = _controlled_m4_source(source)
        try:
            rebuilt = build_m6_replay_locked_m4_gate_terminal_candidate(
                execution_scope=scope,
                pending_commitment=pending,
                source=controlled_source,
            )
        except M6ReplayLockedM4TerminalError:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if (
            rebuilt.case != stored.case
            or rebuilt.canonical_case_document != stored.canonical_document
            or rebuilt.candidate_snapshot.sample_id != stored.sample_id
        ):
            _fail(_FailureCode.CANDIDATE_CONFLICT)
        try:
            return M6ReplayLockedCandidateObservation(
                case=rebuilt.case,
                canonical_document=rebuilt.canonical_case_document,
                case_revision=1,
                case_audit_sequence=stored.case_audit_sequence,
                case_audit_entry_hash=stored.case_audit_entry_hash,
                candidate_snapshot=rebuilt.candidate_snapshot,
            )
        except (TypeError, ValueError):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)


class M6ReplayLockedRoutedCandidateObservationService:
    """Select the independent observer from the persisted route authority."""

    __slots__ = ("_fast", "_m4", "_stored")

    def __init__(
        self,
        *,
        stored_candidate_provider: M6ReplayLockedStoredCandidateProvider,
        fast_observation_provider: M6ReplayLockedCandidateObservationProvider,
        m4_observation_provider: M6ReplayLockedCandidateObservationProvider,
    ) -> None:
        requirements = (
            (stored_candidate_provider, "load_stored_candidate_case"),
            (fast_observation_provider, "load_candidate_observation"),
            (m4_observation_provider, "load_candidate_observation"),
        )
        if any(
            not callable(getattr(dependency, method, None)) for dependency, method in requirements
        ):
            raise TypeError("invalid M6 locked routed observation dependency")
        self._stored = stored_candidate_provider
        self._fast = fast_observation_provider
        self._m4 = m4_observation_provider

    @staticmethod
    def _public_identity(candidate_run_id: object, sample_id: object) -> tuple[str, str]:
        try:
            if not isinstance(candidate_run_id, str) or not isinstance(sample_id, str):
                raise TypeError
            return (
                require_portable_run_id(
                    candidate_run_id,
                    "M6 locked routed observation run_id",
                ),
                require_reference_token(
                    sample_id,
                    "M6 locked routed observation sample_id",
                ),
            )
        except (TypeError, ValueError):
            _fail(_FailureCode.INVALID_ARGUMENT)

    def _attempt_load(
        self,
        candidate_run_id: object,
        sample_id: object,
    ) -> M6ReplayLockedCandidateObservation:
        run_id, controlled_sample = self._public_identity(candidate_run_id, sample_id)
        try:
            observed_stored = self._stored.load_stored_candidate_case(
                run_id,
                controlled_sample,
            )
        except M6ReplayLockedCandidateError:
            raise
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        stored = _controlled_stored(observed_stored)
        if stored.candidate_run_id != run_id or stored.sample_id != controlled_sample:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if stored.route == M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE:
            provider = self._fast
        elif stored.route == M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
            provider = self._m4
        else:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        try:
            observed = provider.load_candidate_observation(run_id, controlled_sample)
        except M6ReplayLockedCandidateError:
            raise
        except Exception:
            _fail(_FailureCode.STORAGE_REJECTED)
        if type(observed) is not M6ReplayLockedCandidateObservation:
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        try:
            controlled = M6ReplayLockedCandidateObservation(
                case=observed.case,
                canonical_document=observed.canonical_document,
                case_revision=observed.case_revision,
                case_audit_sequence=observed.case_audit_sequence,
                case_audit_entry_hash=observed.case_audit_entry_hash,
                candidate_snapshot=observed.candidate_snapshot,
            )
        except (AttributeError, TypeError, ValueError):
            _fail(_FailureCode.STORED_AUTHORITY_INVALID)
        if (
            controlled.case != stored.case
            or controlled.canonical_document != stored.canonical_document
            or controlled.case_audit_sequence != stored.case_audit_sequence
            or controlled.case_audit_entry_hash != stored.case_audit_entry_hash
            or controlled.candidate_snapshot.sample_id != controlled_sample
        ):
            _fail(_FailureCode.CANDIDATE_CONFLICT)
        return controlled

    def load_candidate_observation(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedCandidateObservation:
        """Dispatch from durable route state; never infer a route from Case bytes."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_load(candidate_run_id, sample_id)
        except M6ReplayLockedCandidateError as error:
            failure = error.reason_code
        except Exception:
            failure = _FailureCode.STORAGE_REJECTED
        del self, candidate_run_id, sample_id
        raise _error(failure) from None


__all__ = [
    "M6ReplayLockedFastCandidateObservationService",
    "M6ReplayLockedM4CandidateObservationService",
    "M6ReplayLockedRoutedCandidateObservationService",
]
