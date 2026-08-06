"""Durable state-machine coordinator for protocol-V3 candidate execution."""

from __future__ import annotations

from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.references import require_reference_token
from labcourt.ports.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorError,
    M6UpgradeCandidateCoordinatorFailureCode,
)
from labcourt.ports.m6_upgrade_candidate_observation_producer import (
    M6UpgradeCandidateObservationProducerError,
    M6UpgradeCandidateObservationProducerFailureCode,
    M6UpgradeCandidateObservationProducerV3,
)
from labcourt.ports.m6_upgrade_candidate_output import (
    M6UpgradeCandidateOutputBuilder,
    M6UpgradeCandidateOutputError,
    M6UpgradeCandidateOutputFailureCode,
)
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
    M6UpgradeCandidateRunCutRepository,
)
from labcourt.ports.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderError,
    M6UpgradeDurableSampleAppenderFailureCode,
    M6UpgradeDurableSampleAppenderV3,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Repository,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
    M6UpgradeExecutionObservationV3Repository,
)

_FailureCode = M6UpgradeCandidateCoordinatorFailureCode
_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(code: _FailureCode) -> M6UpgradeCandidateCoordinatorError:
    return M6UpgradeCandidateCoordinatorError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _public_identity(candidate_run_id: object, scope_id: object) -> tuple[str, str]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 candidate coordinator run_id")
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if (
        not isinstance(scope_id, str)
        or len(scope_id) != 64
        or any(character not in "0123456789abcdef" for character in scope_id)
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    return run_id, scope_id


def _canonical_model(value: object, expected: type[_ModelT], failure: _FailureCode) -> _ModelT:
    if type(value) is not expected:
        _fail(failure)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(failure)
    if controlled != value:
        _fail(failure)
    return controlled


def _ledger_failure(code: M6UpgradeExecutionLedgerV3FailureCode) -> _FailureCode:
    direct = {
        M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_CONFLICT: _FailureCode.SCOPE_CONFLICT,
        M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
        M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED: (
            _FailureCode.SAMPLE_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.EXECUTION_STATE_INVALID)


def _producer_failure(code: M6UpgradeCandidateObservationProducerFailureCode) -> _FailureCode:
    direct = {
        M6UpgradeCandidateObservationProducerFailureCode.INVALID_ARGUMENT: (
            _FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeCandidateObservationProducerFailureCode.SCOPE_NOT_FOUND: (
            _FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeCandidateObservationProducerFailureCode.APPEND_STATE_MISMATCH: (
            _FailureCode.EXECUTION_STATE_INVALID
        ),
        M6UpgradeCandidateObservationProducerFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeCandidateObservationProducerFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeCandidateObservationProducerFailureCode.STORAGE_REJECTED: (
            _FailureCode.STORAGE_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.OBSERVATION_REJECTED)


def _observation_failure(code: M6UpgradeExecutionObservationFailureCode) -> _FailureCode:
    direct = {
        M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeExecutionObservationFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.OBSERVATION_REJECTED)


def _appender_failure(code: M6UpgradeDurableSampleAppenderFailureCode) -> _FailureCode:
    direct = {
        M6UpgradeDurableSampleAppenderFailureCode.INVALID_ARGUMENT: (_FailureCode.INVALID_ARGUMENT),
        M6UpgradeDurableSampleAppenderFailureCode.SCOPE_NOT_FOUND: (_FailureCode.SCOPE_NOT_FOUND),
        M6UpgradeDurableSampleAppenderFailureCode.APPEND_STATE_MISMATCH: (
            _FailureCode.EXECUTION_STATE_INVALID
        ),
        M6UpgradeDurableSampleAppenderFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeDurableSampleAppenderFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeDurableSampleAppenderFailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.SAMPLE_REJECTED)


def _run_cut_failure(code: M6UpgradeCandidateRunCutFailureCode) -> _FailureCode:
    direct = {
        M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeCandidateRunCutFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeCandidateRunCutFailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeCandidateRunCutFailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.RUN_CUT_REJECTED)


def _output_failure(code: M6UpgradeCandidateOutputFailureCode) -> _FailureCode:
    direct = {
        M6UpgradeCandidateOutputFailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeCandidateOutputFailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeCandidateOutputFailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6UpgradeCandidateOutputFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeCandidateOutputFailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.TERMINAL_OUTPUT_REJECTED)


class M6UpgradeCandidateCoordinatorServiceV3:
    """Advance durable state and enforce Seal -> Run Cut -> Inventory order."""

    __slots__ = (
        "_appender",
        "_ledger",
        "_observations",
        "_output_builder",
        "_producer",
        "_run_cuts",
    )

    def __init__(
        self,
        *,
        ledger_repository: M6UpgradeExecutionLedgerV3Repository,
        observation_repository: M6UpgradeExecutionObservationV3Repository,
        observation_producer: M6UpgradeCandidateObservationProducerV3,
        sample_appender: M6UpgradeDurableSampleAppenderV3,
        run_cut_repository: M6UpgradeCandidateRunCutRepository,
        candidate_output_builder: M6UpgradeCandidateOutputBuilder,
    ) -> None:
        requirements = (
            (ledger_repository, "begin_execution"),
            (ledger_repository, "resume"),
            (ledger_repository, "seal"),
            (observation_repository, "append"),
            (observation_producer, "produce_next_observation"),
            (sample_appender, "append_pending_sample"),
            (run_cut_repository, "build_or_load"),
            (candidate_output_builder, "build_terminal_inventory"),
        )
        if any(
            not callable(getattr(dependency, method, None)) for dependency, method in requirements
        ):
            raise TypeError("invalid M6 candidate coordinator dependency")
        self._ledger = ledger_repository
        self._observations = observation_repository
        self._producer = observation_producer
        self._appender = sample_appender
        self._run_cuts = run_cut_repository
        self._output_builder = candidate_output_builder

    def _produce_and_persist(self, run_id: str, scope_id: str) -> None:
        try:
            produced = self._producer.produce_next_observation(run_id, scope_id)
        except M6UpgradeCandidateObservationProducerError as error:
            if error.reason_code in {
                M6UpgradeCandidateObservationProducerFailureCode.OBSERVATION_ALREADY_EXISTS,
                M6UpgradeCandidateObservationProducerFailureCode.LEDGER_COMPLETE,
                M6UpgradeCandidateObservationProducerFailureCode.LEDGER_SEALED,
            }:
                return
            raise
        observation = _canonical_model(
            produced,
            M6UpgradeSampleExecutionObservationAuthorityV2,
            _FailureCode.OBSERVATION_REJECTED,
        )
        try:
            persisted = self._observations.append(observation)
        except M6UpgradeExecutionObservationError as error:
            if error.reason_code == M6UpgradeExecutionObservationFailureCode.LEDGER_SEALED:
                return
            raise
        persisted = _canonical_model(
            persisted,
            M6UpgradeSampleExecutionObservationAuthorityV2,
            _FailureCode.OBSERVATION_REJECTED,
        )
        if persisted != observation:
            _fail(_FailureCode.OBSERVATION_REJECTED)

    def _append_pending_sample(self, run_id: str, scope_id: str) -> None:
        try:
            appended = self._appender.append_pending_sample(run_id, scope_id)
        except M6UpgradeDurableSampleAppenderError as error:
            if error.reason_code in {
                M6UpgradeDurableSampleAppenderFailureCode.OBSERVATION_NOT_FOUND,
                M6UpgradeDurableSampleAppenderFailureCode.LEDGER_COMPLETE,
                M6UpgradeDurableSampleAppenderFailureCode.LEDGER_SEALED,
            }:
                return
            raise
        _canonical_model(
            appended,
            M6UpgradeSampleExecutionRecordV2,
            _FailureCode.SAMPLE_REJECTED,
        )

    def _terminal_inventory(
        self,
        run_id: str,
        scope_id: str,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        run_cut = _canonical_model(
            self._run_cuts.build_or_load(run_id, scope_id),
            M6UpgradeCandidateRunCutAuthority,
            _FailureCode.RUN_CUT_REJECTED,
        )
        if run_cut.candidate_run_id != run_id:
            _fail(_FailureCode.RUN_CUT_REJECTED)
        inventory = _canonical_model(
            self._output_builder.build_terminal_inventory(run_id, scope_id),
            M6UpgradeCandidateOutputInventoryAuthorityV3,
            _FailureCode.TERMINAL_OUTPUT_REJECTED,
        )
        if (
            inventory.execution_ledger.execution_scope != scope
            or inventory.candidate_run_cut != run_cut
        ):
            _fail(_FailureCode.TERMINAL_OUTPUT_REJECTED)
        return inventory

    def _coordinate(
        self, run_id: str, scope_id: str
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        maximum_steps: int | None = None
        step = 0
        while maximum_steps is None or step < maximum_steps:
            resume = self._ledger.resume(run_id, scope_id)
            if type(resume) is not M6UpgradeExecutionResumeV3:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            scope = resume.execution_scope
            if scope.candidate_run_id != run_id or scope.execution_scope_authority_id != scope_id:
                _fail(_FailureCode.STORED_AUTHORITY_INVALID)
            if maximum_steps is None:
                maximum_steps = 2 * len(scope.execution_dataset.entries) + 4
            step += 1
            if resume.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION:
                self._produce_and_persist(run_id, scope_id)
                continue
            if resume.status in {
                M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT,
                M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND,
            }:
                self._append_pending_sample(run_id, scope_id)
                continue
            if resume.status == M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL:
                try:
                    sealed = self._ledger.seal(run_id, scope_id)
                except M6UpgradeExecutionLedgerV3Error as error:
                    if error.reason_code == M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED:
                        continue
                    raise
                seal = _canonical_model(
                    sealed,
                    M6UpgradeExecutionLedgerSealV2,
                    _FailureCode.SEAL_REJECTED,
                )
                if seal.execution_scope != scope:
                    _fail(_FailureCode.SEAL_REJECTED)
                return self._terminal_inventory(run_id, scope_id, scope)
            if resume.status == M6UpgradeExecutionLedgerV3Status.SEALED:
                return self._terminal_inventory(run_id, scope_id, scope)
            _fail(_FailureCode.EXECUTION_STATE_INVALID)
        _fail(_FailureCode.COORDINATION_STALLED)

    def _attempt_run_to_terminal(
        self,
        execution_scope: object,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        try:
            scope = _canonical_model(
                execution_scope,
                M6UpgradeExecutionScopeAuthority,
                _FailureCode.INVALID_ARGUMENT,
            )
            persisted = _canonical_model(
                self._ledger.begin_execution(scope),
                M6UpgradeExecutionScopeAuthority,
                _FailureCode.SCOPE_CONFLICT,
            )
            if persisted != scope:
                _fail(_FailureCode.SCOPE_CONFLICT)
            return self._coordinate(
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
        except M6UpgradeCandidateCoordinatorError:
            raise
        except M6UpgradeExecutionLedgerV3Error as error:
            _fail(_ledger_failure(error.reason_code))
        except M6UpgradeCandidateObservationProducerError as error:
            _fail(_producer_failure(error.reason_code))
        except M6UpgradeExecutionObservationError as error:
            _fail(_observation_failure(error.reason_code))
        except M6UpgradeDurableSampleAppenderError as error:
            _fail(_appender_failure(error.reason_code))
        except M6UpgradeCandidateRunCutError as error:
            _fail(_run_cut_failure(error.reason_code))
        except M6UpgradeCandidateOutputError as error:
            _fail(_output_failure(error.reason_code))

    def _attempt_resume_to_terminal(
        self,
        candidate_run_id: object,
        execution_scope_authority_id: object,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        run_id, scope_id = _public_identity(candidate_run_id, execution_scope_authority_id)
        try:
            return self._coordinate(run_id, scope_id)
        except M6UpgradeCandidateCoordinatorError:
            raise
        except M6UpgradeExecutionLedgerV3Error as error:
            _fail(_ledger_failure(error.reason_code))
        except M6UpgradeCandidateObservationProducerError as error:
            _fail(_producer_failure(error.reason_code))
        except M6UpgradeExecutionObservationError as error:
            _fail(_observation_failure(error.reason_code))
        except M6UpgradeDurableSampleAppenderError as error:
            _fail(_appender_failure(error.reason_code))
        except M6UpgradeCandidateRunCutError as error:
            _fail(_run_cut_failure(error.reason_code))
        except M6UpgradeCandidateOutputError as error:
            _fail(_output_failure(error.reason_code))

    def run_to_terminal(
        self,
        execution_scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        """Start idempotently and drive one execution through terminal output."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_run_to_terminal(execution_scope)
        except M6UpgradeCandidateCoordinatorError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, execution_scope
        raise _error(failure) from None

    def resume_to_terminal(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        """Resume only from the two immutable durable identities."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_resume_to_terminal(
                candidate_run_id,
                execution_scope_authority_id,
            )
        except M6UpgradeCandidateCoordinatorError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id
        raise _error(failure) from None


__all__ = ["M6UpgradeCandidateCoordinatorServiceV3"]
