from __future__ import annotations

from collections.abc import Sequence

import pytest

from labcourt.application.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorServiceV3,
)
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
from labcourt.ports.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorError,
    M6UpgradeCandidateCoordinatorFailureCode,
)
from labcourt.ports.m6_upgrade_candidate_observation_producer import (
    M6UpgradeCandidateObservationProducerError,
    M6UpgradeCandidateObservationProducerFailureCode,
)
from labcourt.ports.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderError,
    M6UpgradeDurableSampleAppenderFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)
from tests.unit.test_m6_upgrade_durable_sample_appender import (
    _inventory,
    _pending_resume,
    _ready_for_observation,
    _ready_to_seal,
    _sealed,
)

_FailureCode = M6UpgradeCandidateCoordinatorFailureCode


class _Ledger:
    def __init__(
        self,
        log: list[str],
        states: Sequence[M6UpgradeExecutionResumeV3],
        *,
        resume_error: Exception | None = None,
    ) -> None:
        self.log = log
        self.states = tuple(states)
        self.position = 0
        self.resume_error = resume_error

    @property
    def current(self) -> M6UpgradeExecutionResumeV3:
        return self.states[self.position]

    def advance(self) -> None:
        self.position += 1

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        self.log.append("ledger.begin")
        return scope

    def resume(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV3:
        self.log.append("ledger.resume")
        if self.resume_error is not None:
            raise self.resume_error
        current = self.current
        assert candidate_run_id == current.execution_scope.candidate_run_id
        assert execution_scope_authority_id == (
            current.execution_scope.execution_scope_authority_id
        )
        return current

    def seal(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2:
        self.log.append("ledger.seal")
        assert self.current.status == M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL
        return _inventory().execution_ledger


class _Producer:
    def __init__(
        self,
        log: list[str],
        ledger: _Ledger,
        *,
        error: Exception | None = None,
    ) -> None:
        self.log = log
        self.ledger = ledger
        self.error = error

    def produce_next_observation(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        sequence = self.ledger.current.committed_sample_count
        self.log.append(f"producer[{sequence}]")
        if self.error is not None:
            raise self.error
        return _inventory().execution_observations[sequence]


class _Observations:
    def __init__(
        self,
        log: list[str],
        ledger: _Ledger,
        *,
        graft: M6UpgradeSampleExecutionObservationAuthorityV2 | None = None,
    ) -> None:
        self.log = log
        self.ledger = ledger
        self.graft = graft

    def append(
        self,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        self.log.append(f"observation.append[{observation.ledger_sequence}]")
        if self.graft is not None:
            return self.graft
        assert observation == _inventory().execution_observations[observation.ledger_sequence]
        self.ledger.advance()
        return observation


class _Appender:
    def __init__(
        self,
        log: list[str],
        ledger: _Ledger,
        *,
        error: Exception | None = None,
    ) -> None:
        self.log = log
        self.ledger = ledger
        self.error = error

    def append_pending_sample(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2:
        sequence = self.ledger.current.committed_sample_count
        self.log.append(f"appender[{sequence}]")
        if self.error is not None:
            raise self.error
        record = _inventory().execution_ledger.sample_executions[sequence]
        self.ledger.advance()
        return record


class _RunCuts:
    def __init__(
        self,
        log: list[str],
        result: M6UpgradeCandidateRunCutAuthority | Exception | object,
    ) -> None:
        self.log = log
        self.result = result

    def build_or_load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateRunCutAuthority:
        self.log.append("run-cut")
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


class _Output:
    def __init__(
        self,
        log: list[str],
        result: M6UpgradeCandidateOutputInventoryAuthorityV3 | Exception | object,
    ) -> None:
        self.log = log
        self.result = result

    def build_terminal_inventory(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
        self.log.append("inventory")
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


def _states() -> tuple[M6UpgradeExecutionResumeV3, ...]:
    return (
        _ready_for_observation(0),
        _pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT),
        _ready_for_observation(1),
        _pending_resume(1, M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND),
        _ready_for_observation(2),
        _pending_resume(2, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT),
        _ready_to_seal(),
    )


def _coordinator(
    *,
    states: Sequence[M6UpgradeExecutionResumeV3] | None = None,
    producer_error: Exception | None = None,
    appender_error: Exception | None = None,
    observation_graft: M6UpgradeSampleExecutionObservationAuthorityV2 | None = None,
    run_cut: M6UpgradeCandidateRunCutAuthority | Exception | object | None = None,
    output: M6UpgradeCandidateOutputInventoryAuthorityV3 | Exception | object | None = None,
    resume_error: Exception | None = None,
) -> tuple[M6UpgradeCandidateCoordinatorServiceV3, _Ledger, list[str]]:
    log: list[str] = []
    ledger = _Ledger(log, _states() if states is None else states, resume_error=resume_error)
    coordinator = M6UpgradeCandidateCoordinatorServiceV3(
        ledger_repository=ledger,  # type: ignore[arg-type]
        observation_repository=_Observations(
            log,
            ledger,
            graft=observation_graft,
        ),  # type: ignore[arg-type]
        observation_producer=_Producer(
            log,
            ledger,
            error=producer_error,
        ),  # type: ignore[arg-type]
        sample_appender=_Appender(log, ledger, error=appender_error),  # type: ignore[arg-type]
        run_cut_repository=_RunCuts(
            log,
            _inventory().candidate_run_cut if run_cut is None else run_cut,
        ),  # type: ignore[arg-type]
        candidate_output_builder=_Output(
            log,
            _inventory() if output is None else output,
        ),  # type: ignore[arg-type]
    )
    return coordinator, ledger, log


def test_start_drives_every_durable_phase_and_keeps_terminal_order_atomic() -> None:
    coordinator, _ledger, log = _coordinator()

    result = coordinator.run_to_terminal(_inventory().execution_ledger.execution_scope)

    assert result == _inventory()
    assert log == [
        "ledger.begin",
        "ledger.resume",
        "producer[0]",
        "observation.append[0]",
        "ledger.resume",
        "appender[0]",
        "ledger.resume",
        "producer[1]",
        "observation.append[1]",
        "ledger.resume",
        "appender[1]",
        "ledger.resume",
        "producer[2]",
        "observation.append[2]",
        "ledger.resume",
        "appender[2]",
        "ledger.resume",
        "ledger.seal",
        "run-cut",
        "inventory",
    ]
    assert log.index("ledger.seal") < log.index("run-cut") < log.index("inventory")


def test_resume_from_sealed_state_runs_cut_before_terminal_inventory() -> None:
    coordinator, _ledger, log = _coordinator(states=(_sealed(),))
    scope = _inventory().execution_ledger.execution_scope

    result = coordinator.resume_to_terminal(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert result == _inventory()
    assert log == ["ledger.resume", "run-cut", "inventory"]


def test_observation_repository_cannot_graft_a_different_authority() -> None:
    coordinator, _ledger, log = _coordinator(
        observation_graft=_inventory().execution_observations[1]
    )
    scope = _inventory().execution_ledger.execution_scope

    with pytest.raises(M6UpgradeCandidateCoordinatorError) as rejected:
        coordinator.resume_to_terminal(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == _FailureCode.OBSERVATION_REJECTED
    assert log == ["ledger.resume", "producer[0]", "observation.append[0]"]


def test_terminal_run_cut_and_inventory_are_exactly_joined() -> None:
    coordinator, _ledger, log = _coordinator(states=(_sealed(),), run_cut=object())
    scope = _inventory().execution_ledger.execution_scope

    with pytest.raises(M6UpgradeCandidateCoordinatorError) as rejected:
        coordinator.resume_to_terminal(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == _FailureCode.RUN_CUT_REJECTED
    assert log == ["ledger.resume", "run-cut"]


def test_benign_race_without_actual_progress_is_bounded_and_fails_closed() -> None:
    stalled = _ready_for_observation(0)
    coordinator, _ledger, log = _coordinator(
        states=(stalled,),
        producer_error=M6UpgradeCandidateObservationProducerError(
            M6UpgradeCandidateObservationProducerFailureCode.OBSERVATION_ALREADY_EXISTS
        ),
    )

    with pytest.raises(M6UpgradeCandidateCoordinatorError) as rejected:
        coordinator.resume_to_terminal(
            stalled.execution_scope.candidate_run_id,
            stalled.execution_scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == _FailureCode.COORDINATION_STALLED
    assert log.count("ledger.resume") == 10
    assert log.count("producer[0]") == 10


@pytest.mark.parametrize(
    ("resume_error", "appender_error", "expected"),
    (
        (
            M6UpgradeExecutionLedgerV3Error(M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND),
            None,
            _FailureCode.SCOPE_NOT_FOUND,
        ),
        (
            None,
            M6UpgradeDurableSampleAppenderError(
                M6UpgradeDurableSampleAppenderFailureCode.PHYSICAL_ARTIFACT_REJECTED
            ),
            _FailureCode.SAMPLE_REJECTED,
        ),
    ),
)
def test_lower_failures_are_mapped_to_fresh_payload_free_coordinator_errors(
    resume_error: Exception | None,
    appender_error: Exception | None,
    expected: _FailureCode,
) -> None:
    states = (_pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT),)
    coordinator, _ledger, _log = _coordinator(
        states=states,
        resume_error=resume_error,
        appender_error=appender_error,
    )
    scope = states[0].execution_scope

    with pytest.raises(M6UpgradeCandidateCoordinatorError) as rejected:
        coordinator.resume_to_terminal(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )

    assert rejected.value.reason_code == expected
    assert rejected.value.__context__ is None
    assert rejected.value.__cause__ is None
    assert vars(rejected.value) == {"reason_code": expected}
