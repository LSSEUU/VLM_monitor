from __future__ import annotations

from dataclasses import dataclass

import pytest

from labcourt.application.m6_replay_locked_m4_executor import (
    M6ReplayLockedM4SampleExecutorService,
)
from labcourt.application.m6_replay_locked_m4_source import (
    M6ReplayLockedM4SourceError,
    M6ReplayLockedM4SourceErrorCode,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedM4CandidateWrite,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
    M6ReplayLockedSampleExecutorError,
    M6ReplayLockedSampleExecutorFailureCode,
)
from tests.unit.test_m6_replay_locked_m4_terminal import _execution


@dataclass(slots=True)
class _Publisher:
    write: M6ReplayLockedM4CandidateWrite | None = None
    calls: int = 0
    typed_failure: M6ReplayLockedCandidateFailureCode | None = None
    raw_failure: bool = False

    def publish_m4_candidate(self, _scope, _pending, candidate):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.typed_failure is not None:
            raise M6ReplayLockedCandidateError(self.typed_failure)
        if self.raw_failure:
            raise RuntimeError("private candidate storage payload")
        self.write = candidate


@dataclass(slots=True)
class _SourceProvider:
    source: object
    calls: int = 0
    typed_failure: bool = False
    raw_failure: bool = False

    def load_m4_gate_terminal_source(
        self,
        _closure: M6ReplayInputClosureAuthority,
    ) -> object:
        self.calls += 1
        if self.typed_failure:
            raise M6ReplayLockedM4SourceError(M6ReplayLockedM4SourceErrorCode.ROUTE_REJECTED)
        if self.raw_failure:
            raise RuntimeError("private source storage payload")
        return self.source


def _executor(
    source: _SourceProvider,
    publisher: _Publisher,
) -> M6ReplayLockedM4SampleExecutorService:
    return M6ReplayLockedM4SampleExecutorService(
        m4_source_provider=source,  # type: ignore[arg-type]
        candidate_publisher=publisher,  # type: ignore[arg-type]
    )


def test_executor_publishes_only_one_atomic_m4_gate_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, terminal_source = _execution(monkeypatch)
    source = _SourceProvider(terminal_source)
    publisher = _Publisher()
    expected = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=terminal_source,
    )

    _executor(source, publisher).execute_sample(
        scope,
        pending,
        terminal_source.closure,
    )

    assert source.calls == publisher.calls == 1
    assert type(publisher.write) is M6ReplayLockedM4CandidateWrite
    assert publisher.write.case == expected.case
    assert publisher.write.canonical_document == expected.canonical_case_document
    assert publisher.write.case.verdicts
    assert publisher.write.case.procedural_reviews
    assert not hasattr(publisher.write, "candidate_snapshot")


def test_executor_rejects_a_source_provider_that_returns_another_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, terminal_source = _execution(monkeypatch)
    source = _SourceProvider(terminal_source)
    publisher = _Publisher()
    foreign = terminal_source.closure.model_copy(update={"sample_id": "foreign-m4-sample"})

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        _executor(source, publisher).execute_sample(scope, pending, foreign)

    assert raised.value.reason_code == (
        M6ReplayLockedSampleExecutorFailureCode.SOURCE_INPUT_REJECTED
    )
    assert source.calls == 1
    assert publisher.calls == 0


def test_executor_rejects_an_unsupported_route_before_loading_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, terminal_source = _execution(monkeypatch)
    wrong_route = pending.model_copy(
        update={"route": M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE}
    )
    source = _SourceProvider(terminal_source)
    publisher = _Publisher()

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        _executor(source, publisher).execute_sample(
            scope,
            wrong_route,
            terminal_source.closure,
        )

    assert raised.value.reason_code == (M6ReplayLockedSampleExecutorFailureCode.UNSUPPORTED_ROUTE)
    assert source.calls == publisher.calls == 0


def test_executor_maps_typed_source_rejection_without_exposing_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, terminal_source = _execution(monkeypatch)
    source = _SourceProvider(terminal_source, typed_failure=True)
    publisher = _Publisher()

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        _executor(source, publisher).execute_sample(
            scope,
            pending,
            terminal_source.closure,
        )

    assert raised.value.reason_code == (
        M6ReplayLockedSampleExecutorFailureCode.SOURCE_INPUT_REJECTED
    )
    assert raised.value.__suppress_context__ is True
    assert publisher.calls == 0


def test_executor_maps_existing_candidate_conflict_without_reloading_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, terminal_source = _execution(monkeypatch)
    source = _SourceProvider(terminal_source)
    publisher = _Publisher(typed_failure=M6ReplayLockedCandidateFailureCode.CANDIDATE_CONFLICT)

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        _executor(source, publisher).execute_sample(
            scope,
            pending,
            terminal_source.closure,
        )

    assert raised.value.reason_code == (
        M6ReplayLockedSampleExecutorFailureCode.CANDIDATE_STATE_CONFLICT
    )
    assert source.calls == publisher.calls == 1


@pytest.mark.parametrize("failure_site", ["source", "publisher"])
def test_executor_converts_storage_exceptions_to_payload_free_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure_site: str,
) -> None:
    scope, pending, terminal_source = _execution(monkeypatch)
    source = _SourceProvider(
        terminal_source,
        raw_failure=failure_site == "source",
    )
    publisher = _Publisher(raw_failure=failure_site == "publisher")

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        _executor(source, publisher).execute_sample(
            scope,
            pending,
            terminal_source.closure,
        )

    assert raised.value.reason_code == (M6ReplayLockedSampleExecutorFailureCode.STORAGE_REJECTED)
    assert "private" not in str(raised.value)
    assert raised.value.__suppress_context__ is True
    assert source.calls == 1
    assert publisher.calls == (failure_site == "publisher")
