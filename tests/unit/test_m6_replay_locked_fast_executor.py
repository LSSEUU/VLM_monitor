from __future__ import annotations

from dataclasses import dataclass

import pytest

from labcourt.application.m6_replay_locked_fast_executor import (
    M6ReplayLockedFastSampleExecutorService,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidateWrite,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
    M6ReplayLockedSampleExecutorError,
    M6ReplayLockedSampleExecutorFailureCode,
)
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime


@dataclass(slots=True)
class _Publisher:
    write: M6ReplayLockedCandidateWrite | None = None
    calls: int = 0
    failure: M6ReplayLockedCandidateFailureCode | None = None

    def publish_candidate(self, _scope, _pending, candidate):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.failure is not None:
            raise M6ReplayLockedCandidateError(self.failure)
        self.write = candidate


@dataclass(slots=True)
class _SourceProvider:
    source: object
    calls: int = 0
    fail: bool = False

    def load_fast_terminal_source(
        self,
        _closure: M6ReplayInputClosureAuthority,
    ) -> object:
        self.calls += 1
        if self.fail:
            raise RuntimeError("private source storage payload")
        return self.source


def test_executor_builds_and_publishes_only_canonical_candidate_bytes() -> None:
    runtime = _runtime()
    source = _SourceProvider(runtime.source)
    publisher = _Publisher()
    executor = M6ReplayLockedFastSampleExecutorService(
        fast_source_provider=source,  # type: ignore[arg-type]
        candidate_publisher=publisher,  # type: ignore[arg-type]
    )
    closure = runtime.catalog.source_catalog.entries[0].replay_input_closure

    executor.execute_sample(runtime.scope, runtime.pending, closure)

    assert source.calls == publisher.calls == 1
    assert publisher.write is not None
    assert publisher.write.case == runtime.stored.case
    assert publisher.write.canonical_document == runtime.stored.canonical_document
    assert not hasattr(publisher.write, "candidate_snapshot")


def test_executor_rejects_a_source_provider_that_returns_another_closure() -> None:
    runtime = _runtime()
    source = _SourceProvider(runtime.source)
    publisher = _Publisher()
    executor = M6ReplayLockedFastSampleExecutorService(
        fast_source_provider=source,  # type: ignore[arg-type]
        candidate_publisher=publisher,  # type: ignore[arg-type]
    )
    foreign = runtime.source.closure.model_copy(update={"sample_id": "foreign-sample"})

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        executor.execute_sample(runtime.scope, runtime.pending, foreign)

    assert raised.value.reason_code == (
        M6ReplayLockedSampleExecutorFailureCode.SOURCE_INPUT_REJECTED
    )
    assert publisher.calls == 0


def test_executor_maps_existing_candidate_conflict_without_retrying_source() -> None:
    runtime = _runtime()
    source = _SourceProvider(runtime.source)
    publisher = _Publisher(failure=M6ReplayLockedCandidateFailureCode.CANDIDATE_CONFLICT)
    executor = M6ReplayLockedFastSampleExecutorService(
        fast_source_provider=source,  # type: ignore[arg-type]
        candidate_publisher=publisher,  # type: ignore[arg-type]
    )

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        executor.execute_sample(
            runtime.scope,
            runtime.pending,
            runtime.source.closure,
        )

    assert raised.value.reason_code == (
        M6ReplayLockedSampleExecutorFailureCode.CANDIDATE_STATE_CONFLICT
    )
    assert source.calls == publisher.calls == 1


def test_executor_converts_source_storage_exception_to_payload_free_failure() -> None:
    runtime = _runtime()
    source = _SourceProvider(runtime.source, fail=True)
    publisher = _Publisher()
    executor = M6ReplayLockedFastSampleExecutorService(
        fast_source_provider=source,  # type: ignore[arg-type]
        candidate_publisher=publisher,  # type: ignore[arg-type]
    )

    with pytest.raises(M6ReplayLockedSampleExecutorError) as raised:
        executor.execute_sample(
            runtime.scope,
            runtime.pending,
            runtime.source.closure,
        )

    assert raised.value.reason_code == M6ReplayLockedSampleExecutorFailureCode.STORAGE_REJECTED
    assert "private source storage payload" not in str(raised.value)
    assert raised.value.__suppress_context__ is True
    assert publisher.calls == 0
