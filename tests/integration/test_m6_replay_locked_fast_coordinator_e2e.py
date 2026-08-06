from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.adapters.storage.m6_replay_locked_execution_scope_store import (
    M6ReplayLockedExecutionScopePublisher,
    ReadonlyM6ReplayLockedExecutionScopeStore,
)
from labcourt.adapters.storage.m6_replay_locked_ledger import (
    FilesystemM6ReplayLockedLedgerRepository,
)
from labcourt.adapters.storage.sqlite_m6_replay_locked_candidate import (
    SQLiteM6ReplayLockedCandidateRepository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_replay_locked_candidate_observation import (
    M6ReplayLockedFastCandidateObservationService,
)
from labcourt.application.m6_replay_locked_execution_coordinator import (
    M6ReplayLockedExecutionCoordinatorService,
)
from labcourt.application.m6_replay_locked_fast_executor import (
    M6ReplayLockedFastSampleExecutorService,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_replay_locked_coordinator import (
    M6ReplayLockedCoordinatorError,
    M6ReplayLockedCoordinatorFailureCode,
)
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)
from labcourt.ports.m6_replay_locked_ledger import M6ReplayLockedLedgerStatus
from labcourt.ports.m6_replay_locked_source import M6ReplayLockedSourceProjection
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
)
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime as _inputs


@dataclass(slots=True)
class _SourceFacade:
    source: M6ReplayLockedFastTerminalSource
    fast_reads: int = 0
    projection_reads: int = 0

    def load_fast_terminal_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedFastTerminalSource:
        self.fast_reads += 1
        assert closure == self.source.closure
        return M6ReplayLockedFastTerminalSource(
            source_identity_sha256=self.source.source_identity_sha256,
            closure=self.source.closure,
            projection_context=self.source.projection_context,
            source_snapshot=self.source.source_snapshot,
        )

    def load_source_projection(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedSourceProjection:
        self.projection_reads += 1
        assert closure == self.source.closure
        return M6ReplayLockedSourceProjection(
            source_identity_sha256=self.source.source_identity_sha256,
            closure=self.source.closure,
            source_snapshot=self.source.source_snapshot,
        )


@dataclass(slots=True)
class _FailAfterCandidateCommit:
    inner: M6ReplayLockedFastSampleExecutorService
    calls: int = 0
    fail_once: bool = True

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None:
        self.calls += 1
        self.inner.execute_sample(
            execution_scope,
            pending_commitment,
            replay_input_closure,
        )
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("private crash after candidate commit")


@dataclass(frozen=True, slots=True)
class _Runtime:
    database: Path
    scope: M6ReplayLockedExecutionScopeAuthority
    ledger: FilesystemM6ReplayLockedLedgerRepository
    candidates: SQLiteM6ReplayLockedCandidateRepository
    sources: _SourceFacade
    coordinator: M6ReplayLockedExecutionCoordinatorService
    executor: object
    stored_catalog: object


def _runtime(tmp_path: Path, *, crash_after_candidate: bool = False) -> _Runtime:
    inputs = _inputs()
    authority_root = tmp_path / "authorities"
    authority_root.mkdir()
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        inputs.scope.candidate_run_id,
        inputs.scope.locked_manifest,
    )
    M6ReplayLockedExecutionScopePublisher(authority_root).publish(
        inputs.scope,
        canonical_json(inputs.scope.model_dump(mode="json")),
    )
    stored_catalog = M6RegressionExecutionSourceCatalogPublisher(authority_root).publish(
        inputs.catalog.source_catalog,
        inputs.catalog.canonical_document,
    )
    scope_provider = ReadonlyM6ReplayLockedExecutionScopeStore(authority_root)
    catalog_provider = ReadonlyM6RegressionExecutionSourceCatalogStore(authority_root)
    ledger = FilesystemM6ReplayLockedLedgerRepository(
        authority_root,
        scope_provider=scope_provider,
    )
    candidates = SQLiteM6ReplayLockedCandidateRepository(database, BUSY_TIMEOUT_MS)
    sources = _SourceFacade(inputs.source)
    real_executor = M6ReplayLockedFastSampleExecutorService(
        fast_source_provider=sources,
        candidate_publisher=candidates,
    )
    executor: object = (
        _FailAfterCandidateCommit(real_executor) if crash_after_candidate else real_executor
    )
    observations = M6ReplayLockedFastCandidateObservationService(
        stored_candidate_provider=candidates,
        execution_scope_provider=scope_provider,
        ledger_repository=ledger,
        source_catalog_provider=catalog_provider,
        fast_source_provider=sources,
    )
    coordinator = M6ReplayLockedExecutionCoordinatorService(
        ledger_repository=ledger,
        source_projection_provider=sources,
        sample_executor=executor,  # type: ignore[arg-type]
        candidate_observation_provider=observations,
        candidate_audit_head_provider=candidates,
    )
    return _Runtime(
        database=database,
        scope=inputs.scope,
        ledger=ledger,
        candidates=candidates,
        sources=sources,
        coordinator=coordinator,
        executor=executor,
        stored_catalog=stored_catalog,
    )


def _sqlite_counts(database: Path) -> tuple[int, int, int, int]:
    with sqlite3.connect(database) as connection:
        candidate_count = int(
            connection.execute("SELECT COUNT(*) FROM m6_replay_locked_candidate_cases").fetchone()[
                0
            ]
        )
        audit_count = int(connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0])
        revision, sequence = connection.execute(
            "SELECT revision, audit_head_sequence FROM runs"
        ).fetchone()
    return candidate_count, audit_count, int(revision), int(sequence)


def test_full_offline_fast_route_reaches_seal_and_exact_retry_is_read_only(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)
    counts = _sqlite_counts(runtime.database)
    read_counts = (runtime.sources.fast_reads, runtime.sources.projection_reads)
    exact_retry = runtime.coordinator.run_to_terminal(
        runtime.scope,
        runtime.stored_catalog,
    )

    assert exact_retry == seal
    assert runtime.ledger.resume(runtime.scope).status == M6ReplayLockedLedgerStatus.SEALED
    assert counts == _sqlite_counts(runtime.database) == (1, 1, 1, 0)
    assert read_counts == (2, 2)
    assert (runtime.sources.fast_reads, runtime.sources.projection_reads) == read_counts
    assert seal.sample_execution_count == 1
    assert seal.run_trap_seal.clean
    assert seal.run_trap_seal.counters.total == 0
    assert seal.sample_executions[0].candidate_snapshot.semantic_case_hash == (
        seal.sample_executions[0].source_determinism.first_semantic_case_hash
    )


def test_restart_after_candidate_commit_rebuilds_observation_without_reexecution(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, crash_after_candidate=True)
    assert isinstance(runtime.executor, _FailAfterCandidateCommit)

    with pytest.raises(M6ReplayLockedCoordinatorError) as raised:
        runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert raised.value.reason_code == M6ReplayLockedCoordinatorFailureCode.STORAGE_REJECTED
    assert raised.value.__suppress_context__ is True
    assert runtime.ledger.resume(runtime.scope).status == M6ReplayLockedLedgerStatus.PENDING
    assert _sqlite_counts(runtime.database) == (1, 1, 1, 0)
    assert runtime.executor.calls == 1
    assert (runtime.sources.fast_reads, runtime.sources.projection_reads) == (1, 0)

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert seal.sample_execution_count == 1
    assert runtime.ledger.resume(runtime.scope).status == M6ReplayLockedLedgerStatus.SEALED
    assert runtime.executor.calls == 1
    assert (runtime.sources.fast_reads, runtime.sources.projection_reads) == (2, 2)
    assert _sqlite_counts(runtime.database) == (1, 1, 1, 0)
