from __future__ import annotations

import hashlib
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
    M6ReplayLockedM4CandidateObservationService,
    M6ReplayLockedRoutedCandidateObservationService,
)
from labcourt.application.m6_replay_locked_execution_coordinator import (
    M6ReplayLockedExecutionCoordinatorService,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.application.m6_replay_locked_m4_executor import (
    M6ReplayLockedM4SampleExecutorService,
)
from labcourt.application.m6_replay_locked_routed_executor import (
    M6ReplayLockedRoutedSampleExecutorService,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionExecutionSourceCatalogEntry,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
)
from labcourt.ports.m6_replay_locked_coordinator import (
    M6ReplayLockedCoordinatorError,
    M6ReplayLockedCoordinatorFailureCode,
)
from labcourt.ports.m6_replay_locked_ledger import M6ReplayLockedLedgerStatus
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
    M6ReplayLockedSampleExecutorError,
    M6ReplayLockedSampleExecutorFailureCode,
)
from labcourt.ports.m6_replay_locked_source import M6ReplayLockedSourceProjection
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
)
from tests.unit.test_m6_replay_locked_m4_terminal import _execution


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(value: object) -> tuple[str, str, int]:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    payload = document.encode("utf-8")
    return document, hashlib.sha256(payload).hexdigest(), len(payload)


def _execution_authorities(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    M6ReplayLockedExecutionScopeAuthority,
    M6StoredRegressionExecutionSourceCatalog,
    M6ReplayLockedM4GateTerminalSource,
]:
    template_scope, _template_pending, base_source = _execution(monkeypatch)
    sample_id = _sha("M4-coordinator-sample")
    closure = base_source.closure.model_copy(update={"sample_id": sample_id})
    source = M6ReplayLockedM4GateTerminalSource(
        source_identity_sha256=base_source.source_identity_sha256,
        closure=closure,
        projection_context=base_source.projection_context,
        hearing_record=base_source.hearing_record,
        hearing_verdict_binding=base_source.hearing_verdict_binding,
        gate_current_closure_receipt=base_source.gate_current_closure_receipt,
        source_snapshot=base_source.source_snapshot.model_copy(update={"sample_id": sample_id}),
    )
    closure_document, closure_sha256, closure_size = _identity(closure)
    del closure_document
    catalog_entry = M6RegressionExecutionSourceCatalogEntry(
        source_item_id=_sha("M4-coordinator-source-item"),
        sample_id=closure.sample_id,
        source_seal_id=_sha("M4-coordinator-source-seal"),
        source_seal_content_sha256=_sha("M4-coordinator-source-seal-document"),
        source_seal_size_bytes=1,
        input_authority_id=closure.input_authority_id,
        input_authority_document_sha256=closure.input_authority_document_sha256,
        input_authority_content_sha256=_sha("M4-coordinator-input-content"),
        input_authority_size_bytes=1,
        replay_input_closure_content_sha256=closure_sha256,
        replay_input_closure_size_bytes=closure_size,
        replay_input_closure=closure,
    )
    source_root = sha256_hex(["m6-regression-source-inventory", 1, [catalog_entry.source_item_id]])
    catalog_authority = M6RegressionExecutionSourceCatalogAuthority(
        baseline_manifest_id=template_scope.locked_manifest.manifest_id,
        source_inventory_cut_authority_id=_sha("M4-coordinator-source-cut"),
        source_inventory_cut_content_sha256=_sha("M4-coordinator-source-cut-document"),
        source_inventory_item_count=1,
        source_inventory_root_sha256=source_root,
        entries=(catalog_entry,),
    )
    catalog_document, catalog_sha256, catalog_size = _identity(catalog_authority)
    catalog = M6StoredRegressionExecutionSourceCatalog(
        source_catalog=catalog_authority,
        canonical_document=catalog_document,
        content_sha256=catalog_sha256,
        size_bytes=catalog_size,
    )
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=template_scope.locked_manifest.manifest_id,
        source_catalog_authority_id=catalog_authority.source_catalog_authority_id,
        source_catalog_document_sha256=catalog_sha256,
        entries=(
            M6RegressionExecutionEntry(
                sample_id=closure.sample_id,
                input_authority_id=closure.input_authority_id,
                input_authority_document_sha256=(closure.input_authority_document_sha256),
                replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
                replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
            ),
        ),
    )
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=template_scope.locked_manifest.manifest_id,
        candidate_manifest_id=template_scope.locked_manifest.manifest_id,
        policy_authority=template_scope.command.policy_authority,
    )
    scope = build_m6_replay_locked_execution_scope(
        candidate_run_id=template_scope.candidate_run_id,
        command=command,
        execution_dataset=dataset,
        stored_source_catalog=catalog,
        locked_manifest=template_scope.locked_manifest,
        locked_config=template_scope.locked_config,
        execution_component=template_scope.execution_component,
    )
    return scope, catalog, source


@dataclass(slots=True)
class _SourceFacade:
    source: M6ReplayLockedM4GateTerminalSource
    m4_reads: int = 0
    projection_reads: int = 0

    def load_m4_gate_terminal_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedM4GateTerminalSource:
        self.m4_reads += 1
        assert closure == self.source.closure
        return M6ReplayLockedM4GateTerminalSource(
            source_identity_sha256=self.source.source_identity_sha256,
            closure=self.source.closure,
            projection_context=self.source.projection_context,
            hearing_record=self.source.hearing_record,
            hearing_verdict_binding=self.source.hearing_verdict_binding,
            gate_current_closure_receipt=self.source.gate_current_closure_receipt,
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


class _NeverFastExecutor:
    def execute_sample(self, _scope, _pending, _closure):  # type: ignore[no-untyped-def]
        raise M6ReplayLockedSampleExecutorError(
            M6ReplayLockedSampleExecutorFailureCode.UNSUPPORTED_ROUTE
        )


class _NeverFastObservation:
    def load_candidate_observation(self, _run_id, _sample_id):  # type: ignore[no-untyped-def]
        raise M6ReplayLockedCandidateError(
            M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID
        )


@dataclass(slots=True)
class _FailAfterCandidateCommit:
    inner: M6ReplayLockedRoutedSampleExecutorService
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
            raise RuntimeError("private crash after M4 candidate commit")


@dataclass(frozen=True, slots=True)
class _Runtime:
    database: Path
    scope: M6ReplayLockedExecutionScopeAuthority
    ledger: FilesystemM6ReplayLockedLedgerRepository
    sources: _SourceFacade
    coordinator: M6ReplayLockedExecutionCoordinatorService
    executor: object
    stored_catalog: M6StoredRegressionExecutionSourceCatalog


def _runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    crash_after_candidate: bool = False,
) -> _Runtime:
    scope, catalog, source = _execution_authorities(monkeypatch)
    authority_root = tmp_path / "authorities"
    authority_root.mkdir()
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.locked_manifest,
    )
    M6ReplayLockedExecutionScopePublisher(authority_root).publish(
        scope,
        canonical_json(scope.model_dump(mode="json")),
    )
    stored_catalog = M6RegressionExecutionSourceCatalogPublisher(authority_root).publish(
        catalog.source_catalog,
        catalog.canonical_document,
    )
    scope_provider = ReadonlyM6ReplayLockedExecutionScopeStore(authority_root)
    catalog_provider = ReadonlyM6RegressionExecutionSourceCatalogStore(authority_root)
    ledger = FilesystemM6ReplayLockedLedgerRepository(
        authority_root,
        scope_provider=scope_provider,
    )
    candidates = SQLiteM6ReplayLockedCandidateRepository(database, BUSY_TIMEOUT_MS)
    sources = _SourceFacade(source)
    m4_executor = M6ReplayLockedM4SampleExecutorService(
        m4_source_provider=sources,
        candidate_publisher=candidates,
    )
    routed_executor = M6ReplayLockedRoutedSampleExecutorService(
        fast_executor=_NeverFastExecutor(),
        m4_executor=m4_executor,
    )
    executor: object = (
        _FailAfterCandidateCommit(routed_executor) if crash_after_candidate else routed_executor
    )
    m4_observations = M6ReplayLockedM4CandidateObservationService(
        stored_candidate_provider=candidates,
        execution_scope_provider=scope_provider,
        ledger_repository=ledger,
        source_catalog_provider=catalog_provider,
        m4_source_provider=sources,
    )
    observations = M6ReplayLockedRoutedCandidateObservationService(
        stored_candidate_provider=candidates,
        fast_observation_provider=_NeverFastObservation(),
        m4_observation_provider=m4_observations,
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
        scope=scope,
        ledger=ledger,
        sources=sources,
        coordinator=coordinator,
        executor=executor,
        stored_catalog=stored_catalog,
    )


def _sqlite_counts(database: Path) -> tuple[int, int, int, int, int]:
    with sqlite3.connect(database) as connection:
        fast = int(
            connection.execute("SELECT COUNT(*) FROM m6_replay_locked_candidate_cases").fetchone()[
                0
            ]
        )
        m4 = int(
            connection.execute(
                "SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases"
            ).fetchone()[0]
        )
        audits = int(connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0])
        revision, sequence = connection.execute(
            "SELECT revision, audit_head_sequence FROM runs"
        ).fetchone()
    return fast, m4, audits, int(revision), int(sequence)


def test_full_offline_m4_route_reaches_seal_and_exact_retry_is_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, monkeypatch)

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)
    counts = _sqlite_counts(runtime.database)
    read_counts = (runtime.sources.m4_reads, runtime.sources.projection_reads)
    exact_retry = runtime.coordinator.run_to_terminal(
        runtime.scope,
        runtime.stored_catalog,
    )

    resume = runtime.ledger.resume(runtime.scope)
    assert exact_retry == seal
    assert resume.status == M6ReplayLockedLedgerStatus.SEALED
    assert counts == _sqlite_counts(runtime.database) == (0, 1, 1, 1, 0)
    assert read_counts == (2, 2)
    assert (runtime.sources.m4_reads, runtime.sources.projection_reads) == read_counts
    assert resume.pending_commitments[0].route == (
        M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    )
    assert seal.sample_execution_count == 1
    assert seal.run_trap_seal.clean
    assert seal.run_trap_seal.counters.total == 0
    assert seal.sample_executions[0].candidate_snapshot.semantic_case_hash == (
        seal.sample_executions[0].source_determinism.first_semantic_case_hash
    )


def test_restart_after_m4_candidate_commit_observes_without_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, monkeypatch, crash_after_candidate=True)
    assert isinstance(runtime.executor, _FailAfterCandidateCommit)

    with pytest.raises(M6ReplayLockedCoordinatorError) as raised:
        runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert raised.value.reason_code == M6ReplayLockedCoordinatorFailureCode.STORAGE_REJECTED
    assert runtime.ledger.resume(runtime.scope).status == M6ReplayLockedLedgerStatus.PENDING
    assert _sqlite_counts(runtime.database) == (0, 1, 1, 1, 0)
    assert runtime.executor.calls == 1
    assert (runtime.sources.m4_reads, runtime.sources.projection_reads) == (1, 0)

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert seal.sample_execution_count == 1
    assert runtime.ledger.resume(runtime.scope).status == M6ReplayLockedLedgerStatus.SEALED
    assert runtime.executor.calls == 1
    assert (runtime.sources.m4_reads, runtime.sources.projection_reads) == (2, 2)
    assert _sqlite_counts(runtime.database) == (0, 1, 1, 1, 0)
