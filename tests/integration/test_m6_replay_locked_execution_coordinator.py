from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_replay_locked_execution_scope_store import (
    M6ReplayLockedExecutionScopePublisher,
    ReadonlyM6ReplayLockedExecutionScopeStore,
)
from labcourt.adapters.storage.m6_replay_locked_ledger import (
    FilesystemM6ReplayLockedLedgerRepository,
)
from labcourt.application.m6_replay_locked_execution_coordinator import (
    M6ReplayLockedExecutionCoordinatorService,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidateObservation,
)
from labcourt.ports.m6_replay_locked_coordinator import (
    M6ReplayLockedCoordinatorError,
    M6ReplayLockedCoordinatorFailureCode,
)
from labcourt.ports.m6_replay_locked_ledger import M6ReplayLockedLedgerStatus
from labcourt.ports.m6_replay_locked_source import M6ReplayLockedSourceProjection
from tests.unit.test_m6_replay_locked_execution import (
    _candidate_observation,
    _execution_inputs,
)


def _document(value: object) -> str:
    return canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]


@dataclass(slots=True)
class _CandidateState:
    observation: M6ReplayLockedCandidateObservation | None = None
    execute_count: int = 0
    fail_after_persist: bool = False
    persist_nothing: bool = False
    execution_statuses: list[M6ReplayLockedLedgerStatus] = field(default_factory=list)
    ledger: FilesystemM6ReplayLockedLedgerRepository | None = None

    def load_candidate_observation(
        self,
        _candidate_run_id: str,
        _sample_id: str,
    ) -> M6ReplayLockedCandidateObservation:
        if self.observation is None:
            raise M6ReplayLockedCandidateError(M6ReplayLockedCandidateFailureCode.NOT_FOUND)
        return self.observation

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        _pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        _replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None:
        self.execute_count += 1
        assert self.ledger is not None
        self.execution_statuses.append(self.ledger.resume(execution_scope).status)
        if not self.persist_nothing:
            self.observation = _candidate_observation(execution_scope)
        if self.fail_after_persist:
            self.fail_after_persist = False
            raise RuntimeError("private C:/operator payload")

    def load_candidate_audit_head(self, candidate_run_id: str) -> AuditHead:
        if self.observation is None:
            raise M6ReplayLockedCandidateError(M6ReplayLockedCandidateFailureCode.NOT_FOUND)
        return AuditHead(
            run_id=candidate_run_id,
            manifest_id=self.observation.case.manifest_id,
            run_revision=1,
            sequence=self.observation.case_audit_sequence,
            entry_hash=self.observation.case_audit_entry_hash,
        )


@dataclass(slots=True)
class _SourceProvider:
    projection: M6ReplayLockedSourceProjection
    read_count: int = 0

    def load_source_projection(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedSourceProjection:
        self.read_count += 1
        assert closure == self.projection.closure
        return M6ReplayLockedSourceProjection(
            source_identity_sha256=self.projection.source_identity_sha256,
            closure=self.projection.closure,
            source_snapshot=self.projection.source_snapshot,
        )


def _source_provider(
    scope: M6ReplayLockedExecutionScopeAuthority,
    stored: M6StoredRegressionExecutionSourceCatalog,
) -> _SourceProvider:
    candidate = _candidate_observation(scope).candidate_snapshot
    closure = stored.source_catalog.entries[0].replay_input_closure
    assert closure.source_case_id is not None
    assert closure.source_case_revision is not None
    assert closure.source_case_document_sha256 is not None
    source_snapshot = M6CaseReplaySnapshot(
        sample_id=closure.sample_id,
        source_run_id=closure.source_run_id,
        source_case_id=closure.source_case_id,
        source_case_revision=closure.source_case_revision,
        source_case_document_sha256=closure.source_case_document_sha256,
        manifest_id=closure.source_manifest_id,
        stage_roots=candidate.stage_roots,
        case_status=candidate.case_status,
    )
    assert source_snapshot.semantic_case_hash == candidate.semantic_case_hash
    return _SourceProvider(
        M6ReplayLockedSourceProjection(
            source_identity_sha256=hashlib.sha256(b"source-cut").hexdigest(),
            closure=closure,
            source_snapshot=source_snapshot,
        )
    )


def _runtime(
    root: Path,
    *,
    candidate: _CandidateState | None = None,
) -> tuple[
    M6ReplayLockedExecutionScopeAuthority,
    M6StoredRegressionExecutionSourceCatalog,
    FilesystemM6ReplayLockedLedgerRepository,
    _CandidateState,
    _SourceProvider,
    M6ReplayLockedExecutionCoordinatorService,
]:
    scope, stored = _execution_inputs()
    M6ReplayLockedExecutionScopePublisher(root).publish(scope, _document(scope))
    ledger = FilesystemM6ReplayLockedLedgerRepository(
        root,
        scope_provider=ReadonlyM6ReplayLockedExecutionScopeStore(root),
    )
    candidate_state = candidate or _CandidateState()
    candidate_state.ledger = ledger
    source = _source_provider(scope, stored)
    coordinator = M6ReplayLockedExecutionCoordinatorService(
        ledger_repository=ledger,
        source_projection_provider=source,
        sample_executor=candidate_state,
        candidate_observation_provider=candidate_state,
        candidate_audit_head_provider=candidate_state,
    )
    return scope, stored, ledger, candidate_state, source, coordinator


def test_coordinator_advances_only_after_pending_and_seals_from_fresh_state(
    tmp_path: Path,
) -> None:
    scope, stored, ledger, candidate, source, coordinator = _runtime(tmp_path)

    seal = coordinator.run_to_terminal(scope, stored)
    exact_retry = coordinator.run_to_terminal(scope, stored)

    assert exact_retry == seal
    assert ledger.resume(scope).status == M6ReplayLockedLedgerStatus.SEALED
    assert candidate.execute_count == 1
    assert candidate.execution_statuses == [M6ReplayLockedLedgerStatus.PENDING]
    assert source.read_count == 2
    assert seal.sample_execution_count == 1
    assert seal.execution_receipts[0].candidate_snapshot_id == (
        seal.sample_executions[0].candidate_snapshot_id
    )


def test_restart_after_candidate_commit_skips_reexecution_and_finishes_record(
    tmp_path: Path,
) -> None:
    candidate = _CandidateState(fail_after_persist=True)
    scope, stored, ledger, candidate, source, coordinator = _runtime(
        tmp_path,
        candidate=candidate,
    )

    with pytest.raises(M6ReplayLockedCoordinatorError) as raised:
        coordinator.run_to_terminal(scope, stored)
    assert raised.value.reason_code == M6ReplayLockedCoordinatorFailureCode.STORAGE_REJECTED
    assert raised.value.__suppress_context__ is True
    assert ledger.resume(scope).status == M6ReplayLockedLedgerStatus.PENDING
    assert candidate.observation is not None

    seal = coordinator.run_to_terminal(scope, stored)

    assert seal.sample_execution_count == 1
    assert candidate.execute_count == 1
    assert source.read_count == 2
    assert ledger.resume(scope).status == M6ReplayLockedLedgerStatus.SEALED


def test_executor_that_returns_without_candidate_state_leaves_recoverable_pending(
    tmp_path: Path,
) -> None:
    candidate = _CandidateState(persist_nothing=True)
    scope, stored, ledger, candidate, _, coordinator = _runtime(
        tmp_path,
        candidate=candidate,
    )

    with pytest.raises(M6ReplayLockedCoordinatorError) as raised:
        coordinator.run_to_terminal(scope, stored)

    assert raised.value.reason_code == (
        M6ReplayLockedCoordinatorFailureCode.CANDIDATE_OBSERVATION_MISSING
    )
    assert ledger.resume(scope).status == M6ReplayLockedLedgerStatus.PENDING
    assert candidate.execute_count == 1


def test_scope_catalog_graft_fails_before_candidate_execution(tmp_path: Path) -> None:
    scope, stored, ledger, candidate, _, coordinator = _runtime(tmp_path)
    foreign = scope.model_copy(update={"source_catalog_entry_ids": ("f" * 64,)})

    with pytest.raises(M6ReplayLockedCoordinatorError) as raised:
        coordinator.run_to_terminal(foreign, stored)

    assert raised.value.reason_code == M6ReplayLockedCoordinatorFailureCode.SCOPE_REJECTED
    assert candidate.execute_count == 0
    assert ledger.resume(scope).status == M6ReplayLockedLedgerStatus.READY_FOR_PENDING


def test_coordinator_api_accepts_no_trap_receipt_or_candidate_claims() -> None:
    parameters = inspect.signature(
        M6ReplayLockedExecutionCoordinatorService.run_to_terminal
    ).parameters

    assert tuple(parameters) == ("self", "execution_scope", "stored_source_catalog")
    assert {
        "provider_trap",
        "counters",
        "execution_receipt",
        "candidate_snapshot",
        "candidate_case_binding",
    }.isdisjoint(parameters)
