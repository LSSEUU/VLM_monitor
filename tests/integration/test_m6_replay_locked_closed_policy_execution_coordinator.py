from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_replay_locked_closed_policy_execution_scope_store import (
    M6ReplayLockedClosedPolicyExecutionScopePublisher,
    ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore,
)
from labcourt.adapters.storage.m6_replay_locked_closed_policy_ledger import (
    FilesystemM6ReplayLockedClosedPolicyLedgerRepository,
)
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_scope,
    build_m6_replay_locked_closed_policy_pending_commitment,
)
from labcourt.application.m6_replay_locked_closed_policy_execution_coordinator import (
    M6ReplayLockedClosedPolicyExecutionCoordinatorService,
)
from labcourt.application.m6_replay_locked_closed_pre_policy_source import (
    build_m6_replay_locked_closed_policy_pre_policy_source,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    build_m6_replay_locked_closed_policy_fast_pre_policy_candidate,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    build_m6_replay_locked_closed_policy_m4_pre_policy_candidate,
)
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateError,
    M6ReplayLockedClosedCandidateFailureCode,
    M6ReplayLockedStoredClosedCandidate,
)
from labcourt.ports.m6_replay_locked_closed_policy_coordinator import (
    M6ReplayLockedClosedPolicyCoordinatorError,
    M6ReplayLockedClosedPolicyCoordinatorFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_policy_ledger import (
    M6ReplayLockedClosedPolicyLedgerStatus,
)
from labcourt.ports.m6_replay_locked_closed_policy_sample_executor import (
    M6ReplayLockedClosedPolicySampleExecutorError,
    M6ReplayLockedClosedPolicySampleExecutorFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
    M6ReplayLockedClosedPolicyM4PrePolicySource,
    M6ReplayLockedClosedPolicyPrePolicySource,
)
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
)
from tests.unit.test_m6_replay_locked_candidate_observation import (
    _runtime as _v1_runtime,
)
from tests.unit.test_m6_replay_locked_closed_policy_m4_terminal import (
    _closed_execution as _m4_closed_execution,
)
from tests.unit.test_m6_replay_locked_closed_pre_policy_source_application import (
    _facts as _closed_source_facts,
)
from tests.unit.test_m6_replay_locked_closed_pre_policy_source_application import (
    _policy_for_ready,
)
from tests.unit.test_m6_replay_locked_execution import _route_inputs
from tests.unit.test_m6_replay_locked_policy_source import (
    _closed_case,
    _closing_audit,
    _document,
    _sha,
)


def _canonical_document(value: object) -> str:
    return canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]


def _policy_observation(
    closure: M6ReplayInputClosureAuthority,
    cut: object,
) -> M6ReplayLockedAlertPolicySourceObservation:
    report = M5ArtifactValidationReport(
        run_id=cut.source_ready_case.run_id,  # type: ignore[attr-defined]
        manifest_id=cut.source_ready_case.manifest_id,  # type: ignore[attr-defined]
        config_sha256=cut.source_config_sha256,  # type: ignore[attr-defined]
        authority_root_sha256=cut.source_m5_authority_root_sha256,  # type: ignore[attr-defined]
    )
    return M6ReplayLockedAlertPolicySourceObservation(
        source_identity_sha256=cut.source_identity_sha256,  # type: ignore[attr-defined]
        replay_input_closure=closure,
        replay_input_closure_canonical_document=_document(closure),
        source_validation_report=report,
        source_validation_report_canonical_document=_document(report),
        source_m5_authority_root_sha256=cut.source_m5_authority_root_sha256,  # type: ignore[attr-defined]
        source_ready_case_revision=cut.source_ready_case_revision,  # type: ignore[attr-defined]
        source_ready_case=cut.source_ready_case,  # type: ignore[attr-defined]
        source_ready_case_canonical_document=_document(cut.source_ready_case),  # type: ignore[attr-defined]
        source_closed_case_revision=cut.source_closed_case_revision,  # type: ignore[attr-defined]
        source_closed_case=cut.source_closed_case,  # type: ignore[attr-defined]
        source_closed_case_canonical_document=_document(cut.source_closed_case),  # type: ignore[attr-defined]
        source_alert_policy=cut.source_alert_policy,  # type: ignore[attr-defined]
        source_alert_policy_canonical_document=_document(cut.source_alert_policy),  # type: ignore[attr-defined]
        closing_audit_entry=cut.closing_audit_entry,  # type: ignore[attr-defined]
        closing_audit_entry_canonical_document=_document(cut.closing_audit_entry),  # type: ignore[attr-defined]
        cooldown_eligible_history_rows=(),
    )


@dataclass(slots=True)
class _PolicySources:
    observation: M6ReplayLockedAlertPolicySourceObservation
    read_count: int = 0

    def load_alert_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedAlertPolicySourceObservation:
        self.read_count += 1
        assert closure == self.observation.replay_input_closure
        return self.observation


@dataclass(slots=True)
class _PrePolicySources:
    source: M6ReplayLockedClosedPolicyPrePolicySource
    read_count: int = 0

    def load_closed_policy_pre_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
        source_binding: M6ReplayLockedClosedPolicySourceBindingAuthority,
    ) -> M6ReplayLockedClosedPolicyPrePolicySource:
        self.read_count += 1
        assert closure == self.source.catalog_closure
        assert source_binding == self.source.source_binding
        return self.source


@dataclass(slots=True)
class _CandidateState:
    candidate_to_persist: M6ReplayLockedStoredClosedCandidate
    ledger: FilesystemM6ReplayLockedClosedPolicyLedgerRepository
    stored: M6ReplayLockedStoredClosedCandidate | None = None
    execute_count: int = 0
    load_count: int = 0
    audit_head_count: int = 0
    persist_nothing: bool = False
    fail_after_persist: bool = False
    execution_statuses: list[M6ReplayLockedClosedPolicyLedgerStatus] = field(default_factory=list)

    def load_stored_closed_candidate(
        self,
        candidate_run_id: str,
        sample_id: str,
    ) -> M6ReplayLockedStoredClosedCandidate:
        self.load_count += 1
        if self.stored is None:
            raise M6ReplayLockedClosedCandidateError(
                M6ReplayLockedClosedCandidateFailureCode.NOT_FOUND
            )
        assert candidate_run_id == self.stored.candidate_run_id
        assert sample_id == self.stored.sample_id
        return self.stored

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None:
        self.execute_count += 1
        self.execution_statuses.append(self.ledger.resume(execution_scope).status)
        assert pending_commitment.pending_commitment_authority_id == (
            self.candidate_to_persist.pending_commitment_authority_id
        )
        assert replay_input_closure.sample_id == self.candidate_to_persist.sample_id
        if not self.persist_nothing:
            self.stored = self.candidate_to_persist
        if self.fail_after_persist:
            self.fail_after_persist = False
            raise M6ReplayLockedClosedPolicySampleExecutorError(
                M6ReplayLockedClosedPolicySampleExecutorFailureCode.STORAGE_REJECTED
            )

    def load_closed_candidate_audit_head(self, candidate_run_id: str) -> AuditHead:
        self.audit_head_count += 1
        if self.stored is None:
            raise M6ReplayLockedClosedCandidateError(
                M6ReplayLockedClosedCandidateFailureCode.NOT_FOUND
            )
        assert candidate_run_id == self.stored.candidate_run_id
        return AuditHead(
            run_id=candidate_run_id,
            manifest_id=self.stored.closed_candidate_case.manifest_id,
            run_revision=1,
            sequence=self.stored.case_audit_sequence,
            entry_hash=self.stored.case_audit_entry_hash,
        )


@dataclass(slots=True)
class _FailThirdCommit:
    commit_count: int = 0

    def __call__(self, phase: str) -> None:
        if phase != "before_commit":
            return
        self.commit_count += 1
        if self.commit_count == 3:
            raise RuntimeError("private operator payload")


@dataclass(slots=True)
class _Runtime:
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2
    stored_catalog: M6StoredRegressionExecutionSourceCatalog
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2
    ledger: FilesystemM6ReplayLockedClosedPolicyLedgerRepository
    policy_sources: _PolicySources
    pre_policy_sources: _PrePolicySources
    candidates: _CandidateState
    coordinator: M6ReplayLockedClosedPolicyExecutionCoordinatorService


def _stored_candidate(
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    source: M6ReplayLockedClosedPolicyPrePolicySource,
) -> M6ReplayLockedStoredClosedCandidate:
    if type(source) is M6ReplayLockedClosedPolicyFastPrePolicySource:
        pre_policy_candidate = build_m6_replay_locked_closed_policy_fast_pre_policy_candidate(
            execution_scope=scope,
            pending_commitment=pending,
            source=source,
        )
    else:
        assert type(source) is M6ReplayLockedClosedPolicyM4PrePolicySource
        pre_policy_candidate = build_m6_replay_locked_closed_policy_m4_pre_policy_candidate(
            execution_scope=scope,
            pending_commitment=pending,
            source=source,
        )
    policy = _policy_for_ready(pre_policy_candidate.case)
    closed = _closed_case(pre_policy_candidate.case, policy)
    policy_document = canonical_json(policy.model_dump(mode="json"))
    closed_document = canonical_json(closed.model_dump(mode="json"))
    policy_payload = policy_document.encode("utf-8")
    closed_payload = closed_document.encode("utf-8")
    return M6ReplayLockedStoredClosedCandidate(
        candidate_run_id=scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
        pre_policy_execution_scope_authority_id=(scope.pre_policy_execution_scope_authority_id),
        ledger_sequence=pending.ledger_sequence,
        sample_id=pending.sample_id,
        execution_entry_id=pending.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        pre_policy_pending_commitment_authority_id=(
            pending.pre_policy_pending_commitment.pending_commitment_authority_id
        ),
        source_binding_authority_id=pending.source_binding_authority_id,
        policy_causal_cut_authority_id=pending.policy_causal_cut_authority_id,
        locked_config_sha256=pending.locked_config_sha256,
        pre_policy_route=pending.pre_policy_route,
        candidate_alert_policy=policy,
        canonical_alert_policy_document=policy_document,
        candidate_alert_policy_document_sha256=hashlib.sha256(policy_payload).hexdigest(),
        candidate_alert_policy_size_bytes=len(policy_payload),
        closed_candidate_case=closed,
        canonical_closed_case_document=closed_document,
        closed_candidate_case_document_sha256=hashlib.sha256(closed_payload).hexdigest(),
        closed_candidate_case_size_bytes=len(closed_payload),
        case_audit_sequence=pending.ledger_sequence,
        case_audit_entry_hash=_sha("closed-policy-coordinator-candidate-audit"),
    )


def _runtime(
    root: Path,
    *,
    persist_nothing: bool = False,
    fail_after_persist: bool = False,
    fault_injector: _FailThirdCommit | None = None,
) -> _Runtime:
    _source, closure, cut, _binding, closed_context = _closed_source_facts()
    pre_policy_scope, stored_catalog = _route_inputs(closure, _v1_runtime().scope)
    component = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version=pre_policy_scope.execution_component.version,
        code_commit=pre_policy_scope.execution_component.code_commit,
        pre_policy_component_authority_id=(
            pre_policy_scope.execution_component.component_authority_id
        ),
        supported_pre_policy_routes=pre_policy_scope.execution_component.supported_routes,
    )
    scope = build_m6_replay_locked_closed_policy_execution_scope(
        pre_policy_execution_scope=pre_policy_scope,
        execution_component=component,
    )
    pending = build_m6_replay_locked_closed_policy_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored_catalog,
        policy_causal_cut=cut,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    safe_source = build_m6_replay_locked_closed_policy_pre_policy_source(
        source_binding=pending.source_binding,
        policy_causal_cut=cut,
        catalog_closure=closure,
        closed_projection_context=closed_context,
    )
    assert type(safe_source) is M6ReplayLockedClosedPolicyFastPrePolicySource
    observation = _policy_observation(closure, cut)

    root.mkdir()
    M6ReplayLockedClosedPolicyExecutionScopePublisher(root).publish(
        scope,
        _canonical_document(scope),
    )
    ledger = FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(root),
        fault_injector=fault_injector,
    )
    policy_sources = _PolicySources(observation)
    pre_policy_sources = _PrePolicySources(safe_source)
    candidates = _CandidateState(
        candidate_to_persist=_stored_candidate(scope, pending, safe_source),
        ledger=ledger,
        persist_nothing=persist_nothing,
        fail_after_persist=fail_after_persist,
    )
    coordinator = M6ReplayLockedClosedPolicyExecutionCoordinatorService(
        ledger_repository=ledger,
        policy_source_provider=policy_sources,
        pre_policy_source_provider=pre_policy_sources,
        sample_executor=candidates,
        stored_candidate_provider=candidates,
        candidate_audit_head_provider=candidates,
    )
    return _Runtime(
        scope=scope,
        stored_catalog=stored_catalog,
        pending=pending,
        ledger=ledger,
        policy_sources=policy_sources,
        pre_policy_sources=pre_policy_sources,
        candidates=candidates,
        coordinator=coordinator,
    )


def test_fresh_run_reaches_seal_and_exact_retry_is_read_only(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "fresh")

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)
    counts = (
        runtime.policy_sources.read_count,
        runtime.pre_policy_sources.read_count,
        runtime.candidates.load_count,
        runtime.candidates.execute_count,
        runtime.candidates.audit_head_count,
    )
    exact_retry = runtime.coordinator.run_to_terminal(
        runtime.scope,
        runtime.stored_catalog,
    )

    assert exact_retry == seal
    assert runtime.ledger.resume(runtime.scope).status is (
        M6ReplayLockedClosedPolicyLedgerStatus.SEALED
    )
    assert counts == (2, 3, 2, 1, 1)
    assert (
        runtime.policy_sources.read_count,
        runtime.pre_policy_sources.read_count,
        runtime.candidates.load_count,
        runtime.candidates.execute_count,
        runtime.candidates.audit_head_count,
    ) == counts
    assert runtime.candidates.execution_statuses == [M6ReplayLockedClosedPolicyLedgerStatus.PENDING]
    assert seal.run_trap_seal.clean
    assert seal.run_trap_seal.persisted_transient_ready_case_count == 0


def test_restart_after_candidate_commit_does_not_rerun_policy(
    tmp_path: Path,
) -> None:
    runtime = _runtime(
        tmp_path / "candidate-committed",
        fail_after_persist=True,
    )

    with pytest.raises(M6ReplayLockedClosedPolicyCoordinatorError) as raised:
        runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert raised.value.reason_code is (
        M6ReplayLockedClosedPolicyCoordinatorFailureCode.STORAGE_REJECTED
    )
    assert raised.value.__suppress_context__ is True
    assert runtime.ledger.resume(runtime.scope).status is (
        M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    )
    assert runtime.candidates.stored is not None
    assert runtime.candidates.execute_count == 1

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert seal.sample_execution_count == 1
    assert runtime.candidates.execute_count == 1
    assert runtime.candidates.load_count == 2
    assert runtime.policy_sources.read_count == 3
    assert runtime.pre_policy_sources.read_count == 3


def test_executor_without_durable_candidate_leaves_typed_pending(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path / "missing-candidate", persist_nothing=True)

    with pytest.raises(M6ReplayLockedClosedPolicyCoordinatorError) as raised:
        runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert raised.value.reason_code is (
        M6ReplayLockedClosedPolicyCoordinatorFailureCode.CANDIDATE_OBSERVATION_MISSING
    )
    assert runtime.ledger.resume(runtime.scope).status is (
        M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    )
    assert runtime.candidates.execute_count == 1
    assert runtime.candidates.load_count == 2
    assert runtime.pre_policy_sources.read_count == 0


def test_record_and_seal_recovery_skip_all_earlier_capabilities(
    tmp_path: Path,
) -> None:
    fault = _FailThirdCommit()
    runtime = _runtime(tmp_path / "record-seal", fault_injector=fault)

    with pytest.raises(M6ReplayLockedClosedPolicyCoordinatorError) as raised:
        runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert raised.value.reason_code is (
        M6ReplayLockedClosedPolicyCoordinatorFailureCode.STORAGE_REJECTED
    )
    assert runtime.ledger.resume(runtime.scope).status is (
        M6ReplayLockedClosedPolicyLedgerStatus.READY_TO_SEAL
    )
    before_seal = (
        runtime.policy_sources.read_count,
        runtime.pre_policy_sources.read_count,
        runtime.candidates.load_count,
        runtime.candidates.execute_count,
        runtime.candidates.audit_head_count,
    )

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)
    after_seal = (
        runtime.policy_sources.read_count,
        runtime.pre_policy_sources.read_count,
        runtime.candidates.load_count,
        runtime.candidates.execute_count,
        runtime.candidates.audit_head_count,
    )
    exact_retry = runtime.coordinator.run_to_terminal(
        runtime.scope,
        runtime.stored_catalog,
    )

    assert before_seal[:4] == after_seal[:4]
    assert after_seal[4] == before_seal[4] + 1
    assert exact_retry == seal
    assert (
        runtime.policy_sources.read_count,
        runtime.pre_policy_sources.read_count,
        runtime.candidates.load_count,
        runtime.candidates.execute_count,
        runtime.candidates.audit_head_count,
    ) == after_seal


def _m4_runtime(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_after_persist: bool = False,
) -> _Runtime:
    scope, pending, safe_source = _m4_closed_execution(monkeypatch)
    closure = safe_source.catalog_closure
    rebuilt_scope, stored_catalog = _route_inputs(
        closure,
        scope.pre_policy_execution_scope,
    )
    assert rebuilt_scope == scope.pre_policy_execution_scope
    ready = safe_source.projection_context.case
    policy = _policy_for_ready(ready)
    closed = _closed_case(ready, policy)
    report = M5ArtifactValidationReport(
        run_id=ready.run_id,
        manifest_id=ready.manifest_id,
        config_sha256=policy.request.config_sha256,
        authority_root_sha256=_sha("m4-closed-policy-m5-root"),
    )
    ready_revision = safe_source.source_ready_case_revision
    closing_audit = _closing_audit(
        ready,
        closed,
        policy,
        sequence=ready_revision + 1,
    )
    observation = M6ReplayLockedAlertPolicySourceObservation(
        source_identity_sha256=safe_source.source_identity_sha256,
        replay_input_closure=closure,
        replay_input_closure_canonical_document=_document(closure),
        source_validation_report=report,
        source_validation_report_canonical_document=_document(report),
        source_m5_authority_root_sha256=report.authority_root_sha256,
        source_ready_case_revision=ready_revision,
        source_ready_case=ready,
        source_ready_case_canonical_document=_document(ready),
        source_closed_case_revision=ready_revision + 1,
        source_closed_case=closed,
        source_closed_case_canonical_document=_document(closed),
        source_alert_policy=policy,
        source_alert_policy_canonical_document=_document(policy),
        closing_audit_entry=closing_audit,
        closing_audit_entry_canonical_document=_document(closing_audit),
        cooldown_eligible_history_rows=(),
    )
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    expected_pending = build_m6_replay_locked_closed_policy_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored_catalog,
        policy_causal_cut=cut,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    assert expected_pending == pending

    root.mkdir()
    M6ReplayLockedClosedPolicyExecutionScopePublisher(root).publish(
        scope,
        _canonical_document(scope),
    )
    ledger = FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(root),
    )
    policy_sources = _PolicySources(observation)
    pre_policy_sources = _PrePolicySources(safe_source)
    candidates = _CandidateState(
        candidate_to_persist=_stored_candidate(scope, pending, safe_source),
        ledger=ledger,
        fail_after_persist=fail_after_persist,
    )
    coordinator = M6ReplayLockedClosedPolicyExecutionCoordinatorService(
        ledger_repository=ledger,
        policy_source_provider=policy_sources,
        pre_policy_source_provider=pre_policy_sources,
        sample_executor=candidates,
        stored_candidate_provider=candidates,
        candidate_audit_head_provider=candidates,
    )
    return _Runtime(
        scope=scope,
        stored_catalog=stored_catalog,
        pending=pending,
        ledger=ledger,
        policy_sources=policy_sources,
        pre_policy_sources=pre_policy_sources,
        candidates=candidates,
        coordinator=coordinator,
    )


def test_m4_fresh_run_reaches_seal_and_exact_retry_is_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _m4_runtime(tmp_path / "m4-fresh", monkeypatch)

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)
    counts = (
        runtime.policy_sources.read_count,
        runtime.pre_policy_sources.read_count,
        runtime.candidates.load_count,
        runtime.candidates.execute_count,
        runtime.candidates.audit_head_count,
    )
    exact_retry = runtime.coordinator.run_to_terminal(
        runtime.scope,
        runtime.stored_catalog,
    )

    assert exact_retry == seal
    assert runtime.ledger.resume(runtime.scope).status is (
        M6ReplayLockedClosedPolicyLedgerStatus.SEALED
    )
    assert runtime.pending.pre_policy_route.value == ("M4_HEARING_GATE_TERMINAL_POST_PARSE")
    assert counts == (2, 3, 2, 1, 1)
    assert (
        runtime.policy_sources.read_count,
        runtime.pre_policy_sources.read_count,
        runtime.candidates.load_count,
        runtime.candidates.execute_count,
        runtime.candidates.audit_head_count,
    ) == counts
    assert seal.sample_executions[0].candidate_semantic_case_hash == (
        seal.sample_executions[0].source_semantic_case_hash
    )


def test_m4_candidate_commit_recovery_does_not_reexecute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _m4_runtime(
        tmp_path / "m4-candidate-committed",
        monkeypatch,
        fail_after_persist=True,
    )

    with pytest.raises(M6ReplayLockedClosedPolicyCoordinatorError):
        runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert runtime.ledger.resume(runtime.scope).status is (
        M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    )
    assert runtime.candidates.stored is not None
    assert runtime.candidates.execute_count == 1

    seal = runtime.coordinator.run_to_terminal(runtime.scope, runtime.stored_catalog)

    assert seal.sample_execution_count == 1
    assert runtime.candidates.execute_count == 1
    assert runtime.ledger.resume(runtime.scope).status is (
        M6ReplayLockedClosedPolicyLedgerStatus.SEALED
    )
