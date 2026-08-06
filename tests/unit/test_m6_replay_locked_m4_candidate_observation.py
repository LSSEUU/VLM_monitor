from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace

import pytest

from labcourt.application.m6_replay_locked_candidate_observation import (
    M6ReplayLockedM4CandidateObservationService,
)
from labcourt.application.m6_replay_locked_execution import (
    build_m6_replay_locked_pending_commitment,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.application.m6_replay_locked_m4_terminal import (
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
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
    M6ReplayLockedStoredCandidateCase,
)
from labcourt.ports.m6_replay_locked_execution_scope import (
    M6StoredReplayLockedExecutionScope,
)
from labcourt.ports.m6_replay_locked_ledger import M6ReplayLockedExecutionResume
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)
from tests.unit.test_m6_replay_locked_candidate_observation import (
    _CatalogProvider,
    _Ledger,
    _ScopeProvider,
    _StoredProvider,
)
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime as _fast_runtime
from tests.unit.test_m6_replay_locked_m4_terminal import _execution as _m4_execution


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(value: object) -> tuple[str, str, int]:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    payload = document.encode("utf-8")
    return document, hashlib.sha256(payload).hexdigest(), len(payload)


@dataclass(slots=True)
class _M4SourceProvider:
    value: M6ReplayLockedM4GateTerminalSource
    calls: int = 0
    closures: list[M6ReplayInputClosureAuthority] = field(default_factory=list)

    def load_m4_gate_terminal_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedM4GateTerminalSource:
        self.calls += 1
        self.closures.append(closure)
        return self.value


@dataclass(frozen=True, slots=True)
class _Runtime:
    scope: M6ReplayLockedExecutionScopeAuthority
    pending: M6ReplayLockedPendingSampleCommitmentAuthority
    catalog: M6StoredRegressionExecutionSourceCatalog
    source: M6ReplayLockedM4GateTerminalSource
    stored: M6ReplayLockedStoredCandidateCase
    stored_provider: _StoredProvider
    scope_provider: _ScopeProvider
    ledger: _Ledger
    catalog_provider: _CatalogProvider
    source_provider: _M4SourceProvider
    service: M6ReplayLockedM4CandidateObservationService


def _runtime(monkeypatch: pytest.MonkeyPatch) -> _Runtime:
    template_scope, _, base_source = _m4_execution(monkeypatch)
    manifest = template_scope.locked_manifest
    sample_id = _sha("m4-observation-sample")
    closure = base_source.closure.model_copy(update={"sample_id": sample_id})
    source_snapshot = base_source.source_snapshot.model_copy(update={"sample_id": sample_id})
    source = M6ReplayLockedM4GateTerminalSource(
        source_identity_sha256=base_source.source_identity_sha256,
        closure=closure,
        projection_context=base_source.projection_context,
        hearing_record=base_source.hearing_record,
        hearing_verdict_binding=base_source.hearing_verdict_binding,
        gate_current_closure_receipt=base_source.gate_current_closure_receipt,
        source_snapshot=source_snapshot,
    )
    _, closure_sha256, closure_size = _identity(closure)
    source_item_id = _sha("m4-observation-source-item")
    catalog_entry = M6RegressionExecutionSourceCatalogEntry(
        source_item_id=source_item_id,
        sample_id=closure.sample_id,
        source_seal_id=_sha("m4-observation-source-seal"),
        source_seal_content_sha256=_sha("m4-observation-source-seal-document"),
        source_seal_size_bytes=1,
        input_authority_id=closure.input_authority_id,
        input_authority_document_sha256=closure.input_authority_document_sha256,
        input_authority_content_sha256=_sha("m4-observation-input-content"),
        input_authority_size_bytes=1,
        replay_input_closure_content_sha256=closure_sha256,
        replay_input_closure_size_bytes=closure_size,
        replay_input_closure=closure,
    )
    source_root = sha256_hex(["m6-regression-source-inventory", 1, [source_item_id]])
    catalog_authority = M6RegressionExecutionSourceCatalogAuthority(
        baseline_manifest_id=manifest.manifest_id,
        source_inventory_cut_authority_id=_sha("m4-observation-source-cut"),
        source_inventory_cut_content_sha256=_sha("m4-observation-source-cut-document"),
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
        baseline_manifest_id=manifest.manifest_id,
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
        baseline_manifest_id=manifest.manifest_id,
        candidate_manifest_id=manifest.manifest_id,
        policy_authority=template_scope.command.policy_authority,
    )
    scope = build_m6_replay_locked_execution_scope(
        candidate_run_id="m6-m4-observation-run",
        command=command,
        execution_dataset=dataset,
        stored_source_catalog=catalog,
        locked_manifest=manifest,
        locked_config=template_scope.locked_config,
        execution_component=template_scope.execution_component,
    )
    pending = build_m6_replay_locked_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=catalog,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    case_document = candidate.canonical_case_document
    case_payload = case_document.encode("utf-8")
    stored = M6ReplayLockedStoredCandidateCase(
        candidate_run_id=scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
        ledger_sequence=0,
        sample_id=pending.sample_id,
        execution_entry_id=pending.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        route=pending.route,
        case=candidate.case,
        canonical_document=case_document,
        case_document_sha256=hashlib.sha256(case_payload).hexdigest(),
        case_document_size_bytes=len(case_payload),
        case_audit_sequence=0,
        case_audit_entry_hash=_sha("m4-observation-candidate-audit"),
    )
    scope_document, scope_sha256, scope_size = _identity(scope)
    stored_provider = _StoredProvider(stored)
    scope_provider = _ScopeProvider(
        M6StoredReplayLockedExecutionScope(
            scope=scope,
            canonical_document=scope_document,
            content_sha256=scope_sha256,
            size_bytes=scope_size,
        )
    )
    ledger = _Ledger(
        M6ReplayLockedExecutionResume(
            execution_scope=scope,
            pending_commitments=(pending,),
            sample_records=(),
        )
    )
    catalog_provider = _CatalogProvider(catalog)
    source_provider = _M4SourceProvider(source)
    service = M6ReplayLockedM4CandidateObservationService(
        stored_candidate_provider=stored_provider,
        execution_scope_provider=scope_provider,
        ledger_repository=ledger,
        source_catalog_provider=catalog_provider,
        m4_source_provider=source_provider,
    )
    return _Runtime(
        scope=scope,
        pending=pending,
        catalog=catalog,
        source=source,
        stored=stored,
        stored_provider=stored_provider,
        scope_provider=scope_provider,
        ledger=ledger,
        catalog_provider=catalog_provider,
        source_provider=source_provider,
        service=service,
    )


def test_m4_observation_rebuilds_the_persisted_case_from_exact_source_authorities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(monkeypatch)

    first = runtime.service.load_candidate_observation(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )
    second = runtime.service.load_candidate_observation(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )

    assert runtime.pending.route == (
        M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    )
    assert first == second
    assert first.case == runtime.stored.case
    assert first.canonical_document == runtime.stored.canonical_document
    assert first.case_audit_sequence == runtime.stored.case_audit_sequence
    assert first.case_audit_entry_hash == runtime.stored.case_audit_entry_hash
    assert first.candidate_snapshot.source_case_document_sha256 == (
        runtime.stored.case_document_sha256
    )
    assert runtime.stored_provider.calls == 2
    assert runtime.scope_provider.calls == 2
    assert runtime.ledger.calls == 2
    assert runtime.catalog_provider.calls == 2
    assert runtime.source_provider.calls == 2
    assert runtime.source_provider.closures == [runtime.source.closure] * 2


def test_m4_observation_rejects_a_canonical_foreign_source_graft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(monkeypatch)
    foreign_sample = _sha("foreign-m4-observation-sample")
    foreign_closure = runtime.source.closure.model_copy(update={"sample_id": foreign_sample})
    foreign_snapshot = runtime.source.source_snapshot.model_copy(
        update={"sample_id": foreign_sample}
    )
    runtime.source_provider.value = M6ReplayLockedM4GateTerminalSource(
        source_identity_sha256=runtime.source.source_identity_sha256,
        closure=foreign_closure,
        projection_context=runtime.source.projection_context,
        hearing_record=runtime.source.hearing_record,
        hearing_verdict_binding=runtime.source.hearing_verdict_binding,
        gate_current_closure_receipt=runtime.source.gate_current_closure_receipt,
        source_snapshot=foreign_snapshot,
    )

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.service.load_candidate_observation(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )

    assert raised.value.reason_code == (M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID)
    assert runtime.source_provider.calls == 1


def test_m4_observation_rejects_a_real_fast_route_before_scope_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fast = _fast_runtime()
    runtime = _runtime(monkeypatch)
    runtime.stored_provider.value = fast.stored

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.service.load_candidate_observation(
            fast.scope.candidate_run_id,
            fast.pending.sample_id,
        )

    assert raised.value.reason_code == (M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID)
    assert runtime.stored_provider.calls == 1
    assert runtime.scope_provider.calls == 0
    assert runtime.ledger.calls == 0
    assert runtime.catalog_provider.calls == 0
    assert runtime.source_provider.calls == 0


def test_m4_observation_reports_a_byte_different_persisted_case_as_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(monkeypatch)
    different_case = runtime.stored.case.model_copy(
        update={"semantic_case_hash": _sha("persisted-m4-case-drift")}
    )
    different_document = canonical_json(different_case.model_dump(mode="json"))
    different_payload = different_document.encode("utf-8")
    runtime.stored_provider.value = replace(
        runtime.stored,
        case=different_case,
        canonical_document=different_document,
        case_document_sha256=hashlib.sha256(different_payload).hexdigest(),
        case_document_size_bytes=len(different_payload),
    )

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.service.load_candidate_observation(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )

    assert raised.value.reason_code == M6ReplayLockedCandidateFailureCode.CANDIDATE_CONFLICT
    assert runtime.source_provider.calls == 1
