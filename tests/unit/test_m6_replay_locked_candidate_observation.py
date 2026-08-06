from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

import pytest

from labcourt.application.m6_replay_locked_candidate_observation import (
    M6ReplayLockedFastCandidateObservationService,
)
from labcourt.application.m6_replay_locked_execution import (
    build_m6_replay_locked_pending_commitment,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    build_m6_replay_locked_fast_terminal_candidate,
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
from labcourt.contracts.m6_replay_locked_execution import (
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
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)
from labcourt.ports.m6_replay_locked_ledger import M6ReplayLockedExecutionResume
from tests.unit.test_m6_replay_locked_execution_scope import _inputs
from tests.unit.test_m6_replay_locked_fast_source import _terminal_source


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(value: object) -> tuple[str, str, int]:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    payload = document.encode("utf-8")
    return document, hashlib.sha256(payload).hexdigest(), len(payload)


@dataclass(slots=True)
class _StoredProvider:
    value: M6ReplayLockedStoredCandidateCase
    calls: int = 0
    missing: bool = False

    def load_stored_candidate_case(
        self,
        _candidate_run_id: str,
        _sample_id: str,
    ) -> M6ReplayLockedStoredCandidateCase:
        self.calls += 1
        if self.missing:
            raise M6ReplayLockedCandidateError(M6ReplayLockedCandidateFailureCode.NOT_FOUND)
        return self.value


@dataclass(slots=True)
class _ScopeProvider:
    value: M6StoredReplayLockedExecutionScope
    calls: int = 0

    def load(
        self,
        _candidate_run_id: str,
        _execution_scope_authority_id: str,
    ) -> M6StoredReplayLockedExecutionScope:
        self.calls += 1
        return self.value


@dataclass(slots=True)
class _Ledger:
    value: M6ReplayLockedExecutionResume
    calls: int = 0

    def resume(
        self,
        _scope: M6ReplayLockedExecutionScopeAuthority,
    ) -> M6ReplayLockedExecutionResume:
        self.calls += 1
        return self.value


@dataclass(slots=True)
class _CatalogProvider:
    value: M6StoredRegressionExecutionSourceCatalog
    calls: int = 0

    def load(
        self,
        _source_catalog_authority_id: str,
        _source_catalog_document_sha256: str,
    ) -> M6StoredRegressionExecutionSourceCatalog:
        self.calls += 1
        return self.value


@dataclass(slots=True)
class _FastSourceProvider:
    value: M6ReplayLockedFastTerminalSource
    calls: int = 0
    reject: bool = False

    def load_fast_terminal_source(self, _closure):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.reject:
            raise RuntimeError("private source reader payload")
        return self.value


@dataclass(frozen=True, slots=True)
class _Runtime:
    scope: M6ReplayLockedExecutionScopeAuthority
    pending: M6ReplayLockedPendingSampleCommitmentAuthority
    catalog: M6StoredRegressionExecutionSourceCatalog
    source: M6ReplayLockedFastTerminalSource
    stored: M6ReplayLockedStoredCandidateCase
    stored_provider: _StoredProvider
    scope_provider: _ScopeProvider
    ledger: _Ledger
    catalog_provider: _CatalogProvider
    source_provider: _FastSourceProvider
    service: M6ReplayLockedFastCandidateObservationService


def _runtime() -> _Runtime:
    values = _inputs()
    config = values["locked_config"]
    manifest = values["locked_manifest"]
    component = values["execution_component"]
    template_command = values["command"]
    base_source = _terminal_source(
        gate_config=config.procedural_gate,  # type: ignore[union-attr]
        alert_config=config.alerts,  # type: ignore[union-attr]
    )
    sample_id = _sha("fast-observation-sample")
    closure = base_source.closure.model_copy(update={"sample_id": sample_id})
    source_snapshot = base_source.source_snapshot.model_copy(update={"sample_id": sample_id})
    source = M6ReplayLockedFastTerminalSource(
        source_identity_sha256=base_source.source_identity_sha256,
        closure=closure,
        projection_context=base_source.projection_context,
        source_snapshot=source_snapshot,
    )
    closure_document, closure_sha256, closure_size = _identity(closure)
    del closure_document
    catalog_entry = M6RegressionExecutionSourceCatalogEntry(
        source_item_id=_sha("fast-source-item"),
        sample_id=sample_id,
        source_seal_id=_sha("fast-source-seal"),
        source_seal_content_sha256=_sha("fast-source-seal-document"),
        source_seal_size_bytes=1,
        input_authority_id=closure.input_authority_id,
        input_authority_document_sha256=closure.input_authority_document_sha256,
        input_authority_content_sha256=_sha("fast-input-content"),
        input_authority_size_bytes=1,
        replay_input_closure_content_sha256=closure_sha256,
        replay_input_closure_size_bytes=closure_size,
        replay_input_closure=closure,
    )
    source_root = sha256_hex(["m6-regression-source-inventory", 1, [catalog_entry.source_item_id]])
    catalog_authority = M6RegressionExecutionSourceCatalogAuthority(
        baseline_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        source_inventory_cut_authority_id=_sha("fast-source-cut"),
        source_inventory_cut_content_sha256=_sha("fast-source-cut-document"),
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
        baseline_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        source_catalog_authority_id=catalog_authority.source_catalog_authority_id,
        source_catalog_document_sha256=catalog_sha256,
        entries=(
            M6RegressionExecutionEntry(
                sample_id=sample_id,
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
        baseline_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        candidate_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        policy_authority=template_command.policy_authority,  # type: ignore[union-attr]
    )
    scope = build_m6_replay_locked_execution_scope(
        candidate_run_id="m6-fast-observation-run",
        command=command,
        execution_dataset=dataset,
        stored_source_catalog=catalog,
        locked_manifest=manifest,
        locked_config=config,
        execution_component=component,
    )
    pending = build_m6_replay_locked_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=catalog,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    candidate = build_m6_replay_locked_fast_terminal_candidate(
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
        sample_id=sample_id,
        execution_entry_id=pending.execution_entry_id,
        source_catalog_entry_id=pending.source_catalog_entry_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        route=pending.route,
        case=candidate.case,
        canonical_document=case_document,
        case_document_sha256=hashlib.sha256(case_payload).hexdigest(),
        case_document_size_bytes=len(case_payload),
        case_audit_sequence=0,
        case_audit_entry_hash=_sha("fast-candidate-audit"),
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
    source_provider = _FastSourceProvider(source)
    service = M6ReplayLockedFastCandidateObservationService(
        stored_candidate_provider=stored_provider,
        execution_scope_provider=scope_provider,
        ledger_repository=ledger,
        source_catalog_provider=catalog_provider,
        fast_source_provider=source_provider,
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


def test_observation_rebuilds_snapshot_from_source_in_pending_state() -> None:
    runtime = _runtime()

    first = runtime.service.load_candidate_observation(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )
    second = runtime.service.load_candidate_observation(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )

    assert first == second
    assert first.case == runtime.stored.case
    assert first.candidate_snapshot.source_case_document_sha256 == (
        runtime.stored.case_document_sha256
    )
    assert runtime.stored_provider.calls == 2
    assert runtime.scope_provider.calls == 2
    assert runtime.ledger.calls == 2
    assert runtime.catalog_provider.calls == 2
    assert runtime.source_provider.calls == 2


def test_missing_candidate_row_short_circuits_all_authority_reads() -> None:
    runtime = _runtime()
    runtime.stored_provider.missing = True

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.service.load_candidate_observation(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )

    assert raised.value.reason_code == M6ReplayLockedCandidateFailureCode.NOT_FOUND
    assert runtime.scope_provider.calls == 0
    assert runtime.ledger.calls == 0
    assert runtime.catalog_provider.calls == 0
    assert runtime.source_provider.calls == 0


def test_pending_pointer_graft_fails_before_catalog_or_source_body() -> None:
    runtime = _runtime()
    runtime.stored_provider.value = replace(
        runtime.stored,
        pending_commitment_authority_id=_sha("foreign-pending"),
    )

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.service.load_candidate_observation(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )

    assert raised.value.reason_code == (M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID)
    assert runtime.catalog_provider.calls == 0
    assert runtime.source_provider.calls == 0


def test_byte_different_persisted_case_is_a_candidate_conflict() -> None:
    runtime = _runtime()
    different_case = runtime.stored.case.model_copy(
        update={"semantic_case_hash": _sha("persisted-case-drift")}
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


def test_source_reconstruction_failure_is_payload_free_stored_invalid() -> None:
    runtime = _runtime()
    runtime.source_provider.reject = True

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.service.load_candidate_observation(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )

    assert raised.value.reason_code == (M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID)
    assert "private source reader payload" not in str(raised.value)
    assert raised.value.__suppress_context__ is True
