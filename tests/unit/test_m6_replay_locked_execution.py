from __future__ import annotations

import hashlib
import inspect

import pytest

from labcourt.application.m6_replay_locked_execution import (
    M6ReplayLockedExecutionError,
    M6ReplayLockedExecutionErrorCode,
    build_m6_replay_locked_execution_seal,
    build_m6_replay_locked_pending_commitment,
    build_m6_replay_locked_sample_record,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
    M6RegressionStage,
    M6SemanticStageRoot,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionExecutionSourceCatalogEntry,
)
from labcourt.contracts.m6_replay_locked import (
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionComponentAuthority,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
)
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateObservation,
)
from tests.unit.test_m6_replay_locked_candidate_observation import (
    _runtime as _fast_runtime,
)
from tests.unit.test_m6_replay_locked_execution_scope import _inputs as _scope_inputs
from tests.unit.test_m6_replay_locked_m4_terminal import _execution as _m4_execution
from tests.unit.test_m6_semantic_projection import _event


def _execution_inputs() -> tuple[
    M6ReplayLockedExecutionScopeAuthority,
    M6StoredRegressionExecutionSourceCatalog,
]:
    runtime = _fast_runtime()
    return runtime.scope, runtime.catalog


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _route_inputs(
    closure: M6ReplayInputClosureAuthority,
    template_scope: M6ReplayLockedExecutionScopeAuthority,
    *,
    component: M6ReplayLockedExecutionComponentAuthority | None = None,
) -> tuple[
    M6ReplayLockedExecutionScopeAuthority,
    M6StoredRegressionExecutionSourceCatalog,
]:
    if len(closure.sample_id) != 64:
        closure = closure.model_copy(update={"sample_id": _sha(closure.sample_id)})
    closure_document = canonical_json(closure.model_dump(mode="json"))
    closure_payload = closure_document.encode("utf-8")
    source_item_id = _sha(f"route-source-item:{closure.replay_input_closure_authority_id}")
    catalog_entry = M6RegressionExecutionSourceCatalogEntry(
        source_item_id=source_item_id,
        sample_id=closure.sample_id,
        source_seal_id=_sha(f"route-source-seal:{closure.sample_id}"),
        source_seal_content_sha256=_sha(f"route-source-seal-document:{closure.sample_id}"),
        source_seal_size_bytes=1,
        input_authority_id=closure.input_authority_id,
        input_authority_document_sha256=closure.input_authority_document_sha256,
        input_authority_content_sha256=_sha(f"route-input:{closure.sample_id}"),
        input_authority_size_bytes=1,
        replay_input_closure_content_sha256=hashlib.sha256(closure_payload).hexdigest(),
        replay_input_closure_size_bytes=len(closure_payload),
        replay_input_closure=closure,
    )
    catalog = M6RegressionExecutionSourceCatalogAuthority(
        baseline_manifest_id=closure.source_manifest_id,
        source_inventory_cut_authority_id=_sha(f"route-cut:{closure.sample_id}"),
        source_inventory_cut_content_sha256=_sha(f"route-cut-document:{closure.sample_id}"),
        source_inventory_item_count=1,
        source_inventory_root_sha256=_sha(
            canonical_json(["m6-regression-source-inventory", 1, [source_item_id]])
        ),
        entries=(catalog_entry,),
    )
    catalog_document = canonical_json(catalog.model_dump(mode="json"))
    catalog_payload = catalog_document.encode("utf-8")
    stored = M6StoredRegressionExecutionSourceCatalog(
        source_catalog=catalog,
        canonical_document=catalog_document,
        content_sha256=hashlib.sha256(catalog_payload).hexdigest(),
        size_bytes=len(catalog_payload),
    )
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=closure.source_manifest_id,
        source_catalog_authority_id=catalog.source_catalog_authority_id,
        source_catalog_document_sha256=stored.content_sha256,
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
        mode=template_scope.command.mode,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=closure.source_manifest_id,
        candidate_manifest_id=closure.source_manifest_id,
        policy_authority=template_scope.command.policy_authority,
    )
    scope = build_m6_replay_locked_execution_scope(
        candidate_run_id=template_scope.candidate_run_id,
        command=command,
        execution_dataset=dataset,
        stored_source_catalog=stored,
        locked_manifest=template_scope.locked_manifest,
        locked_config=template_scope.locked_config,
        execution_component=component or template_scope.execution_component,
    )
    return scope, stored


def _candidate_observation(
    scope: M6ReplayLockedExecutionScopeAuthority,
) -> M6ReplayLockedCandidateObservation:
    event = _event(manifest_id=scope.locked_manifest.manifest_id)
    case = Case(
        run_id=scope.candidate_run_id,
        status=CaseStatus.CANDIDATE,
        event=event,
        manifest_id=scope.locked_manifest.manifest_id,
    )
    document = canonical_json(case.model_dump(mode="json"))
    document_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
    snapshot = M6CaseReplaySnapshot(
        sample_id=scope.execution_dataset.entries[0].sample_id,
        source_run_id=scope.candidate_run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=document_sha256,
        manifest_id=scope.locked_manifest.manifest_id,
        stage_roots=tuple(
            M6SemanticStageRoot(
                stage=stage,
                projection_sha256=hashlib.sha256(stage.value.encode("utf-8")).hexdigest(),
            )
            for stage in M6RegressionStage
        ),
        case_status=CaseStatus.CANDIDATE,
    )
    return M6ReplayLockedCandidateObservation(
        case=case,
        canonical_document=document,
        case_revision=1,
        case_audit_sequence=0,
        case_audit_entry_hash=hashlib.sha256(b"candidate-audit-entry").hexdigest(),
        candidate_snapshot=snapshot,
    )


def _source_proof(
    scope: M6ReplayLockedExecutionScopeAuthority,
    stored: M6StoredRegressionExecutionSourceCatalog,
    semantic_case_hash: str,
) -> M6ReplayLockedSourceDeterminismAuthority:
    entry = scope.execution_dataset.entries[0]
    closure = stored.source_catalog.entries[0].replay_input_closure
    source_snapshot_id = hashlib.sha256(b"source-snapshot").hexdigest()
    return M6ReplayLockedSourceDeterminismAuthority(
        command_id=scope.command.command_id,
        execution_entry_id=entry.execution_entry_id,
        sample_id=entry.sample_id,
        source_run_id=closure.source_run_id,
        candidate_run_id=scope.candidate_run_id,
        source_manifest_id=closure.source_manifest_id,
        execution_component_manifest_id=(scope.execution_component.component_authority_id),
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
        source_identity_sha256=hashlib.sha256(b"source-identity").hexdigest(),
        first_source_snapshot_id=source_snapshot_id,
        second_source_snapshot_id=source_snapshot_id,
        first_semantic_case_hash=semantic_case_hash,
        second_semantic_case_hash=semantic_case_hash,
    )


def _facts():  # type: ignore[no-untyped-def]
    scope, stored = _execution_inputs()
    observation = _candidate_observation(scope)
    pending = build_m6_replay_locked_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    proof = _source_proof(
        scope,
        stored,
        observation.candidate_snapshot.semantic_case_hash,
    )
    record = build_m6_replay_locked_sample_record(
        execution_scope=scope,
        stored_source_catalog=stored,
        pending_commitment=pending,
        source_determinism=proof,
        candidate_observation=observation,
    )
    head = AuditHead(
        run_id=scope.candidate_run_id,
        manifest_id=scope.locked_manifest.manifest_id,
        run_revision=1,
        sequence=0,
        entry_hash=observation.case_audit_entry_hash,
    )
    return scope, stored, observation, pending, proof, record, head


def test_builders_derive_pending_record_trap_receipt_and_terminal_seal() -> None:
    scope, stored, observation, pending, proof, record, head = _facts()

    seal = build_m6_replay_locked_execution_seal(
        execution_scope=scope,
        stored_source_catalog=stored,
        sample_records=(record,),
        candidate_audit_head=head,
    )

    assert pending.execution_entry == scope.execution_dataset.entries[0]
    assert pending.source_catalog_entry_id == scope.source_catalog_entry_ids[0]
    assert record.pending_commitment == pending
    assert (
        record.candidate_case.case_document_sha256
        == hashlib.sha256(observation.canonical_document.encode("utf-8")).hexdigest()
    )
    assert record.source_determinism == proof
    assert seal.run_trap_seal.clean
    assert seal.execution_receipts[0].candidate_snapshot_id == record.candidate_snapshot_id


def test_public_builders_do_not_accept_trap_counter_receipt_or_snapshot_claims() -> None:
    pending_parameters = inspect.signature(build_m6_replay_locked_pending_commitment).parameters
    record_parameters = inspect.signature(build_m6_replay_locked_sample_record).parameters
    seal_parameters = inspect.signature(build_m6_replay_locked_execution_seal).parameters

    forbidden = {
        "provider_trap",
        "counters",
        "execution_receipt",
        "candidate_snapshot",
        "candidate_case_binding",
    }
    assert forbidden.isdisjoint(pending_parameters)
    assert forbidden.isdisjoint(record_parameters)
    assert forbidden.isdisjoint(seal_parameters)


def test_pending_builder_rejects_a_scope_catalog_graft() -> None:
    scope, stored = _execution_inputs()
    forged_scope = scope.model_copy(update={"source_catalog_entry_ids": ("f" * 64,)})

    with pytest.raises(M6ReplayLockedExecutionError) as raised:
        build_m6_replay_locked_pending_commitment(
            execution_scope=forged_scope,
            stored_source_catalog=stored,
            ledger_sequence=0,
            previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
        )

    assert raised.value.code == M6ReplayLockedExecutionErrorCode.SCOPE_CATALOG_MISMATCH


def test_pending_builder_classifies_exact_fast_and_m4_gate_closures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fast = _fast_runtime()
    fast_pending = build_m6_replay_locked_pending_commitment(
        execution_scope=fast.scope,
        stored_source_catalog=fast.catalog,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    template_scope, _, m4_source = _m4_execution(monkeypatch)
    m4_scope, m4_catalog = _route_inputs(m4_source.closure, template_scope)

    m4_pending = build_m6_replay_locked_pending_commitment(
        execution_scope=m4_scope,
        stored_source_catalog=m4_catalog,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )

    assert fast_pending.route == (M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE)
    assert m4_pending.route == (M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE)
    assert m4_pending.execution_entry == m4_scope.execution_dataset.entries[0]
    assert m4_pending.source_catalog_entry_id == m4_scope.source_catalog_entry_ids[0]


def test_pending_builder_rejects_unknown_and_incomplete_mixed_closures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _scope_inputs()
    unknown_scope = build_m6_replay_locked_execution_scope(**values)
    unknown_catalog = values["stored_source_catalog"]
    assert isinstance(unknown_catalog, M6StoredRegressionExecutionSourceCatalog)
    template_scope, _, m4_source = _m4_execution(monkeypatch)
    incomplete_hearing = m4_source.closure.model_copy(
        update={"model_calls": m4_source.closure.model_calls[:-1]}
    )
    no_retrieval = m4_source.closure.model_copy(
        update={
            "historical_cut": m4_source.closure.historical_cut.model_copy(
                update={"retrieval_cycles": ()}
            )
        }
    )
    rejected = [(unknown_scope, unknown_catalog)]
    rejected.extend(
        _route_inputs(closure, template_scope) for closure in (incomplete_hearing, no_retrieval)
    )

    for scope, stored in rejected:
        with pytest.raises(M6ReplayLockedExecutionError) as raised:
            build_m6_replay_locked_pending_commitment(
                execution_scope=scope,
                stored_source_catalog=stored,
                ledger_sequence=0,
                previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
            )
        assert raised.value.code == M6ReplayLockedExecutionErrorCode.UNSUPPORTED_ROUTE


def test_pending_builder_requires_the_classified_m4_route_in_component(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template_scope, _, m4_source = _m4_execution(monkeypatch)
    fast_only = M6ReplayLockedExecutionComponentAuthority(
        version=template_scope.execution_component.version,
        code_commit=template_scope.execution_component.code_commit,
        supported_routes=(M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,),
    )
    scope, stored = _route_inputs(
        m4_source.closure,
        template_scope,
        component=fast_only,
    )

    with pytest.raises(M6ReplayLockedExecutionError) as raised:
        build_m6_replay_locked_pending_commitment(
            execution_scope=scope,
            stored_source_catalog=stored,
            ledger_sequence=0,
            previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
        )

    assert raised.value.code == M6ReplayLockedExecutionErrorCode.UNSUPPORTED_ROUTE


def test_record_builder_rejects_a_foreign_pending_or_source_proof() -> None:
    scope, stored, observation, pending, proof, _, _ = _facts()
    foreign_pending = pending.model_copy(update={"source_catalog_entry_id": "f" * 64})

    with pytest.raises(M6ReplayLockedExecutionError) as pending_error:
        build_m6_replay_locked_sample_record(
            execution_scope=scope,
            stored_source_catalog=stored,
            pending_commitment=foreign_pending,
            source_determinism=proof,
            candidate_observation=observation,
        )
    assert pending_error.value.code == M6ReplayLockedExecutionErrorCode.PENDING_REJECTED

    foreign_proof = proof.model_copy(update={"command_id": "e" * 64})
    with pytest.raises(M6ReplayLockedExecutionError) as proof_error:
        build_m6_replay_locked_sample_record(
            execution_scope=scope,
            stored_source_catalog=stored,
            pending_commitment=pending,
            source_determinism=foreign_proof,
            candidate_observation=observation,
        )
    assert proof_error.value.code == M6ReplayLockedExecutionErrorCode.RECORD_REJECTED


def test_seal_builder_rejects_an_incomplete_or_foreign_audit_head() -> None:
    scope, stored, _, _, _, record, head = _facts()
    foreign = AuditHead(
        run_id=head.run_id,
        manifest_id=head.manifest_id,
        run_revision=head.run_revision,
        sequence=head.sequence,
        entry_hash="f" * 64,
    )

    with pytest.raises(M6ReplayLockedExecutionError) as missing:
        build_m6_replay_locked_execution_seal(
            execution_scope=scope,
            stored_source_catalog=stored,
            sample_records=(),
            candidate_audit_head=head,
        )
    assert missing.value.code == M6ReplayLockedExecutionErrorCode.AUDIT_HEAD_MISMATCH

    with pytest.raises(M6ReplayLockedExecutionError) as mismatched:
        build_m6_replay_locked_execution_seal(
            execution_scope=scope,
            stored_source_catalog=stored,
            sample_records=(record,),
            candidate_audit_head=foreign,
        )
    assert mismatched.value.code == M6ReplayLockedExecutionErrorCode.AUDIT_HEAD_MISMATCH
