from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace
from typing import cast

import pytest
from pydantic import BaseModel

from labcourt.application.m6_replay_locked_alert_policy import (
    build_m6_replay_locked_closed_policy_candidate,
)
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionError,
    M6ReplayLockedClosedPolicyExecutionErrorCode,
    build_m6_replay_locked_closed_policy_execution_scope,
    build_m6_replay_locked_closed_policy_execution_seal,
    build_m6_replay_locked_closed_policy_pending_commitment,
    build_m6_replay_locked_closed_policy_sample_record,
)
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked import (
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedCandidateBindingAuthority,
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedCandidateCaseBinding,
    M6ReplayLockedExecutionScopeAuthority,
)
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateObservation,
)
from tests.contract.test_m6_replay_locked_closed_policy_execution_contracts import (
    _ready_case_for_run,
)
from tests.unit.test_m5_alert_policy import _manifest_with_stream
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime
from tests.unit.test_m6_replay_locked_execution import _route_inputs
from tests.unit.test_m6_replay_locked_policy_source import (
    _document,
    _observation,
    _sha,
)
from tests.unit.test_m6_semantic_projection import _snapshot


def _facts():  # type: ignore[no-untyped-def]
    template = _runtime()
    source = _observation()
    fast_closure = template.source.closure
    closure = source.replay_input_closure.model_copy(
        update={
            "sample_id": _sha(source.replay_input_closure.sample_id),
            "model_calls": fast_closure.model_calls,
            "historical_cut": fast_closure.historical_cut,
        }
    )
    closure = M6ReplayInputClosureAuthority.model_validate(
        closure.model_dump(mode="json", exclude_computed_fields=True)
    )
    source = replace(
        source,
        replay_input_closure=closure,
        replay_input_closure_canonical_document=_document(closure),
    )
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=source)
    source_manifest_template = cast(
        M6ReplayLockedExecutionScopeAuthority,
        BaseModel.model_copy(
            template.scope,
            update={"locked_manifest": _manifest_with_stream()},
        ),
    )
    pre_policy_scope, stored = _route_inputs(closure, source_manifest_template)
    component = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version=pre_policy_scope.execution_component.version,
        code_commit=pre_policy_scope.execution_component.code_commit,
        pre_policy_component_authority_id=(
            pre_policy_scope.execution_component.component_authority_id
        ),
        supported_pre_policy_routes=(pre_policy_scope.execution_component.supported_routes),
    )
    scope = build_m6_replay_locked_closed_policy_execution_scope(
        pre_policy_execution_scope=pre_policy_scope,
        execution_component=component,
    )
    return scope, stored, cut


def _terminal_facts():  # type: ignore[no-untyped-def]
    scope, stored, cut = _facts()
    pending = build_m6_replay_locked_closed_policy_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored,
        policy_causal_cut=cut,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    candidate_ready = _ready_case_for_run(
        scope.pre_policy_execution_scope.locked_manifest,
        scope.candidate_run_id,
    )
    candidate = build_m6_replay_locked_closed_policy_candidate(
        ready_case=candidate_ready,
        source_binding=pending.source_binding,
        locked_config=scope.pre_policy_execution_scope.locked_config,
        locked_manifest=scope.pre_policy_execution_scope.locked_manifest,
    )
    case_document = canonical_json(candidate.closed_case.model_dump(mode="json"))
    case_payload = case_document.encode("utf-8")
    persisted = M6ReplayLockedCandidateCaseBinding(
        candidate_run_id=scope.candidate_run_id,
        sample_id=pending.sample_id,
        case_id=candidate.closed_case.case_id,
        case_revision=1,
        case_document_sha256=hashlib.sha256(case_payload).hexdigest(),
        case_document_size_bytes=len(case_payload),
        case_audit_sequence=0,
        case_audit_entry_hash=_sha("closed-candidate-audit"),
    )
    binding = M6ReplayLockedClosedCandidateBindingAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        source_binding_authority_id=pending.source_binding_authority_id,
        policy_causal_cut_authority_id=pending.policy_causal_cut_authority_id,
        pre_policy_route=pending.pre_policy_route,
        locked_config_sha256=pending.locked_config_sha256,
        transient_ready_case=candidate.ready_case,
        candidate_alert_policy=candidate.alert_policy,
        closed_candidate_case=candidate.closed_case,
        persisted_candidate_case=persisted,
    )
    closure = stored.source_catalog.entries[0].replay_input_closure
    source_snapshot = _snapshot(
        cut.source_closed_case,
        revision=cut.source_closed_case_revision,
    ).model_copy(update={"sample_id": pending.sample_id})
    candidate_snapshot = _snapshot(candidate.closed_case, revision=1).model_copy(
        update={"sample_id": pending.sample_id}
    )
    proof = M6ReplayLockedSourceDeterminismAuthority(
        command_id=scope.command_id,
        execution_entry_id=pending.execution_entry_id,
        sample_id=pending.sample_id,
        source_run_id=closure.source_run_id,
        candidate_run_id=scope.candidate_run_id,
        source_manifest_id=closure.source_manifest_id,
        execution_component_manifest_id=(
            scope.pre_policy_execution_scope.execution_component.component_authority_id
        ),
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
        source_identity_sha256=cut.source_identity_sha256,
        first_source_snapshot_id=source_snapshot.snapshot_id,
        second_source_snapshot_id=source_snapshot.snapshot_id,
        first_semantic_case_hash=source_snapshot.semantic_case_hash,
        second_semantic_case_hash=source_snapshot.semantic_case_hash,
    )
    observation = M6ReplayLockedClosedCandidateObservation(
        closed_candidate_binding=binding,
        candidate_snapshot=candidate_snapshot,
    )
    head = AuditHead(
        run_id=scope.candidate_run_id,
        manifest_id=scope.candidate_manifest_id,
        run_revision=1,
        sequence=0,
        entry_hash=persisted.case_audit_entry_hash,
    )
    return scope, stored, cut, pending, proof, observation, head


def test_builders_freeze_a_candidate_safe_policy_cut_before_execution() -> None:
    scope, stored, cut = _facts()

    pending = build_m6_replay_locked_closed_policy_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored,
        policy_causal_cut=cut,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )

    binding = pending.source_binding
    cut_document = _document(cut)
    assert pending.execution_scope_authority_id == scope.execution_scope_authority_id
    assert pending.locked_config_sha256 == scope.locked_config_sha256
    assert binding.policy_causal_cut_authority_id == cut.policy_causal_cut_authority_id
    assert (
        binding.policy_causal_cut_content_sha256
        == hashlib.sha256(cut_document.encode("utf-8")).hexdigest()
    )
    assert binding.policy_causal_cut_size_bytes == len(cut_document.encode("utf-8"))
    candidate_document = binding.model_dump(mode="json")
    assert "source_alert_policy" not in candidate_document
    assert "source_closed_case" not in candidate_document
    assert "source_ready_case" not in candidate_document


def test_pending_builder_rejects_a_policy_cut_from_another_closure() -> None:
    scope, stored, _ = _facts()
    foreign = build_m6_replay_locked_alert_policy_causal_cut(observation=_observation())

    with pytest.raises(M6ReplayLockedClosedPolicyExecutionError) as captured:
        build_m6_replay_locked_closed_policy_pending_commitment(
            execution_scope=scope,
            stored_source_catalog=stored,
            policy_causal_cut=foreign,
            ledger_sequence=0,
            previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
        )

    assert captured.value.code == (
        M6ReplayLockedClosedPolicyExecutionErrorCode.POLICY_CAUSAL_CUT_MISMATCH
    )
    assert not hasattr(captured.value, "policy_causal_cut")


def test_scope_builder_rejects_a_foreign_pre_policy_component() -> None:
    scope, _, _ = _facts()
    foreign = scope.execution_component.model_copy(
        update={"pre_policy_component_authority_id": "f" * 64}
    )

    with pytest.raises(M6ReplayLockedClosedPolicyExecutionError) as captured:
        build_m6_replay_locked_closed_policy_execution_scope(
            pre_policy_execution_scope=scope.pre_policy_execution_scope,
            execution_component=foreign,
        )

    assert captured.value.code == M6ReplayLockedClosedPolicyExecutionErrorCode.SCOPE_REJECTED


def test_trusted_record_and_seal_builders_rejoin_only_after_closed_commit() -> None:
    scope, stored, cut, pending, proof, observation, head = _terminal_facts()

    record = build_m6_replay_locked_closed_policy_sample_record(
        execution_scope=scope,
        stored_source_catalog=stored,
        pending_commitment=pending,
        source_determinism=proof,
        policy_causal_cut=cut,
        candidate_observation=observation,
    )
    seal = build_m6_replay_locked_closed_policy_execution_seal(
        execution_scope=scope,
        sample_records=(record,),
        candidate_audit_head=head,
    )

    assert record.policy_causal_cut == cut
    assert record.closed_candidate_binding == observation.closed_candidate_binding
    assert record.candidate_semantic_case_hash == record.source_semantic_case_hash
    assert seal.sample_executions == (record,)
    assert seal.run_trap_seal.clean
    assert seal.run_trap_seal.persisted_transient_ready_case_count == 0


def test_record_builder_rejects_a_full_cut_outside_the_frozen_pending() -> None:
    scope, stored, _, pending, proof, observation, _ = _terminal_facts()
    foreign = build_m6_replay_locked_alert_policy_causal_cut(observation=_observation())

    with pytest.raises(M6ReplayLockedClosedPolicyExecutionError) as captured:
        build_m6_replay_locked_closed_policy_sample_record(
            execution_scope=scope,
            stored_source_catalog=stored,
            pending_commitment=pending,
            source_determinism=proof,
            policy_causal_cut=foreign,
            candidate_observation=observation,
        )

    assert captured.value.code == (
        M6ReplayLockedClosedPolicyExecutionErrorCode.POLICY_CAUSAL_CUT_MISMATCH
    )


def test_seal_builder_derives_trap_and_rejects_a_foreign_audit_head() -> None:
    scope, stored, cut, pending, proof, observation, head = _terminal_facts()
    record = build_m6_replay_locked_closed_policy_sample_record(
        execution_scope=scope,
        stored_source_catalog=stored,
        pending_commitment=pending,
        source_determinism=proof,
        policy_causal_cut=cut,
        candidate_observation=observation,
    )
    foreign = AuditHead(
        run_id=head.run_id,
        manifest_id=head.manifest_id,
        run_revision=head.run_revision,
        sequence=head.sequence,
        entry_hash="f" * 64,
    )

    with pytest.raises(M6ReplayLockedClosedPolicyExecutionError) as captured:
        build_m6_replay_locked_closed_policy_execution_seal(
            execution_scope=scope,
            sample_records=(record,),
            candidate_audit_head=foreign,
        )

    assert captured.value.code == (M6ReplayLockedClosedPolicyExecutionErrorCode.AUDIT_HEAD_MISMATCH)
    forbidden = {"provider_trap", "counters", "run_trap_seal"}
    assert forbidden.isdisjoint(
        inspect.signature(build_m6_replay_locked_closed_policy_execution_seal).parameters
    )
