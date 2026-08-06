from __future__ import annotations

import hashlib

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

import labcourt.contracts.m6_replay_locked_closed_policy_execution as subject
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.config_loader import load_config
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry, UsageSummary
from labcourt.contracts.enums import ArtifactKind, CaseStatus, ReproducibilityMode
from labcourt.contracts.evidence import EvidencePack, EvidencePackDraft
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked import (
    M6ProviderCapabilityCounters,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedCandidateBindingAuthority,
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionRoute,
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2,
    M6ReplayLockedClosedPolicySampleExecutionRecordV2,
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedCandidateCaseBinding,
    M6ReplayLockedExecutionComponentAuthority,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import (
    ProceduralDefect,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
)
from labcourt.domain.alert_policy import plan_case_alert
from tests.contract.test_m3_contracts import (
    _parsed,
    _presence_pack,
    _review,
    _screening,
    _verdict,
)
from tests.contract.test_m6_replay_locked_alert_policy_contracts import (
    _closed_case,
    _cut,
)
from tests.contract.test_m6_replay_locked_execution_contracts import _scope
from tests.unit.test_m5_alert_policy import ROOT, _manifest_with_stream
from tests.unit.test_m6_replay_locked_policy_source import _observation
from tests.unit.test_m6_semantic_projection import _snapshot


def _identity(value: BaseModel) -> tuple[str, int]:
    document = canonical_json(value.model_dump(mode="json"))
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _authorities() -> tuple[
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
]:
    pre_policy_scope = _scope()
    component = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version="0.1.0",
        code_commit=pre_policy_scope.locked_manifest.code_commit,
        pre_policy_component_authority_id=(
            pre_policy_scope.execution_component.component_authority_id
        ),
        supported_pre_policy_routes=(M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,),
    )
    pre_policy_scope_sha, pre_policy_scope_size = _identity(pre_policy_scope)
    component_sha, component_size = _identity(component)
    scope = M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2(
        pre_policy_execution_scope=pre_policy_scope,
        pre_policy_execution_scope_content_sha256=pre_policy_scope_sha,
        pre_policy_execution_scope_size_bytes=pre_policy_scope_size,
        execution_component=component,
        execution_component_content_sha256=component_sha,
        execution_component_size_bytes=component_size,
    )

    entry = pre_policy_scope.execution_dataset.entries[0]
    pre_policy_pending = M6ReplayLockedPendingSampleCommitmentAuthority(
        execution_scope_authority_id=pre_policy_scope.execution_scope_authority_id,
        candidate_run_id=pre_policy_scope.candidate_run_id,
        command_id=pre_policy_scope.command.command_id,
        execution_dataset_snapshot_id=(
            pre_policy_scope.execution_dataset.execution_dataset_snapshot_id
        ),
        execution_component_authority_id=(
            pre_policy_scope.execution_component.component_authority_id
        ),
        source_catalog_entry_id=pre_policy_scope.source_catalog_entry_ids[0],
        route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        execution_entry=entry,
        ledger_sequence=0,
        previous_ledger_entry_hash="0" * 64,
    )
    cut = _cut()
    cut_sha, cut_size = _identity(cut)
    source_binding = M6ReplayLockedClosedPolicySourceBindingAuthority(
        source_catalog_entry_id=pre_policy_scope.source_catalog_entry_ids[0],
        sample_id=entry.sample_id,
        execution_entry_id=entry.execution_entry_id,
        replay_input_closure_authority_id=(entry.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(entry.replay_input_closure_document_sha256),
        pre_policy_route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        source_config_sha256=cut.source_config_sha256,
        policy_causal_cut_authority_id=cut.policy_causal_cut_authority_id,
        policy_causal_cut_content_sha256=cut_sha,
        policy_causal_cut_size_bytes=cut_size,
        cooldown_causal_head=cut.cooldown_causal_head,
        emergency_causal_basis=cut.emergency_causal_basis,
    )
    pending = M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        execution_component_authority_id=component.component_authority_id,
        locked_config_sha256=scope.locked_config_sha256,
        pre_policy_pending_commitment=pre_policy_pending,
        source_binding=source_binding,
    )
    return scope, pending


def _ready_case_for_run(manifest: RunManifest, run_id: str) -> Case:
    base = _presence_pack()
    event = base.event.model_copy(update={"manifest_id": manifest.manifest_id})
    draft = EvidencePackDraft(
        run_id=run_id,
        case_id=base.case_id,
        version=base.version,
        complete=base.complete,
        event=event,
        key_frame_ids=base.key_frame_ids,
        panorama_crops=base.panorama_crops,
        subject_crops=base.subject_crops,
        focus_crops=base.focus_crops,
        temporal_crops=base.temporal_crops,
        objective_facts=base.objective_facts,
        track_summary=base.track_summary,
        confirmation_record=base.confirmation_record,
        observation_sufficiency_input=base.observation_sufficiency_input,
        tool_results=base.tool_results,
        manifest_id=manifest.manifest_id,
    )
    pack = EvidencePack(
        **draft.model_dump(mode="python", exclude={"pack_id"}),
        closure_report=ClosureReport(
            run_id=draft.run_id,
            root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
            manifest_id=draft.manifest_id,
            input_sha256=draft.closure_input_sha256,
            checked_refs=draft.expected_closure_refs(),
        ),
    )
    parsed = _parsed(
        run_id=pack.run_id,
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        manifest_id=pack.manifest_id,
    )
    screening = _screening(parsed, l1_score=pack.event.l1_score)
    verdict = _verdict(screening)
    review = _review(verdict)
    return Case(
        run_id=pack.run_id,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=pack.event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        verdicts=(verdict,),
        procedural_reviews=(review,),
        manifest_id=pack.manifest_id,
    )


def test_fast_route_classification_retains_operational_timeline_and_usage() -> None:
    ready = _ready_case_for_run(_manifest_with_stream(), "m6-operational-fast-source")
    operational = Case.model_validate(
        {
            **ready.model_dump(mode="json", exclude_computed_fields=True),
            "timeline": (
                TimelineEntry(
                    sequence=0,
                    action="CASE_STATE_CHANGED",
                    stage="M3_SCREENING",
                    object_ref=ready.case_id,
                    details={"status": CaseStatus.READY_FOR_ALERT_POLICY.value},
                ).model_dump(mode="json"),
            ),
            "usage": UsageSummary(
                input_images=1,
                input_pixels=20_000,
                input_tokens=23,
                output_tokens=11,
                provider_latency_ms=17,
            ).model_dump(mode="json"),
        }
    )

    assert subject._is_fast_ready_case(operational)


def _closed_terminal() -> M6ReplayLockedClosedPolicyExecutionSealAuthorityV2:
    observation = _observation()
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    closure = observation.replay_input_closure
    manifest = _manifest_with_stream()
    config = load_config(ROOT / "configs/demo.yaml")
    entry = M6RegressionExecutionEntry(
        sample_id=closure.sample_id,
        input_authority_id=closure.input_authority_id,
        input_authority_document_sha256=(closure.input_authority_document_sha256),
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
    )
    source_catalog_document_sha256 = _sha("closed-policy-source-catalog")
    source_catalog_entry_id = _sha("closed-policy-source-catalog-entry")
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=manifest.manifest_id,
        source_catalog_authority_id=_sha("closed-policy-source-catalog-authority"),
        source_catalog_document_sha256=source_catalog_document_sha256,
        entries=(entry,),
    )
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=manifest.manifest_id,
        candidate_manifest_id=manifest.manifest_id,
        policy_authority=M6RegressionPolicyAuthority(
            config_sha256=config.config_sha256,
            policy_version="m6-replay-locked-closed-policy-v2",
            maximum_machine_flip_rate=0.05,
            gold_set_max_accuracy_drop=0.0,
        ),
    )
    pre_policy_component = M6ReplayLockedExecutionComponentAuthority(
        version="0.1.0",
        code_commit=manifest.code_commit,
    )
    command_sha, command_size = _identity(command)
    dataset_sha, dataset_size = _identity(dataset)
    manifest_sha, manifest_size = _identity(manifest)
    config_sha, config_size = _identity(config)
    pre_component_sha, pre_component_size = _identity(pre_policy_component)
    pre_policy_scope = M6ReplayLockedExecutionScopeAuthority(
        candidate_run_id="m6-closed-policy-candidate-run",
        command=command,
        command_content_sha256=command_sha,
        command_size_bytes=command_size,
        execution_dataset=dataset,
        execution_dataset_content_sha256=dataset_sha,
        execution_dataset_size_bytes=dataset_size,
        source_catalog_content_sha256=source_catalog_document_sha256,
        source_catalog_size_bytes=1,
        source_catalog_entry_count=1,
        source_catalog_entry_ids=(source_catalog_entry_id,),
        source_run_ids=(closure.source_run_id,),
        locked_manifest=manifest,
        locked_manifest_content_sha256=manifest_sha,
        locked_manifest_size_bytes=manifest_size,
        locked_config=config,
        locked_config_content_sha256=config_sha,
        locked_config_size_bytes=config_size,
        execution_component=pre_policy_component,
        execution_component_content_sha256=pre_component_sha,
        execution_component_size_bytes=pre_component_size,
        execution_start_audit_head_sequence=-1,
        execution_start_audit_head_hash=AUDIT_GENESIS_HASH,
    )
    component = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version="0.1.0",
        code_commit=manifest.code_commit,
        pre_policy_component_authority_id=pre_policy_component.component_authority_id,
        supported_pre_policy_routes=pre_policy_component.supported_routes,
    )
    pre_scope_sha, pre_scope_size = _identity(pre_policy_scope)
    component_sha, component_size = _identity(component)
    scope = M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2(
        pre_policy_execution_scope=pre_policy_scope,
        pre_policy_execution_scope_content_sha256=pre_scope_sha,
        pre_policy_execution_scope_size_bytes=pre_scope_size,
        execution_component=component,
        execution_component_content_sha256=component_sha,
        execution_component_size_bytes=component_size,
    )
    pre_policy_pending = M6ReplayLockedPendingSampleCommitmentAuthority(
        execution_scope_authority_id=pre_policy_scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset_snapshot_id,
        execution_component_authority_id=(pre_policy_component.component_authority_id),
        source_catalog_entry_id=source_catalog_entry_id,
        route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        execution_entry=entry,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    cut_sha, cut_size = _identity(cut)
    source_binding = M6ReplayLockedClosedPolicySourceBindingAuthority(
        source_catalog_entry_id=source_catalog_entry_id,
        sample_id=entry.sample_id,
        execution_entry_id=entry.execution_entry_id,
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
        pre_policy_route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        source_config_sha256=cut.source_config_sha256,
        policy_causal_cut_authority_id=cut.policy_causal_cut_authority_id,
        policy_causal_cut_content_sha256=cut_sha,
        policy_causal_cut_size_bytes=cut_size,
        cooldown_causal_head=cut.cooldown_causal_head,
        emergency_causal_basis=cut.emergency_causal_basis,
    )
    pending = M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        execution_component_authority_id=component.component_authority_id,
        locked_config_sha256=config.config_sha256,
        pre_policy_pending_commitment=pre_policy_pending,
        source_binding=source_binding,
    )
    candidate_ready = _ready_case_for_run(manifest, scope.candidate_run_id)
    candidate_policy = plan_case_alert(
        candidate_ready,
        config,
        manifest,
        prior_cooldown=cut.cooldown_causal_head.prior_authority,
        prior_emergency_delivery=None,
    )
    candidate_closed = _closed_case(candidate_ready, candidate_policy)
    closed_sha, closed_size = _identity(candidate_closed)
    persisted = M6ReplayLockedCandidateCaseBinding(
        candidate_run_id=scope.candidate_run_id,
        sample_id=entry.sample_id,
        case_id=candidate_closed.case_id,
        case_revision=1,
        case_document_sha256=closed_sha,
        case_document_size_bytes=closed_size,
        case_audit_sequence=0,
        case_audit_entry_hash=_sha("closed-policy-candidate-case-audit"),
    )
    candidate = M6ReplayLockedClosedCandidateBindingAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        pending_commitment_authority_id=pending.pending_commitment_authority_id,
        source_binding_authority_id=source_binding.source_binding_authority_id,
        policy_causal_cut_authority_id=cut.policy_causal_cut_authority_id,
        pre_policy_route=pending.pre_policy_route,
        locked_config_sha256=config.config_sha256,
        transient_ready_case=candidate_ready,
        candidate_alert_policy=candidate_policy,
        closed_candidate_case=candidate_closed,
        persisted_candidate_case=persisted,
    )
    source_snapshot = _snapshot(
        observation.source_closed_case,
        revision=closure.source_case_revision,
    ).model_copy(update={"sample_id": closure.sample_id})
    candidate_snapshot = _snapshot(candidate_closed, revision=1).model_copy(
        update={"sample_id": closure.sample_id}
    )
    proof = M6ReplayLockedSourceDeterminismAuthority(
        command_id=scope.command_id,
        execution_entry_id=entry.execution_entry_id,
        sample_id=entry.sample_id,
        source_run_id=closure.source_run_id,
        candidate_run_id=scope.candidate_run_id,
        source_manifest_id=closure.source_manifest_id,
        execution_component_manifest_id=(pre_policy_component.component_authority_id),
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
        source_identity_sha256=cut.source_identity_sha256,
        first_source_snapshot_id=source_snapshot.snapshot_id,
        second_source_snapshot_id=source_snapshot.snapshot_id,
        first_semantic_case_hash=source_snapshot.semantic_case_hash,
        second_semantic_case_hash=source_snapshot.semantic_case_hash,
    )
    record = M6ReplayLockedClosedPolicySampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset_snapshot_id,
        candidate_manifest_id=scope.candidate_manifest_id,
        execution_entry=entry,
        pending_commitment=pending,
        replay_input_closure=closure,
        source_determinism=proof,
        policy_causal_cut=cut,
        closed_candidate_binding=candidate,
        candidate_snapshot=candidate_snapshot,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    inventory_root = sha256_hex(
        [
            "m6-replay-locked-closed-policy-sample-execution-inventory",
            2,
            [record.sample_execution_record_id],
        ]
    )
    trap = M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        command_id=scope.command_id,
        candidate_run_id=scope.candidate_run_id,
        execution_component_authority_id=component.component_authority_id,
        counters=M6ProviderCapabilityCounters(),
        sealed_sample_execution_count=1,
        sealed_sample_execution_inventory_root_sha256=inventory_root,
        terminal_ledger_sequence=0,
        terminal_sample_execution_record_id=record.sample_execution_record_id,
    )
    scope_sha, scope_size = _identity(scope)
    return M6ReplayLockedClosedPolicyExecutionSealAuthorityV2(
        execution_scope=scope,
        execution_scope_content_sha256=scope_sha,
        execution_scope_size_bytes=scope_size,
        candidate_audit_head_sequence=0,
        candidate_audit_head_hash=persisted.case_audit_entry_hash,
        sample_executions=(record,),
        run_trap_seal=trap,
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value))
    return set()


def test_closed_policy_pending_prebinds_candidate_safe_cut_identity() -> None:
    scope, pending = _authorities()

    assert pending.route == M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED
    assert pending.execution_scope_authority_id == scope.execution_scope_authority_id
    assert (
        pending.pre_policy_execution_scope_authority_id
        == scope.pre_policy_execution_scope_authority_id
    )
    assert (
        pending.pre_policy_execution_component_authority_id
        == scope.execution_component.pre_policy_component_authority_id
    )
    assert pending.sample_id == pending.source_binding.sample_id
    assert pending.execution_entry_id == pending.source_binding.execution_entry_id
    assert (
        pending.policy_causal_cut_authority_id
        == pending.source_binding.policy_causal_cut_authority_id
    )

    wire = pending.model_dump(mode="json")
    keys = _all_keys(wire)
    assert "policy_causal_cut" not in keys
    assert "source_ready_case" not in keys
    assert "source_closed_case" not in keys
    assert "source_alert_policy" not in keys
    assert "final_decision" not in keys
    assert scope.execution_component.evaluator_fields_accessible is False
    assert scope.execution_component.alert_channel_ports_exposed is False
    assert scope.execution_component.cooldown_write_ports_exposed is False
    assert scope.execution_component.outbox_write_ports_exposed is False


def test_closed_policy_scope_rejects_mismatched_pre_policy_component() -> None:
    scope, _ = _authorities()
    mismatched = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version=scope.execution_component.version,
        code_commit=scope.execution_component.code_commit,
        pre_policy_component_authority_id=(
            scope.execution_component.pre_policy_component_authority_id
        ),
        supported_pre_policy_routes=(
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        ),
    )
    mismatched_sha, mismatched_size = _identity(mismatched)
    payload = scope.model_dump(mode="json", exclude_computed_fields=True)
    payload.update(
        {
            "execution_component": mismatched.model_dump(mode="json"),
            "execution_component_content_sha256": mismatched_sha,
            "execution_component_size_bytes": mismatched_size,
        }
    )

    with pytest.raises(ValidationError, match="exact offline start cut"):
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sample_id", "another-sample"),
        ("execution_entry_id", "1" * 64),
        ("replay_input_closure_authority_id", "2" * 64),
        ("replay_input_closure_document_sha256", "3" * 64),
        (
            "pre_policy_route",
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE.value,
        ),
    ),
)
def test_closed_policy_pending_rejects_source_binding_drift(
    field: str,
    value: object,
) -> None:
    _, pending = _authorities()
    payload = pending.model_dump(mode="json", exclude_computed_fields=True)
    source_binding = pending.source_binding.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    source_binding[field] = value
    payload["source_binding"] = source_binding

    with pytest.raises(ValidationError, match="frozen source cut"):
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2.model_validate(payload)


def test_closed_policy_start_contracts_round_trip_and_reject_spoofed_ids() -> None:
    scope, pending = _authorities()
    models = (
        scope.execution_component,
        scope,
        pending.source_binding,
        pending,
    )
    for model in models:
        model_type = type(model)
        wire = model.model_dump(mode="json")
        assert model_type.model_validate(wire) == model
        schema = model_type.model_json_schema(mode="serialization")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(wire)

    spoofed = pending.model_dump(mode="json")
    spoofed["pending_commitment_authority_id"] = "f" * 64
    with pytest.raises(ValidationError, match="serialized pending_commitment_authority_id"):
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2.model_validate(spoofed)


def test_closed_policy_record_and_seal_close_only_the_final_candidate() -> None:
    seal = _closed_terminal()
    record = seal.sample_executions[0]
    candidate = record.closed_candidate_binding

    assert candidate.transient_ready_case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert candidate.closed_candidate_case.status == CaseStatus.CLOSED
    assert candidate.persisted_candidate_case.case_revision == 1
    assert (
        candidate.persisted_candidate_case.case_document_sha256
        == candidate.closed_candidate_case_content_sha256
    )
    assert (
        record.policy_causal_cut.policy_causal_cut_authority_id
        == record.pending_commitment.policy_causal_cut_authority_id
    )
    assert record.candidate_semantic_case_hash == record.source_semantic_case_hash
    assert record.candidate_snapshot_id != record.source_snapshot_id
    assert seal.run_trap_seal.persisted_transient_ready_case_count == 0
    assert seal.run_trap_seal.candidate_alert_outbox_write_count == 0
    assert seal.run_trap_seal.candidate_cooldown_write_count == 0
    assert seal.execution_receipts[0].candidate_snapshot_id == record.candidate_snapshot_id


def test_closed_policy_record_rejects_full_cut_that_differs_from_pending() -> None:
    record = _closed_terminal().sample_executions[0]
    payload = record.model_dump(mode="json", exclude_computed_fields=True)
    causal_cut = record.policy_causal_cut.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    causal_cut["source_m5_authority_root_sha256"] = "e" * 64
    payload["policy_causal_cut"] = causal_cut

    with pytest.raises(ValidationError, match="prebound safe identity"):
        M6ReplayLockedClosedPolicySampleExecutionRecordV2.model_validate(payload)


def test_closed_policy_candidate_rejects_rework_before_consuming_cut() -> None:
    candidate = _closed_terminal().sample_executions[0].closed_candidate_binding
    payload = candidate.model_dump(mode="json", exclude_computed_fields=True)
    ready = candidate.transient_ready_case
    verdict = ready.verdicts[-1]
    defect = ProceduralDefect(
        code=ProceduralDefectCode.VIOLATION_TYPE_MISMATCH,
        origin=ProceduralDefectOrigin.PROCEDURAL_GATE,
        reason_code=ProceduralReasonCode.CASE_VIOLATION_CONFLICT,
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.VERDICT,
            artifact_id=verdict.verdict_id,
        ),
        field=ProceduralField.VIOLATION_TYPE,
        related_refs=(ArtifactRef(kind=ArtifactKind.CASE, artifact_id=ready.case_id),),
    )
    failed_review = _review(
        verdict,
        defects=(defect,),
    )
    rework = ready.model_copy(
        update={
            "status": CaseStatus.REWORK_REQUIRED,
            "procedural_reviews": (failed_review,),
        }
    )
    payload["transient_ready_case"] = rework.model_dump(mode="json")

    with pytest.raises(ValidationError, match="REWORK cannot consume a cut"):
        M6ReplayLockedClosedCandidateBindingAuthority.model_validate(payload)


def test_closed_policy_trap_rejects_policy_side_effects() -> None:
    trap = _closed_terminal().run_trap_seal
    payload = trap.model_dump(mode="json", exclude_computed_fields=True)
    payload["candidate_alert_outbox_write_count"] = 1

    with pytest.raises(ValidationError):
        M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2.model_validate(payload)


def test_closed_policy_terminal_contracts_round_trip_and_validate_schemas() -> None:
    seal = _closed_terminal()
    record = seal.sample_executions[0]
    models = (
        record.closed_candidate_binding,
        record,
        seal.run_trap_seal,
        seal,
    )
    for model in models:
        model_type = type(model)
        wire = model.model_dump(mode="json")
        assert model_type.model_validate(wire) == model
        schema = model_type.model_json_schema(mode="serialization")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(wire)
