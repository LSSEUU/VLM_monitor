from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.application.m6_regression_source_catalog import (
    build_m6_regression_source_catalog,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import CaseStatus, ReproducibilityMode, VerdictDecision
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
    M6RegressionStage,
    M6SemanticStageRoot,
)
from labcourt.contracts.m6_replay_locked import (
    M6ProviderCapabilityCounters,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedCandidateCaseBinding,
    M6ReplayLockedExecutionComponentAuthority,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    M6ReplayLockedRunTrapSealAuthority,
    M6ReplayLockedSampleExecutionRecord,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.schema_export import expected_schema_files
from tests.unit.test_m6_regression_source_catalog import _sealed_source
from tests.unit.test_m6_replay_locked_execution_scope import _inputs
from tests.unit.test_m6_source_authority import _bundle


def _identity(value: object) -> tuple[str, int]:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _scope() -> M6ReplayLockedExecutionScopeAuthority:
    run_scope, source = _sealed_source()
    catalog_bundle = build_m6_regression_source_catalog(
        run_scopes=(run_scope,),
        sealed_sources=(source,),
    )
    catalog = catalog_bundle.execution_source_catalog
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=catalog.baseline_manifest_id,
        source_catalog_authority_id=catalog.source_catalog_authority_id,
        source_catalog_document_sha256=(catalog_bundle.execution_source_catalog_content_sha256),
        entries=tuple(
            M6RegressionExecutionEntry(
                sample_id=item.sample_id,
                input_authority_id=item.input_authority_id,
                input_authority_document_sha256=item.input_authority_document_sha256,
                replay_input_closure_authority_id=(
                    item.replay_input_closure.replay_input_closure_authority_id
                ),
                replay_input_closure_document_sha256=(
                    item.replay_input_closure.replay_input_closure_document_sha256
                ),
            )
            for item in catalog.entries
        ),
    )
    config = _bundle().config
    manifest = source.source_manifest
    assert config.config_sha256 == manifest.config_sha256
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=manifest.manifest_id,
        candidate_manifest_id=manifest.manifest_id,
        policy_authority=M6RegressionPolicyAuthority(
            config_sha256=config.config_sha256,
            policy_version="m6-replay-locked-m3-fast-v1",
            maximum_machine_flip_rate=0.05,
            gold_set_max_accuracy_drop=0.0,
        ),
    )
    component = M6ReplayLockedExecutionComponentAuthority(
        version="0.1.0",
        code_commit=manifest.code_commit,
    )
    command_sha, command_size = _identity(command)
    dataset_sha, dataset_size = _identity(dataset)
    manifest_sha, manifest_size = _identity(manifest)
    config_sha, config_size = _identity(config)
    component_sha, component_size = _identity(component)
    source_run_ids = tuple(
        sorted({entry.replay_input_closure.source_run_id for entry in catalog.entries})
    )
    return M6ReplayLockedExecutionScopeAuthority(
        candidate_run_id="m6-locked-candidate-run",
        command=command,
        command_content_sha256=command_sha,
        command_size_bytes=command_size,
        execution_dataset=dataset,
        execution_dataset_content_sha256=dataset_sha,
        execution_dataset_size_bytes=dataset_size,
        source_catalog_content_sha256=(catalog_bundle.execution_source_catalog_content_sha256),
        source_catalog_size_bytes=len(
            catalog_bundle.execution_source_catalog_document.encode("utf-8")
        ),
        source_catalog_entry_count=catalog.entry_count,
        source_catalog_entry_ids=tuple(item.catalog_entry_id for item in catalog.entries),
        source_run_ids=source_run_ids,
        locked_manifest=manifest,
        locked_manifest_content_sha256=manifest_sha,
        locked_manifest_size_bytes=manifest_size,
        locked_config=config,
        locked_config_content_sha256=config_sha,
        locked_config_size_bytes=config_size,
        execution_component=component,
        execution_component_content_sha256=component_sha,
        execution_component_size_bytes=component_size,
        execution_start_audit_head_sequence=-1,
        execution_start_audit_head_hash=AUDIT_GENESIS_HASH,
    )


def _locked_terminal() -> M6ReplayLockedExecutionSealAuthority:
    inputs = _inputs()
    scope = build_m6_replay_locked_execution_scope(**inputs)
    stored = inputs["stored_source_catalog"]
    assert isinstance(stored, M6StoredRegressionExecutionSourceCatalog)
    entry = scope.execution_dataset.entries[0]
    catalog_entry = stored.source_catalog.entries[0]
    closure = catalog_entry.replay_input_closure
    case_document_sha256 = hashlib.sha256(b"independent-candidate-case").hexdigest()
    candidate_case = M6ReplayLockedCandidateCaseBinding(
        candidate_run_id=scope.candidate_run_id,
        sample_id=entry.sample_id,
        case_id="candidate-case-001",
        case_revision=1,
        case_document_sha256=case_document_sha256,
        case_document_size_bytes=1_024,
        case_audit_sequence=0,
        case_audit_entry_hash=hashlib.sha256(b"candidate-audit-entry").hexdigest(),
    )
    candidate_snapshot = M6CaseReplaySnapshot(
        sample_id=entry.sample_id,
        source_run_id=scope.candidate_run_id,
        source_case_id=candidate_case.case_id,
        source_case_revision=candidate_case.case_revision,
        source_case_document_sha256=candidate_case.case_document_sha256,
        manifest_id=scope.locked_manifest.manifest_id,
        stage_roots=tuple(
            M6SemanticStageRoot(
                stage=stage,
                projection_sha256=hashlib.sha256(stage.value.encode("utf-8")).hexdigest(),
            )
            for stage in M6RegressionStage
        ),
        case_status=CaseStatus.CLOSED,
        final_decision=VerdictDecision.ESTABLISHED,
    )
    source_proof = M6ReplayLockedSourceDeterminismAuthority(
        command_id=scope.command.command_id,
        execution_entry_id=entry.execution_entry_id,
        sample_id=entry.sample_id,
        source_run_id=closure.source_run_id,
        candidate_run_id=scope.candidate_run_id,
        source_manifest_id=closure.source_manifest_id,
        execution_component_manifest_id=(scope.execution_component.component_authority_id),
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
        source_identity_sha256=hashlib.sha256(b"source-snapshot-identity").hexdigest(),
        first_source_snapshot_id=hashlib.sha256(b"source-snapshot").hexdigest(),
        second_source_snapshot_id=hashlib.sha256(b"source-snapshot").hexdigest(),
        first_semantic_case_hash=candidate_snapshot.semantic_case_hash,
        second_semantic_case_hash=candidate_snapshot.semantic_case_hash,
    )
    pending = M6ReplayLockedPendingSampleCommitmentAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
        execution_component_authority_id=(scope.execution_component.component_authority_id),
        source_catalog_entry_id=catalog_entry.catalog_entry_id,
        route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        execution_entry=entry,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    record = M6ReplayLockedSampleExecutionRecord(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
        candidate_manifest_id=scope.locked_manifest.manifest_id,
        route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        execution_entry=entry,
        pending_commitment=pending,
        replay_input_closure=closure,
        source_determinism=source_proof,
        candidate_case=candidate_case,
        candidate_snapshot=candidate_snapshot,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    record_inventory_root = sha256_hex(
        [
            "m6-replay-locked-sample-execution-inventory",
            1,
            [record.sample_execution_record_id],
        ]
    )
    trap = M6ReplayLockedRunTrapSealAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        command_id=scope.command.command_id,
        candidate_run_id=scope.candidate_run_id,
        execution_component_authority_id=(scope.execution_component.component_authority_id),
        counters=M6ProviderCapabilityCounters(),
        sealed_sample_execution_count=1,
        sealed_sample_execution_inventory_root_sha256=record_inventory_root,
        terminal_ledger_sequence=0,
        terminal_sample_execution_record_id=record.sample_execution_record_id,
    )
    scope_sha256, scope_size = _identity(scope)
    return M6ReplayLockedExecutionSealAuthority(
        execution_scope=scope,
        execution_scope_content_sha256=scope_sha256,
        execution_scope_size_bytes=scope_size,
        candidate_audit_head_sequence=0,
        candidate_audit_head_hash=candidate_case.case_audit_entry_hash,
        sample_executions=(record,),
        run_trap_seal=trap,
    )


def test_scope_freezes_exact_blinded_offline_locked_start_cut() -> None:
    scope = _scope()

    assert scope.command.mode == ReproducibilityMode.REPLAY_LOCKED
    assert scope.command.baseline_manifest_id == scope.command.candidate_manifest_id
    assert scope.candidate_run_id not in scope.source_run_ids
    assert len(scope.source_catalog_entry_ids) == scope.source_catalog_entry_count
    assert scope.execution_start_audit_head_sequence == -1
    assert scope.execution_start_audit_head_hash == AUDIT_GENESIS_HASH
    assert not scope.execution_component.network_allowed
    assert not scope.execution_component.provider_ports_exposed
    assert not scope.execution_component.recovery_ports_exposed
    assert not scope.execution_component.cache_write_ports_exposed
    assert not scope.execution_component.live_tail_ports_exposed
    assert not scope.execution_component.raw_model_response_accessible
    assert not scope.execution_component.safety_signal_accessible
    assert M6ReplayLockedExecutionScopeAuthority.model_validate(scope.model_dump(mode="json")) == (
        scope
    )
    serialized = canonical_json(scope.model_dump(mode="json"))
    for forbidden in (
        "memberships",
        "baseline_snapshot",
        "gold_truth",
        "expected_decision",
        "provider_trap",
        "candidate_snapshot",
    ):
        assert forbidden not in serialized


def test_scope_rejects_source_run_reuse_and_non_locked_command() -> None:
    scope = _scope()

    with pytest.raises(ValidationError, match="differ from every source run"):
        scope.model_copy(update={"candidate_run_id": scope.source_run_ids[0]})

    command = scope.command.model_copy(update={"mode": ReproducibilityMode.REINFER_PINNED})
    command_sha, command_size = _identity(command)
    with pytest.raises(ValidationError, match="exact offline start cut"):
        scope.model_copy(
            update={
                "command": command,
                "command_content_sha256": command_sha,
                "command_size_bytes": command_size,
            }
        )


@pytest.mark.parametrize("candidate_run_id", ["NUL", "CON.txt", "run."])
def test_scope_rejects_a_nonportable_candidate_run_id(candidate_run_id: str) -> None:
    with pytest.raises(ValidationError, match="portable run filesystem identity"):
        _scope().model_copy(update={"candidate_run_id": candidate_run_id})


@pytest.mark.parametrize(
    "update",
    [
        {"execution_start_audit_head_sequence": 0},
        {"execution_start_audit_head_hash": "1" * 64},
    ],
)
def test_scope_rejects_a_non_fresh_candidate_run_start_cut(
    update: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="fresh audit genesis"):
        _scope().model_copy(update=update)


@pytest.mark.parametrize(
    "update",
    [
        {"source_catalog_content_sha256": "0" * 64},
        {"source_catalog_entry_count": 2},
        {"execution_dataset_content_sha256": "0" * 64},
        {"locked_manifest_content_sha256": "0" * 64},
        {"locked_config_content_sha256": "0" * 64},
        {"execution_component_content_sha256": "0" * 64},
    ],
)
def test_scope_rejects_any_physical_or_catalog_identity_graft(
    update: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _scope().model_copy(update=update)


def test_component_capability_flags_cannot_be_relaxed() -> None:
    component = _scope().execution_component
    payload = component.model_dump(mode="python", exclude_computed_fields=True)

    for field in (
        "network_allowed",
        "gpu_required",
        "evaluator_fields_accessible",
        "provider_ports_exposed",
        "recovery_ports_exposed",
        "cache_write_ports_exposed",
        "live_tail_ports_exposed",
        "raw_model_response_accessible",
        "safety_signal_accessible",
    ):
        with pytest.raises(ValidationError):
            M6ReplayLockedExecutionComponentAuthority(**{**payload, field: True})


def test_component_adds_m4_terminal_route_without_changing_the_m3_default_vector() -> None:
    component = _scope().execution_component

    assert component.supported_routes == (M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,)
    assert component.component_authority_id == (
        "a5acd1e4ccc3fe77125d960e135b2b63cc21ea6455b081ed44b9671cd6fb5583"
    )
    extended = M6ReplayLockedExecutionComponentAuthority(
        version=component.version,
        code_commit=component.code_commit,
        supported_routes=(
            M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        ),
    )

    assert extended.supported_routes[-1] == (
        M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    )
    assert extended.component_authority_id != component.component_authority_id


def test_existing_m3_execution_identity_chain_remains_frozen() -> None:
    seal = _locked_terminal()
    scope = seal.execution_scope
    record = seal.sample_executions[0]

    assert scope.execution_component.component_authority_id == (
        "a5acd1e4ccc3fe77125d960e135b2b63cc21ea6455b081ed44b9671cd6fb5583"
    )
    assert scope.execution_scope_authority_id == (
        "72f6984651302aa1773793757783b2f8f7eec1534e4e91926075a99738a67096"
    )
    assert record.pending_commitment_authority_id == (
        "6f433a9225a9d822f7b9d2fea0ff4c129527880bd0d921702e52553ec1e8a793"
    )
    assert record.sample_execution_record_id == (
        "157a7f4261c14122f9d430b0d3cd4254b1c9afcb730a87f8e3fce34da9b34320"
    )
    assert seal.execution_seal_authority_id == (
        "6fc421c5daf5e278f4c5f972accbb35c4e14bedba785e11b3ec6483145800d9d"
    )


def test_pending_and_record_hashes_are_route_domain_separated() -> None:
    m3_record = _locked_terminal().sample_executions[0]
    m4_pending = M6ReplayLockedPendingSampleCommitmentAuthority.model_validate(
        {
            **m3_record.pending_commitment.model_dump(
                mode="json",
                exclude_computed_fields=True,
            ),
            "route": M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        }
    )
    m4_record = M6ReplayLockedSampleExecutionRecord.model_validate(
        {
            **m3_record.model_dump(mode="json", exclude_computed_fields=True),
            "route": M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
            "pending_commitment": m4_pending.model_dump(mode="json"),
        }
    )

    assert m4_pending.pending_commitment_authority_id != (m3_record.pending_commitment_authority_id)
    assert m4_record.sample_execution_record_id != m3_record.sample_execution_record_id


def test_locked_execution_schemas_validate_complete_documents() -> None:
    scope = _scope()
    schemas = expected_schema_files()

    for name, artifact in (
        ("m6-replay-locked-execution-component-authority", scope.execution_component),
        ("m6-replay-locked-execution-scope-authority", scope),
    ):
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))


def test_terminal_seal_derives_one_run_wide_trap_and_every_receipt() -> None:
    seal = _locked_terminal()
    record = seal.sample_executions[0]
    receipt = seal.execution_receipts[0]

    assert record.source_snapshot_id != record.candidate_snapshot_id
    assert record.source_semantic_case_hash == record.candidate_semantic_case_hash
    assert seal.run_trap_seal.clean
    assert seal.run_trap_seal.external_capability_call_count == 0
    assert receipt.provider_call_count == 0
    assert receipt.provider_trap_authority_id == (
        seal.run_trap_seal.provider_trap.provider_trap_authority_id
    )
    assert receipt.candidate_snapshot_id == record.candidate_snapshot_id
    assert receipt.execution_component_manifest_id == (
        seal.execution_scope.execution_component.component_authority_id
    )
    assert M6ReplayLockedExecutionSealAuthority.model_validate(seal.model_dump(mode="json")) == seal


def test_sample_record_rejects_a_source_snapshot_copy_or_semantic_divergence() -> None:
    record = _locked_terminal().sample_executions[0]
    closure = record.replay_input_closure
    assert closure.source_case_id is not None
    assert closure.source_case_document_sha256 is not None

    copied_case = record.candidate_case.model_copy(
        update={
            "case_id": closure.source_case_id,
            "case_document_sha256": closure.source_case_document_sha256,
        }
    )
    with pytest.raises(ValidationError, match="independent persisted output"):
        record.model_copy(update={"candidate_case": copied_case})

    roots = list(record.candidate_snapshot.stage_roots)
    roots[0] = roots[0].model_copy(update={"projection_sha256": "f" * 64})
    divergent = record.candidate_snapshot.model_copy(update={"stage_roots": tuple(roots)})
    with pytest.raises(ValidationError, match="source-semantically identical"):
        record.model_copy(update={"candidate_snapshot": divergent})


def test_sample_record_rejects_a_foreign_entry_closure_or_source_proof() -> None:
    record = _locked_terminal().sample_executions[0]

    foreign_closure = record.replay_input_closure.model_copy(
        update={"input_authority_id": "f" * 64}
    )
    with pytest.raises(ValidationError, match="input closure differs"):
        record.model_copy(update={"replay_input_closure": foreign_closure})

    foreign_proof = record.source_determinism.model_copy(update={"command_id": "e" * 64})
    with pytest.raises(ValidationError, match="sample execution scope"):
        record.model_copy(update={"source_determinism": foreign_proof})

    foreign_pending = record.pending_commitment.model_copy(
        update={"source_catalog_entry_id": "d" * 64}
    )
    forged_record = record.model_copy(update={"pending_commitment": foreign_pending})
    seal = _locked_terminal()
    with pytest.raises(ValidationError, match="sample chain or execution scope"):
        seal.model_copy(update={"sample_executions": (forged_record,)})


def test_run_trap_rejects_any_external_capability_use() -> None:
    trap = _locked_terminal().run_trap_seal

    with pytest.raises(ValidationError, match="external capability call"):
        trap.model_copy(
            update={
                "counters": M6ProviderCapabilityCounters(
                    cache_write_calls=1,
                    live_precedent_tail_query_calls=1,
                )
            }
        )


def test_terminal_seal_rejects_foreign_component_chain_and_audit_head() -> None:
    seal = _locked_terminal()
    record = seal.sample_executions[0]
    foreign_proof = record.source_determinism.model_copy(
        update={"execution_component_manifest_id": "f" * 64}
    )
    foreign_record = record.model_copy(update={"source_determinism": foreign_proof})

    with pytest.raises(ValidationError, match="sample chain or execution scope"):
        seal.model_copy(update={"sample_executions": (foreign_record,)})
    with pytest.raises(ValidationError, match="terminal Case anchor"):
        seal.model_copy(update={"candidate_audit_head_hash": "f" * 64})


def test_serialized_receipt_and_trap_claims_cannot_be_injected() -> None:
    seal = _locked_terminal()
    payload = seal.model_dump(mode="json")
    payload["execution_receipts"][0]["provider_call_count"] = 1
    with pytest.raises(ValidationError, match="execution_receipts"):
        M6ReplayLockedExecutionSealAuthority.model_validate(payload)

    trap_payload = seal.run_trap_seal.model_dump(mode="json")
    trap_payload["provider_trap"]["candidate_run_id"] = "foreign-run"
    with pytest.raises(ValidationError, match="provider_trap"):
        M6ReplayLockedRunTrapSealAuthority.model_validate(trap_payload)


def test_locked_terminal_execution_schemas_validate_complete_documents() -> None:
    seal = _locked_terminal()
    record = seal.sample_executions[0]
    schemas = expected_schema_files()

    for name, artifact in (
        ("m6-replay-locked-candidate-case-binding", record.candidate_case),
        (
            "m6-replay-locked-pending-sample-commitment",
            record.pending_commitment,
        ),
        ("m6-replay-locked-sample-execution-record", record),
        ("m6-replay-locked-run-trap-seal-authority", seal.run_trap_seal),
        ("m6-replay-locked-execution-seal-authority", seal),
    ):
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))
