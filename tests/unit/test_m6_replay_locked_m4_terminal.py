from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_replay_locked_m4_terminal import (
    M6ReplayLockedM4TerminalError,
    M6ReplayLockedM4TerminalErrorCode,
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionComponentAuthority,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.domain.m6_model_reference_authority import M6CaseModelReferenceAuthority
from labcourt.domain.m6_semantic_projection import (
    M6ReplayLockedM4CandidateProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)
from tests.unit.test_m6_replay_locked_execution_scope import _inputs
from tests.unit.test_m6_replay_locked_m4_source import _terminal_source


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(value: object) -> tuple[str, int]:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _execution(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    M6ReplayLockedM4GateTerminalSource,
]:
    inputs = _inputs()
    config = inputs["locked_config"]
    manifest = inputs["locked_manifest"]
    template_component = inputs["execution_component"]
    template_command = inputs["command"]
    source = _terminal_source(monkeypatch)
    manifest_sha, manifest_size = _identity(manifest)
    closure = source.closure.model_copy(update={"source_manifest_document_sha256": manifest_sha})
    source = M6ReplayLockedM4GateTerminalSource(
        source_identity_sha256=source.source_identity_sha256,
        closure=closure,
        projection_context=source.projection_context,
        hearing_record=source.hearing_record,
        hearing_verdict_binding=source.hearing_verdict_binding,
        gate_current_closure_receipt=source.gate_current_closure_receipt,
        source_snapshot=source.source_snapshot,
    )
    entry = M6RegressionExecutionEntry(
        sample_id=closure.sample_id,
        input_authority_id=closure.input_authority_id,
        input_authority_document_sha256=closure.input_authority_document_sha256,
        replay_input_closure_authority_id=(closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
    )
    catalog_id = _sha("m4-gate-terminal-catalog-authority")
    catalog_document_sha = _sha("m4-gate-terminal-catalog-document")
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        source_catalog_authority_id=catalog_id,
        source_catalog_document_sha256=catalog_document_sha,
        entries=(entry,),
    )
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        candidate_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        policy_authority=template_command.policy_authority,  # type: ignore[union-attr]
    )
    component = M6ReplayLockedExecutionComponentAuthority(
        version=template_component.version,  # type: ignore[union-attr]
        code_commit=template_component.code_commit,  # type: ignore[union-attr]
        supported_routes=(
            M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        ),
    )
    command_sha, command_size = _identity(command)
    dataset_sha, dataset_size = _identity(dataset)
    config_sha, config_size = _identity(config)
    component_sha, component_size = _identity(component)
    catalog_entry_id = _sha("m4-gate-terminal-catalog-entry")
    scope = M6ReplayLockedExecutionScopeAuthority(
        candidate_run_id="m6-m4-gate-terminal-candidate-run",
        command=command,
        command_content_sha256=command_sha,
        command_size_bytes=command_size,
        execution_dataset=dataset,
        execution_dataset_content_sha256=dataset_sha,
        execution_dataset_size_bytes=dataset_size,
        source_catalog_content_sha256=catalog_document_sha,
        source_catalog_size_bytes=len("m4-gate-terminal-catalog-document"),
        source_catalog_entry_count=1,
        source_catalog_entry_ids=(catalog_entry_id,),
        source_run_ids=(closure.source_run_id,),
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
    pending = M6ReplayLockedPendingSampleCommitmentAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        execution_component_authority_id=component.component_authority_id,
        source_catalog_entry_id=catalog_entry_id,
        route=M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        execution_entry=entry,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    return scope, pending, source


def test_builder_replays_hearing_and_gate_without_forging_source_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _execution(monkeypatch)

    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )

    source_case = source.projection_context.case
    source_binding = source.projection_context.model_reference_authority.verdict_bindings[0]
    candidate_binding = candidate.projection_context.model_reference_authority.verdict_bindings[0]
    source_retrieval = source.projection_context.retrieval_cycles[0].degraded_receipt
    candidate_retrieval = candidate.projection_context.retrieval_cycles[0].degraded_receipt
    assert source_retrieval is not None
    assert candidate_retrieval is not None
    assert candidate.case.run_id == scope.candidate_run_id
    assert candidate.case.case_id == source_case.case_id
    assert candidate.case.evidence_packs[0].pack_id == source_case.evidence_packs[0].pack_id
    assert candidate.case.screening_results[0].screening_id != (
        source_case.screening_results[0].screening_id
    )
    assert candidate.case.verdicts[0].verdict_id != source_case.verdicts[0].verdict_id
    assert candidate.case.procedural_reviews[0].review_id != (
        source_case.procedural_reviews[0].review_id
    )
    assert candidate_binding.verdict_id == candidate.case.verdicts[0].verdict_id
    assert candidate_binding.hearing_record_id == source_binding.hearing_record_id
    assert candidate_binding.judge_round_id == source_binding.judge_round_id
    assert candidate_binding.role_bindings == source_binding.role_bindings
    assert candidate_retrieval == source_retrieval
    assert candidate_retrieval.run_id == source_case.run_id
    assert candidate_retrieval.run_id != candidate.case.run_id
    assert candidate.projection_context.model_responses == (
        source.projection_context.model_responses
    )
    assert candidate.projection_context.model_reference_authority.source_identity_sha256 == (
        source.source_identity_sha256
    )
    assert candidate.case.usage == UsageSummary()
    assert candidate.case.timeline == ()
    assert candidate.candidate_snapshot.stage_roots == source.source_snapshot.stage_roots
    assert candidate.candidate_snapshot.semantic_case_hash == (
        source.source_snapshot.semantic_case_hash
    )
    assert candidate.candidate_snapshot.source_case_document_sha256 != (
        source.source_snapshot.source_case_document_sha256
    )


def test_builder_rejects_m4_work_under_the_m3_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _execution(monkeypatch)
    wrong_route = pending.model_copy(
        update={"route": M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE}
    )

    with pytest.raises(M6ReplayLockedM4TerminalError) as raised:
        build_m6_replay_locked_m4_gate_terminal_candidate(
            execution_scope=scope,
            pending_commitment=wrong_route,
            source=source,
        )

    assert raised.value.code == M6ReplayLockedM4TerminalErrorCode.SCOPE_MISMATCH


def test_builder_rejects_a_source_hearing_binding_graft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _execution(monkeypatch)
    forged = object.__new__(M6ReplayLockedM4GateTerminalSource)
    for name in (
        "source_identity_sha256",
        "closure",
        "projection_context",
        "hearing_record",
        "hearing_verdict_binding",
        "gate_current_closure_receipt",
        "source_snapshot",
    ):
        object.__setattr__(forged, name, getattr(source, name))
    object.__setattr__(
        forged,
        "hearing_verdict_binding",
        source.hearing_verdict_binding.model_copy(update={"hearing_record_id": "f" * 64}),
    )

    with pytest.raises(M6ReplayLockedM4TerminalError) as raised:
        build_m6_replay_locked_m4_gate_terminal_candidate(
            execution_scope=scope,
            pending_commitment=pending,
            source=forged,
        )

    assert raised.value.code == M6ReplayLockedM4TerminalErrorCode.SOURCE_INPUT_REJECTED


def test_candidate_context_rejects_source_identity_and_hearing_history_grafts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    context = candidate.projection_context
    references = context.model_reference_authority
    binding = references.verdict_bindings[0]
    foreign_binding = binding.__class__(
        verdict_id=binding.verdict_id,
        hearing_record_id="f" * 64,
        judge_round_id=binding.judge_round_id,
        role_bindings=binding.role_bindings,
    )

    for foreign in (
        M6CaseModelReferenceAuthority(
            source_identity_sha256="e" * 64,
            run_id=references.run_id,
            case_id=references.case_id,
            manifest_id=references.manifest_id,
            screening_bindings=references.screening_bindings,
            verdict_bindings=references.verdict_bindings,
        ),
        M6CaseModelReferenceAuthority(
            source_identity_sha256=references.source_identity_sha256,
            run_id=references.run_id,
            case_id=references.case_id,
            manifest_id=references.manifest_id,
            screening_bindings=references.screening_bindings,
            verdict_bindings=(foreign_binding,),
        ),
    ):
        with pytest.raises(ValueError):
            M6ReplayLockedM4CandidateProjectionContext(
                case=context.case,
                source_context=context.source_context,
                model_reference_authority=foreign,
                procedural_gate_authority=context.procedural_gate_authority,
            )


def test_candidate_snapshot_rejects_noninitial_revision_and_duck_typed_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, pending, source = _execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )

    with pytest.raises(ValueError, match="revision one"):
        build_m6_case_replay_snapshot(
            context=candidate.projection_context,
            sample_id=pending.sample_id,
            source_case_revision=2,
        )
    with pytest.raises(TypeError, match="verified M6 projection context"):
        build_m6_case_replay_snapshot(
            context=object(),  # type: ignore[arg-type]
            sample_id=pending.sample_id,
            source_case_revision=1,
        )
