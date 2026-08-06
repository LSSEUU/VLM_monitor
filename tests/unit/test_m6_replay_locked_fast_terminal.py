from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_replay_locked_fast_terminal import (
    M6ReplayLockedFastTerminalError,
    M6ReplayLockedFastTerminalErrorCode,
    build_m6_replay_locked_fast_terminal_candidate,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.config import AlertConfig
from labcourt.contracts.enums import AlertLevel, ReproducibilityMode
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from tests.unit.test_m6_replay_locked_execution_scope import _inputs
from tests.unit.test_m6_replay_locked_fast_source import _terminal_source


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(value: object) -> tuple[str, int]:
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _execution() -> tuple[
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    object,
]:
    inputs = _inputs()
    config = inputs["locked_config"]
    manifest = inputs["locked_manifest"]
    component = inputs["execution_component"]
    source = _terminal_source(
        gate_config=config.procedural_gate,  # type: ignore[union-attr]
        alert_config=config.alerts,  # type: ignore[union-attr]
    )
    entry = M6RegressionExecutionEntry(
        sample_id=source.closure.sample_id,
        input_authority_id=source.closure.input_authority_id,
        input_authority_document_sha256=(source.closure.input_authority_document_sha256),
        replay_input_closure_authority_id=(source.closure.replay_input_closure_authority_id),
        replay_input_closure_document_sha256=(source.closure.replay_input_closure_document_sha256),
    )
    catalog_id = _sha("fast-terminal-catalog-authority")
    catalog_document_sha = _sha("fast-terminal-catalog-document")
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        source_catalog_authority_id=catalog_id,
        source_catalog_document_sha256=catalog_document_sha,
        entries=(entry,),
    )
    template_command = inputs["command"]
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        candidate_manifest_id=manifest.manifest_id,  # type: ignore[union-attr]
        policy_authority=template_command.policy_authority,  # type: ignore[union-attr]
    )
    command_sha, command_size = _identity(command)
    dataset_sha, dataset_size = _identity(dataset)
    manifest_sha, manifest_size = _identity(manifest)
    config_sha, config_size = _identity(config)
    component_sha, component_size = _identity(component)
    catalog_entry_id = _sha("fast-terminal-catalog-entry")
    scope = M6ReplayLockedExecutionScopeAuthority(
        candidate_run_id="m6-fast-terminal-candidate-run",
        command=command,
        command_content_sha256=command_sha,
        command_size_bytes=command_size,
        execution_dataset=dataset,
        execution_dataset_content_sha256=dataset_sha,
        execution_dataset_size_bytes=dataset_size,
        source_catalog_content_sha256=catalog_document_sha,
        source_catalog_size_bytes=len("fast-terminal-catalog-document"),
        source_catalog_entry_count=1,
        source_catalog_entry_ids=(catalog_entry_id,),
        source_run_ids=(source.closure.source_run_id,),
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
        execution_component_authority_id=component.component_authority_id,  # type: ignore[union-attr]
        source_catalog_entry_id=catalog_entry_id,
        route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        execution_entry=entry,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    return scope, pending, source


def test_builder_reexecutes_fast_route_with_identical_six_stage_semantics() -> None:
    scope, pending, source = _execution()

    candidate = build_m6_replay_locked_fast_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )

    source_case = source.projection_context.case
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
    assert candidate.case.usage == UsageSummary()
    assert candidate.case.timeline == ()
    assert candidate.candidate_snapshot.stage_roots == source.source_snapshot.stage_roots
    assert (
        candidate.candidate_snapshot.semantic_case_hash == source.source_snapshot.semantic_case_hash
    )
    assert tuple(
        ref.artifact_id for ref in candidate.case.verdicts[0].model_response_refs
    ) == tuple(ref.artifact_id for ref in source_case.verdicts[0].model_response_refs)


def test_builder_rejects_a_pending_commitment_outside_the_exact_scope() -> None:
    scope, pending, source = _execution()
    foreign = pending.model_copy(update={"source_catalog_entry_id": "f" * 64})

    with pytest.raises(M6ReplayLockedFastTerminalError) as raised:
        build_m6_replay_locked_fast_terminal_candidate(
            execution_scope=scope,
            pending_commitment=foreign,
            source=source,
        )

    assert raised.value.code == M6ReplayLockedFastTerminalErrorCode.SCOPE_MISMATCH


def test_builder_rejects_a_source_run_missing_from_the_frozen_inventory() -> None:
    scope, pending, source = _execution()
    foreign_scope = M6ReplayLockedExecutionScopeAuthority.model_validate(
        {
            **scope.model_dump(mode="json", exclude_computed_fields=True),
            "source_run_ids": ("unrelated-source-run",),
        }
    )
    foreign_pending = pending.model_copy(
        update={"execution_scope_authority_id": (foreign_scope.execution_scope_authority_id)}
    )

    with pytest.raises(M6ReplayLockedFastTerminalError) as raised:
        build_m6_replay_locked_fast_terminal_candidate(
            execution_scope=foreign_scope,
            pending_commitment=foreign_pending,
            source=source,
        )

    assert raised.value.code == M6ReplayLockedFastTerminalErrorCode.SCOPE_MISMATCH


def test_builder_rejects_source_gate_configuration_outside_the_locked_manifest() -> None:
    scope, pending, _source = _execution()
    foreign_source = _terminal_source(
        gate_config=scope.locked_config.procedural_gate,
        alert_config=AlertConfig(
            cooldown_seconds=31.0,
            repeat_window_days=7,
            confirmed_min_confidence=0.8,
            insufficient_evidence_max_level=AlertLevel.ADVISORY,
        ),
    )

    with pytest.raises(M6ReplayLockedFastTerminalError) as raised:
        build_m6_replay_locked_fast_terminal_candidate(
            execution_scope=scope,
            pending_commitment=pending,
            source=foreign_source,
        )

    assert raised.value.code == M6ReplayLockedFastTerminalErrorCode.SOURCE_INPUT_REJECTED
