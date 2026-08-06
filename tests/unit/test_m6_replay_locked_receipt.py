from __future__ import annotations

import pytest

from labcourt.application.m6_replay_locked import (
    M6ReplayLockedReceiptError,
    M6ReplayLockedReceiptErrorCode,
    build_m6_replay_locked_execution_receipt,
)
from labcourt.contracts.enums import CaseStatus, ReproducibilityMode, VerdictDecision
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionExecutionEntry,
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
    M6RegressionStage,
    M6ReplayExecutionOutcome,
    M6SemanticStageRoot,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedDetectionInput,
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingInput,
    M6LockedEmbeddingScope,
    M6LockedFrameInput,
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6LockedToolResultInput,
    M6ProviderCapabilityCounters,
    M6ProviderTrapAuthority,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
    M6ReplayInputClosureAuthority,
)


def _sha(character: str) -> str:
    return character * 64


def _ref(
    kind: M6ReplayAuthorityKind,
    artifact_id: str,
    character: str,
) -> M6ReplayAuthorityRef:
    return M6ReplayAuthorityRef(
        kind=kind,
        artifact_id=artifact_id,
        document_sha256=_sha(character),
    )


def _closure() -> M6ReplayInputClosureAuthority:
    return M6ReplayInputClosureAuthority(
        sample_id="sample-locked-001",
        source_run_id="run-baseline",
        source_case_id="case-baseline",
        source_case_revision=7,
        source_case_document_sha256=_sha("1"),
        source_manifest_id=_sha("a"),
        source_manifest_document_sha256=_sha("2"),
        input_authority_id=_sha("3"),
        input_authority_document_sha256=_sha("4"),
        source_validation_report_id=_sha("5"),
        source_validation_report_document_sha256=_sha("6"),
        frames=(
            M6LockedFrameInput(
                frame_id="camera-01:stream-01:10",
                document_sha256=_sha("7"),
                content_sha256=_sha("8"),
            ),
        ),
        detections=(
            M6LockedDetectionInput(
                detection_id="detection-001",
                frame_id="camera-01:stream-01:10",
                document_sha256=_sha("9"),
                model_manifest_id=_sha("b"),
            ),
        ),
        model_calls=(
            M6LockedModelCallInput(
                layer=M6LockedModelCallLayer.SCREENING,
                role=M6LockedModelRole.SCREENING,
                attempt_index=0,
                request_ref=_ref(
                    M6ReplayAuthorityKind.M3_MODEL_REQUEST,
                    "screening-request",
                    "a",
                ),
                result_kind=M6LockedModelCallResultKind.RESPONSE,
                response_ref=_ref(
                    M6ReplayAuthorityKind.M3_MODEL_RESPONSE,
                    "screening-response",
                    "b",
                ),
                cache_ref=_ref(
                    M6ReplayAuthorityKind.M3_MODEL_CACHE,
                    "screening-cache",
                    "c",
                ),
                parse_receipt_ref=_ref(
                    M6ReplayAuthorityKind.M3_PARSE_RECEIPT,
                    "screening-parse-receipt",
                    "d",
                ),
                parsed_output_ref=_ref(
                    M6ReplayAuthorityKind.M3_PARSED_OUTPUT,
                    "screening-output",
                    "e",
                ),
                raw_content_sha256=_sha("f"),
                raw_size_bytes=123,
            ),
        ),
        embeddings=(
            M6LockedEmbeddingInput(
                scope=M6LockedEmbeddingScope.QUERY,
                channel=M6LockedEmbeddingChannel.TEXT,
                embedding_ref=_ref(
                    M6ReplayAuthorityKind.M5_EMBEDDING,
                    "query-embedding",
                    "1",
                ),
                request_id=_sha("2"),
                model_manifest_id=_sha("3"),
            ),
        ),
        tool_results=(
            M6LockedToolResultInput(
                tool_result_id=_sha("4"),
                tool_result_document_sha256=_sha("5"),
                acquisition_request_ref=_ref(
                    M6ReplayAuthorityKind.M4_ACQUISITION_REQUEST,
                    "acquisition-request",
                    "6",
                ),
                execution_manifest_ref=_ref(
                    M6ReplayAuthorityKind.M4_TOOL_EXECUTION_MANIFEST,
                    "tool-execution-manifest",
                    "7",
                ),
                execution_publication_ref=_ref(
                    M6ReplayAuthorityKind.M4_ACQUISITION_PUBLICATION,
                    "acquisition-publication",
                    "8",
                ),
                tool_receipt_ref=_ref(
                    M6ReplayAuthorityKind.M4_TOOL_EXECUTION_RECEIPT,
                    "tool-execution-receipt",
                    "9",
                ),
                evidence_pack_derivation_ref=_ref(
                    M6ReplayAuthorityKind.M4_EVIDENCE_PACK_DERIVATION,
                    "pack-derivation",
                    "a",
                ),
                resulting_evidence_pack_ref=_ref(
                    M6ReplayAuthorityKind.EVIDENCE_PACK,
                    "resulting-pack",
                    "b",
                ),
            ),
        ),
    )


def _command(
    *,
    mode: ReproducibilityMode = ReproducibilityMode.REPLAY_LOCKED,
    manifest_id: str = _sha("a"),
) -> M6RegressionRunCommand:
    return M6RegressionRunCommand(
        mode=mode,
        execution_dataset_snapshot_id=_sha("c"),
        baseline_manifest_id=manifest_id,
        candidate_manifest_id=manifest_id,
        policy_authority=M6RegressionPolicyAuthority(
            config_sha256=_sha("d"),
            policy_version="m6-regression-v1",
            maximum_machine_flip_rate=0.05,
            gold_set_max_accuracy_drop=0.0,
        ),
    )


def _entry(closure: M6ReplayInputClosureAuthority) -> M6RegressionExecutionEntry:
    return M6RegressionExecutionEntry(
        sample_id=closure.sample_id,
        input_authority_id=closure.input_authority_id,
        input_authority_document_sha256=closure.input_authority_document_sha256,
        replay_input_closure_authority_id=closure.replay_input_closure_authority_id,
        replay_input_closure_document_sha256=(closure.replay_input_closure_document_sha256),
    )


def _trap(
    command: M6RegressionRunCommand,
    *,
    candidate_run_id: str = "run-candidate",
    component_manifest_id: str = _sha("e"),
    counters: M6ProviderCapabilityCounters | None = None,
) -> M6ProviderTrapAuthority:
    return M6ProviderTrapAuthority(
        command_id=command.command_id,
        candidate_run_id=candidate_run_id,
        execution_component_manifest_id=component_manifest_id,
        counters=counters or M6ProviderCapabilityCounters(),
    )


def _snapshot(
    *,
    sample_id: str = "sample-locked-001",
    run_id: str = "run-candidate",
    manifest_id: str = _sha("a"),
) -> M6CaseReplaySnapshot:
    return M6CaseReplaySnapshot(
        sample_id=sample_id,
        source_run_id=run_id,
        source_case_id="case-candidate",
        source_case_revision=1,
        source_case_document_sha256=_sha("f"),
        manifest_id=manifest_id,
        stage_roots=tuple(
            M6SemanticStageRoot(stage=stage, projection_sha256=_sha(str(index)))
            for index, stage in enumerate(M6RegressionStage, start=1)
        ),
        case_status=CaseStatus.CLOSED,
        final_decision=VerdictDecision.ESTABLISHED,
    )


def _build(
    *,
    command: M6RegressionRunCommand | None = None,
    closure: M6ReplayInputClosureAuthority | None = None,
    entry: M6RegressionExecutionEntry | None = None,
    trap: M6ProviderTrapAuthority | None = None,
    candidate_run_id: str = "run-candidate",
    component_manifest_id: str = _sha("e"),
    outcome: M6ReplayExecutionOutcome = M6ReplayExecutionOutcome.CASE_REPLAYED,
    snapshot: M6CaseReplaySnapshot | object | None = ...,
):
    resolved_command = command or _command()
    resolved_closure = closure or _closure()
    resolved_entry = entry or _entry(resolved_closure)
    resolved_trap = trap or _trap(
        resolved_command,
        candidate_run_id=candidate_run_id,
        component_manifest_id=component_manifest_id,
    )
    resolved_snapshot = _snapshot() if snapshot is ... else snapshot
    return build_m6_replay_locked_execution_receipt(
        command=resolved_command,
        execution_entry=resolved_entry,
        closure=resolved_closure,
        provider_trap=resolved_trap,
        candidate_run_id=candidate_run_id,
        execution_component_manifest_id=component_manifest_id,
        outcome=outcome,
        candidate_snapshot=resolved_snapshot,
    )


def test_locked_receipt_is_derived_from_exact_closure_and_clean_trap() -> None:
    closure = _closure()
    command = _command()
    trap = _trap(command)

    receipt = _build(command=command, closure=closure, trap=trap)

    assert receipt.command_id == command.command_id
    assert receipt.execution_entry_id == _entry(closure).execution_entry_id
    assert receipt.candidate_snapshot_id == _snapshot().snapshot_id
    assert (
        receipt.detection_count,
        receipt.detection_inventory_root_sha256,
        receipt.model_response_count,
        receipt.model_response_inventory_root_sha256,
        receipt.embedding_count,
        receipt.embedding_inventory_root_sha256,
        receipt.tool_result_count,
        receipt.tool_result_inventory_root_sha256,
    ) == (
        closure.detection_count,
        closure.detection_inventory_root_sha256,
        closure.model_response_count,
        closure.model_response_inventory_root_sha256,
        closure.embedding_count,
        closure.embedding_inventory_root_sha256,
        closure.tool_result_count,
        closure.tool_result_inventory_root_sha256,
    )
    assert receipt.provider_call_count == 0
    assert receipt.provider_trap_authority_id == trap.provider_trap_authority_id
    assert receipt.provider_trap_document_sha256 == trap.provider_trap_document_sha256


def test_locked_receipt_supports_an_explicit_no_case_result() -> None:
    receipt = _build(
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        snapshot=None,
    )

    assert receipt.outcome == M6ReplayExecutionOutcome.NO_CASE
    assert receipt.candidate_snapshot_id is None


def test_receipt_builder_rejects_non_locked_mode() -> None:
    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(command=_command(mode=ReproducibilityMode.REINFER_PINNED))

    assert raised.value.code == M6ReplayLockedReceiptErrorCode.MODE_NOT_REPLAY_LOCKED


@pytest.mark.parametrize(
    "update",
    [
        {"sample_id": "sample-foreign"},
        {"input_authority_id": _sha("0")},
        {"input_authority_document_sha256": _sha("0")},
        {"replay_input_closure_authority_id": _sha("0")},
        {"replay_input_closure_document_sha256": _sha("0")},
    ],
)
def test_receipt_builder_rejects_any_execution_entry_closure_mismatch(
    update: dict[str, object],
) -> None:
    closure = _closure()

    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(entry=_entry(closure).model_copy(update=update), closure=closure)

    assert raised.value.code == M6ReplayLockedReceiptErrorCode.EXECUTION_ENTRY_CLOSURE_MISMATCH


def test_receipt_builder_rejects_a_closure_from_another_locked_manifest() -> None:
    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(command=_command(manifest_id=_sha("0")))

    assert raised.value.code == M6ReplayLockedReceiptErrorCode.COMMAND_CLOSURE_MANIFEST_MISMATCH


@pytest.mark.parametrize(
    "trap_update",
    [
        {"command_id": _sha("0")},
        {"candidate_run_id": "run-foreign"},
        {"execution_component_manifest_id": _sha("0")},
    ],
)
def test_receipt_builder_rejects_any_provider_trap_scope_mismatch(
    trap_update: dict[str, object],
) -> None:
    command = _command()

    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(command=command, trap=_trap(command).model_copy(update=trap_update))

    assert raised.value.code == M6ReplayLockedReceiptErrorCode.PROVIDER_TRAP_SCOPE_MISMATCH


def test_receipt_builder_rejects_any_external_capability_use() -> None:
    command = _command()
    trap = _trap(
        command,
        counters=M6ProviderCapabilityCounters(
            embedding_provider_calls=1,
            live_precedent_tail_query_calls=1,
        ),
    )

    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(command=command, trap=trap)

    assert trap.clean is False
    assert trap.external_capability_call_count == 2
    assert raised.value.code == M6ReplayLockedReceiptErrorCode.PROVIDER_CAPABILITY_USED


def test_receipt_builder_canonical_revalidates_constructed_trap() -> None:
    command = _command()
    forged_counters = M6ProviderCapabilityCounters.model_construct(
        perception_provider_calls=0,
        screening_vlm_provider_calls=0,
        hearing_vlm_provider_calls=0,
        embedding_provider_calls=1,
        acquisition_provider_calls=0,
        safety_signal_provider_calls=0,
        alert_channel_calls=0,
        response_recovery_calls=0,
        cache_write_calls=-1,
        live_precedent_tail_query_calls=0,
        live_training_label_tail_query_calls=0,
    )
    forged_trap = M6ProviderTrapAuthority.model_construct(
        schema_version="m6-provider-trap-authority-v1",
        command_id=command.command_id,
        candidate_run_id="run-candidate",
        execution_component_manifest_id=_sha("e"),
        counters=forged_counters,
    )

    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(command=command, trap=forged_trap)

    assert raised.value.code == M6ReplayLockedReceiptErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize(
    ("outcome", "snapshot"),
    [
        (M6ReplayExecutionOutcome.CASE_REPLAYED, None),
        (M6ReplayExecutionOutcome.NO_CASE, _snapshot()),
    ],
)
def test_receipt_builder_rejects_an_invalid_outcome_snapshot_matrix(
    outcome: M6ReplayExecutionOutcome,
    snapshot: M6CaseReplaySnapshot | None,
) -> None:
    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(outcome=outcome, snapshot=snapshot)

    assert raised.value.code == M6ReplayLockedReceiptErrorCode.OUTCOME_SNAPSHOT_MISMATCH


@pytest.mark.parametrize(
    "snapshot",
    [
        _snapshot(sample_id="sample-foreign"),
        _snapshot(run_id="run-foreign"),
        _snapshot(manifest_id=_sha("0")),
    ],
)
def test_receipt_builder_rejects_a_candidate_snapshot_from_another_scope(
    snapshot: M6CaseReplaySnapshot,
) -> None:
    with pytest.raises(M6ReplayLockedReceiptError) as raised:
        _build(snapshot=snapshot)

    assert raised.value.code == M6ReplayLockedReceiptErrorCode.CANDIDATE_SNAPSHOT_SCOPE_MISMATCH
