from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.config_loader import load_config
from labcourt.contracts.artifact_validation import (
    ArtifactValidationReport,
    M3ArtifactValidationReport,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationCounts,
    M5ArtifactValidationReport,
)
from labcourt.contracts.m6_regression import (
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateArtifactKind,
    M6UpgradeCandidateArtifactRef,
    M6UpgradeCandidateCaseDocumentRef,
    M6UpgradeCandidateModelCallAuthority,
    M6UpgradeCandidateOutputInventoryAuthority,
    M6UpgradeCandidateRunCutAuthority,
    M6UpgradeCandidateSampleOutputAuthority,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionComponentAuthority,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactSource,
    M6UpgradePhysicalByteAuthority,
    m6_upgrade_physical_byte_authority_for,
)
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m6_regression_contracts import (
    _candidate_snapshot,
    _minimal_dataset,
)
from tests.unit.test_m6_perception_authority import _manifest

PROJECT_ROOT = Path(__file__).parents[2]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _physical_sha(value) -> str:  # type: ignore[no-untyped-def]
    return _sha(canonical_json(value.model_dump(mode="json")))


def _physical_size(value) -> int:  # type: ignore[no-untyped-def]
    return len(canonical_json(value.model_dump(mode="json")).encode("utf-8"))


def _artifact(
    kind: M6UpgradeCandidateArtifactKind,
    sample_id: str,
    suffix: str,
) -> M6UpgradeCandidateArtifactRef:
    if kind in {
        M6UpgradeCandidateArtifactKind.FRAME,
        M6UpgradeCandidateArtifactKind.DETECTION,
    }:
        source = M6UpgradePhysicalArtifactSource.M2_PERCEPTION
    elif kind in {
        M6UpgradeCandidateArtifactKind.MODEL_REQUEST,
        M6UpgradeCandidateArtifactKind.MODEL_RESPONSE,
        M6UpgradeCandidateArtifactKind.MODEL_CACHE,
        M6UpgradeCandidateArtifactKind.MODEL_PARSE_RECEIPT,
        M6UpgradeCandidateArtifactKind.MODEL_PARSED_OUTPUT,
        M6UpgradeCandidateArtifactKind.MODEL_CALL_FAILURE,
        M6UpgradeCandidateArtifactKind.MODEL_USAGE_RECEIPT,
    }:
        source = M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
    elif kind == M6UpgradeCandidateArtifactKind.EMBEDDING:
        source = M6UpgradePhysicalArtifactSource.M5_PRECEDENT
    elif kind == M6UpgradeCandidateArtifactKind.TOOL_RESULT:
        source = M6UpgradePhysicalArtifactSource.M4_ACQUISITION
    else:
        raise AssertionError(f"test fixture has no source for {kind}")
    frame_id = f"camera-{sample_id[:8]}:stream:0"
    document_sha256 = _sha(f"document:{sample_id}:{suffix}")
    byte_authority = m6_upgrade_physical_byte_authority_for(source, kind)
    return M6UpgradeCandidateArtifactRef(
        source=source,
        kind=kind,
        artifact_id=(
            frame_id
            if kind == M6UpgradeCandidateArtifactKind.FRAME
            else f"{sample_id[:12]}-{suffix}"
        ),
        container_id=(frame_id if kind == M6UpgradeCandidateArtifactKind.DETECTION else None),
        document_sha256=document_sha256,
        content_sha256=(
            document_sha256
            if byte_authority
            in {
                M6UpgradePhysicalByteAuthority.CANONICAL_JSON,
                M6UpgradePhysicalByteAuthority.DERIVED_CANONICAL_JSON,
            }
            else _sha(f"content:{sample_id}:{suffix}")
        ),
        size_bytes=100 + len(suffix),
    )


def _model_call(sample_id: str, model_manifest_id: str):
    return M6UpgradeCandidateModelCallAuthority(
        sample_id=sample_id,
        layer=M6LockedModelCallLayer.SCREENING,
        role=M6LockedModelRole.SCREENING,
        attempt_index=0,
        timeout_ms=5_000,
        execution_model_manifest_id=model_manifest_id,
        provider_invoked=True,
        request_ref=_artifact(
            M6UpgradeCandidateArtifactKind.MODEL_REQUEST,
            sample_id,
            "request",
        ).model_copy(
            update={"artifact_id": _sha(f"request:{sample_id}")},
        ),
        cache_ref=_artifact(
            M6UpgradeCandidateArtifactKind.MODEL_CACHE,
            sample_id,
            "cache",
        ),
        result_kind=M6LockedModelCallResultKind.RESPONSE,
        response_ref=_artifact(
            M6UpgradeCandidateArtifactKind.MODEL_RESPONSE,
            sample_id,
            "response",
        ),
        parse_receipt_ref=_artifact(
            M6UpgradeCandidateArtifactKind.MODEL_PARSE_RECEIPT,
            sample_id,
            "parse",
        ),
        parsed_output_ref=_artifact(
            M6UpgradeCandidateArtifactKind.MODEL_PARSED_OUTPUT,
            sample_id,
            "output",
        ),
        usage_receipt_ref=_artifact(
            M6UpgradeCandidateArtifactKind.MODEL_USAGE_RECEIPT,
            sample_id,
            "usage",
        ),
    )


def _inventory(
    *,
    candidate_run_id: str = "run-candidate",
) -> M6UpgradeCandidateOutputInventoryAuthority:
    evaluator_dataset = _minimal_dataset()
    execution_dataset = evaluator_dataset.execution_dataset
    baseline_manifest, _ = _manifest()
    baseline_config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    candidate_config = baseline_config.model_copy(
        update={
            "run": baseline_config.run.model_copy(
                update={"reproducibility_mode": (ReproducibilityMode.UPGRADE_REGRESSION)}
            )
        }
    )
    candidate_manifest = baseline_manifest.model_copy(
        update={
            "reproducibility_mode": ReproducibilityMode.UPGRADE_REGRESSION,
            "config_sha256": candidate_config.config_sha256,
        }
    )
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.UPGRADE_REGRESSION,
        execution_dataset_snapshot_id=execution_dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=execution_dataset.baseline_manifest_id,
        candidate_manifest_id=candidate_manifest.manifest_id,
        policy_authority=M6RegressionPolicyAuthority(
            config_sha256=candidate_manifest.config_sha256,
            policy_version="m6-upgrade-regression-v1",
            maximum_machine_flip_rate=0.05,
            gold_set_max_accuracy_drop=0.0,
        ),
    )
    case_count = sum(entry.baseline_snapshot is not None for entry in evaluator_dataset.entries)
    m2_report = ArtifactValidationReport(
        run_id=candidate_run_id,
        manifest_id=candidate_manifest.manifest_id,
        audit_head_sequence=11,
        audit_head_hash=_sha("candidate-audit-head"),
    )
    m3_report = M3ArtifactValidationReport(
        run_id=m2_report.run_id,
        m2_report=m2_report,
    )
    m4_report = M4ArtifactValidationReport(
        run_id=m2_report.run_id,
        m3_report=m3_report,
        authority_root_sha256=_sha("candidate-m4-authority-root"),
    )
    validation_report = M5ArtifactValidationReport(
        run_id=candidate_run_id,
        manifest_id=candidate_manifest.manifest_id,
        config_sha256=candidate_manifest.config_sha256,
        predecessor_report=m4_report,
        authority_root_sha256=_sha("candidate-m5-authority-root"),
        counts=M5ArtifactValidationCounts(case_roots=case_count),
    )
    component = M6UpgradeExecutionComponentAuthority(
        version="0.1.0",
        code_commit=candidate_manifest.code_commit,
    )
    run_cut = M6UpgradeCandidateRunCutAuthority(
        candidate_run_id=validation_report.run_id,
        candidate_manifest=candidate_manifest,
        candidate_manifest_content_sha256=_physical_sha(candidate_manifest),
        candidate_config=candidate_config,
        candidate_config_content_sha256=_physical_sha(candidate_config),
        execution_component_manifest_id=component.component_authority_id,
        audit_head_sequence=11,
        audit_head_hash=_sha("candidate-audit-head"),
        validation_report=validation_report,
        validation_report_content_sha256=_physical_sha(validation_report),
    )
    execution_scope = M6UpgradeExecutionScopeAuthority(
        candidate_run_id=run_cut.candidate_run_id,
        command=command,
        command_content_sha256=_physical_sha(command),
        command_size_bytes=_physical_size(command),
        execution_dataset=execution_dataset,
        execution_dataset_content_sha256=_physical_sha(execution_dataset),
        execution_dataset_size_bytes=_physical_size(execution_dataset),
        candidate_manifest=candidate_manifest,
        candidate_manifest_content_sha256=_physical_sha(candidate_manifest),
        candidate_manifest_size_bytes=_physical_size(candidate_manifest),
        candidate_config=candidate_config,
        candidate_config_content_sha256=_physical_sha(candidate_config),
        candidate_config_size_bytes=_physical_size(candidate_config),
        execution_component=component,
        execution_component_content_sha256=_physical_sha(component),
        execution_component_size_bytes=_physical_size(component),
        execution_start_audit_head_sequence=-1,
        execution_start_audit_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
    )
    evaluator_by_sample = {item.sample_id: item for item in evaluator_dataset.entries}
    prepared = []
    for execution_entry in execution_dataset.entries:
        evaluator_entry = evaluator_by_sample[execution_entry.sample_id]
        baseline = evaluator_entry.baseline_snapshot
        snapshot = (
            _candidate_snapshot(
                baseline,
                manifest_id=candidate_manifest.manifest_id,
                candidate_run_id=candidate_run_id,
            )
            if baseline is not None
            else None
        )
        frames = (
            _artifact(
                M6UpgradeCandidateArtifactKind.FRAME,
                execution_entry.sample_id,
                "frame",
            ),
        )
        detections = (
            _artifact(
                M6UpgradeCandidateArtifactKind.DETECTION,
                execution_entry.sample_id,
                "detection",
            ),
        )
        model_calls = (
            (
                _model_call(
                    execution_entry.sample_id,
                    candidate_manifest.models["screening"].model_manifest_id,
                ),
            )
            if snapshot is not None
            else ()
        )
        embeddings = (
            (
                _artifact(
                    M6UpgradeCandidateArtifactKind.EMBEDDING,
                    execution_entry.sample_id,
                    "embedding",
                ),
            )
            if snapshot is not None
            else ()
        )
        tool_results = (
            (
                _artifact(
                    M6UpgradeCandidateArtifactKind.TOOL_RESULT,
                    execution_entry.sample_id,
                    "tool",
                ),
            )
            if snapshot is not None
            else ()
        )
        prepared.append(
            (
                execution_entry,
                snapshot,
                (
                    M6ReplayExecutionOutcome.CASE_REPLAYED
                    if snapshot is not None
                    else M6ReplayExecutionOutcome.NO_CASE
                ),
                frames,
                detections,
                model_calls,
                embeddings,
                tool_results,
            )
        )

    records: list[M6UpgradeSampleExecutionRecord] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for index, (
        execution_entry,
        snapshot,
        outcome,
        frames,
        detections,
        model_calls,
        embeddings,
        tool_results,
    ) in enumerate(prepared):
        refs = tuple(
            sorted(
                frames
                + detections
                + tuple(ref for call in model_calls for ref in call.artifact_refs)
                + embeddings
                + tool_results,
                key=lambda item: item.sort_key,
            )
        )
        links = tuple(
            M6UpgradeSampleArtifactLink(
                ordinal=ordinal,
                usage=(
                    M6UpgradeArtifactUsage.CONSUMED
                    if ref.kind == M6UpgradeCandidateArtifactKind.FRAME
                    else M6UpgradeArtifactUsage.PRODUCED
                ),
                artifact=ref,
            )
            for ordinal, ref in enumerate(refs)
        )
        candidate_case = (
            M6UpgradeCandidateCaseBinding(
                case_id=snapshot.source_case_id,
                case_revision=snapshot.source_case_revision,
                case_document_sha256=snapshot.source_case_document_sha256,
                case_audit_sequence=5 + index,
                case_audit_entry_hash=_sha(f"case-audit:{execution_entry.sample_id}"),
            )
            if snapshot is not None
            else None
        )
        record = M6UpgradeSampleExecutionRecord(
            execution_scope_authority_id=execution_scope.execution_scope_authority_id,
            candidate_run_id=run_cut.candidate_run_id,
            command_id=command.command_id,
            execution_dataset_snapshot_id=execution_dataset.execution_dataset_snapshot_id,
            execution_entry=execution_entry,
            outcome=outcome,
            candidate_case=candidate_case,
            artifact_links=links,
            ledger_sequence=index,
            previous_ledger_entry_hash=previous,
        )
        records.append(record)
        previous = record.sample_execution_record_id

    ledger = M6UpgradeExecutionLedgerSeal(
        execution_scope=execution_scope,
        execution_scope_content_sha256=_physical_sha(execution_scope),
        execution_scope_size_bytes=_physical_size(execution_scope),
        source_audit_head_sequence=run_cut.audit_head_sequence,
        source_audit_head_hash=run_cut.audit_head_hash,
        sample_executions=tuple(records),
    )

    outputs: list[M6UpgradeCandidateSampleOutputAuthority] = []
    for record, (
        execution_entry,
        snapshot,
        outcome,
        frames,
        detections,
        model_calls,
        embeddings,
        tool_results,
    ) in zip(records, prepared, strict=True):
        outputs.append(
            M6UpgradeCandidateSampleOutputAuthority(
                command_id=command.command_id,
                execution_dataset_snapshot_id=execution_dataset.execution_dataset_snapshot_id,
                execution_entry=execution_entry,
                sample_execution_record_id=record.sample_execution_record_id,
                candidate_run_cut_authority_id=run_cut.candidate_run_cut_authority_id,
                candidate_run_id=run_cut.candidate_run_id,
                candidate_manifest_id=candidate_manifest.manifest_id,
                execution_component_manifest_id=run_cut.execution_component_manifest_id,
                outcome=outcome,
                candidate_snapshot=snapshot,
                frames=frames,
                detections=detections,
                model_calls=model_calls,
                embeddings=embeddings,
                tool_results=tool_results,
            )
        )
    cases = tuple(
        sorted(
            (
                M6UpgradeCandidateCaseDocumentRef(
                    case_id=snapshot.source_case_id,
                    case_revision=snapshot.source_case_revision,
                    case_document_sha256=snapshot.source_case_document_sha256,
                )
                for output in outputs
                if (snapshot := output.candidate_snapshot) is not None
            ),
            key=lambda item: item.sort_key,
        )
    )
    return M6UpgradeCandidateOutputInventoryAuthority(
        command=command,
        execution_dataset=execution_dataset,
        candidate_run_cut=run_cut,
        execution_ledger=ledger,
        execution_ledger_content_sha256=_physical_sha(ledger),
        execution_ledger_size_bytes=_physical_size(ledger),
        candidate_cases=cases,
        outputs=tuple(outputs),
    )


def _rechain_ledger(
    ledger: M6UpgradeExecutionLedgerSeal,
    replacements: dict[int, M6UpgradeSampleExecutionRecord],
) -> M6UpgradeExecutionLedgerSeal:
    records: list[M6UpgradeSampleExecutionRecord] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for index, original in enumerate(ledger.sample_executions):
        candidate = replacements.get(index, original)
        record = candidate.model_copy(
            update={
                "ledger_sequence": index,
                "previous_ledger_entry_hash": previous,
            }
        )
        records.append(record)
        previous = record.sample_execution_record_id
    return ledger.model_copy(update={"sample_executions": tuple(records)})


def test_candidate_output_inventory_is_complete_blind_and_derives_receipts() -> None:
    inventory = _inventory()
    assert inventory.output_count == len(inventory.execution_dataset.entries) == 3
    assert inventory.candidate_case_count == 2
    assert inventory.artifact_count > inventory.output_count
    assert all(
        output.execution_receipt.execution_entry_id == output.execution_entry.execution_entry_id
        for output in inventory.outputs
    )
    serialized = canonical_json(inventory.model_dump(mode="json"))
    for forbidden in (
        "memberships",
        "gold_truth",
        "expected_decision",
        "baseline_snapshot",
    ):
        assert forbidden not in serialized


def test_inventory_distinguishes_explicit_no_case_from_missing_output() -> None:
    inventory = _inventory()
    no_case = next(
        item for item in inventory.outputs if item.outcome == M6ReplayExecutionOutcome.NO_CASE
    )
    assert no_case.candidate_snapshot is None
    assert no_case.execution_receipt.outcome == M6ReplayExecutionOutcome.NO_CASE
    assert not no_case.model_calls
    assert not no_case.embeddings
    assert not no_case.precedent_exposures
    assert not no_case.tool_execution_manifests
    assert not no_case.tool_results
    assert not no_case.evidence_packs

    case_output = next(item for item in inventory.outputs if item.candidate_snapshot is not None)
    grafted_call = case_output.model_calls[0].model_copy(update={"sample_id": no_case.sample_id})
    with pytest.raises(ValidationError, match="no-Case sample cannot claim case-scoped"):
        no_case.model_copy(update={"model_calls": (grafted_call,)})
    with pytest.raises(ValidationError, match="no-Case sample cannot claim case-scoped"):
        no_case.model_copy(update={"embeddings": case_output.embeddings})

    with pytest.raises(ValidationError, match="cover every execution entry"):
        inventory.model_copy(update={"outputs": inventory.outputs[:-1]})


def test_legacy_candidate_output_v1_preserves_pre_budget_semantics() -> None:
    output = _inventory().outputs[0]
    frame = output.frames[0]
    oversized = frame.model_copy(update={"size_bytes": MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES + 1})

    legacy = output.model_copy(update={"frames": (oversized, *output.frames[1:])})
    assert legacy.schema_version == "m6-upgrade-candidate-sample-output-authority-v1"


def test_inventory_bijects_ledger_records_cases_and_physical_bytes() -> None:
    inventory = _inventory()
    first_output = inventory.outputs[0]
    first_record, second_record = inventory.execution_ledger.sample_executions[:2]

    with pytest.raises(ValidationError, match="exact run scope"):
        inventory.model_copy(
            update={
                "outputs": (
                    first_output.model_copy(
                        update={
                            "sample_execution_record_id": second_record.sample_execution_record_id
                        }
                    ),
                    *inventory.outputs[1:],
                )
            }
        )

    changed_frame = first_output.frames[0].model_copy(
        update={"content_sha256": _sha("changed-output-frame-bytes")}
    )
    changed_output = first_output.model_copy(update={"frames": (changed_frame,)})
    with pytest.raises(ValidationError, match="output and ledger artifacts differ"):
        inventory.model_copy(update={"outputs": (changed_output, *inventory.outputs[1:])})

    first_frame_link = first_record.artifact_links[0]
    changed_ledger_frame = first_frame_link.artifact.model_copy(
        update={"content_sha256": _sha("changed-ledger-frame-bytes")}
    )
    changed_record = first_record.model_copy(
        update={
            "artifact_links": (
                first_frame_link.model_copy(update={"artifact": changed_ledger_frame}),
                *first_record.artifact_links[1:],
            )
        }
    )
    changed_ledger = _rechain_ledger(inventory.execution_ledger, {0: changed_record})
    rebound_outputs = tuple(
        output.model_copy(
            update={
                "sample_execution_record_id": changed_ledger.sample_executions[
                    index
                ].sample_execution_record_id
            }
        )
        for index, output in enumerate(inventory.outputs)
    )
    with pytest.raises(ValidationError, match="output and ledger artifacts differ"):
        inventory.model_copy(
            update={
                "execution_ledger": changed_ledger,
                "execution_ledger_content_sha256": _physical_sha(changed_ledger),
                "execution_ledger_size_bytes": _physical_size(changed_ledger),
                "outputs": rebound_outputs,
            }
        )

    first_detection = first_output.detections[0]
    first_frame = first_output.frames[0]
    second_detection_index = next(
        index
        for index, link in enumerate(second_record.artifact_links)
        if link.artifact.kind == M6UpgradeCandidateArtifactKind.DETECTION
    )
    shared_links = tuple(
        link.model_copy(update={"artifact": first_detection})
        if index == second_detection_index
        else (
            link.model_copy(update={"artifact": first_frame})
            if link.artifact.kind == M6UpgradeCandidateArtifactKind.FRAME
            else link
        )
        for index, link in enumerate(second_record.artifact_links)
    )
    shared_second_record = second_record.model_copy(update={"artifact_links": shared_links})
    shared_ledger = _rechain_ledger(inventory.execution_ledger, {1: shared_second_record})
    shared_outputs = tuple(
        output.model_copy(
            update={
                "sample_execution_record_id": shared_ledger.sample_executions[
                    index
                ].sample_execution_record_id,
                **(
                    {"frames": (first_frame,), "detections": (first_detection,)}
                    if index == 1
                    else {}
                ),
            }
        )
        for index, output in enumerate(inventory.outputs)
    )
    shared_inventory = inventory.model_copy(
        update={
            "execution_ledger": shared_ledger,
            "execution_ledger_content_sha256": _physical_sha(shared_ledger),
            "execution_ledger_size_bytes": _physical_size(shared_ledger),
            "outputs": shared_outputs,
        }
    )
    assert shared_inventory.artifact_link_count == inventory.artifact_link_count
    assert shared_inventory.artifact_count == inventory.artifact_count - 2


def test_inventory_rejects_run_component_case_and_artifact_grafts() -> None:
    inventory = _inventory()
    first = inventory.outputs[0]
    foreign_detection = first.detections[0].model_copy(
        update={"container_id": "foreign-camera:stream:0"}
    )
    with pytest.raises(ValidationError, match="Frame in the same sample"):
        first.model_copy(update={"detections": (foreign_detection,)})

    run_cut = inventory.candidate_run_cut
    forged_counts = run_cut.validation_report.counts.model_copy(
        update={"case_roots": inventory.candidate_case_count + 7}
    )
    forged_report = run_cut.validation_report.model_copy(update={"counts": forged_counts})
    forged_cut = run_cut.model_copy(
        update={
            "validation_report": forged_report,
            "validation_report_content_sha256": _physical_sha(forged_report),
        }
    )
    forged_outputs = tuple(
        output.model_copy(
            update={"candidate_run_cut_authority_id": forged_cut.candidate_run_cut_authority_id}
        )
        for output in inventory.outputs
    )
    with pytest.raises(ValidationError, match="command, ledger, and run cut differ"):
        inventory.model_copy(update={"candidate_run_cut": forged_cut, "outputs": forged_outputs})

    with pytest.raises(ValidationError, match="exact run scope"):
        inventory.model_copy(
            update={
                "outputs": (
                    first.model_copy(
                        update={"execution_component_manifest_id": _sha("foreign-component")}
                    ),
                    *inventory.outputs[1:],
                )
            }
        )

    case_outputs = [item for item in inventory.outputs if item.candidate_snapshot is not None]
    first_snapshot = case_outputs[0].candidate_snapshot
    second_snapshot = case_outputs[1].candidate_snapshot
    assert first_snapshot is not None and second_snapshot is not None
    cloned_snapshot = second_snapshot.model_copy(
        update={
            "source_case_id": first_snapshot.source_case_id,
            "source_case_revision": first_snapshot.source_case_revision,
            "source_case_document_sha256": first_snapshot.source_case_document_sha256,
        }
    )
    cloned_outputs = tuple(
        item.model_copy(update={"candidate_snapshot": cloned_snapshot})
        if item.candidate_output_authority_id == case_outputs[1].candidate_output_authority_id
        else item
        for item in inventory.outputs
    )
    with pytest.raises(ValidationError, match="Cases must be unique"):
        inventory.model_copy(
            update={
                "candidate_cases": (
                    inventory.candidate_cases[0],
                    inventory.candidate_cases[0],
                ),
                "outputs": cloned_outputs,
            }
        )

    model_output = case_outputs[0]
    call = model_output.model_calls[0]
    with pytest.raises(ValidationError, match="another physical model layer"):
        call.model_copy(
            update={
                "cache_ref": call.cache_ref.model_copy(
                    update={
                        "kind": M6UpgradeCandidateArtifactKind.TOOL_RESULT,
                        "source": M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                    }
                )
            }
        )

    foreign_call = call.model_copy(
        update={"execution_model_manifest_id": _sha("foreign-model-manifest")}
    )
    foreign_output = model_output.model_copy(update={"model_calls": (foreign_call,)})
    with pytest.raises(ValidationError, match="offline candidate profile"):
        inventory.model_copy(
            update={
                "outputs": tuple(
                    foreign_output if item.sample_id == model_output.sample_id else item
                    for item in inventory.outputs
                )
            }
        )

    oversized_timeout_call = call.model_copy(update={"timeout_ms": 15_001})
    oversized_timeout_output = model_output.model_copy(
        update={"model_calls": (oversized_timeout_call,)}
    )
    with pytest.raises(ValidationError, match="offline candidate profile"):
        inventory.model_copy(
            update={
                "outputs": tuple(
                    oversized_timeout_output if item.sample_id == model_output.sample_id else item
                    for item in inventory.outputs
                )
            }
        )


def test_run_cut_rejects_a_real_provider_disguised_as_fake_offline() -> None:
    inventory = _inventory()
    run_cut = inventory.candidate_run_cut
    config = run_cut.candidate_config
    profile_name = config.screening.provider_profile
    real_profile = config.providers[profile_name].model_copy(
        update={"provider": "real-cloud-provider", "model": "remote-model"}
    )
    real_config = config.model_copy(
        update={"providers": {**config.providers, profile_name: real_profile}}
    )
    screening = run_cut.candidate_manifest.models["screening"].model_copy(
        update={"provider": real_profile.provider, "model": real_profile.model}
    )
    real_manifest = run_cut.candidate_manifest.model_copy(
        update={
            "config_sha256": real_config.config_sha256,
            "models": {
                **run_cut.candidate_manifest.models,
                "screening": screening,
            },
        }
    )
    real_report = run_cut.validation_report.model_copy(
        update={
            "manifest_id": real_manifest.manifest_id,
            "config_sha256": real_config.config_sha256,
        }
    )
    with pytest.raises(ValidationError, match="one exact passing run"):
        run_cut.model_copy(
            update={
                "candidate_manifest": real_manifest,
                "candidate_manifest_content_sha256": _physical_sha(real_manifest),
                "candidate_config": real_config,
                "candidate_config_content_sha256": _physical_sha(real_config),
                "validation_report": real_report,
                "validation_report_content_sha256": _physical_sha(real_report),
            }
        )

    remote_perception = config.perception.model_copy(update={"provider": "remote-gpu-detector"})
    remote_config = config.model_copy(update={"perception": remote_perception})
    remote_detector = run_cut.candidate_manifest.models["detector"].model_copy(
        update={"provider": remote_perception.provider}
    )
    remote_manifest = run_cut.candidate_manifest.model_copy(
        update={
            "config_sha256": remote_config.config_sha256,
            "models": {
                **run_cut.candidate_manifest.models,
                "detector": remote_detector,
            },
        }
    )
    remote_report = run_cut.validation_report.model_copy(
        update={
            "manifest_id": remote_manifest.manifest_id,
            "config_sha256": remote_config.config_sha256,
        }
    )
    with pytest.raises(ValidationError, match="one exact passing run"):
        run_cut.model_copy(
            update={
                "candidate_manifest": remote_manifest,
                "candidate_manifest_content_sha256": _physical_sha(remote_manifest),
                "candidate_config": remote_config,
                "candidate_config_content_sha256": _physical_sha(remote_config),
                "validation_report": remote_report,
                "validation_report_content_sha256": _physical_sha(remote_report),
            }
        )

    hidden_model = run_cut.candidate_manifest.models["screening"].model_copy(
        update={
            "component": "hidden_remote",
            "provider": "cloud-provider",
            "model": "hidden-model",
        }
    )
    hidden_manifest = run_cut.candidate_manifest.model_copy(
        update={
            "models": {
                **run_cut.candidate_manifest.models,
                hidden_model.component: hidden_model,
            }
        }
    )
    hidden_report = run_cut.validation_report.model_copy(
        update={"manifest_id": hidden_manifest.manifest_id}
    )
    with pytest.raises(ValidationError, match="one exact passing run"):
        run_cut.model_copy(
            update={
                "candidate_manifest": hidden_manifest,
                "candidate_manifest_content_sha256": _physical_sha(hidden_manifest),
                "validation_report": hidden_report,
                "validation_report_content_sha256": _physical_sha(hidden_report),
            }
        )


def test_run_cut_requires_the_full_validation_chain_and_exact_audit_head() -> None:
    inventory = _inventory()
    run_cut = inventory.candidate_run_cut

    without_predecessor = run_cut.validation_report.model_copy(update={"predecessor_report": None})
    with pytest.raises(ValidationError, match="complete M4 predecessor"):
        run_cut.model_copy(
            update={
                "validation_report": without_predecessor,
                "validation_report_content_sha256": _physical_sha(without_predecessor),
            }
        )

    with pytest.raises(ValidationError, match="one exact passing run"):
        run_cut.model_copy(update={"audit_head_hash": _sha("invented-audit-head")})


def test_model_call_identity_changes_the_sample_and_global_output_authorities() -> None:
    inventory = _inventory()
    first = next(item for item in inventory.outputs if item.model_calls)
    call = first.model_calls[0]
    changed_call = call.model_copy(update={"attempt_index": 1, "timeout_ms": 9_876})
    assert changed_call.model_call_authority_id != call.model_call_authority_id

    changed_output = first.model_copy(update={"model_calls": (changed_call,)})
    assert changed_output.model_call_inventory_root_sha256 != (
        first.model_call_inventory_root_sha256
    )
    assert changed_output.candidate_output_authority_id != (first.candidate_output_authority_id)

    changed_inventory = inventory.model_copy(
        update={
            "outputs": tuple(
                changed_output if item.sample_id == first.sample_id else item
                for item in inventory.outputs
            )
        }
    )
    assert changed_inventory.model_call_inventory_root_sha256 != (
        inventory.model_call_inventory_root_sha256
    )
    assert changed_inventory.candidate_output_inventory_authority_id != (
        inventory.candidate_output_inventory_authority_id
    )


def test_failed_model_call_rejects_success_only_cache_and_response_artifacts() -> None:
    call = next(item for item in _inventory().outputs if item.model_calls).model_calls[0]
    assert call.cache_ref is not None
    failed = {
        "result_kind": M6LockedModelCallResultKind.FAILURE,
        "response_ref": None,
        "parse_receipt_ref": None,
        "parsed_output_ref": None,
        "usage_receipt_ref": None,
        "failure_ref": _artifact(
            M6UpgradeCandidateArtifactKind.MODEL_CALL_FAILURE,
            call.sample_id,
            "failure",
        ),
    }

    with pytest.raises(ValidationError, match="failed model-call closure is incomplete"):
        call.model_copy(update=failed)

    controlled = call.model_copy(update={**failed, "cache_ref": None})
    assert controlled.result_kind == M6LockedModelCallResultKind.FAILURE
    assert controlled.artifact_refs == (controlled.request_ref, controlled.failure_ref)


def test_inventory_uses_route_scoped_physical_identity_and_rejects_case_grafts() -> None:
    inventory = _inventory()
    first, second = inventory.outputs[:2]

    duplicated_detection = second.detections[0].model_copy(
        update={"artifact_id": first.detections[0].artifact_id}
    )
    duplicate_output = second.model_copy(update={"detections": (duplicated_detection,)})
    with pytest.raises(ValidationError, match="output and ledger artifacts differ"):
        inventory.model_copy(update={"outputs": (first, duplicate_output, *inventory.outputs[2:])})

    call = next(item for item in inventory.outputs if item.model_calls).model_calls[0]
    reused_physical_id = call.request_ref.artifact_id
    assert call.usage_receipt_ref is not None
    shared_durable_primary_key = call.model_copy(
        update={
            "usage_receipt_ref": call.usage_receipt_ref.model_copy(
                update={"artifact_id": reused_physical_id}
            )
        }
    )
    assert shared_durable_primary_key.request_ref.artifact_id == (
        shared_durable_primary_key.usage_receipt_ref.artifact_id
    )
    assert shared_durable_primary_key.request_ref.physical_key != (
        shared_durable_primary_key.usage_receipt_ref.physical_key
    )

    shared_output = second.model_copy(
        update={"frames": first.frames, "detections": first.detections}
    )
    with pytest.raises(ValidationError, match="output and ledger artifacts differ"):
        inventory.model_copy(update={"outputs": (first, shared_output, *inventory.outputs[2:])})

    case_outputs = [item for item in inventory.outputs if item.candidate_snapshot is not None]
    first_snapshot = case_outputs[0].candidate_snapshot
    second_snapshot = case_outputs[1].candidate_snapshot
    assert first_snapshot is not None and second_snapshot is not None
    revised_snapshot = second_snapshot.model_copy(
        update={
            "source_case_id": first_snapshot.source_case_id,
            "source_case_revision": first_snapshot.source_case_revision + 1,
        }
    )
    revised_outputs = tuple(
        item.model_copy(update={"candidate_snapshot": revised_snapshot})
        if item.candidate_output_authority_id == case_outputs[1].candidate_output_authority_id
        else item
        for item in inventory.outputs
    )
    revised_cases = tuple(
        sorted(
            (
                M6UpgradeCandidateCaseDocumentRef(
                    case_id=snapshot.source_case_id,
                    case_revision=snapshot.source_case_revision,
                    case_document_sha256=snapshot.source_case_document_sha256,
                )
                for output in revised_outputs
                if (snapshot := output.candidate_snapshot) is not None
            ),
            key=lambda item: item.sort_key,
        )
    )
    with pytest.raises(ValidationError, match="Cases must be unique"):
        inventory.model_copy(update={"candidate_cases": revised_cases, "outputs": revised_outputs})


def test_candidate_output_derived_claims_and_schemas_reject_tampering() -> None:
    inventory = _inventory()
    payload = inventory.model_dump(mode="json")
    payload["artifact_count"] = 0
    with pytest.raises(ValidationError, match="artifact_count"):
        M6UpgradeCandidateOutputInventoryAuthority.model_validate(payload)

    output = next(item for item in inventory.outputs if item.model_calls)
    output_payload = output.model_dump(mode="json")
    output_payload["provider_call_count"] = 0
    with pytest.raises(ValidationError, match="provider_call_count"):
        M6UpgradeCandidateSampleOutputAuthority.model_validate(output_payload)

    output_payload = output.model_dump(mode="json")
    output_payload["model_call_inventory_root_sha256"] = _sha("forged-call-root")
    with pytest.raises(ValidationError, match="model_call_inventory_root_sha256"):
        M6UpgradeCandidateSampleOutputAuthority.model_validate(output_payload)

    artifacts = {
        "m6-upgrade-candidate-run-cut-authority": inventory.candidate_run_cut,
        "m6-upgrade-candidate-sample-output-authority": inventory.outputs[0],
        "m6-upgrade-candidate-output-inventory-authority": inventory,
    }
    schemas = expected_schema_files()
    for name, artifact in artifacts.items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))
