from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest
from pydantic import BaseModel

from labcourt.application.m6_replay_locked_alert_policy import (
    build_m6_replay_locked_closed_policy_candidate,
)
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_scope,
    build_m6_replay_locked_closed_policy_execution_seal,
    build_m6_replay_locked_closed_policy_pending_commitment,
    build_m6_replay_locked_closed_policy_sample_record,
)
from labcourt.application.m6_replay_locked_closed_policy_regression import (
    M6ReplayLockedClosedPolicyRegressionAssemblyError,
    M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode,
    assemble_m6_replay_locked_closed_policy_regression_report,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.config_loader import load_config
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    ReproducibilityMode,
)
from labcourt.contracts.events import derive_case_id
from labcourt.contracts.evidence import EvidencePack, EvidencePackDraft
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression import (
    M6BaselineAuthorityKind,
    M6ChallengeKind,
    M6GoldTruthAuthority,
    M6GoldTruthAuthorityKind,
    M6RegressionDatasetEntry,
    M6RegressionDatasetKind,
    M6RegressionDatasetSnapshot,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionExecutionSourceCatalogEntry,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedCandidateBindingAuthority,
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedCandidateCaseBinding,
    M6ReplayLockedExecutionComponentAuthority,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.domain.alert_policy import plan_case_alert
from labcourt.ports.evidence_repository import AuditHead
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateObservation,
)
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
)
from tests.contract.test_m3_contracts import (
    _parsed,
    _presence_pack,
    _review,
    _screening,
    _verdict,
)
from tests.contract.test_m6_replay_locked_alert_policy_contracts import (
    _closed_case,
    _closing_audit,
)
from tests.unit.test_m5_alert_policy import ROOT, _manifest_with_stream
from tests.unit.test_m6_replay_locked_candidate_observation import _runtime
from tests.unit.test_m6_semantic_projection import _snapshot


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _identity(value: BaseModel) -> tuple[str, int]:
    payload = _document(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _ready_case(
    *,
    manifest_id: str,
    run_id: str,
    event_index: int,
) -> Case:
    base = _presence_pack()
    event = base.event.model_copy(
        update={
            "manifest_id": manifest_id,
            "start_frame": event_index - 1,
        }
    )
    case_id = derive_case_id(event.event_id)
    draft = EvidencePackDraft(
        run_id=run_id,
        case_id=case_id,
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
        manifest_id=manifest_id,
    )
    pack = EvidencePack(
        **draft.model_dump(mode="python", exclude={"pack_id"}),
        closure_report=ClosureReport(
            run_id=run_id,
            root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id),
            manifest_id=manifest_id,
            input_sha256=draft.closure_input_sha256,
            checked_refs=draft.expected_closure_refs(),
        ),
    )
    parsed = _parsed(
        run_id=run_id,
        case_id=case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        manifest_id=manifest_id,
    )
    screening = _screening(parsed, l1_score=pack.event.l1_score)
    verdict = _verdict(screening)
    review = _review(verdict)
    return Case(
        run_id=run_id,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=event,
        evidence_packs=(pack,),
        screening_results=(screening,),
        verdicts=(verdict,),
        procedural_reviews=(review,),
        manifest_id=manifest_id,
    )


@dataclass(frozen=True, slots=True)
class _Source:
    sample_id: str
    event_index: int
    closure: M6ReplayInputClosureAuthority
    cut: object
    baseline: object


def _source(index: int, *, manifest_id: str, config_sha256: str) -> _Source:
    sample_id = _sha(f"closed-report-sample-{index}")
    run_id = f"closed-report-source-{index}"
    ready = _ready_case(
        manifest_id=manifest_id,
        run_id=run_id,
        event_index=index,
    )
    config = load_config(ROOT / "configs/demo.yaml")
    policy = plan_case_alert(ready, config, _manifest_with_stream())
    closed = _closed_case(ready, policy)
    audit = _closing_audit(ready, closed, policy, sequence=7)
    report = M5ArtifactValidationReport(
        run_id=run_id,
        manifest_id=manifest_id,
        config_sha256=config_sha256,
        authority_root_sha256=_sha(f"closed-report-m5-root-{index}"),
    )
    report_document = _document(report)
    closed_document = _document(closed)
    fast_closure = _runtime().source.closure
    closure = M6ReplayInputClosureAuthority(
        sample_id=sample_id,
        source_run_id=run_id,
        source_case_id=closed.case_id,
        source_case_revision=7,
        source_case_document_sha256=_sha(closed_document),
        source_manifest_id=manifest_id,
        source_manifest_document_sha256=_sha("closed-report-manifest-document"),
        input_authority_id=_sha(f"closed-report-input-{index}"),
        input_authority_document_sha256=_sha(f"closed-report-input-document-{index}"),
        source_validation_report_id=report.report_id,
        source_validation_report_document_sha256=_sha(report_document),
        frames=(
            M6LockedFrameInput(
                frame_id=f"camera-main:stream-main:{100 + index}",
                document_sha256=_sha(f"closed-report-frame-document-{index}"),
                content_sha256=_sha(f"closed-report-frame-content-{index}"),
            ),
        ),
        model_calls=fast_closure.model_calls,
        historical_cut=fast_closure.historical_cut,
    )
    observation = M6ReplayLockedAlertPolicySourceObservation(
        source_identity_sha256=_sha(f"closed-report-source-identity-{index}"),
        replay_input_closure=closure,
        replay_input_closure_canonical_document=_document(closure),
        source_validation_report=report,
        source_validation_report_canonical_document=report_document,
        source_m5_authority_root_sha256=report.authority_root_sha256,
        source_ready_case_revision=6,
        source_ready_case=ready,
        source_ready_case_canonical_document=_document(ready),
        source_closed_case_revision=7,
        source_closed_case=closed,
        source_closed_case_canonical_document=closed_document,
        source_alert_policy=policy,
        source_alert_policy_canonical_document=_document(policy),
        closing_audit_entry=audit,
        closing_audit_entry_canonical_document=_document(audit),
        cooldown_eligible_history_rows=(),
    )
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    baseline = _snapshot(closed, revision=7).model_copy(update={"sample_id": sample_id})
    return _Source(sample_id, index, closure, cut, baseline)


@dataclass(frozen=True, slots=True)
class _Facts:
    stored_catalog: M6StoredRegressionExecutionSourceCatalog
    dataset: M6RegressionDatasetSnapshot
    seal: M6ReplayLockedClosedPolicyExecutionSealAuthorityV2


def _facts() -> _Facts:
    manifest = _manifest_with_stream()
    config = load_config(ROOT / "configs/demo.yaml")
    sources = tuple(
        _source(index, manifest_id=manifest.manifest_id, config_sha256=config.config_sha256)
        for index in (1, 2)
    )
    catalog_entries = []
    for index, source in enumerate(sources, start=1):
        closure_sha, closure_size = _identity(source.closure)
        catalog_entries.append(
            M6RegressionExecutionSourceCatalogEntry(
                source_item_id=_sha(f"closed-report-source-item-{index}"),
                sample_id=source.sample_id,
                source_seal_id=_sha(f"closed-report-source-seal-{index}"),
                source_seal_content_sha256=_sha(f"closed-report-source-seal-document-{index}"),
                source_seal_size_bytes=1,
                input_authority_id=source.closure.input_authority_id,
                input_authority_document_sha256=(source.closure.input_authority_document_sha256),
                input_authority_content_sha256=_sha(f"closed-report-input-content-{index}"),
                input_authority_size_bytes=1,
                replay_input_closure_content_sha256=closure_sha,
                replay_input_closure_size_bytes=closure_size,
                replay_input_closure=source.closure,
            )
        )
    ordered_catalog_entries = tuple(sorted(catalog_entries, key=lambda item: item.sample_id))
    source_by_sample = {item.sample_id: item for item in sources}
    source_item_ids = [item.source_item_id for item in ordered_catalog_entries]
    catalog = M6RegressionExecutionSourceCatalogAuthority(
        baseline_manifest_id=manifest.manifest_id,
        source_inventory_cut_authority_id=_sha("closed-report-source-cut"),
        source_inventory_cut_content_sha256=_sha("closed-report-source-cut-document"),
        source_inventory_item_count=len(ordered_catalog_entries),
        source_inventory_root_sha256=sha256_hex(
            ["m6-regression-source-inventory", 1, source_item_ids]
        ),
        entries=ordered_catalog_entries,
    )
    catalog_document = _document(catalog)
    catalog_payload = catalog_document.encode("utf-8")
    stored = M6StoredRegressionExecutionSourceCatalog(
        source_catalog=catalog,
        canonical_document=catalog_document,
        content_sha256=hashlib.sha256(catalog_payload).hexdigest(),
        size_bytes=len(catalog_payload),
    )
    execution_entries = tuple(
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
        for item in ordered_catalog_entries
    )
    execution_dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=manifest.manifest_id,
        source_catalog_authority_id=catalog.source_catalog_authority_id,
        source_catalog_document_sha256=stored.content_sha256,
        entries=execution_entries,
    )
    evaluator_entries = []
    for index, execution_entry in enumerate(execution_entries):
        source = source_by_sample[execution_entry.sample_id]
        baseline_document = _document(source.baseline)
        memberships = (
            (
                M6RegressionDatasetKind.STABILITY,
                M6RegressionDatasetKind.CHALLENGE,
            )
            if index == 0
            else (M6RegressionDatasetKind.GOLD,)
        )
        gold = None
        challenge = ()
        if index == 0:
            challenge = (M6ChallengeKind.DIFFICULT_NEGATIVE,)
        else:
            gold = M6GoldTruthAuthority(
                sample_id=execution_entry.sample_id,
                baseline_snapshot_id=source.baseline.snapshot_id,
                baseline_source_run_id=source.baseline.source_run_id,
                baseline_source_case_id=source.baseline.source_case_id,
                baseline_source_case_revision=source.baseline.source_case_revision,
                authority_kind=M6GoldTruthAuthorityKind.PRESET_GOLD,
                decision_authority_id=_sha("closed-report-gold-decision"),
                decision_authority_document_sha256=_sha("closed-report-gold-decision-document"),
                expected_decision=source.baseline.final_decision,
            )
        evaluator_entries.append(
            M6RegressionDatasetEntry(
                sample_id=execution_entry.sample_id,
                input_authority_id=execution_entry.input_authority_id,
                input_authority_document_sha256=(execution_entry.input_authority_document_sha256),
                replay_input_closure_authority_id=(
                    execution_entry.replay_input_closure_authority_id
                ),
                replay_input_closure_document_sha256=(
                    execution_entry.replay_input_closure_document_sha256
                ),
                baseline_authority_kind=(M6BaselineAuthorityKind.MACHINE_TERMINAL_CASE),
                baseline_authority_id=source.baseline.snapshot_id,
                baseline_authority_document_sha256=_sha(baseline_document),
                baseline_snapshot=source.baseline,
                memberships=memberships,
                gold_truth=gold,
                challenge_kinds=challenge,
            )
        )
    dataset = M6RegressionDatasetSnapshot(
        baseline_manifest_id=manifest.manifest_id,
        execution_dataset=execution_dataset,
        source_inventory_cut_authority_id=catalog.source_inventory_cut_authority_id,
        source_inventory_cut_document_sha256=(catalog.source_inventory_cut_content_sha256),
        source_inventory_item_count=catalog.source_inventory_item_count,
        source_inventory_root_sha256=catalog.source_inventory_root_sha256,
        eligibility_policy_authority_id=_sha("closed-report-eligibility"),
        eligibility_policy_document_sha256=_sha("closed-report-eligibility-document"),
        selection_inventory_authority_id=_sha("closed-report-selection"),
        selection_inventory_document_sha256=_sha("closed-report-selection-document"),
        selection_receipt_count=len(evaluator_entries),
        selection_inventory_root_sha256=_sha("closed-report-selection-root"),
        entries=tuple(evaluator_entries),
    )
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=execution_dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=manifest.manifest_id,
        candidate_manifest_id=manifest.manifest_id,
        policy_authority=M6RegressionPolicyAuthority(
            config_sha256=config.config_sha256,
            policy_version="closed-policy-regression-v1",
            maximum_machine_flip_rate=0.05,
            gold_set_max_accuracy_drop=0.0,
        ),
    )
    pre_policy_component = M6ReplayLockedExecutionComponentAuthority(
        version="0.1.0",
        code_commit=manifest.code_commit,
    )
    pre_policy_scope = build_m6_replay_locked_execution_scope(
        candidate_run_id="closed-report-candidate",
        command=command,
        execution_dataset=execution_dataset,
        stored_source_catalog=stored,
        locked_manifest=manifest,
        locked_config=config,
        execution_component=pre_policy_component,
    )
    component = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version=pre_policy_component.version,
        code_commit=pre_policy_component.code_commit,
        pre_policy_component_authority_id=pre_policy_component.component_authority_id,
        supported_pre_policy_routes=pre_policy_component.supported_routes,
    )
    scope = build_m6_replay_locked_closed_policy_execution_scope(
        pre_policy_execution_scope=pre_policy_scope,
        execution_component=component,
    )
    records = []
    previous = AUDIT_GENESIS_HASH
    last_audit_hash = AUDIT_GENESIS_HASH
    for index, catalog_entry in enumerate(ordered_catalog_entries):
        source = source_by_sample[catalog_entry.sample_id]
        pending = build_m6_replay_locked_closed_policy_pending_commitment(
            execution_scope=scope,
            stored_source_catalog=stored,
            policy_causal_cut=source.cut,
            ledger_sequence=index,
            previous_ledger_entry_hash=previous,
        )
        candidate_ready = _ready_case(
            manifest_id=manifest.manifest_id,
            run_id=scope.candidate_run_id,
            event_index=source.event_index,
        )
        candidate = build_m6_replay_locked_closed_policy_candidate(
            ready_case=candidate_ready,
            source_binding=pending.source_binding,
            locked_config=config,
            locked_manifest=manifest,
        )
        closed_sha, closed_size = _identity(candidate.closed_case)
        last_audit_hash = _sha(f"closed-report-candidate-audit-{index}")
        persisted = M6ReplayLockedCandidateCaseBinding(
            candidate_run_id=scope.candidate_run_id,
            sample_id=pending.sample_id,
            case_id=candidate.closed_case.case_id,
            case_revision=1,
            case_document_sha256=closed_sha,
            case_document_size_bytes=closed_size,
            case_audit_sequence=index,
            case_audit_entry_hash=last_audit_hash,
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
        candidate_snapshot = _snapshot(candidate.closed_case, revision=1).model_copy(
            update={"sample_id": pending.sample_id}
        )
        proof = M6ReplayLockedSourceDeterminismAuthority(
            command_id=scope.command_id,
            execution_entry_id=pending.execution_entry_id,
            sample_id=pending.sample_id,
            source_run_id=source.closure.source_run_id,
            candidate_run_id=scope.candidate_run_id,
            source_manifest_id=source.closure.source_manifest_id,
            execution_component_manifest_id=pre_policy_component.component_authority_id,
            replay_input_closure_authority_id=(source.closure.replay_input_closure_authority_id),
            replay_input_closure_document_sha256=(
                source.closure.replay_input_closure_document_sha256
            ),
            source_identity_sha256=source.cut.source_identity_sha256,
            first_source_snapshot_id=source.baseline.snapshot_id,
            second_source_snapshot_id=source.baseline.snapshot_id,
            first_semantic_case_hash=source.baseline.semantic_case_hash,
            second_semantic_case_hash=source.baseline.semantic_case_hash,
        )
        observation = M6ReplayLockedClosedCandidateObservation(
            closed_candidate_binding=binding,
            candidate_snapshot=candidate_snapshot,
        )
        record = build_m6_replay_locked_closed_policy_sample_record(
            execution_scope=scope,
            stored_source_catalog=stored,
            pending_commitment=pending,
            source_determinism=proof,
            policy_causal_cut=source.cut,
            candidate_observation=observation,
        )
        records.append(record)
        previous = record.sample_execution_record_id
    seal = build_m6_replay_locked_closed_policy_execution_seal(
        execution_scope=scope,
        sample_records=tuple(records),
        candidate_audit_head=AuditHead(
            run_id=scope.candidate_run_id,
            manifest_id=scope.candidate_manifest_id,
            run_revision=len(records),
            sequence=len(records) - 1,
            entry_hash=last_audit_hash,
        ),
    )
    return _Facts(stored, dataset, seal)


def _assemble(facts: _Facts):  # type: ignore[no-untyped-def]
    return assemble_m6_replay_locked_closed_policy_regression_report(
        stored_source_catalog=facts.stored_catalog,
        evaluator_dataset=facts.dataset,
        evaluator_dataset_document=_document(facts.dataset),
        execution_seal=facts.seal,
        execution_seal_document=_document(facts.seal),
    )


def test_closed_policy_report_joins_catalog_evaluator_dataset_and_seal() -> None:
    facts = _facts()

    bundle = _assemble(facts)

    assert bundle.report.command.mode is ReproducibilityMode.REPLAY_LOCKED
    assert bundle.report.dataset == facts.dataset
    assert bundle.execution_seal == facts.seal
    assert bundle.stored_source_catalog == facts.stored_catalog
    assert bundle.report.execution_receipts == facts.seal.execution_receipts
    assert bundle.report.release_allowed
    assert bundle.report.gate_reason_codes == ()
    assert bundle.report.stability_case_count == 1
    assert bundle.report.gold_case_count == 1
    assert bundle.report.challenge_case_count == 1
    assert all(item.semantic_identical for item in bundle.report.results)
    assert _sha(bundle.report_document) == bundle.report_content_sha256
    assert _sha(bundle.execution_seal_document) == (bundle.execution_seal_content_sha256)


def test_closed_policy_report_rejects_dataset_and_baseline_grafts() -> None:
    facts = _facts()
    foreign_execution = facts.dataset.execution_dataset.model_copy(
        update={"source_catalog_document_sha256": _sha("foreign-catalog")}
    )
    foreign_dataset = facts.dataset.model_copy(update={"execution_dataset": foreign_execution})

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionAssemblyError) as catalog:
        assemble_m6_replay_locked_closed_policy_regression_report(
            stored_source_catalog=facts.stored_catalog,
            evaluator_dataset=foreign_dataset,
            evaluator_dataset_document=_document(foreign_dataset),
            execution_seal=facts.seal,
            execution_seal_document=_document(facts.seal),
        )
    assert catalog.value.code in {
        M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.SOURCE_CATALOG_MISMATCH,
        M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.COMMAND_DATASET_MISMATCH,
    }

    entry = facts.dataset.entries[0]
    assert entry.baseline_snapshot is not None
    foreign_baseline = entry.baseline_snapshot.model_copy(
        update={"source_case_revision": entry.baseline_snapshot.source_case_revision + 1}
    )
    baseline_document = _document(foreign_baseline)
    foreign_entry = entry.model_copy(
        update={
            "baseline_snapshot": foreign_baseline,
            "baseline_authority_id": foreign_baseline.snapshot_id,
            "baseline_authority_document_sha256": _sha(baseline_document),
        }
    )
    foreign_entries = (foreign_entry, *facts.dataset.entries[1:])
    baseline_dataset = facts.dataset.model_copy(update={"entries": foreign_entries})

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionAssemblyError) as baseline:
        assemble_m6_replay_locked_closed_policy_regression_report(
            stored_source_catalog=facts.stored_catalog,
            evaluator_dataset=baseline_dataset,
            evaluator_dataset_document=_document(baseline_dataset),
            execution_seal=facts.seal,
            execution_seal_document=_document(facts.seal),
        )
    assert baseline.value.code is (
        M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.BASELINE_SOURCE_MISMATCH
    )


def test_closed_policy_report_rejects_noncanonical_documents_without_payloads() -> None:
    facts = _facts()

    with pytest.raises(M6ReplayLockedClosedPolicyRegressionAssemblyError) as raised:
        assemble_m6_replay_locked_closed_policy_regression_report(
            stored_source_catalog=facts.stored_catalog,
            evaluator_dataset=facts.dataset,
            evaluator_dataset_document=_document(facts.dataset) + " ",
            execution_seal=facts.seal,
            execution_seal_document=_document(facts.seal),
        )

    assert raised.value.code is (
        M6ReplayLockedClosedPolicyRegressionAssemblyErrorCode.DOCUMENT_INVALID
    )
    assert not hasattr(raised.value, "evaluator_dataset")
    assert not hasattr(raised.value, "execution_seal")


def test_closed_policy_report_is_exactly_retryable() -> None:
    facts = _facts()

    assert _assemble(facts) == _assemble(facts)
