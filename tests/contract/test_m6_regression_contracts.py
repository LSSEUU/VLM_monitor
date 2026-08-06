from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    AlertLevel,
    CaseStatus,
    ReproducibilityMode,
    VerdictDecision,
)
from labcourt.contracts.m6_regression import (
    M6BaselineAuthorityKind,
    M6CaseReplaySnapshot,
    M6ChallengeKind,
    M6EmergencyRegressionReview,
    M6EmergencyReviewDecision,
    M6GoldTruthAuthority,
    M6GoldTruthAuthorityKind,
    M6RegressionCaseDisposition,
    M6RegressionCaseResult,
    M6RegressionDatasetEntry,
    M6RegressionDatasetKind,
    M6RegressionDatasetSnapshot,
    M6RegressionDisposition,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionGateReason,
    M6RegressionPolicyAuthority,
    M6RegressionReport,
    M6RegressionRunCommand,
    M6RegressionStage,
    M6ReplayExecutionOutcome,
    M6ReplayExecutionReceipt,
    M6SemanticStageRoot,
)
from labcourt.schema_export import expected_schema_files

BASELINE_MANIFEST_ID = "a" * 64
CANDIDATE_MANIFEST_ID = "b" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _content_sha256(value: M6CaseReplaySnapshot) -> str:
    document = canonical_json(value.model_dump(mode="json"))
    return _sha(document)


def _stage_roots(
    seed: str,
    *,
    changed: Iterable[M6RegressionStage] = (),
) -> tuple[M6SemanticStageRoot, ...]:
    changed_set = set(changed)
    return tuple(
        M6SemanticStageRoot(
            stage=stage,
            projection_sha256=_sha(
                f"{seed}:{stage.value}:{'changed' if stage in changed_set else 'stable'}"
            ),
        )
        for stage in M6RegressionStage
    )


def _baseline_snapshot(
    sample_id: str,
    *,
    decision: VerdictDecision = VerdictDecision.ESTABLISHED,
    alert: AlertLevel | None = AlertLevel.CONFIRMED,
    roots_seed: str | None = None,
) -> M6CaseReplaySnapshot:
    return M6CaseReplaySnapshot(
        sample_id=sample_id,
        source_run_id="run-baseline",
        source_case_id=f"case-{sample_id}",
        source_case_revision=7,
        source_case_document_sha256=_sha(f"baseline-case:{sample_id}"),
        manifest_id=BASELINE_MANIFEST_ID,
        stage_roots=_stage_roots(roots_seed or sample_id),
        case_status=CaseStatus.CLOSED,
        final_decision=decision,
        highest_alert_level=alert,
    )


def _candidate_snapshot(
    baseline: M6CaseReplaySnapshot,
    *,
    manifest_id: str = CANDIDATE_MANIFEST_ID,
    candidate_run_id: str = "run-candidate",
    decision: VerdictDecision | object | None = ...,
    case_status: CaseStatus | None = None,
    alert: AlertLevel | object | None = ...,
    changed: Iterable[M6RegressionStage] = (),
) -> M6CaseReplaySnapshot:
    changed_stages = tuple(changed)
    updates: dict[str, object] = {
        "source_run_id": candidate_run_id,
        "source_case_revision": 1,
        "source_case_document_sha256": _sha(f"candidate-case:{baseline.sample_id}"),
        "manifest_id": manifest_id,
        "stage_roots": tuple(
            M6SemanticStageRoot(
                stage=root.stage,
                projection_sha256=(
                    _sha(f"candidate:{baseline.sample_id}:{root.stage.value}")
                    if root.stage in changed_stages
                    else root.projection_sha256
                ),
            )
            for root in baseline.stage_roots
        ),
    }
    if decision is not ...:
        updates["final_decision"] = decision
    if case_status is not None:
        updates["case_status"] = case_status
    if alert is not ...:
        updates["highest_alert_level"] = alert
    return baseline.model_copy(update=updates)


def _appeal_truth(
    baseline: M6CaseReplaySnapshot,
    expected: VerdictDecision = VerdictDecision.ESTABLISHED,
) -> M6GoldTruthAuthority:
    return M6GoldTruthAuthority(
        sample_id=baseline.sample_id,
        baseline_snapshot_id=baseline.snapshot_id,
        baseline_source_run_id=baseline.source_run_id,
        baseline_source_case_id=baseline.source_case_id,
        baseline_source_case_revision=baseline.source_case_revision,
        authority_kind=M6GoldTruthAuthorityKind.APPEAL_RESOLUTION,
        decision_authority_id=_sha(f"appeal-authority:{expected.value}"),
        decision_authority_document_sha256=_sha(f"appeal-document:{expected.value}"),
        expected_decision=expected,
        resolution_commit_id=_sha(f"appeal-commit:{expected.value}"),
        resolution_commit_document_sha256=_sha(f"appeal-commit-document:{expected.value}"),
    )


def _stability_entry(
    sample_id: str,
    *,
    decision: VerdictDecision = VerdictDecision.ESTABLISHED,
    alert: AlertLevel | None = AlertLevel.CONFIRMED,
    challenge: M6ChallengeKind | None = None,
) -> M6RegressionDatasetEntry:
    memberships = (M6RegressionDatasetKind.STABILITY,)
    challenge_kinds: tuple[M6ChallengeKind, ...] = ()
    if challenge is not None:
        memberships = (*memberships, M6RegressionDatasetKind.CHALLENGE)
        challenge_kinds = (challenge,)
    baseline = _baseline_snapshot(sample_id, decision=decision, alert=alert)
    return M6RegressionDatasetEntry(
        sample_id=sample_id,
        input_authority_id=_sha(f"input:{sample_id}"),
        input_authority_document_sha256=_sha(f"input-document:{sample_id}"),
        replay_input_closure_authority_id=_sha(f"input-closure:{sample_id}"),
        replay_input_closure_document_sha256=_sha(f"input-closure-document:{sample_id}"),
        baseline_authority_kind=M6BaselineAuthorityKind.MACHINE_TERMINAL_CASE,
        baseline_authority_id=baseline.snapshot_id,
        baseline_authority_document_sha256=_content_sha256(baseline),
        baseline_snapshot=baseline,
        memberships=memberships,
        challenge_kinds=challenge_kinds,
    )


def _gold_entry(
    sample_id: str = "gold-001",
    *,
    baseline_decision: VerdictDecision = VerdictDecision.ESTABLISHED,
    expected_decision: VerdictDecision = VerdictDecision.ESTABLISHED,
    challenge: M6ChallengeKind | None = None,
) -> M6RegressionDatasetEntry:
    memberships = (M6RegressionDatasetKind.GOLD,)
    challenge_kinds: tuple[M6ChallengeKind, ...] = ()
    if challenge is not None:
        memberships = (*memberships, M6RegressionDatasetKind.CHALLENGE)
        challenge_kinds = (challenge,)
    baseline = _baseline_snapshot(sample_id, decision=baseline_decision)
    return M6RegressionDatasetEntry(
        sample_id=sample_id,
        input_authority_id=_sha(f"input:{sample_id}"),
        input_authority_document_sha256=_sha(f"input-document:{sample_id}"),
        replay_input_closure_authority_id=_sha(f"input-closure:{sample_id}"),
        replay_input_closure_document_sha256=_sha(f"input-closure-document:{sample_id}"),
        baseline_authority_kind=M6BaselineAuthorityKind.PRE_APPEAL_CLOSED_CASE,
        baseline_authority_id=baseline.snapshot_id,
        baseline_authority_document_sha256=_content_sha256(baseline),
        baseline_snapshot=baseline,
        memberships=memberships,
        gold_truth=_appeal_truth(baseline, expected_decision),
        challenge_kinds=challenge_kinds,
    )


def _no_case_challenge_entry(sample_id: str = "challenge-001") -> M6RegressionDatasetEntry:
    return M6RegressionDatasetEntry(
        sample_id=sample_id,
        input_authority_id=_sha(f"input:{sample_id}"),
        input_authority_document_sha256=_sha(f"input-document:{sample_id}"),
        replay_input_closure_authority_id=_sha(f"input-closure:{sample_id}"),
        replay_input_closure_document_sha256=_sha(f"input-closure-document:{sample_id}"),
        baseline_authority_kind=M6BaselineAuthorityKind.CHALLENGE_NO_CASE,
        baseline_authority_id=_sha(f"no-case-authority:{sample_id}"),
        baseline_authority_document_sha256=_sha(f"no-case-document:{sample_id}"),
        memberships=(M6RegressionDatasetKind.CHALLENGE,),
        challenge_kinds=(M6ChallengeKind.DIFFICULT_NEGATIVE,),
    )


def _dataset(
    entries: Iterable[M6RegressionDatasetEntry],
) -> M6RegressionDatasetSnapshot:
    ordered = tuple(sorted(entries, key=lambda entry: entry.sample_id))
    execution_dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=BASELINE_MANIFEST_ID,
        source_catalog_authority_id=_sha("source-catalog-authority"),
        source_catalog_document_sha256=_sha("source-catalog-document"),
        entries=tuple(
            M6RegressionExecutionEntry(
                sample_id=entry.sample_id,
                input_authority_id=entry.input_authority_id,
                input_authority_document_sha256=(entry.input_authority_document_sha256),
                replay_input_closure_authority_id=(entry.replay_input_closure_authority_id),
                replay_input_closure_document_sha256=(entry.replay_input_closure_document_sha256),
            )
            for entry in ordered
        ),
    )
    return M6RegressionDatasetSnapshot(
        baseline_manifest_id=BASELINE_MANIFEST_ID,
        execution_dataset=execution_dataset,
        source_inventory_cut_authority_id=_sha("source-inventory-cut-authority"),
        source_inventory_cut_document_sha256=_sha("source-inventory-cut-document"),
        source_inventory_item_count=len(ordered),
        source_inventory_root_sha256=_sha("source-inventory-root"),
        eligibility_policy_authority_id=_sha("eligibility-policy-authority"),
        eligibility_policy_document_sha256=_sha("eligibility-policy-document"),
        selection_inventory_authority_id=_sha("selection-inventory-authority"),
        selection_inventory_document_sha256=_sha("selection-inventory-document"),
        selection_receipt_count=len(ordered),
        selection_inventory_root_sha256=_sha("selection-inventory-root"),
        entries=ordered,
    )


def _minimal_dataset(
    *,
    stability_entries: Iterable[M6RegressionDatasetEntry] = (),
    gold_entry: M6RegressionDatasetEntry | None = None,
    challenge_entry: M6RegressionDatasetEntry | None = None,
) -> M6RegressionDatasetSnapshot:
    stability = tuple(stability_entries) or (_stability_entry("stability-001"),)
    return _dataset(
        (
            *stability,
            gold_entry or _gold_entry(),
            challenge_entry or _no_case_challenge_entry(),
        )
    )


def _result(
    entry: M6RegressionDatasetEntry,
    *,
    candidate_manifest_id: str,
    decision: VerdictDecision | object | None = ...,
    case_status: CaseStatus | None = None,
    alert: AlertLevel | object | None = ...,
    changed: Iterable[M6RegressionStage] = (),
    missing: bool = False,
    added: bool = False,
) -> M6RegressionCaseResult:
    baseline = entry.baseline_snapshot
    if baseline is None:
        candidate = (
            _baseline_snapshot(entry.sample_id).model_copy(
                update={
                    "source_run_id": "run-candidate",
                    "source_case_revision": 1,
                    "source_case_document_sha256": _sha(f"candidate-case:{entry.sample_id}"),
                    "manifest_id": candidate_manifest_id,
                }
            )
            if added
            else None
        )
    else:
        candidate = (
            None
            if missing
            else _candidate_snapshot(
                baseline,
                manifest_id=candidate_manifest_id,
                decision=decision,
                case_status=case_status,
                alert=alert,
                changed=changed,
            )
        )
    return M6RegressionCaseResult(
        entry_id=entry.entry_id,
        sample_id=entry.sample_id,
        baseline_snapshot=baseline,
        candidate_snapshot=candidate,
    )


def _policy(
    *,
    maximum_machine_flip_rate: float,
    gold_set_max_accuracy_drop: float,
) -> M6RegressionPolicyAuthority:
    return M6RegressionPolicyAuthority(
        config_sha256=_sha("resolved-config"),
        policy_version="regression-v1",
        maximum_machine_flip_rate=maximum_machine_flip_rate,
        gold_set_max_accuracy_drop=gold_set_max_accuracy_drop,
    )


def _execution_receipt(
    *,
    command: M6RegressionRunCommand,
    execution_entry: M6RegressionExecutionEntry,
    result: M6RegressionCaseResult,
) -> M6ReplayExecutionReceipt:
    candidate = result.candidate_snapshot
    locked = command.mode == ReproducibilityMode.REPLAY_LOCKED
    return M6ReplayExecutionReceipt(
        command_id=command.command_id,
        mode=command.mode,
        sample_id=result.sample_id,
        execution_entry_id=execution_entry.execution_entry_id,
        candidate_run_id=(candidate.source_run_id if candidate is not None else "run-candidate"),
        candidate_manifest_id=command.candidate_manifest_id,
        execution_component_manifest_id=_sha("m6-execution-component"),
        outcome=(
            M6ReplayExecutionOutcome.CASE_REPLAYED
            if candidate is not None
            else M6ReplayExecutionOutcome.NO_CASE
        ),
        candidate_snapshot_id=candidate.snapshot_id if candidate is not None else None,
        detection_count=1,
        detection_inventory_root_sha256=_sha(f"detections:{result.sample_id}"),
        model_response_count=1,
        model_response_inventory_root_sha256=_sha(f"responses:{result.sample_id}"),
        embedding_count=1,
        embedding_inventory_root_sha256=_sha(f"embeddings:{result.sample_id}"),
        tool_result_count=1,
        tool_result_inventory_root_sha256=_sha(f"tools:{result.sample_id}"),
        provider_call_count=0 if locked else 1,
        provider_trap_authority_id=_sha("provider-trap") if locked else None,
        provider_trap_document_sha256=_sha("provider-trap-document") if locked else None,
    )


def _report(
    dataset: M6RegressionDatasetSnapshot,
    *,
    mode: ReproducibilityMode = ReproducibilityMode.UPGRADE_REGRESSION,
    overrides: dict[str, dict[str, object]] | None = None,
    maximum_machine_flip_rate: float = 0.05,
    gold_set_max_accuracy_drop: float = 0.0,
    emergency_reviews: tuple[M6EmergencyRegressionReview, ...] = (),
) -> M6RegressionReport:
    candidate_manifest_id = (
        CANDIDATE_MANIFEST_ID
        if mode == ReproducibilityMode.UPGRADE_REGRESSION
        else BASELINE_MANIFEST_ID
    )
    per_sample = overrides or {}
    results = tuple(
        _result(
            entry,
            candidate_manifest_id=candidate_manifest_id,
            **per_sample.get(entry.sample_id, {}),
        )
        for entry in dataset.entries
    )
    command = M6RegressionRunCommand(
        mode=mode,
        execution_dataset_snapshot_id=(dataset.execution_dataset.execution_dataset_snapshot_id),
        baseline_manifest_id=dataset.baseline_manifest_id,
        candidate_manifest_id=candidate_manifest_id,
        policy_authority=_policy(
            maximum_machine_flip_rate=maximum_machine_flip_rate,
            gold_set_max_accuracy_drop=gold_set_max_accuracy_drop,
        ),
    )
    receipts = tuple(
        _execution_receipt(
            command=command,
            execution_entry=execution_entry,
            result=result,
        )
        for execution_entry, result in zip(
            dataset.execution_dataset.entries,
            results,
            strict=True,
        )
    )
    return M6RegressionReport(
        command=command,
        dataset=dataset,
        results=results,
        execution_receipts=receipts,
        emergency_reviews=emergency_reviews,
    )


def test_case_snapshot_computed_claims_round_trip_and_tamper_fail_closed() -> None:
    snapshot = _baseline_snapshot("snapshot-001")
    serialized = snapshot.model_dump(mode="json")

    assert M6CaseReplaySnapshot.model_validate(serialized) == snapshot
    assert len(snapshot.semantic_case_hash) == len(snapshot.snapshot_id) == 64
    for claim in ("semantic_case_hash", "snapshot_id"):
        attacked = dict(serialized)
        attacked[claim] = "f" * 64
        with pytest.raises(ValidationError, match=claim):
            M6CaseReplaySnapshot.model_validate(attacked)


def test_snapshot_requires_exact_six_stage_order_and_reports_first_divergence() -> None:
    baseline = _baseline_snapshot("stages-001")
    assert tuple(root.stage for root in baseline.stage_roots) == tuple(M6RegressionStage)

    with pytest.raises(ValidationError, match="exact stable stage order"):
        baseline.model_copy(update={"stage_roots": tuple(reversed(baseline.stage_roots))})
    with pytest.raises(ValidationError):
        baseline.model_copy(update={"stage_roots": baseline.stage_roots[:-1]})

    candidate = _candidate_snapshot(
        baseline,
        manifest_id=BASELINE_MANIFEST_ID,
        changed=(M6RegressionStage.SCREENING, M6RegressionStage.GATE),
    )
    result = M6RegressionCaseResult(
        entry_id=_sha("entry:stages-001"),
        sample_id=baseline.sample_id,
        baseline_snapshot=baseline,
        candidate_snapshot=candidate,
    )
    assert tuple(item.stage for item in result.stage_comparisons) == tuple(M6RegressionStage)
    assert result.changed_stages == (
        M6RegressionStage.SCREENING,
        M6RegressionStage.GATE,
    )
    assert result.first_divergence_stage == M6RegressionStage.SCREENING


def test_sample_id_is_the_pairing_authority_at_entry_result_and_inventory_boundaries() -> None:
    baseline = _baseline_snapshot("sample-001")
    with pytest.raises(ValidationError, match="sample_id differ"):
        _stability_entry("sample-002").model_copy(update={"baseline_snapshot": baseline})

    entry = _stability_entry("sample-001")
    foreign_candidate = _candidate_snapshot(
        _baseline_snapshot("sample-002"),
        manifest_id=BASELINE_MANIFEST_ID,
    )
    with pytest.raises(ValidationError, match="snapshot sample_id differs"):
        M6RegressionCaseResult(
            entry_id=entry.entry_id,
            sample_id=entry.sample_id,
            baseline_snapshot=entry.baseline_snapshot,
            candidate_snapshot=foreign_candidate,
        )

    gold = _gold_entry("gold-001")
    challenge = _no_case_challenge_entry("challenge-001")
    valid_dataset = _dataset((entry, gold, challenge))
    with pytest.raises(ValidationError, match="stable sample_id order"):
        valid_dataset.model_copy(update={"entries": (entry, gold, challenge)})
    with pytest.raises(ValidationError, match="sample_ids must be unique"):
        _dataset((entry, entry, gold, challenge))

    renamed_snapshot = entry.baseline_snapshot
    assert renamed_snapshot is not None
    renamed_snapshot = renamed_snapshot.model_copy(update={"sample_id": "sample-renamed"})
    renamed = entry.model_copy(
        update={
            "sample_id": "sample-renamed",
            "input_authority_id": _sha("renamed-input"),
            "replay_input_closure_authority_id": _sha("renamed-input-closure"),
            "baseline_authority_id": renamed_snapshot.snapshot_id,
            "baseline_authority_document_sha256": _content_sha256(renamed_snapshot),
            "baseline_snapshot": renamed_snapshot,
        }
    )
    with pytest.raises(ValidationError, match="source Case revisions must be unique"):
        _dataset((entry, renamed, gold, challenge))

    duplicate_input = _stability_entry("sample-other").model_copy(
        update={"input_authority_id": entry.input_authority_id}
    )
    with pytest.raises(ValidationError, match="input authorities must be unique"):
        _dataset((entry, duplicate_input, gold, challenge))


def test_membership_overlap_gold_truth_and_pre_appeal_baseline_are_fail_closed() -> None:
    stability_challenge = _stability_entry(
        "stability-challenge",
        challenge=M6ChallengeKind.OCCLUSION,
    )
    gold_challenge = _gold_entry(
        "gold-challenge",
        challenge=M6ChallengeKind.DETECTOR_MISS,
    )
    assert stability_challenge.memberships == (
        M6RegressionDatasetKind.STABILITY,
        M6RegressionDatasetKind.CHALLENGE,
    )
    assert gold_challenge.memberships == (
        M6RegressionDatasetKind.GOLD,
        M6RegressionDatasetKind.CHALLENGE,
    )

    with pytest.raises(ValidationError, match="cannot overlap"):
        baseline = stability_challenge.baseline_snapshot
        assert baseline is not None
        stability_challenge.model_copy(
            update={
                "memberships": (
                    M6RegressionDatasetKind.STABILITY,
                    M6RegressionDatasetKind.GOLD,
                    M6RegressionDatasetKind.CHALLENGE,
                ),
                "gold_truth": _appeal_truth(baseline),
            }
        )
    with pytest.raises(ValidationError, match="must coincide"):
        gold_challenge.model_copy(update={"gold_truth": None})
    with pytest.raises(ValidationError, match="pre-appeal closed machine baseline"):
        gold_challenge.model_copy(
            update={"baseline_authority_kind": M6BaselineAuthorityKind.MACHINE_TERMINAL_CASE}
        )

    for update in (
        {"baseline_authority_id": "f" * 64},
        {"baseline_authority_document_sha256": "e" * 64},
    ):
        with pytest.raises(ValidationError, match="embedded snapshot"):
            gold_challenge.model_copy(update=update)

    truth = gold_challenge.gold_truth
    assert truth is not None
    with pytest.raises(ValidationError, match="resolution commit authority"):
        truth.model_copy(
            update={
                "resolution_commit_id": None,
                "resolution_commit_document_sha256": None,
            }
        )

    with pytest.raises(ValidationError, match="exact machine baseline"):
        gold_challenge.model_copy(
            update={"gold_truth": truth.model_copy(update={"baseline_snapshot_id": "f" * 64})}
        )

    second_gold = _gold_entry("gold-second")
    second_truth = second_gold.gold_truth
    assert second_truth is not None
    second_gold = second_gold.model_copy(
        update={
            "gold_truth": second_truth.model_copy(
                update={
                    "decision_authority_id": truth.decision_authority_id,
                    "resolution_commit_id": truth.resolution_commit_id,
                }
            )
        }
    )
    with pytest.raises(ValidationError, match="decision authorities must be unique"):
        _dataset(
            (
                _stability_entry("stable-for-truth"),
                gold_challenge,
                second_gold,
                _no_case_challenge_entry("challenge-for-truth"),
            )
        )


def test_candidate_missing_and_added_are_explicit_complete_stage_differences() -> None:
    missing_entry = _stability_entry("missing-001")
    missing = _result(
        missing_entry,
        candidate_manifest_id=CANDIDATE_MANIFEST_ID,
        missing=True,
    )
    assert missing.disposition == M6RegressionCaseDisposition.CANDIDATE_MISSING
    assert missing.direction_flipped
    assert missing.changed_stages == tuple(M6RegressionStage)
    assert missing.first_divergence_stage == M6RegressionStage.PERCEPTION

    added_entry = _no_case_challenge_entry("added-001")
    added = _result(
        added_entry,
        candidate_manifest_id=CANDIDATE_MANIFEST_ID,
        added=True,
    )
    assert added.disposition == M6RegressionCaseDisposition.CANDIDATE_ADDED
    assert added.direction_flipped
    assert added.changed_stages == tuple(M6RegressionStage)
    assert added.first_divergence_stage == M6RegressionStage.PERCEPTION

    stability = tuple(_stability_entry(f"missing-gate-{index:02d}") for index in range(20))
    dataset = _minimal_dataset(stability_entries=stability)
    report = _report(
        dataset,
        overrides={stability[0].sample_id: {"missing": True}},
    )
    assert report.machine_flip_rate == 0.05
    assert M6RegressionGateReason.REQUIRED_CANDIDATE_MISSING in report.gate_reason_codes
    assert report.disposition == M6RegressionDisposition.FAILED


def test_nonterminal_candidate_cannot_retain_a_decision_and_is_a_hard_failure() -> None:
    baseline = _baseline_snapshot("nonterminal-001")
    with pytest.raises(ValidationError, match=r"non-terminal.*cannot carry"):
        baseline.model_copy(update={"case_status": CaseStatus.BACKLOGGED})

    entry = _stability_entry("nonterminal-001")
    report = _report(
        _minimal_dataset(stability_entries=(entry,)),
        overrides={
            entry.sample_id: {
                "case_status": CaseStatus.BACKLOGGED,
                "decision": None,
                "changed": (M6RegressionStage.POLICY,),
            }
        },
    )
    assert M6RegressionGateReason.REQUIRED_CANDIDATE_NONTERMINAL in report.gate_reason_codes
    assert report.disposition == M6RegressionDisposition.FAILED


def test_case_result_and_dataset_computed_inventory_claims_reject_tampering() -> None:
    dataset = _minimal_dataset()
    entry = dataset.entries[0]
    entry_payload = entry.model_dump(mode="json")
    entry_payload["entry_id"] = "f" * 64
    with pytest.raises(ValidationError, match="entry_id"):
        M6RegressionDatasetEntry.model_validate(entry_payload)

    dataset_payload = dataset.model_dump(mode="json")
    dataset_payload["gold_count"] = 99
    with pytest.raises(ValidationError, match="gold_count"):
        M6RegressionDatasetSnapshot.model_validate(dataset_payload)

    result = _result(
        entry,
        candidate_manifest_id=BASELINE_MANIFEST_ID,
    )
    result_payload = result.model_dump(mode="json")
    result_payload["disposition"] = M6RegressionCaseDisposition.DECISION_FLIP.value
    with pytest.raises(ValidationError, match="disposition"):
        M6RegressionCaseResult.model_validate(result_payload)


@pytest.mark.parametrize(
    ("stability_count", "expected_disposition", "expected_reason"),
    [
        (20, M6RegressionDisposition.PASSED, None),
        (
            19,
            M6RegressionDisposition.FAILED,
            M6RegressionGateReason.MACHINE_FLIP_RATE_EXCEEDED,
        ),
    ],
)
def test_upgrade_machine_flip_gate_uses_exact_five_percent_decimal_boundary(
    stability_count: int,
    expected_disposition: M6RegressionDisposition,
    expected_reason: M6RegressionGateReason | None,
) -> None:
    stability = tuple(
        _stability_entry(f"stability-{index:03d}") for index in range(stability_count)
    )
    dataset = _minimal_dataset(stability_entries=stability)
    flipped_sample = stability[0].sample_id
    report = _report(
        dataset,
        overrides={
            flipped_sample: {
                "decision": VerdictDecision.NOT_ESTABLISHED,
                "changed": (M6RegressionStage.POLICY,),
            }
        },
        maximum_machine_flip_rate=0.05,
    )

    assert report.machine_flip_count == 1
    assert report.machine_flip_rate == 1 / stability_count
    assert report.disposition == expected_disposition
    assert (expected_reason in report.gate_reason_codes) is (expected_reason is not None)


def test_gold_accuracy_drop_is_measured_against_explicit_human_truth() -> None:
    gold = _gold_entry(
        baseline_decision=VerdictDecision.ESTABLISHED,
        expected_decision=VerdictDecision.ESTABLISHED,
    )
    dataset = _minimal_dataset(gold_entry=gold)
    report = _report(
        dataset,
        overrides={
            gold.sample_id: {
                "decision": VerdictDecision.NOT_ESTABLISHED,
                "changed": (M6RegressionStage.POLICY,),
            }
        },
    )

    assert report.baseline_gold_correct_count == 1
    assert report.candidate_gold_correct_count == 0
    assert report.gold_accuracy_drop == 1.0
    assert M6RegressionGateReason.GOLD_ACCURACY_DROP_EXCEEDED in report.gate_reason_codes
    assert report.disposition == M6RegressionDisposition.FAILED


def test_emergency_degradation_requires_exact_review_and_rejected_review_blocks() -> None:
    emergency = _stability_entry("stability-emergency", alert=AlertLevel.EMERGENCY)
    dataset = _minimal_dataset(stability_entries=(emergency,))
    overrides = {
        emergency.sample_id: {
            "alert": AlertLevel.CONFIRMED,
            "changed": (M6RegressionStage.POLICY,),
        }
    }
    unreviewed = _report(dataset, overrides=overrides)
    emergency_result = next(
        result for result in unreviewed.results if result.sample_id == emergency.sample_id
    )

    assert unreviewed.emergency_degradation_sample_ids == (emergency.sample_id,)
    assert unreviewed.disposition == M6RegressionDisposition.REQUIRES_HUMAN_REVIEW
    assert M6RegressionGateReason.EMERGENCY_DEGRADATION_UNREVIEWED in unreviewed.gate_reason_codes

    def review(decision: M6EmergencyReviewDecision) -> M6EmergencyRegressionReview:
        assert emergency_result.baseline_snapshot is not None
        assert emergency_result.candidate_snapshot is not None
        return M6EmergencyRegressionReview(
            result_id=emergency_result.result_id,
            baseline_snapshot_id=emergency_result.baseline_snapshot.snapshot_id,
            candidate_snapshot_id=emergency_result.candidate_snapshot.snapshot_id,
            human_input_authority_id=_sha("emergency-human-input"),
            human_input_authority_document_sha256=_sha("emergency-human-input-document"),
            reviewer_capability_authority_id=_sha("reviewer-capability"),
            reviewer_capability_document_sha256=_sha("reviewer-capability-document"),
            reviewer_id="safety-officer",
            decision=decision,
            summary="Explicit review of the emergency downgrade.",
        )

    approved = _report(
        dataset,
        overrides=overrides,
        emergency_reviews=(review(M6EmergencyReviewDecision.APPROVED),),
    )
    assert approved.disposition == M6RegressionDisposition.PASSED
    assert approved.release_allowed

    rejected = _report(
        dataset,
        overrides=overrides,
        emergency_reviews=(review(M6EmergencyReviewDecision.REJECTED),),
    )
    assert rejected.disposition == M6RegressionDisposition.FAILED
    assert M6RegressionGateReason.EMERGENCY_DEGRADATION_REJECTED in rejected.gate_reason_codes

    hard_failure = _report(
        dataset,
        overrides={
            emergency.sample_id: {
                "alert": AlertLevel.CONFIRMED,
                "decision": VerdictDecision.NOT_ESTABLISHED,
                "changed": (M6RegressionStage.POLICY,),
            }
        },
    )
    assert M6RegressionGateReason.EMERGENCY_DEGRADATION_UNREVIEWED in (
        hard_failure.gate_reason_codes
    )
    assert M6RegressionGateReason.MACHINE_FLIP_RATE_EXCEEDED in (hard_failure.gate_reason_codes)
    assert hard_failure.disposition == M6RegressionDisposition.FAILED


def test_emergency_direction_flip_requires_review_even_when_alert_label_is_retained() -> None:
    stability = tuple(
        _stability_entry(
            f"emergency-boundary-{index:02d}",
            alert=(AlertLevel.EMERGENCY if index == 0 else AlertLevel.CONFIRMED),
        )
        for index in range(20)
    )
    report = _report(
        _minimal_dataset(stability_entries=stability),
        overrides={
            stability[0].sample_id: {
                "decision": VerdictDecision.NOT_ESTABLISHED,
                "alert": AlertLevel.EMERGENCY,
                "changed": (M6RegressionStage.POLICY,),
            }
        },
        maximum_machine_flip_rate=0.05,
    )

    assert report.machine_flip_rate == 0.05
    assert M6RegressionGateReason.MACHINE_FLIP_RATE_EXCEEDED not in report.gate_reason_codes
    assert M6RegressionGateReason.EMERGENCY_DEGRADATION_UNREVIEWED in (report.gate_reason_codes)
    assert report.disposition == M6RegressionDisposition.REQUIRES_HUMAN_REVIEW


def test_locked_pinned_and_upgrade_modes_have_distinct_release_dispositions() -> None:
    dataset = _minimal_dataset()

    locked = _report(dataset, mode=ReproducibilityMode.REPLAY_LOCKED)
    assert locked.disposition == M6RegressionDisposition.PASSED
    assert locked.release_allowed
    assert not locked.gate_reason_codes

    copied_result = next(
        result for result in locked.results if result.baseline_snapshot is not None
    )
    copied_results = tuple(
        result.model_copy(update={"candidate_snapshot": result.baseline_snapshot})
        if result.result_id == copied_result.result_id
        else result
        for result in locked.results
    )
    with pytest.raises(ValidationError, match="distinct replay run"):
        locked.model_copy(update={"results": copied_results})

    changed_sample = next(
        entry.sample_id for entry in dataset.entries if entry.baseline_snapshot is not None
    )
    locked_drift = _report(
        dataset,
        mode=ReproducibilityMode.REPLAY_LOCKED,
        overrides={changed_sample: {"changed": (M6RegressionStage.SCREENING,)}},
    )
    assert locked_drift.disposition == M6RegressionDisposition.FAILED
    assert locked_drift.gate_reason_codes == (M6RegressionGateReason.LOCKED_SEMANTIC_MISMATCH,)

    pinned = _report(
        dataset,
        mode=ReproducibilityMode.REINFER_PINNED,
        overrides={changed_sample: {"changed": (M6RegressionStage.HEARING,)}},
    )
    assert pinned.disposition == M6RegressionDisposition.DIAGNOSTIC_COMPLETE
    assert not pinned.release_allowed
    assert not pinned.gate_reason_codes

    upgrade = _report(dataset, mode=ReproducibilityMode.UPGRADE_REGRESSION)
    assert upgrade.disposition == M6RegressionDisposition.PASSED
    assert upgrade.release_allowed
    assert all(
        result.disposition == M6RegressionCaseDisposition.MANIFEST_ONLY_CHANGE
        for result in upgrade.results
        if result.baseline_snapshot is not None
    )
    assert all(
        result.first_divergence_stage is None
        for result in upgrade.results
        if result.disposition == M6RegressionCaseDisposition.MANIFEST_ONLY_CHANGE
    )


def test_policy_authority_cannot_loosen_normative_m6_gates() -> None:
    with pytest.raises(ValidationError):
        _policy(maximum_machine_flip_rate=0.050001, gold_set_max_accuracy_drop=0.0)
    with pytest.raises(ValidationError):
        _policy(maximum_machine_flip_rate=0.05, gold_set_max_accuracy_drop=0.01)


def test_blinded_execution_dataset_and_execution_receipts_close_trust_inputs() -> None:
    dataset = _minimal_dataset()
    blinded = dataset.execution_dataset.model_dump(mode="json")
    serialized_blinded = json.dumps(blinded, sort_keys=True)
    for forbidden in (
        "expected_decision",
        "gold_truth",
        "memberships",
        "baseline_snapshot",
    ):
        assert forbidden not in serialized_blinded

    with pytest.raises(ValidationError, match="inventory cut, selection"):
        dataset.model_copy(update={"selection_receipt_count": len(dataset.entries) + 1})

    locked = _report(dataset, mode=ReproducibilityMode.REPLAY_LOCKED)
    receipt_index = next(
        index
        for index, result in enumerate(locked.results)
        if result.candidate_snapshot is not None
    )
    receipt = locked.execution_receipts[receipt_index]
    assert M6ReplayExecutionReceipt.model_validate(receipt.model_dump(mode="json")) == receipt
    with pytest.raises(ValidationError, match="zero provider calls and a trap"):
        receipt.model_copy(
            update={
                "provider_trap_authority_id": None,
                "provider_trap_document_sha256": None,
            }
        )
    with pytest.raises(ValidationError, match="does not bind its exact replay result"):
        attacked_receipts = list(locked.execution_receipts)
        attacked_receipts[receipt_index] = receipt.model_copy(
            update={"candidate_run_id": "foreign-run"}
        )
        locked.model_copy(update={"execution_receipts": tuple(attacked_receipts)})


def test_report_requires_the_complete_ordered_dataset_inventory() -> None:
    gold_challenge = _gold_entry(
        "gold-challenge",
        challenge=M6ChallengeKind.INSUFFICIENT_OBSERVATION,
    )
    dataset = _minimal_dataset(gold_entry=gold_challenge)
    report = _report(dataset)

    assert len(report.results) == len(dataset.entries) == 3
    assert report.stability_case_count == dataset.stability_count == 1
    assert report.gold_case_count == dataset.gold_count == 1
    assert report.challenge_case_count == dataset.challenge_count == 2

    with pytest.raises(ValidationError):
        report.model_copy(update={"results": report.results[:-1]})
    with pytest.raises(ValidationError, match="does not match its dataset entry"):
        report.model_copy(update={"results": tuple(reversed(report.results))})


def test_command_and_report_derived_claims_round_trip_and_reject_tampering() -> None:
    report = _report(_minimal_dataset())
    policy_payload = report.command.policy_authority.model_dump(mode="json")
    policy_payload["policy_authority_id"] = "f" * 64
    with pytest.raises(ValidationError, match="policy_authority_id"):
        M6RegressionPolicyAuthority.model_validate(policy_payload)

    execution_payload = report.dataset.execution_dataset.model_dump(mode="json")
    execution_payload["entry_count"] = 99
    with pytest.raises(ValidationError, match="entry_count"):
        M6RegressionExecutionDatasetSnapshot.model_validate(execution_payload)

    command_payload = report.command.model_dump(mode="json")
    command_payload["command_id"] = "f" * 64
    with pytest.raises(ValidationError, match="command_id"):
        M6RegressionRunCommand.model_validate(command_payload)

    serialized = report.model_dump(mode="json")
    assert M6RegressionReport.model_validate(serialized) == report
    for claim, forged in (
        ("machine_flip_count", 99),
        ("gold_accuracy_drop", 0.5),
        ("gate_reason_codes", [M6RegressionGateReason.MACHINE_FLIP_RATE_EXCEEDED.value]),
        ("disposition", M6RegressionDisposition.FAILED.value),
        ("release_allowed", False),
        ("report_id", "f" * 64),
    ):
        attacked = dict(serialized)
        attacked[claim] = forged
        with pytest.raises(ValidationError, match=claim):
            M6RegressionReport.model_validate(attacked)


def test_five_public_m6_serialization_schemas_validate_complete_documents() -> None:
    report = _report(_minimal_dataset())
    artifacts = {
        "m6-case-replay-snapshot": next(
            result.baseline_snapshot
            for result in report.results
            if result.baseline_snapshot is not None
        ),
        "m6-regression-dataset-snapshot": report.dataset,
        "m6-regression-execution-dataset-snapshot": report.dataset.execution_dataset,
        "m6-regression-run-command": report.command,
        "m6-regression-report": report,
    }
    schemas = expected_schema_files()
    for name, artifact in artifacts.items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))
