from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from labcourt.application.m6_regression_selection import (
    M6RegressionSelectionError,
    M6RegressionSelectionErrorCode,
    build_m6_regression_selection_inventory,
)
from labcourt.application.m6_verified_projection_context import M6SqliteProjectionAssembly
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_regression import M6ChallengeKind
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceRunCut,
)
from labcourt.contracts.m6_regression_selection import (
    M6ChallengeDesignationAuthority,
    M6SyntheticChallengeScenarioAuthority,
)
from labcourt.ports.m6_challenge_scenarios import M6ChallengeScenarioObservation
from labcourt.ports.m6_regression_appeals import (
    M6RegressionAppealHistoryObservation,
    M6RegressionAppealState,
)
from tests.contract.test_m6_regression_selection_contracts import _stability_receipt
from tests.unit.test_m6_verified_projection_context import _assemble, _bundle


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _inputs():  # type: ignore[no-untyped-def]
    selected = _stability_receipt(challenge=False)
    item = selected.source_item
    baseline = selected.baseline_snapshot
    base = _assemble(_bundle())
    closure = base.closure.model_copy(
        update={
            "sample_id": item.sample_id,
            "source_run_id": item.source_run_id,
            "source_case_id": item.source_case_id,
            "source_case_revision": item.source_case_revision,
            "source_case_document_sha256": item.source_case_document_sha256,
            "source_manifest_id": item.source_manifest_id,
            "input_authority_id": item.input_authority_id,
            "input_authority_document_sha256": item.input_authority_document_sha256,
            "source_validation_report_id": item.sealed_source_validation_report_id,
            "source_validation_report_document_sha256": (
                item.sealed_source_validation_report_document_sha256
            ),
        }
    )
    item = item.model_copy(
        update={
            "replay_input_closure_authority_id": (closure.replay_input_closure_authority_id),
            "replay_input_closure_document_sha256": (closure.replay_input_closure_document_sha256),
        }
    )
    run_cut = M6RegressionSourceRunCut(
        source_run_id=item.source_run_id,
        baseline_manifest_id=item.source_manifest_id,
        source_config_sha256="1" * 64,
        audit_head_sequence=item.sealed_audit_head_sequence,
        audit_head_hash=item.sealed_audit_head_hash,
        m5_validation_report_id=item.sealed_source_validation_report_id,
        m5_validation_report_content_sha256=(item.sealed_source_validation_report_document_sha256),
        m5_authority_root_sha256=item.sealed_source_m5_authority_root_sha256,
        source_item_count=1,
        source_scope_root_sha256=sha256_hex(
            [
                "m6-regression-source-run-scope",
                1,
                item.source_run_id,
                [item.source_scope_key],
            ]
        ),
    )
    cut = M6RegressionSourceInventoryCutAuthority(
        baseline_manifest_id=item.source_manifest_id,
        run_cuts=(run_cut,),
        items=(item,),
    )
    history = M6RegressionAppealHistoryObservation(
        source_identity_sha256=base.source_identity_sha256,
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        source_item=item,
        run_cut=run_cut,
        m5_authority_root_sha256=run_cut.m5_authority_root_sha256,
        current_case_revision=item.source_case_revision,
        current_case_document_sha256=item.source_case_document_sha256,
        current_case_status=CaseStatus.CLOSED,
        current_case_root_sha256=_sha("current-case-root"),
        state=M6RegressionAppealState.NONE,
    )
    projection = object.__new__(M6SqliteProjectionAssembly)
    for name, value in (
        ("source_identity_sha256", base.source_identity_sha256),
        ("closure", closure),
        ("model_calls", closure.model_calls),
        ("embeddings", base.embeddings),
        ("projection_context", base.projection_context),
        ("case_replay_snapshot", baseline),
    ):
        object.__setattr__(projection, name, value)
    scenario = M6SyntheticChallengeScenarioAuthority(
        scenario_name="occlusion-synthetic-001",
        scenario_revision=1,
        source_item_id=item.source_item_id,
        sample_id=item.sample_id,
        input_authority_id=item.input_authority_id,
        input_authority_document_sha256=item.input_authority_document_sha256,
        replay_input_closure_authority_id=item.replay_input_closure_authority_id,
        replay_input_closure_document_sha256=(item.replay_input_closure_document_sha256),
        challenge_kinds=(M6ChallengeKind.OCCLUSION,),
    )
    scenario_document = canonical_json(scenario.model_dump(mode="json"))
    challenge = M6ChallengeScenarioObservation(
        scenario=scenario,
        canonical_document=scenario_document,
        content_sha256=_sha(scenario_document),
        size_bytes=len(scenario_document.encode("utf-8")),
    )
    return cut, projection, history, challenge


def test_builder_emits_complete_stability_selection_from_verified_projection() -> None:
    cut, projection, history, challenge = _inputs()
    cut_document = canonical_json(cut.model_dump(mode="json"))

    result = build_m6_regression_selection_inventory(
        source_inventory_cut=cut,
        source_inventory_cut_document=cut_document,
        baseline_projections=(projection,),
        appeal_histories=(history,),
        challenge_scenarios=(challenge,),
    )

    inventory = result.selection_inventory
    assert inventory.receipt_count == inventory.selected_count == 1
    assert inventory.stability_count == inventory.challenge_count == 1
    assert inventory.gold_count == inventory.blocked_count == 0
    receipt = inventory.receipts[0]
    assert receipt.baseline_snapshot == projection.case_replay_snapshot
    assert receipt.source_item == cut.items[0]
    assert result.selection_inventory_document == canonical_json(inventory.model_dump(mode="json"))
    assert result.eligibility_policy_content_sha256 == _sha(result.eligibility_policy_document)


def test_builder_rejects_missing_projection_and_cross_snapshot_history() -> None:
    cut, projection, history, challenge = _inputs()
    cut_document = canonical_json(cut.model_dump(mode="json"))

    with pytest.raises(M6RegressionSelectionError) as missing:
        build_m6_regression_selection_inventory(
            source_inventory_cut=cut,
            source_inventory_cut_document=cut_document,
            baseline_projections=(),
            appeal_histories=(history,),
            challenge_scenarios=(challenge,),
        )
    assert missing.value.code == M6RegressionSelectionErrorCode.SOURCE_SCOPE_INCOMPLETE

    object.__setattr__(projection, "source_identity_sha256", _sha("foreign-snapshot"))
    with pytest.raises(M6RegressionSelectionError) as grafted:
        build_m6_regression_selection_inventory(
            source_inventory_cut=cut,
            source_inventory_cut_document=cut_document,
            baseline_projections=(projection,),
            appeal_histories=(history,),
            challenge_scenarios=(challenge,),
        )
    assert grafted.value.code == M6RegressionSelectionErrorCode.SNAPSHOT_IDENTITY_MISMATCH


def test_builder_rejects_forged_source_cut_bytes_and_projection_scope() -> None:
    cut, projection, history, challenge = _inputs()
    cut_document = canonical_json(cut.model_dump(mode="json"))
    with pytest.raises(M6RegressionSelectionError) as document:
        build_m6_regression_selection_inventory(
            source_inventory_cut=cut,
            source_inventory_cut_document=cut_document + " ",
            baseline_projections=(projection,),
            appeal_histories=(history,),
            challenge_scenarios=(challenge,),
        )
    assert document.value.code == M6RegressionSelectionErrorCode.SOURCE_CUT_DOCUMENT_INVALID

    closure = projection.closure.model_copy(update={"source_case_id": "foreign-case"})
    object.__setattr__(projection, "closure", closure)
    with pytest.raises(M6RegressionSelectionError) as scope:
        build_m6_regression_selection_inventory(
            source_inventory_cut=cut,
            source_inventory_cut_document=cut_document,
            baseline_projections=(projection,),
            appeal_histories=(history,),
            challenge_scenarios=(challenge,),
        )
    assert scope.value.code == M6RegressionSelectionErrorCode.BASELINE_PROJECTION_INVALID


def test_builder_requires_resolved_physical_challenge_scenario() -> None:
    cut, projection, history, challenge = _inputs()
    cut_document = canonical_json(cut.model_dump(mode="json"))
    raw_designation = M6ChallengeDesignationAuthority(
        source_item_id=challenge.scenario.source_item_id,
        sample_id=challenge.scenario.sample_id,
        source_authority_id=challenge.scenario.scenario_authority_id,
        source_authority_document_sha256=challenge.content_sha256,
        challenge_kinds=challenge.scenario.challenge_kinds,
    )
    with pytest.raises(M6RegressionSelectionError) as unresolved:
        build_m6_regression_selection_inventory(
            source_inventory_cut=cut,
            source_inventory_cut_document=cut_document,
            baseline_projections=(projection,),
            appeal_histories=(history,),
            challenge_scenarios=(raw_designation,),
        )
    assert unresolved.value.code == M6RegressionSelectionErrorCode.INVALID_ARGUMENT

    tampered = replace(
        challenge,
        canonical_document=challenge.canonical_document + " ",
    )
    with pytest.raises(M6RegressionSelectionError) as document:
        build_m6_regression_selection_inventory(
            source_inventory_cut=cut,
            source_inventory_cut_document=cut_document,
            baseline_projections=(projection,),
            appeal_histories=(history,),
            challenge_scenarios=(tampered,),
        )
    assert document.value.code == (M6RegressionSelectionErrorCode.CHALLENGE_AUTHORITY_INVALID)
