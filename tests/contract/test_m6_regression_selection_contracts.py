from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import AppealStatus, CaseStatus
from labcourt.contracts.m6_regression import M6ChallengeKind, M6RegressionDatasetKind
from labcourt.contracts.m6_regression_selection import (
    M6ChallengeDesignationAuthority,
    M6RegressionEligibilityPolicyAuthority,
    M6RegressionSelectionDisposition,
    M6RegressionSelectionInventoryAuthority,
    M6RegressionSelectionReceipt,
    M6SyntheticChallengeScenarioAuthority,
)
from labcourt.schema_export import expected_schema_files
from tests.contract.test_m6_regression_gold_contracts import _authority
from tests.unit.test_m5_training_provenance import _chain


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _policy() -> M6RegressionEligibilityPolicyAuthority:
    return M6RegressionEligibilityPolicyAuthority()


def _scenario(
    item,  # type: ignore[no-untyped-def]
) -> M6SyntheticChallengeScenarioAuthority:
    return M6SyntheticChallengeScenarioAuthority(
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


def _stability_receipt(*, challenge: bool = True) -> M6RegressionSelectionReceipt:
    source = _authority()
    sample_id = _sha("stability-source")
    item = source.source_item.model_copy(
        update={
            "sample_id": sample_id,
            "source_case_id": "case-stability",
            "source_case_document_sha256": _sha("stability-case-document"),
            "source_seal_id": _sha("stability-seal"),
            "source_seal_content_sha256": _sha("stability-seal-content"),
            "input_authority_id": _sha("stability-input"),
            "input_authority_document_sha256": _sha("stability-input-document"),
            "input_authority_content_sha256": _sha("stability-input-content"),
            "replay_input_closure_authority_id": _sha("stability-closure"),
            "replay_input_closure_document_sha256": _sha("stability-closure-document"),
            "replay_input_closure_content_sha256": _sha("stability-closure-content"),
        }
    )
    baseline = source.baseline_snapshot.model_copy(
        update={
            "sample_id": sample_id,
            "source_case_id": item.source_case_id,
            "source_case_document_sha256": item.source_case_document_sha256,
        }
    )
    scenario = _scenario(item)
    scenario_document = canonical_json(scenario.model_dump(mode="json"))
    designation = (
        M6ChallengeDesignationAuthority(
            source_item_id=item.source_item_id,
            sample_id=item.sample_id,
            source_authority_id=scenario.scenario_authority_id,
            source_authority_document_sha256=_sha(scenario_document),
            challenge_kinds=scenario.challenge_kinds,
        )
        if challenge
        else None
    )
    return M6RegressionSelectionReceipt(
        source_inventory_cut_authority_id=_sha("source-cut"),
        eligibility_policy_authority_id=_policy().eligibility_policy_authority_id,
        source_item=item,
        baseline_snapshot=baseline,
        source_m5_authority_root_sha256=item.sealed_source_m5_authority_root_sha256,
        current_case_authority_root_sha256=_sha("stability-case-root"),
        current_case_revision=item.source_case_revision,
        current_case_document_sha256=item.source_case_document_sha256,
        current_case_status=CaseStatus.CLOSED,
        challenge_designation=designation,
    )


def _gold_receipt(
    status: AppealStatus = AppealStatus.OVERTURNED,
) -> M6RegressionSelectionReceipt:
    gold = _authority(status)
    item = gold.source_item
    return M6RegressionSelectionReceipt(
        source_inventory_cut_authority_id=_sha("source-cut"),
        eligibility_policy_authority_id=_policy().eligibility_policy_authority_id,
        source_item=item,
        baseline_snapshot=gold.baseline_snapshot,
        source_m5_authority_root_sha256=item.sealed_source_m5_authority_root_sha256,
        current_case_authority_root_sha256=_sha(f"gold-case-root:{status.value}"),
        current_case_revision=gold.resolution_commit.resulting_case_revision,
        current_case_document_sha256=(gold.resolution_commit.resulting_case_document_sha256),
        current_case_status=CaseStatus.APPEAL_RESOLVED,
        current_appeal_authority=gold.terminal_appeal_authority,
        appeal_gold_authority=gold,
    )


def _pending_receipt() -> M6RegressionSelectionReceipt:
    source = _authority()
    reviewed = _chain().review_authority
    item = source.source_item
    return M6RegressionSelectionReceipt(
        source_inventory_cut_authority_id=_sha("source-cut"),
        eligibility_policy_authority_id=_policy().eligibility_policy_authority_id,
        source_item=item,
        baseline_snapshot=source.baseline_snapshot,
        source_m5_authority_root_sha256=item.sealed_source_m5_authority_root_sha256,
        current_case_authority_root_sha256=_sha("pending-case-root"),
        current_case_revision=item.source_case_revision + reviewed.version,
        current_case_document_sha256=_sha("pending-case-document"),
        current_case_status=CaseStatus.APPEALED,
        current_appeal_authority=reviewed,
    )


def _inventory() -> M6RegressionSelectionInventoryAuthority:
    receipts = tuple(
        sorted((_stability_receipt(), _gold_receipt()), key=lambda item: item.source_item.sample_id)
    )
    return M6RegressionSelectionInventoryAuthority(
        baseline_manifest_id=receipts[0].source_item.source_manifest_id,
        source_inventory_cut_authority_id=_sha("source-cut"),
        source_inventory_cut_content_sha256=_sha("source-cut-content"),
        source_inventory_item_count=len(receipts),
        source_inventory_root_sha256=sha256_hex(
            [
                "m6-regression-source-inventory",
                1,
                [item.source_item.source_item_id for item in receipts],
            ]
        ),
        eligibility_policy=_policy(),
        receipts=receipts,
    )


def test_fixed_policy_cannot_enable_unsupported_gold_sources() -> None:
    policy = _policy()
    assert (
        M6RegressionEligibilityPolicyAuthority.model_validate(policy.model_dump(mode="json"))
        == policy
    )
    payload = policy.model_dump(mode="json", exclude_computed_fields=True)
    payload["gold_authority_policy"] = "HUMAN_REVIEW_OR_PRESET"
    with pytest.raises(ValidationError, match="APPEAL_RESOLUTION_ONLY"):
        M6RegressionEligibilityPolicyAuthority.model_validate(payload)


def test_explicit_challenge_designation_requires_exact_ordered_source_binding() -> None:
    receipt = _stability_receipt()
    designation = receipt.challenge_designation
    assert designation is not None
    assert receipt.memberships == (
        M6RegressionDatasetKind.STABILITY,
        M6RegressionDatasetKind.CHALLENGE,
    )
    with pytest.raises(ValidationError, match="unique and ordered"):
        designation.model_copy(
            update={
                "challenge_kinds": (
                    M6ChallengeKind.OCCLUSION,
                    M6ChallengeKind.DIFFICULT_NEGATIVE,
                )
            }
        )
    with pytest.raises(ValidationError, match="another source item"):
        receipt.model_copy(
            update={
                "challenge_designation": designation.model_copy(
                    update={"source_item_id": _sha("foreign-source-item")}
                )
            }
        )


def test_synthetic_challenge_scenario_is_source_bound_and_tamper_evident() -> None:
    receipt = _stability_receipt(challenge=False)
    scenario = _scenario(receipt.source_item)
    assert (
        M6SyntheticChallengeScenarioAuthority.model_validate(scenario.model_dump(mode="json"))
        == scenario
    )
    with pytest.raises(ValidationError, match="unique and ordered"):
        scenario.model_copy(
            update={
                "challenge_kinds": (
                    M6ChallengeKind.OCCLUSION,
                    M6ChallengeKind.DIFFICULT_NEGATIVE,
                )
            }
        )
    payload = scenario.model_dump(mode="json")
    payload["scenario_authority_id"] = "f" * 64
    with pytest.raises(ValidationError, match="scenario_authority_id"):
        M6SyntheticChallengeScenarioAuthority.model_validate(payload)


@pytest.mark.parametrize("status", [AppealStatus.UPHELD, AppealStatus.OVERTURNED])
def test_both_terminal_appeal_outcomes_are_selected_as_gold(status: AppealStatus) -> None:
    receipt = _gold_receipt(status)
    assert receipt.selection_disposition == (M6RegressionSelectionDisposition.SELECTED_APPEAL_GOLD)
    assert receipt.memberships == (M6RegressionDatasetKind.GOLD,)
    assert receipt.appeal_gold_authority is not None
    assert receipt.appeal_gold_authority.gold_truth.expected_decision == (
        receipt.current_appeal_authority.appeal.resolved_decision
    )


def test_pending_appeal_has_a_blocking_receipt_and_cannot_be_challenge_selected() -> None:
    receipt = _pending_receipt()
    assert receipt.selection_disposition == (
        M6RegressionSelectionDisposition.BLOCKED_PENDING_APPEAL
    )
    assert receipt.memberships == ()
    assert receipt.appeal_gold_authority is None

    challenge = _stability_receipt().challenge_designation
    assert challenge is not None
    challenge = challenge.model_copy(
        update={
            "source_item_id": receipt.source_item.source_item_id,
            "sample_id": receipt.source_item.sample_id,
        }
    )
    with pytest.raises(ValidationError, match="state matrix"):
        receipt.model_copy(update={"challenge_designation": challenge})


def test_selection_receipt_rejects_terminal_downgrade_and_current_case_forgery() -> None:
    gold = _gold_receipt()
    with pytest.raises(ValidationError, match="state matrix"):
        gold.model_copy(
            update={
                "current_case_status": CaseStatus.CLOSED,
                "current_case_revision": gold.source_item.source_case_revision,
                "current_case_document_sha256": gold.source_item.source_case_document_sha256,
            }
        )
    with pytest.raises(ValidationError, match="state matrix"):
        gold.model_copy(update={"current_case_document_sha256": _sha("forged-current-case")})


def test_selection_inventory_is_complete_and_rejects_omission_reorder_and_claim_tamper() -> None:
    inventory = _inventory()
    restored = M6RegressionSelectionInventoryAuthority.model_validate(
        inventory.model_dump(mode="json")
    )
    assert restored == inventory
    assert inventory.receipt_count == inventory.selected_count == 2
    assert inventory.blocked_count == 0
    assert inventory.stability_count == inventory.gold_count == inventory.challenge_count == 1

    with pytest.raises(ValidationError, match="cover every source item"):
        inventory.model_copy(
            update={
                "receipts": (inventory.receipts[0],),
                "source_inventory_root_sha256": sha256_hex(
                    [
                        "m6-regression-source-inventory",
                        1,
                        [inventory.receipts[0].source_item.source_item_id],
                    ]
                ),
            }
        )
    with pytest.raises(ValidationError, match="ordered by sample_id"):
        inventory.model_copy(update={"receipts": tuple(reversed(inventory.receipts))})

    payload = inventory.model_dump(mode="json")
    payload["selection_inventory_root_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="selection_inventory_root_sha256"):
        M6RegressionSelectionInventoryAuthority.model_validate(payload)


def test_selection_contract_schemas_validate_complete_documents() -> None:
    inventory = _inventory()
    scenario = _scenario(inventory.receipts[0].source_item)
    artifacts = {
        "m6-regression-eligibility-policy": inventory.eligibility_policy,
        "m6-challenge-designation-authority": inventory.receipts[0].challenge_designation,
        "m6-synthetic-challenge-scenario-authority": scenario,
        "m6-regression-selection-receipt": inventory.receipts[0],
        "m6-regression-selection-inventory": inventory,
    }
    schemas = expected_schema_files()
    for name, artifact in artifacts.items():
        assert artifact is not None
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))
