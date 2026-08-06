from __future__ import annotations

import hashlib

import pytest

import labcourt.application.m6_regression_dataset as dataset_module
from labcourt.application.m6_regression_dataset import (
    M6RegressionDatasetAssemblyError,
    M6RegressionDatasetAssemblyErrorCode,
    assemble_m6_regression_dataset,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_regression import M6ChallengeKind
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionExecutionSourceCatalogEntry,
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceInventoryItem,
    M6RegressionSourceRunCut,
)
from labcourt.contracts.m6_regression_gold import M6AppealGoldTruthAuthority
from labcourt.contracts.m6_regression_selection import (
    M6ChallengeDesignationAuthority,
    M6RegressionEligibilityPolicyAuthority,
    M6RegressionSelectionInventoryAuthority,
    M6RegressionSelectionReceipt,
)
from tests.contract.test_m6_regression_selection_contracts import (
    _gold_receipt,
    _stability_receipt,
)
from tests.unit.test_m5_training_provenance import _chain
from tests.unit.test_m6_verified_projection_context import _bundle


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _with_closure(
    item: M6RegressionSourceInventoryItem,
):  # type: ignore[no-untyped-def]
    closure = _bundle().closure.model_copy(
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
    document = canonical_json(closure.model_dump(mode="json"))
    return (
        item.model_copy(
            update={
                "replay_input_closure_authority_id": (closure.replay_input_closure_authority_id),
                "replay_input_closure_document_sha256": (
                    closure.replay_input_closure_document_sha256
                ),
                "replay_input_closure_content_sha256": _sha(document),
                "replay_input_closure_size_bytes": len(document.encode("utf-8")),
            }
        ),
        closure,
        document,
    )


def _inputs():  # type: ignore[no-untyped-def]
    stability_old = _stability_receipt(challenge=False)
    gold_old = _gold_receipt()
    stability_item, stability_closure, stability_closure_document = _with_closure(
        stability_old.source_item
    )
    gold_item, gold_closure, gold_closure_document = _with_closure(gold_old.source_item)
    source_items = tuple(sorted((stability_item, gold_item), key=lambda item: item.sample_id))
    run_id = source_items[0].source_run_id
    run_cut = M6RegressionSourceRunCut(
        source_run_id=run_id,
        baseline_manifest_id=source_items[0].source_manifest_id,
        source_config_sha256="1" * 64,
        audit_head_sequence=source_items[0].sealed_audit_head_sequence,
        audit_head_hash=source_items[0].sealed_audit_head_hash,
        m5_validation_report_id=source_items[0].sealed_source_validation_report_id,
        m5_validation_report_content_sha256=(
            source_items[0].sealed_source_validation_report_document_sha256
        ),
        m5_authority_root_sha256=source_items[0].sealed_source_m5_authority_root_sha256,
        source_item_count=len(source_items),
        source_scope_root_sha256=sha256_hex(
            [
                "m6-regression-source-run-scope",
                1,
                run_id,
                [item.source_scope_key for item in source_items],
            ]
        ),
    )
    cut = M6RegressionSourceInventoryCutAuthority(
        baseline_manifest_id=source_items[0].source_manifest_id,
        run_cuts=(run_cut,),
        items=source_items,
    )
    cut_document = canonical_json(cut.model_dump(mode="json"))
    closure_by_sample = {
        stability_item.sample_id: (stability_closure, stability_closure_document),
        gold_item.sample_id: (gold_closure, gold_closure_document),
    }
    catalog_entries = tuple(
        M6RegressionExecutionSourceCatalogEntry(
            source_item_id=item.source_item_id,
            sample_id=item.sample_id,
            source_seal_id=item.source_seal_id,
            source_seal_content_sha256=item.source_seal_content_sha256,
            source_seal_size_bytes=item.source_seal_size_bytes,
            input_authority_id=item.input_authority_id,
            input_authority_document_sha256=item.input_authority_document_sha256,
            input_authority_content_sha256=item.input_authority_content_sha256,
            input_authority_size_bytes=item.input_authority_size_bytes,
            replay_input_closure_content_sha256=(item.replay_input_closure_content_sha256),
            replay_input_closure_size_bytes=item.replay_input_closure_size_bytes,
            replay_input_closure=closure_by_sample[item.sample_id][0],
        )
        for item in source_items
    )
    catalog = M6RegressionExecutionSourceCatalogAuthority(
        baseline_manifest_id=cut.baseline_manifest_id,
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        source_inventory_cut_content_sha256=_sha(cut_document),
        source_inventory_item_count=cut.source_item_count,
        source_inventory_root_sha256=cut.source_inventory_root_sha256,
        entries=catalog_entries,
    )
    catalog_document = canonical_json(catalog.model_dump(mode="json"))
    policy = M6RegressionEligibilityPolicyAuthority()
    challenge = M6ChallengeDesignationAuthority(
        source_item_id=stability_item.source_item_id,
        sample_id=stability_item.sample_id,
        source_authority_id=_sha("challenge-scenario"),
        source_authority_document_sha256=_sha("challenge-scenario-document"),
        challenge_kinds=(M6ChallengeKind.OCCLUSION,),
    )
    stability_receipt = M6RegressionSelectionReceipt(
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        eligibility_policy_authority_id=policy.eligibility_policy_authority_id,
        source_item=stability_item,
        baseline_snapshot=stability_old.baseline_snapshot,
        source_m5_authority_root_sha256=(stability_item.sealed_source_m5_authority_root_sha256),
        current_case_authority_root_sha256=_sha("stability-case-root"),
        current_case_revision=stability_item.source_case_revision,
        current_case_document_sha256=stability_item.source_case_document_sha256,
        current_case_status=CaseStatus.CLOSED,
        challenge_designation=challenge,
    )
    old_gold = gold_old.appeal_gold_authority
    assert old_gold is not None
    appeal_gold = M6AppealGoldTruthAuthority(
        source_item=gold_item,
        baseline_snapshot=old_gold.baseline_snapshot,
        terminal_appeal_authority=old_gold.terminal_appeal_authority,
        resolution_intent=old_gold.resolution_intent,
        resolution_commit=old_gold.resolution_commit,
        gold_truth=old_gold.gold_truth,
    )
    gold_receipt = M6RegressionSelectionReceipt(
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        eligibility_policy_authority_id=policy.eligibility_policy_authority_id,
        source_item=gold_item,
        baseline_snapshot=appeal_gold.baseline_snapshot,
        source_m5_authority_root_sha256=gold_item.sealed_source_m5_authority_root_sha256,
        current_case_authority_root_sha256=_sha("gold-case-root"),
        current_case_revision=appeal_gold.resolution_commit.resulting_case_revision,
        current_case_document_sha256=(appeal_gold.resolution_commit.resulting_case_document_sha256),
        current_case_status=CaseStatus.APPEAL_RESOLVED,
        current_appeal_authority=appeal_gold.terminal_appeal_authority,
        appeal_gold_authority=appeal_gold,
    )
    receipts = tuple(
        sorted((stability_receipt, gold_receipt), key=lambda item: item.source_item.sample_id)
    )
    selection = M6RegressionSelectionInventoryAuthority(
        baseline_manifest_id=cut.baseline_manifest_id,
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        source_inventory_cut_content_sha256=_sha(cut_document),
        source_inventory_item_count=cut.source_item_count,
        source_inventory_root_sha256=cut.source_inventory_root_sha256,
        eligibility_policy=policy,
        receipts=receipts,
    )
    return {
        "source_inventory_cut": cut,
        "source_inventory_cut_document": cut_document,
        "execution_source_catalog": catalog,
        "execution_source_catalog_document": catalog_document,
        "eligibility_policy": policy,
        "eligibility_policy_document": canonical_json(policy.model_dump(mode="json")),
        "selection_inventory": selection,
        "selection_inventory_document": canonical_json(selection.model_dump(mode="json")),
    }


def test_assembler_derives_paired_views_and_keeps_candidate_dataset_blind() -> None:
    inputs = _inputs()
    result = assemble_m6_regression_dataset(**inputs)

    evaluator = result.evaluator_dataset
    execution = result.execution_dataset
    assert evaluator.stability_count == evaluator.gold_count == evaluator.challenge_count == 1
    assert evaluator.selection_receipt_count == evaluator.source_inventory_item_count == 2
    assert tuple(item.sample_id for item in execution.entries) == tuple(
        item.sample_id for item in evaluator.entries
    )
    serialized = result.execution_dataset_document
    for forbidden in (
        "baseline_snapshot",
        "memberships",
        "gold_truth",
        "expected_decision",
        "challenge_kinds",
        "selection_receipt",
    ):
        assert forbidden not in serialized
    assert result.execution_dataset_content_sha256 == _sha(serialized)
    assert result.evaluator_dataset_content_sha256 == _sha(result.evaluator_dataset_document)


def test_assembler_rejects_physical_tamper_and_catalog_graft() -> None:
    inputs = _inputs()
    tampered = dict(inputs)
    tampered["source_inventory_cut_document"] = str(inputs["source_inventory_cut_document"]) + " "
    with pytest.raises(M6RegressionDatasetAssemblyError) as document:
        assemble_m6_regression_dataset(**tampered)
    assert document.value.code == M6RegressionDatasetAssemblyErrorCode.DOCUMENT_INVALID

    catalog = inputs["execution_source_catalog"]
    assert isinstance(catalog, M6RegressionExecutionSourceCatalogAuthority)
    entry = catalog.entries[0].model_copy(update={"input_authority_content_sha256": "f" * 64})
    attacked = catalog.model_copy(update={"entries": (entry, *catalog.entries[1:])})
    grafted = dict(inputs)
    grafted["execution_source_catalog"] = attacked
    grafted["execution_source_catalog_document"] = canonical_json(attacked.model_dump(mode="json"))
    with pytest.raises(M6RegressionDatasetAssemblyError) as raised:
        assemble_m6_regression_dataset(**grafted)
    assert raised.value.code == M6RegressionDatasetAssemblyErrorCode.SOURCE_CATALOG_MISMATCH

    for field in (
        "source_seal_size_bytes",
        "input_authority_size_bytes",
    ):
        entry = catalog.entries[0]
        resized_entry = entry.model_copy(update={field: getattr(entry, field) + 1})
        resized_catalog = catalog.model_copy(
            update={"entries": (resized_entry, *catalog.entries[1:])}
        )
        resized = dict(inputs)
        resized["execution_source_catalog"] = resized_catalog
        resized["execution_source_catalog_document"] = canonical_json(
            resized_catalog.model_dump(mode="json")
        )
        with pytest.raises(M6RegressionDatasetAssemblyError) as size_graft:
            assemble_m6_regression_dataset(**resized)
        assert size_graft.value.code == (
            M6RegressionDatasetAssemblyErrorCode.SOURCE_CATALOG_MISMATCH
        )

    cut = inputs["source_inventory_cut"]
    assert isinstance(cut, M6RegressionSourceInventoryCutAuthority)
    resized_item = cut.items[0].model_copy(
        update={
            "replay_input_closure_size_bytes": (cut.items[0].replay_input_closure_size_bytes + 1)
        }
    )
    resized_items = (resized_item, *cut.items[1:])
    run_cut = cut.run_cuts[0].model_copy(
        update={
            "source_scope_root_sha256": sha256_hex(
                [
                    "m6-regression-source-run-scope",
                    1,
                    cut.run_cuts[0].source_run_id,
                    [item.source_scope_key for item in resized_items],
                ]
            )
        }
    )
    resized_cut = cut.model_copy(update={"run_cuts": (run_cut,), "items": resized_items})
    resized_cut_document = canonical_json(resized_cut.model_dump(mode="json"))
    resized_catalog_entry = catalog.entries[0].model_copy(
        update={"source_item_id": resized_item.source_item_id}
    )
    resized_catalog = M6RegressionExecutionSourceCatalogAuthority(
        baseline_manifest_id=resized_cut.baseline_manifest_id,
        source_inventory_cut_authority_id=(resized_cut.source_inventory_cut_authority_id),
        source_inventory_cut_content_sha256=_sha(resized_cut_document),
        source_inventory_item_count=resized_cut.source_item_count,
        source_inventory_root_sha256=resized_cut.source_inventory_root_sha256,
        entries=(resized_catalog_entry, *catalog.entries[1:]),
    )
    closure_size_graft = dict(inputs)
    closure_size_graft.update(
        {
            "source_inventory_cut": resized_cut,
            "source_inventory_cut_document": resized_cut_document,
            "execution_source_catalog": resized_catalog,
            "execution_source_catalog_document": canonical_json(
                resized_catalog.model_dump(mode="json")
            ),
        }
    )
    with pytest.raises(M6RegressionDatasetAssemblyError) as closure_size:
        assemble_m6_regression_dataset(**closure_size_graft)
    assert closure_size.value.code == (M6RegressionDatasetAssemblyErrorCode.SOURCE_CATALOG_MISMATCH)


def test_pending_block_precedes_empty_set_errors() -> None:
    inputs = _inputs()
    selection = inputs["selection_inventory"]
    assert isinstance(selection, M6RegressionSelectionInventoryAuthority)
    gold = selection.receipts[-1]
    reviewed = _chain().review_authority
    pending = M6RegressionSelectionReceipt(
        source_inventory_cut_authority_id=gold.source_inventory_cut_authority_id,
        eligibility_policy_authority_id=gold.eligibility_policy_authority_id,
        source_item=gold.source_item,
        baseline_snapshot=gold.baseline_snapshot,
        source_m5_authority_root_sha256=gold.source_m5_authority_root_sha256,
        current_case_authority_root_sha256=_sha("pending-case-root"),
        current_case_revision=gold.source_item.source_case_revision + 2,
        current_case_document_sha256=_sha("pending-case-document"),
        current_case_status=CaseStatus.APPEALED,
        current_appeal_authority=reviewed,
    )
    receipts = tuple(
        sorted(
            (selection.receipts[0], pending),
            key=lambda item: item.source_item.sample_id,
        )
    )
    blocked = selection.model_copy(update={"receipts": receipts})
    attacked = dict(inputs)
    attacked["selection_inventory"] = blocked
    attacked["selection_inventory_document"] = canonical_json(blocked.model_dump(mode="json"))
    with pytest.raises(M6RegressionDatasetAssemblyError) as raised:
        assemble_m6_regression_dataset(**attacked)
    assert raised.value.code == (M6RegressionDatasetAssemblyErrorCode.PENDING_APPEAL_BLOCKS_DATASET)


def test_assembler_enforces_an_explicit_document_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs()
    monkeypatch.setattr(dataset_module, "MAX_M6_REGRESSION_ASSEMBLY_DOCUMENT_BYTES", 1)

    with pytest.raises(M6RegressionDatasetAssemblyError) as raised:
        assemble_m6_regression_dataset(**inputs)
    assert raised.value.code == M6RegressionDatasetAssemblyErrorCode.DOCUMENT_TOO_LARGE
