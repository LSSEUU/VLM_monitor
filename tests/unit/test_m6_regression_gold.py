from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_regression_gold import (
    M6AppealGoldTruthError,
    M6AppealGoldTruthErrorCode,
    build_m6_appeal_gold_truth_authority,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus, VerdictDecision
from labcourt.contracts.m6_regression_dataset import M6RegressionSourceRunCut
from labcourt.ports.m6_regression_appeals import (
    M6RegressionAppealHistoryObservation,
    M6RegressionAppealState,
)
from tests.contract.test_m6_regression_gold_contracts import _authority


def _observation():  # type: ignore[no-untyped-def]
    source = _authority()
    item = source.source_item
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
        source_scope_root_sha256="2" * 64,
    )
    return source, M6RegressionAppealHistoryObservation(
        source_identity_sha256="3" * 64,
        source_inventory_cut_authority_id="4" * 64,
        source_item=item,
        run_cut=run_cut,
        m5_authority_root_sha256=run_cut.m5_authority_root_sha256,
        current_case_revision=source.resolution_commit.resulting_case_revision,
        current_case_document_sha256=(source.resolution_commit.resulting_case_document_sha256),
        current_case_status=CaseStatus.APPEAL_RESOLVED,
        current_case_root_sha256="5" * 64,
        state=M6RegressionAppealState.TERMINAL,
        current_appeal_authority=source.terminal_appeal_authority,
        current_appeal_document=canonical_json(
            source.terminal_appeal_authority.model_dump(mode="json")
        ),
        resolution_intent=source.resolution_intent,
        resolution_intent_document=canonical_json(source.resolution_intent.model_dump(mode="json")),
        resolution_commit=source.resolution_commit,
        resolution_commit_document=canonical_json(source.resolution_commit.model_dump(mode="json")),
    )


def test_builder_derives_truth_and_physical_authority_identity() -> None:
    source, observation = _observation()

    result = build_m6_appeal_gold_truth_authority(
        appeal_history=observation,
        baseline_snapshot=source.baseline_snapshot,
    )

    assert result.authority == source
    assert result.authority.gold_truth.expected_decision == VerdictDecision.NOT_ESTABLISHED
    assert result.authority_document == canonical_json(source.model_dump(mode="json"))
    payload = result.authority_document.encode("utf-8")
    assert result.authority_content_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.authority_size_bytes == len(payload)


def test_builder_rejects_non_contract_input_with_typed_failure() -> None:
    source, _ = _observation()

    with pytest.raises(M6AppealGoldTruthError) as raised:
        build_m6_appeal_gold_truth_authority(
            appeal_history={"sample_id": source.source_item.sample_id},
            baseline_snapshot=source.baseline_snapshot,
        )
    assert raised.value.code == M6AppealGoldTruthErrorCode.INVALID_ARGUMENT


def test_builder_rejects_cross_grafted_commit_with_typed_failure() -> None:
    source, observation = _observation()
    foreign_commit = source.resolution_commit.model_copy(update={"case_id": "foreign-case"})
    object.__setattr__(observation, "resolution_commit", foreign_commit)

    with pytest.raises(M6AppealGoldTruthError) as raised:
        build_m6_appeal_gold_truth_authority(
            appeal_history=observation,
            baseline_snapshot=source.baseline_snapshot,
        )
    assert raised.value.code == M6AppealGoldTruthErrorCode.APPEAL_GOLD_CHAIN_INVALID


def test_builder_does_not_accept_a_training_label_authority_in_truth_slot() -> None:
    source, observation = _observation()
    training_label = source.resolution_intent.training_labels[0]
    object.__setattr__(observation, "current_appeal_authority", training_label)

    with pytest.raises(M6AppealGoldTruthError) as raised:
        build_m6_appeal_gold_truth_authority(
            appeal_history=observation,
            baseline_snapshot=source.baseline_snapshot,
        )
    assert raised.value.code == M6AppealGoldTruthErrorCode.INVALID_ARGUMENT
