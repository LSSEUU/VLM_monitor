from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import AlertLevel, AppealStatus, CaseStatus
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6GoldTruthAuthority,
    M6GoldTruthAuthorityKind,
    M6RegressionStage,
    M6SemanticStageRoot,
)
from labcourt.contracts.m6_regression_dataset import M6RegressionSourceInventoryItem
from labcourt.contracts.m6_regression_gold import M6AppealGoldTruthAuthority
from labcourt.schema_export import expected_schema_files
from tests.unit.test_m5_training_provenance import _chain


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _content_sha256(value: FrozenContractModel) -> str:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _authority(
    status: AppealStatus = AppealStatus.OVERTURNED,
) -> M6AppealGoldTruthAuthority:
    chain = _chain(status)
    terminal = chain.terminal_authority
    source = terminal.source_case_authority
    sample_id = _sha(f"appeal-gold:{terminal.appeal.appeal_id}")
    source_item = M6RegressionSourceInventoryItem(
        sample_id=sample_id,
        source_run_id=source.run_id,
        source_case_id=source.case_id,
        source_case_revision=source.case_revision,
        source_case_document_sha256=_sha("source-case-document"),
        source_manifest_id=source.manifest_id,
        sealed_source_validation_report_id=_sha("validation-report-id"),
        sealed_source_validation_report_document_sha256=_sha("validation-report-document"),
        sealed_source_m5_authority_root_sha256=_sha("m5-authority-root"),
        sealed_audit_head_sequence=7,
        sealed_audit_head_hash=_sha("audit-head"),
        source_seal_id=_sha("source-seal-id"),
        source_seal_content_sha256=_sha("source-seal-content"),
        source_seal_size_bytes=1,
        input_authority_id=_sha("input-authority-id"),
        input_authority_document_sha256=_sha("input-authority-document"),
        input_authority_content_sha256=_sha("input-authority-content"),
        input_authority_size_bytes=1,
        replay_input_closure_authority_id=_sha("input-closure-id"),
        replay_input_closure_document_sha256=_sha("input-closure-document"),
        replay_input_closure_content_sha256=_sha("input-closure-content"),
        replay_input_closure_size_bytes=1,
    )
    baseline = M6CaseReplaySnapshot(
        sample_id=sample_id,
        source_run_id=source.run_id,
        source_case_id=source.case_id,
        source_case_revision=source.case_revision,
        source_case_document_sha256=source_item.source_case_document_sha256,
        manifest_id=source.manifest_id,
        stage_roots=tuple(
            M6SemanticStageRoot(
                stage=stage,
                projection_sha256=_sha(f"baseline-stage:{stage.value}"),
            )
            for stage in M6RegressionStage
        ),
        case_status=CaseStatus.CLOSED,
        final_decision=source.final_decision,
        highest_alert_level=AlertLevel.CONFIRMED,
    )
    gold_truth = M6GoldTruthAuthority(
        sample_id=sample_id,
        baseline_snapshot_id=baseline.snapshot_id,
        baseline_source_run_id=source.run_id,
        baseline_source_case_id=source.case_id,
        baseline_source_case_revision=source.case_revision,
        authority_kind=M6GoldTruthAuthorityKind.APPEAL_RESOLUTION,
        decision_authority_id=terminal.authority_sha256,
        decision_authority_document_sha256=_content_sha256(terminal),
        expected_decision=terminal.appeal.resolved_decision,
        resolution_commit_id=chain.commit_receipt.receipt_id,
        resolution_commit_document_sha256=_content_sha256(chain.commit_receipt),
    )
    return M6AppealGoldTruthAuthority(
        source_item=source_item,
        baseline_snapshot=baseline,
        terminal_appeal_authority=terminal,
        resolution_intent=chain.intent,
        resolution_commit=chain.commit_receipt,
        gold_truth=gold_truth,
    )


@pytest.mark.parametrize("status", [AppealStatus.UPHELD, AppealStatus.OVERTURNED])
def test_appeal_gold_closes_exact_human_decision_chain(status: AppealStatus) -> None:
    authority = _authority(status)
    restored = M6AppealGoldTruthAuthority.model_validate(authority.model_dump(mode="json"))

    assert restored == authority
    assert restored.gold_truth.expected_decision == authority.resolution_intent.final_decision
    assert restored.baseline_snapshot.final_decision == authority.resolution_intent.source_decision
    assert restored.gold_truth.decision_authority_document_sha256 == (
        authority.terminal_appeal_content_sha256
    )
    assert restored.gold_truth.resolution_commit_document_sha256 == (
        authority.resolution_commit_content_sha256
    )


@pytest.mark.parametrize(
    "claim",
    [
        "terminal_appeal_content_sha256",
        "resolution_intent_content_sha256",
        "resolution_commit_content_sha256",
        "appeal_gold_authority_id",
    ],
)
def test_appeal_gold_rejects_forged_serialized_computed_claims(claim: str) -> None:
    payload = _authority().model_dump(mode="json")
    payload[claim] = "f" * 64

    with pytest.raises(ValidationError, match=claim):
        M6AppealGoldTruthAuthority.model_validate(payload)


def test_appeal_gold_rejects_cross_case_commit_and_intent_digest_forgery() -> None:
    authority = _authority()
    foreign_commit = authority.resolution_commit.model_copy(update={"case_id": "foreign-case"})
    with pytest.raises(ValidationError, match="commit differs"):
        M6AppealGoldTruthAuthority(
            source_item=authority.source_item,
            baseline_snapshot=authority.baseline_snapshot,
            terminal_appeal_authority=authority.terminal_appeal_authority,
            resolution_intent=authority.resolution_intent,
            resolution_commit=foreign_commit,
            gold_truth=authority.gold_truth,
        )

    forged_digest = authority.resolution_commit.model_copy(
        update={"resolution_document_sha256": "e" * 64}
    )
    with pytest.raises(ValidationError, match="commit differs"):
        M6AppealGoldTruthAuthority(
            source_item=authority.source_item,
            baseline_snapshot=authority.baseline_snapshot,
            terminal_appeal_authority=authority.terminal_appeal_authority,
            resolution_intent=authority.resolution_intent,
            resolution_commit=forged_digest,
            gold_truth=authority.gold_truth,
        )


def test_appeal_gold_rejects_commit_shaped_for_the_opposite_terminal_outcome() -> None:
    overturned = _authority(AppealStatus.OVERTURNED)
    upheld_shaped_commit = overturned.resolution_commit.model_copy(
        update={
            "verdict_rescission_ids": (),
            "alert_rescission_ids": (),
            "precedent_revocation_receipt_ids": (),
            "replacement_precedent_authority_id": None,
            "training_label_ids": (),
        }
    )
    forged_truth = overturned.gold_truth.model_copy(
        update={
            "resolution_commit_id": upheld_shaped_commit.receipt_id,
            "resolution_commit_document_sha256": _content_sha256(upheld_shaped_commit),
        }
    )
    with pytest.raises(ValidationError, match="effect inventory differs"):
        M6AppealGoldTruthAuthority(
            source_item=overturned.source_item,
            baseline_snapshot=overturned.baseline_snapshot,
            terminal_appeal_authority=overturned.terminal_appeal_authority,
            resolution_intent=overturned.resolution_intent,
            resolution_commit=upheld_shaped_commit,
            gold_truth=forged_truth,
        )

    upheld = _authority(AppealStatus.UPHELD)
    overturned_shaped_commit = upheld.resolution_commit.model_copy(
        update={
            "verdict_rescission_ids": ("1" * 64,),
            "precedent_revocation_receipt_ids": ("2" * 64,),
            "replacement_precedent_authority_id": "3" * 64,
        }
    )
    forged_truth = upheld.gold_truth.model_copy(
        update={
            "resolution_commit_id": overturned_shaped_commit.receipt_id,
            "resolution_commit_document_sha256": _content_sha256(overturned_shaped_commit),
        }
    )
    with pytest.raises(ValidationError, match="effect inventory differs"):
        M6AppealGoldTruthAuthority(
            source_item=upheld.source_item,
            baseline_snapshot=upheld.baseline_snapshot,
            terminal_appeal_authority=upheld.terminal_appeal_authority,
            resolution_intent=upheld.resolution_intent,
            resolution_commit=overturned_shaped_commit,
            gold_truth=forged_truth,
        )


def test_appeal_gold_rejects_post_appeal_baseline_and_forged_expected_decision() -> None:
    authority = _authority()
    with pytest.raises(ValidationError, match="pre-appeal Case"):
        M6AppealGoldTruthAuthority(
            source_item=authority.source_item,
            baseline_snapshot=authority.baseline_snapshot.model_copy(
                update={"case_status": CaseStatus.APPEAL_RESOLVED}
            ),
            terminal_appeal_authority=authority.terminal_appeal_authority,
            resolution_intent=authority.resolution_intent,
            resolution_commit=authority.resolution_commit,
            gold_truth=authority.gold_truth,
        )

    wrong_decision = authority.resolution_intent.source_decision
    forged_truth = authority.gold_truth.model_copy(update={"expected_decision": wrong_decision})
    with pytest.raises(ValidationError, match="human decision chain"):
        M6AppealGoldTruthAuthority(
            source_item=authority.source_item,
            baseline_snapshot=authority.baseline_snapshot,
            terminal_appeal_authority=authority.terminal_appeal_authority,
            resolution_intent=authority.resolution_intent,
            resolution_commit=authority.resolution_commit,
            gold_truth=forged_truth,
        )


def test_appeal_gold_shape_cannot_accept_training_labels_as_case_truth() -> None:
    payload = _authority().model_dump(mode="json")
    payload["training_label_authority"] = {"label_id": "crop-label-is-not-a-case-decision"}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        M6AppealGoldTruthAuthority.model_validate(payload)


def test_appeal_gold_schema_is_exported_and_enforces_computed_identity() -> None:
    schema = json.loads(expected_schema_files()["m6-appeal-gold-truth-authority.schema.json"])
    Draft202012Validator.check_schema(schema)
    payload = _authority().model_dump(mode="json")
    Draft202012Validator(schema).validate(payload)
    assert schema["properties"]["appeal_gold_authority_id"]["readOnly"] is True
