"""Evaluator-only M6 appeal gold-truth closure."""

from __future__ import annotations

import hashlib
from typing import Literal, Self

from pydantic import ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import AppealStatus, CaseStatus
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_appeals import (
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6GoldTruthAuthority,
    M6GoldTruthAuthorityKind,
)
from labcourt.contracts.m6_regression_dataset import M6RegressionSourceInventoryItem


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M6 appeal gold authority")


def _canonical_content_sha256(value: FrozenContractModel) -> str:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class M6AppealGoldTruthAuthority(FrozenContractModel):
    """Full pre-appeal baseline -> terminal human decision -> commit chain."""

    schema_version: Literal["m6-appeal-gold-truth-authority-v1"] = (
        "m6-appeal-gold-truth-authority-v1"
    )
    source_item: M6RegressionSourceInventoryItem
    baseline_snapshot: M6CaseReplaySnapshot
    terminal_appeal_authority: AppealVersionAuthority
    resolution_intent: AppealResolutionSideEffectIntent
    resolution_commit: M5AppealResolutionCommitReceipt
    gold_truth: M6GoldTruthAuthority

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "terminal_appeal_content_sha256",
                "resolution_intent_content_sha256",
                "resolution_commit_content_sha256",
                "appeal_gold_authority_id",
            ),
        )
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_exact_appeal_chain(self) -> Self:
        source_item = M6RegressionSourceInventoryItem.model_validate(
            self.source_item.model_dump(mode="json", exclude_computed_fields=True)
        )
        baseline = M6CaseReplaySnapshot.model_validate(
            self.baseline_snapshot.model_dump(mode="json", exclude_computed_fields=True)
        )
        terminal = AppealVersionAuthority.model_validate(
            self.terminal_appeal_authority.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        intent = AppealResolutionSideEffectIntent.model_validate(
            self.resolution_intent.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        commit = M5AppealResolutionCommitReceipt.model_validate(
            self.resolution_commit.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        truth = M6GoldTruthAuthority.model_validate(
            self.gold_truth.model_dump(mode="json", exclude_computed_fields=True)
        )
        if (
            source_item != self.source_item
            or baseline != self.baseline_snapshot
            or terminal != self.terminal_appeal_authority
            or intent != self.resolution_intent
            or commit != self.resolution_commit
            or truth != self.gold_truth
        ):
            raise ValueError("M6 appeal gold authority contains a non-canonical document")

        closed = terminal.source_case_authority
        resolved_decision = terminal.appeal.resolved_decision
        if (
            baseline.sample_id != source_item.sample_id
            or baseline.source_run_id != source_item.source_run_id
            or baseline.source_case_id != source_item.source_case_id
            or baseline.source_case_revision != source_item.source_case_revision
            or baseline.source_case_document_sha256 != source_item.source_case_document_sha256
            or baseline.manifest_id != source_item.source_manifest_id
            or baseline.case_status != CaseStatus.CLOSED
            or baseline.final_decision is None
            or baseline.terminal_appeal_status is not None
        ):
            raise ValueError("M6 appeal gold baseline is not the exact sealed pre-appeal Case")
        if (
            terminal.version != 3
            or terminal.appeal.status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
            or resolved_decision is None
            or terminal.run_id != source_item.source_run_id
            or terminal.appeal.case_id != source_item.source_case_id
            or terminal.source_case_revision != source_item.source_case_revision
            or terminal.source_case_authority_sha256 != closed.authority_sha256
            or terminal.source_decision != baseline.final_decision
            or terminal.manifest_id != source_item.source_manifest_id
            or closed.run_id != source_item.source_run_id
            or closed.case_id != source_item.source_case_id
            or closed.case_revision != source_item.source_case_revision
            or closed.final_decision != baseline.final_decision
            or closed.manifest_id != source_item.source_manifest_id
        ):
            raise ValueError("M6 appeal gold terminal authority differs from its baseline")
        if (
            intent.appeal_authority != terminal
            or intent.run_id != source_item.source_run_id
            or intent.case_id != source_item.source_case_id
            or intent.expected_case_revision != source_item.source_case_revision
            or intent.source_decision != baseline.final_decision
            or intent.final_decision != resolved_decision
            or intent.manifest_id != source_item.source_manifest_id
        ):
            raise ValueError("M6 appeal gold resolution intent differs from terminal authority")
        if (
            commit.run_id != source_item.source_run_id
            or commit.resolution_intent_id != intent.intent_id
            or commit.resolution_document_sha256 != self.resolution_intent_content_sha256
            or commit.appeal_id != terminal.appeal.appeal_id
            or commit.appeal_authority_sha256 != terminal.authority_sha256
            or commit.case_id != source_item.source_case_id
            or commit.source_case_revision != source_item.source_case_revision
            or commit.manifest_id != source_item.source_manifest_id
        ):
            raise ValueError("M6 appeal gold commit differs from the exact resolution intent")
        replacement = intent.appeal_precedent_authority
        if (
            len(commit.verdict_rescission_ids) != int(intent.verdict_rescission is not None)
            or len(commit.alert_rescission_ids) != len(intent.alert_rescissions)
            or len(commit.precedent_revocation_receipt_ids) != len(intent.precedent_revocations)
            or commit.replacement_precedent_authority_id
            != (replacement.authority_id if replacement is not None else None)
            or commit.training_label_ids
            != tuple(label.label_id for label in intent.training_labels)
            or commit.affected_citation_report_sha256 != intent.affected_citations.report_sha256
        ):
            raise ValueError("M6 appeal gold commit effect inventory differs from its intent")
        expected_truth = M6GoldTruthAuthority(
            sample_id=source_item.sample_id,
            baseline_snapshot_id=baseline.snapshot_id,
            baseline_source_run_id=baseline.source_run_id,
            baseline_source_case_id=baseline.source_case_id,
            baseline_source_case_revision=baseline.source_case_revision,
            authority_kind=M6GoldTruthAuthorityKind.APPEAL_RESOLUTION,
            decision_authority_id=terminal.authority_sha256,
            decision_authority_document_sha256=self.terminal_appeal_content_sha256,
            expected_decision=resolved_decision,
            resolution_commit_id=commit.receipt_id,
            resolution_commit_document_sha256=self.resolution_commit_content_sha256,
        )
        if truth != expected_truth:
            raise ValueError("M6 appeal gold truth was not derived from the human decision chain")
        object.__setattr__(self, "source_item", source_item)
        object.__setattr__(self, "baseline_snapshot", baseline)
        object.__setattr__(self, "terminal_appeal_authority", terminal)
        object.__setattr__(self, "resolution_intent", intent)
        object.__setattr__(self, "resolution_commit", commit)
        object.__setattr__(self, "gold_truth", truth)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def terminal_appeal_content_sha256(self) -> Sha256Hex:
        return _canonical_content_sha256(self.terminal_appeal_authority)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resolution_intent_content_sha256(self) -> Sha256Hex:
        return _canonical_content_sha256(self.resolution_intent)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resolution_commit_content_sha256(self) -> Sha256Hex:
        return _canonical_content_sha256(self.resolution_commit)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def appeal_gold_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-appeal-gold-truth-authority",
                1,
                self.source_item.source_item_id,
                self.baseline_snapshot.snapshot_id,
                self.terminal_appeal_authority.authority_sha256,
                self.terminal_appeal_content_sha256,
                self.resolution_intent.intent_id,
                self.resolution_intent_content_sha256,
                self.resolution_commit.receipt_id,
                self.resolution_commit_content_sha256,
                self.gold_truth.truth_id,
            ]
        )


__all__ = ["M6AppealGoldTruthAuthority"]
