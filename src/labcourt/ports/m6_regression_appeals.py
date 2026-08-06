"""Typed same-snapshot appeal observations used by M6 dataset selection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m5_appeals import (
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionSourceInventoryItem,
    M6RegressionSourceRunCut,
)


def _require_sha256(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _require_document(value: FrozenContractModel, document: object, label: str) -> None:
    if not isinstance(document, str) or canonical_json(value.model_dump(mode="json")) != document:
        raise ValueError(f"{label} must be the exact canonical document")


class M6RegressionAppealState(StrEnum):
    NONE = "NONE"
    PENDING = "PENDING"
    TERMINAL = "TERMINAL"


@dataclass(frozen=True, slots=True)
class M6RegressionAppealHistoryObservation:
    """One source Case's complete appeal state from one validated M5 snapshot."""

    source_identity_sha256: str
    source_inventory_cut_authority_id: str
    source_item: M6RegressionSourceInventoryItem
    run_cut: M6RegressionSourceRunCut
    m5_authority_root_sha256: str
    current_case_revision: int
    current_case_document_sha256: str
    current_case_status: CaseStatus
    current_case_root_sha256: str
    state: M6RegressionAppealState
    current_appeal_authority: AppealVersionAuthority | None = None
    current_appeal_document: str | None = None
    resolution_intent: AppealResolutionSideEffectIntent | None = None
    resolution_intent_document: str | None = None
    resolution_commit: M5AppealResolutionCommitReceipt | None = None
    resolution_commit_document: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.source_identity_sha256, "M6 source snapshot identity"),
            (self.source_inventory_cut_authority_id, "M6 source inventory cut"),
            (self.m5_authority_root_sha256, "M6 appeal M5 authority root"),
            (self.current_case_document_sha256, "M6 current Case document"),
            (self.current_case_root_sha256, "M6 current Case authority root"),
        ):
            _require_sha256(value, label)
        if not isinstance(self.source_item, M6RegressionSourceInventoryItem):
            raise TypeError("M6 appeal observation requires a typed source item")
        if not isinstance(self.run_cut, M6RegressionSourceRunCut):
            raise TypeError("M6 appeal observation requires a typed run cut")
        if (
            not isinstance(self.current_case_revision, int)
            or isinstance(self.current_case_revision, bool)
            or self.current_case_revision <= 0
        ):
            raise ValueError("M6 appeal current Case revision must be positive")
        if not isinstance(self.current_case_status, CaseStatus):
            raise TypeError("M6 appeal current Case status must be a CaseStatus")
        if not isinstance(self.state, M6RegressionAppealState):
            raise TypeError("M6 appeal state must be an M6RegressionAppealState")
        item_snapshot = (
            self.source_item.sealed_source_validation_report_id,
            self.source_item.sealed_source_validation_report_document_sha256,
            self.source_item.sealed_source_m5_authority_root_sha256,
            self.source_item.sealed_audit_head_sequence,
            self.source_item.sealed_audit_head_hash,
        )
        run_snapshot = (
            self.run_cut.m5_validation_report_id,
            self.run_cut.m5_validation_report_content_sha256,
            self.run_cut.m5_authority_root_sha256,
            self.run_cut.audit_head_sequence,
            self.run_cut.audit_head_hash,
        )
        if (
            self.source_item.source_run_id != self.run_cut.source_run_id
            or self.source_item.source_manifest_id != self.run_cut.baseline_manifest_id
            or item_snapshot != run_snapshot
            or self.m5_authority_root_sha256 != self.run_cut.m5_authority_root_sha256
        ):
            raise ValueError("M6 appeal observation differs from its source snapshot")
        chain = (
            self.current_appeal_authority,
            self.current_appeal_document,
            self.resolution_intent,
            self.resolution_intent_document,
            self.resolution_commit,
            self.resolution_commit_document,
        )
        if self.state == M6RegressionAppealState.NONE:
            if self.current_case_status != CaseStatus.CLOSED or any(
                value is not None for value in chain
            ):
                raise ValueError("M6 no-appeal observation has an appeal authority")
            if self.current_case_revision != self.source_item.source_case_revision:
                raise ValueError("M6 no-appeal source is not the current CLOSED Case")
            return
        appeal = self.current_appeal_authority
        appeal_document = self.current_appeal_document
        if appeal is None or appeal_document is None:
            raise ValueError("M6 appeal observation requires its current appeal document")
        _require_document(appeal, appeal_document, "M6 current appeal")
        source = appeal.source_case_authority
        if (
            appeal.run_id != self.source_item.source_run_id
            or appeal.appeal.case_id != self.source_item.source_case_id
            or appeal.source_case_revision != self.source_item.source_case_revision
            or appeal.manifest_id != self.source_item.source_manifest_id
            or source.final_decision is None
        ):
            raise ValueError("M6 current appeal differs from the sealed source Case")
        if self.state == M6RegressionAppealState.PENDING:
            if (
                self.current_case_status != CaseStatus.APPEALED
                or appeal.version not in {1, 2}
                or self.current_case_revision
                != self.source_item.source_case_revision + appeal.version
                or any(value is not None for value in chain[2:])
            ):
                raise ValueError("M6 pending appeal observation has a terminal chain")
            return
        intent = self.resolution_intent
        intent_document = self.resolution_intent_document
        commit = self.resolution_commit
        commit_document = self.resolution_commit_document
        if (
            self.current_case_status != CaseStatus.APPEAL_RESOLVED
            or appeal.version != 3
            or self.current_case_revision != self.source_item.source_case_revision + 3
            or intent is None
            or intent_document is None
            or commit is None
            or commit_document is None
        ):
            raise ValueError("M6 terminal appeal observation lacks its complete commit chain")
        _require_document(intent, intent_document, "M6 appeal resolution intent")
        _require_document(commit, commit_document, "M6 appeal resolution commit")
        if (
            intent.appeal_authority != appeal
            or commit.resolution_intent_id != intent.intent_id
            or commit.resolution_document_sha256
            != hashlib.sha256(intent_document.encode("utf-8")).hexdigest()
            or commit.appeal_authority_sha256 != appeal.authority_sha256
            or commit.resulting_case_revision != self.current_case_revision
            or commit.resulting_case_document_sha256 != self.current_case_document_sha256
        ):
            raise ValueError("M6 terminal appeal observation contains a cross-grafted chain")


__all__ = [
    "M6RegressionAppealHistoryObservation",
    "M6RegressionAppealState",
]
