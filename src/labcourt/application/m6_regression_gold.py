"""Derive evaluator-only M6 appeal gold truth from the exact M5 commit chain."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
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
from labcourt.contracts.m6_regression_gold import M6AppealGoldTruthAuthority
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_regression_appeals import (
    M6RegressionAppealHistoryObservation,
    M6RegressionAppealState,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6AppealGoldTruthErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_ITEM_INVALID = "SOURCE_ITEM_INVALID"
    BASELINE_SNAPSHOT_INVALID = "BASELINE_SNAPSHOT_INVALID"
    TERMINAL_APPEAL_INVALID = "TERMINAL_APPEAL_INVALID"
    RESOLUTION_INTENT_INVALID = "RESOLUTION_INTENT_INVALID"
    RESOLUTION_COMMIT_INVALID = "RESOLUTION_COMMIT_INVALID"
    APPEAL_NOT_TERMINAL = "APPEAL_NOT_TERMINAL"
    APPEAL_GOLD_CHAIN_INVALID = "APPEAL_GOLD_CHAIN_INVALID"


class M6AppealGoldTruthError(LabCourtError):
    """An M5 appeal graph could not become one case-level M6 truth authority."""

    def __init__(self, code: M6AppealGoldTruthErrorCode) -> None:
        if not isinstance(code, M6AppealGoldTruthErrorCode):
            raise TypeError("code must be an M6AppealGoldTruthErrorCode")
        self.code = code
        super().__init__(f"M6 appeal gold truth failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6AppealGoldTruthBundle:
    authority: M6AppealGoldTruthAuthority
    authority_document: str
    authority_content_sha256: str
    authority_size_bytes: int


def _fail(code: M6AppealGoldTruthErrorCode) -> NoReturn:
    raise M6AppealGoldTruthError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    code: M6AppealGoldTruthErrorCode,
) -> _ModelT:
    if not isinstance(value, expected):
        _fail(M6AppealGoldTruthErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(code)
    if controlled != value:
        _fail(code)
    return controlled


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _content_identity(document: str) -> tuple[str, int]:
    payload = document.encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(payload)


def build_m6_appeal_gold_truth_authority(
    *,
    appeal_history: object,
    baseline_snapshot: object,
) -> M6AppealGoldTruthBundle:
    """Derive truth only from a same-snapshot terminal appeal observation."""

    if not isinstance(appeal_history, M6RegressionAppealHistoryObservation):
        _fail(M6AppealGoldTruthErrorCode.INVALID_ARGUMENT)
    if appeal_history.state != M6RegressionAppealState.TERMINAL:
        _fail(M6AppealGoldTruthErrorCode.APPEAL_NOT_TERMINAL)
    terminal = appeal_history.current_appeal_authority
    intent = appeal_history.resolution_intent
    commit = appeal_history.resolution_commit
    if terminal is None or intent is None or commit is None:
        _fail(M6AppealGoldTruthErrorCode.APPEAL_GOLD_CHAIN_INVALID)
    controlled_source = _canonical_model(
        appeal_history.source_item,
        M6RegressionSourceInventoryItem,
        M6AppealGoldTruthErrorCode.SOURCE_ITEM_INVALID,
    )
    controlled_baseline = _canonical_model(
        baseline_snapshot,
        M6CaseReplaySnapshot,
        M6AppealGoldTruthErrorCode.BASELINE_SNAPSHOT_INVALID,
    )
    controlled_terminal = _canonical_model(
        terminal,
        AppealVersionAuthority,
        M6AppealGoldTruthErrorCode.TERMINAL_APPEAL_INVALID,
    )
    controlled_intent = _canonical_model(
        intent,
        AppealResolutionSideEffectIntent,
        M6AppealGoldTruthErrorCode.RESOLUTION_INTENT_INVALID,
    )
    controlled_commit = _canonical_model(
        commit,
        M5AppealResolutionCommitReceipt,
        M6AppealGoldTruthErrorCode.RESOLUTION_COMMIT_INVALID,
    )
    resolved_decision = controlled_terminal.appeal.resolved_decision
    if resolved_decision is None:
        _fail(M6AppealGoldTruthErrorCode.TERMINAL_APPEAL_INVALID)
    terminal_document = appeal_history.current_appeal_document
    commit_document = appeal_history.resolution_commit_document
    if terminal_document is None or commit_document is None:
        _fail(M6AppealGoldTruthErrorCode.APPEAL_GOLD_CHAIN_INVALID)
    terminal_content_sha256, _ = _content_identity(terminal_document)
    commit_content_sha256, _ = _content_identity(commit_document)
    try:
        truth = M6GoldTruthAuthority(
            sample_id=controlled_source.sample_id,
            baseline_snapshot_id=controlled_baseline.snapshot_id,
            baseline_source_run_id=controlled_baseline.source_run_id,
            baseline_source_case_id=controlled_baseline.source_case_id,
            baseline_source_case_revision=controlled_baseline.source_case_revision,
            authority_kind=M6GoldTruthAuthorityKind.APPEAL_RESOLUTION,
            decision_authority_id=controlled_terminal.authority_sha256,
            decision_authority_document_sha256=terminal_content_sha256,
            expected_decision=resolved_decision,
            resolution_commit_id=controlled_commit.receipt_id,
            resolution_commit_document_sha256=commit_content_sha256,
        )
        authority = M6AppealGoldTruthAuthority(
            source_item=controlled_source,
            baseline_snapshot=controlled_baseline,
            terminal_appeal_authority=controlled_terminal,
            resolution_intent=controlled_intent,
            resolution_commit=controlled_commit,
            gold_truth=truth,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6AppealGoldTruthErrorCode.APPEAL_GOLD_CHAIN_INVALID)
    document = _document(authority)
    content_sha256, size_bytes = _content_identity(document)
    return M6AppealGoldTruthBundle(
        authority=authority,
        authority_document=document,
        authority_content_sha256=content_sha256,
        authority_size_bytes=size_bytes,
    )


__all__ = [
    "M6AppealGoldTruthBundle",
    "M6AppealGoldTruthError",
    "M6AppealGoldTruthErrorCode",
    "build_m6_appeal_gold_truth_authority",
]
