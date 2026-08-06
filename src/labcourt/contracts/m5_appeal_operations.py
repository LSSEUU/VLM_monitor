"""Stable reports emitted by the additive M5 appeal command boundary."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import AppealStatus, VerdictDecision
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken

MAX_M5_APPEAL_REPORT_ITEMS = 10_000


def _require_stable_unique(values: tuple[str, ...], name: str) -> None:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique and use stable order")


class M5AppealSubmissionCommandReport(FrozenContractModel):
    """Durable identity returned for NONE/absent -> SUBMITTED."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    appeal_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    committed_case_revision: int = Field(gt=0, strict=True)
    appeal_version: Literal[1] = 1
    status: Literal[AppealStatus.SUBMITTED] = AppealStatus.SUBMITTED
    appeal_authority_sha256: Sha256Hex

    @model_validator(mode="after")
    def validate_revision_transition(self) -> Self:
        if self.committed_case_revision != self.source_case_revision + 1:
            raise ValueError("appeal submission Case revisions must be adjacent")
        return self


class M5AppealReviewCommandReport(FrozenContractModel):
    """Durable identity returned for SUBMITTED -> UNDER_REVIEW."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    appeal_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    committed_case_revision: int = Field(gt=0, strict=True)
    appeal_version: Literal[2] = 2
    status: Literal[AppealStatus.UNDER_REVIEW] = AppealStatus.UNDER_REVIEW
    reviewer_id: ReferenceToken
    previous_appeal_authority_sha256: Sha256Hex
    appeal_authority_sha256: Sha256Hex

    @model_validator(mode="after")
    def validate_revision_transition(self) -> Self:
        if self.committed_case_revision != self.source_case_revision + 2:
            raise ValueError("appeal review Case revision must follow submission")
        if self.previous_appeal_authority_sha256 == self.appeal_authority_sha256:
            raise ValueError("appeal review authority must differ from its predecessor")
        return self


class M5AppealResolutionCommandReport(FrozenContractModel):
    """Audit-safe terminal report without reproducing human-authored free text."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    appeal_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    committed_case_revision: int = Field(gt=0, strict=True)
    appeal_version: Literal[3] = 3
    status: Literal[AppealStatus.UPHELD, AppealStatus.OVERTURNED]
    reviewer_id: ReferenceToken
    source_decision: VerdictDecision
    final_decision: VerdictDecision
    previous_appeal_authority_sha256: Sha256Hex
    appeal_authority_sha256: Sha256Hex
    precedent_snapshot_sha256: Sha256Hex
    affected_citation_report_sha256: Sha256Hex
    resolution_intent_id: Sha256Hex
    rescinded_alert_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_REPORT_ITEMS,
    )
    revoked_precedent_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_REPORT_ITEMS,
    )
    replacement_precedent_id: ReferenceToken | None = None
    training_label_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_REPORT_ITEMS,
    )
    affected_citation_case_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_REPORT_ITEMS,
    )

    @model_validator(mode="after")
    def validate_terminal_effect_matrix(self) -> Self:
        if self.committed_case_revision != self.source_case_revision + 3:
            raise ValueError("terminal appeal Case revision must follow review")
        if self.previous_appeal_authority_sha256 == self.appeal_authority_sha256:
            raise ValueError("terminal appeal authority must differ from its predecessor")
        _require_stable_unique(self.rescinded_alert_ids, "rescinded alert IDs")
        _require_stable_unique(self.revoked_precedent_ids, "revoked precedent IDs")
        _require_stable_unique(self.training_label_ids, "training label IDs")
        _require_stable_unique(
            self.affected_citation_case_ids,
            "affected citation Case IDs",
        )
        decision_changed = self.final_decision != self.source_decision
        if self.status == AppealStatus.UPHELD:
            if decision_changed:
                raise ValueError("an upheld appeal must preserve the source decision")
            if (
                self.rescinded_alert_ids
                or self.revoked_precedent_ids
                or self.replacement_precedent_id is not None
                or self.affected_citation_case_ids
            ):
                raise ValueError("an upheld appeal cannot report overturn-only effects")
        else:
            if not decision_changed:
                raise ValueError("an overturned appeal must change the source decision")
            if (
                not self.revoked_precedent_ids
                or self.replacement_precedent_id is None
                or not self.training_label_ids
            ):
                raise ValueError(
                    "an overturned appeal requires revocation, replacement, and labels"
                )
        return self


__all__ = [
    "MAX_M5_APPEAL_REPORT_ITEMS",
    "M5AppealResolutionCommandReport",
    "M5AppealReviewCommandReport",
    "M5AppealSubmissionCommandReport",
]
