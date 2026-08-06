"""Public result and controlled failures for the bounded M4 driver."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingRecord,
    HearingSession,
)
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot


class HearingCoordinatorErrorCode(StrEnum):
    """Stable failures that require recovery or operator inspection."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_CASE_STATE = "INVALID_CASE_STATE"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    ROLE_RECOVERY_REQUIRED = "ROLE_RECOVERY_REQUIRED"
    PERSISTENCE_CONFLICT = "PERSISTENCE_CONFLICT"
    STEP_LIMIT_EXCEEDED = "STEP_LIMIT_EXCEEDED"


class HearingCoordinatorError(ContractViolation):
    """The driver cannot safely advance the supplied hearing authority."""

    def __init__(
        self,
        reason_code: HearingCoordinatorErrorCode,
        *,
        case_id: str,
    ) -> None:
        if not isinstance(reason_code, HearingCoordinatorErrorCode):
            raise TypeError("reason_code must be a HearingCoordinatorErrorCode")
        if not isinstance(case_id, str):
            raise TypeError("case_id must be a string")
        self.reason_code = reason_code
        self.case_id = case_id
        super().__init__(f"hearing coordination failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class HearingPipelineOutcome:
    """One bounded driver invocation's terminal, backlog, or human result."""

    case: CaseSnapshot
    session: HearingSession | None = None
    checkpoint: HearingCheckpoint | None = None
    record: HearingRecord | None = None
    verdict: Verdict | None = None
    review: ProceduralReview | None = None
    backlog_item_id: str | None = None
    cache_hit_count: int = 0
    recovered_response_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.case, CaseSnapshot):
            raise TypeError("case must be a CaseSnapshot")
        expected = (
            (self.session, HearingSession, "session"),
            (self.checkpoint, HearingCheckpoint, "checkpoint"),
            (self.record, HearingRecord, "record"),
            (self.verdict, Verdict, "verdict"),
            (self.review, ProceduralReview, "review"),
        )
        for value, kind, name in expected:
            if value is not None and not isinstance(value, kind):
                raise TypeError(f"{name} has the wrong contract type")
        for name in ("cache_hit_count", "recovered_response_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError(f"{name} must be a non-negative integer")

        status = self.case.case.status
        if status not in {
            CaseStatus.READY_FOR_ALERT_POLICY,
            CaseStatus.BACKLOGGED,
            CaseStatus.HUMAN_REVIEW,
        }:
            raise ValueError("hearing outcome requires a bounded terminal disposition")
        if status == CaseStatus.BACKLOGGED:
            if (
                self.backlog_item_id is None
                or self.backlog_item_id != self.case.case.current_backlog_item_id
            ):
                raise ValueError("backlogged outcome lacks the current backlog identity")
        elif self.backlog_item_id is not None:
            raise ValueError("only a backlogged outcome may carry a backlog identity")
        if (self.verdict is None) != (self.review is None):
            raise ValueError("verdict and review must be returned together")
        if self.review is not None and (
            status != CaseStatus.READY_FOR_ALERT_POLICY
            or not self.review.passed
            or self.case.case.verdicts[-1] != self.verdict
            or self.case.case.procedural_reviews[-1] != self.review
        ):
            raise ValueError("successful outcome conflicts with its terminal review")
        if self.session is not None and self.session.case_id != self.case.case.case_id:
            raise ValueError("outcome session belongs to another Case")
        if self.checkpoint is not None and (
            self.checkpoint.case_id != self.case.case.case_id
            or (
                self.session is not None
                and self.checkpoint.hearing_session_id != self.session.session_id
            )
        ):
            raise ValueError("outcome checkpoint belongs to another hearing")


__all__ = [
    "HearingCoordinatorError",
    "HearingCoordinatorErrorCode",
    "HearingPipelineOutcome",
]
