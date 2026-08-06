"""Human appeal contracts."""

from __future__ import annotations

from pydantic import Field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import AppealStatus, VerdictDecision


class Appeal(FrozenContractModel):
    appeal_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    status: AppealStatus
    reason: str = Field(min_length=1)
    submitted_by: str = Field(min_length=1)
    reviewer_id: str | None = None
    resolution_summary: str | None = None
    resolved_decision: VerdictDecision | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> Appeal:
        terminal = self.status in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
        resolution_fields = (
            self.reviewer_id,
            self.resolution_summary,
            self.resolved_decision,
        )
        if terminal and any(value is None for value in resolution_fields):
            raise ValueError("terminal appeals require reviewer, summary, and resolved decision")
        if not terminal and any(value is not None for value in resolution_fields):
            raise ValueError("non-terminal appeals cannot contain resolution fields")
        return self
