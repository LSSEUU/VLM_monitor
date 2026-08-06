"""M4-only precedent retrieval boundary.

The port deliberately returns only a complete successful result.  Controlled
runtime unavailability is represented by one typed exception and can therefore
never be confused with a partial ranking.
"""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalResult,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalReceipt,
)


class HearingPrecedentRetrievalUnavailable(RuntimeError):
    """Controlled provider/model/index outage with no partial retrieval payload."""

    def __init__(self, reason: HearingPrecedentDegradedReason) -> None:
        if not isinstance(reason, HearingPrecedentDegradedReason):
            raise TypeError("reason must be a HearingPrecedentDegradedReason")
        self.reason = reason
        super().__init__(reason.value)


class HearingPrecedentRetriever(Protocol):
    """Retrieve one exact successful result or raise typed unavailability."""

    def retrieve(
        self,
        query: HearingPrecedentRetrievalQuery,
    ) -> HearingPrecedentRetrievalResult: ...


class HearingPrecedentRetrievalOutcomeCommitter(Protocol):
    """Commit one retrieval outcome and return the durable canonical receipt."""

    def commit(
        self,
        outcome: HearingPrecedentRetrievalOutcome,
    ) -> HearingPrecedentRetrievalReceipt: ...


__all__ = [
    "HearingPrecedentRetrievalOutcomeCommitter",
    "HearingPrecedentRetrievalUnavailable",
    "HearingPrecedentRetriever",
]
