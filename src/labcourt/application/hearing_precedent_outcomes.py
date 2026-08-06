"""Commit boundaries for M4 retrieval outcomes."""

from __future__ import annotations

from labcourt.contracts.hearing_retrieval import HearingPrecedentRetrievalOutcome
from labcourt.contracts.hearing_state import HearingPrecedentRetrievalReceipt
from labcourt.exceptions import ContractViolation
from labcourt.ports.hearing_repository import HearingRepository


class AppendOnlyHearingPrecedentOutcomeCommitter:
    """Default M4 behavior: append its receipt and return that same authority."""

    def __init__(self, repository: HearingRepository) -> None:
        if not callable(getattr(repository, "append_precedent_retrieval", None)):
            raise TypeError("repository must implement append_precedent_retrieval")
        self._repository = repository

    def commit(
        self,
        outcome: HearingPrecedentRetrievalOutcome,
    ) -> HearingPrecedentRetrievalReceipt:
        if not isinstance(outcome, HearingPrecedentRetrievalOutcome):
            raise TypeError("outcome must be a HearingPrecedentRetrievalOutcome")
        try:
            validated = HearingPrecedentRetrievalOutcome.model_validate(
                outcome.model_dump(mode="json")
            )
        except (TypeError, ValueError) as exc:
            raise ContractViolation("precedent retrieval outcome is not canonical") from exc
        self._repository.append_precedent_retrieval(
            validated.query.run_id,
            validated.receipt,
        )
        return validated.receipt


__all__ = ["AppendOnlyHearingPrecedentOutcomeCommitter"]
