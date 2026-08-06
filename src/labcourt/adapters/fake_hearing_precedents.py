"""Controlled offline M4 precedent retriever with injected deterministic scores."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import Field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import PrecedentStatus
from labcourt.contracts.hearing_retrieval import (
    MAX_HEARING_PRECEDENT_CANDIDATES,
    MAX_HEARING_PRECEDENT_FUSED_SCORE,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalResult,
)
from labcourt.contracts.hearing_state import HearingPrecedentDegradedReason
from labcourt.contracts.precedents import Precedent, ScoredPrecedent
from labcourt.contracts.references import require_reference_token
from labcourt.ports.hearing_precedents import (
    HearingPrecedentRetrievalUnavailable,
)


class FakeHearingPrecedentFixture(FrozenContractModel):
    """One exact-query fixture; success scores every candidate surviving the filter."""

    query: HearingPrecedentRetrievalQuery
    candidate_precedents: tuple[Precedent, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PRECEDENT_CANDIDATES,
    )
    scored_precedents: tuple[ScoredPrecedent, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PRECEDENT_CANDIDATES,
    )
    unavailable_reason: HearingPrecedentDegradedReason | None = None

    @model_validator(mode="after")
    def validate_fixture(self) -> FakeHearingPrecedentFixture:
        if self.unavailable_reason is not None:
            if self.candidate_precedents or self.scored_precedents:
                raise ValueError("unavailable fake fixture cannot expose partial candidates")
            return self

        candidate_ids = tuple(item.precedent_id for item in self.candidate_precedents)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("fake precedent candidates contain a duplicate precedent ID")
        for precedent_id in candidate_ids:
            require_reference_token(precedent_id, "fake precedent candidate ID")

        scored_ids = tuple(scored.precedent.precedent_id for scored in self.scored_precedents)
        if len(scored_ids) != len(set(scored_ids)):
            raise ValueError("fake scored precedents contain a duplicate precedent ID")
        for scored in self.scored_precedents:
            try:
                revalidated = ScoredPrecedent.model_validate(scored.model_dump(mode="json"))
            except (TypeError, ValueError):
                raise ValueError("fake scored precedent violates its strict score bounds") from None
            if revalidated != scored:
                raise ValueError("fake scored precedent changes during strict revalidation")
        if any(
            scored.fused_score > MAX_HEARING_PRECEDENT_FUSED_SCORE
            for scored in self.scored_precedents
        ):
            raise ValueError("fake scored precedent exceeds the bounded fused score")

        candidate_by_id = {item.precedent_id: item for item in self.candidate_precedents}
        query = self.query
        for scored in self.scored_precedents:
            precedent = scored.precedent
            if candidate_by_id.get(precedent.precedent_id) != precedent:
                raise ValueError("fake score does not bind the exact candidate document")
            if (
                precedent.status != PrecedentStatus.ACTIVE
                or precedent.evidence_class != query.evidence_class
                or precedent.violation_type != query.violation_type
                or precedent.rule_version != query.rule_version
            ):
                raise ValueError("fake scored precedent bypasses the exact active-scope filter")

        eligible_ids = {
            item.precedent_id
            for item in self.candidate_precedents
            if item.status == PrecedentStatus.ACTIVE
            and item.evidence_class == query.evidence_class
            and item.violation_type == query.violation_type
            and item.rule_version == query.rule_version
        }
        if set(scored_ids) != eligible_ids:
            raise ValueError("fake fixture must score every and only filtered candidate")
        return self


class FakeHearingPrecedentRetriever:
    """Exact-query fake that filters first, then stably ranks and truncates."""

    def __init__(self, fixtures: Iterable[FakeHearingPrecedentFixture]) -> None:
        indexed: dict[str, FakeHearingPrecedentFixture] = {}
        for fixture in fixtures:
            if not isinstance(fixture, FakeHearingPrecedentFixture):
                raise TypeError("fixtures must contain FakeHearingPrecedentFixture values")
            query_id = fixture.query.query_id
            if query_id in indexed:
                raise ValueError("fake precedent fixtures contain a duplicate query ID")
            indexed[query_id] = fixture
        self._fixtures = indexed

    def retrieve(
        self,
        query: HearingPrecedentRetrievalQuery,
    ) -> HearingPrecedentRetrievalResult:
        if not isinstance(query, HearingPrecedentRetrievalQuery):
            raise TypeError("query must be a HearingPrecedentRetrievalQuery")
        fixture = self._fixtures.get(query.query_id)
        if fixture is None or fixture.query != query:
            raise HearingPrecedentRetrievalUnavailable(
                HearingPrecedentDegradedReason.PRECEDENT_INDEX_UNAVAILABLE
            )
        if fixture.unavailable_reason is not None:
            raise HearingPrecedentRetrievalUnavailable(fixture.unavailable_reason)

        candidates = tuple(
            sorted(
                fixture.candidate_precedents,
                key=lambda item: item.precedent_id,
            )
        )
        eligible_candidates = tuple(
            item
            for item in candidates
            if item.status == PrecedentStatus.ACTIVE
            and item.evidence_class == query.evidence_class
            and item.violation_type == query.violation_type
            and item.rule_version == query.rule_version
        )
        score_by_id = {item.precedent.precedent_id: item for item in fixture.scored_precedents}
        ranked = tuple(
            sorted(
                (score_by_id[item.precedent_id] for item in eligible_candidates),
                key=lambda item: (-item.fused_score, item.precedent.precedent_id),
            )[: query.top_k]
        )
        visible = tuple(
            sorted(
                (item.precedent for item in ranked),
                key=lambda item: item.precedent_id,
            )
        )
        return HearingPrecedentRetrievalResult(
            query=query,
            candidate_precedents=candidates,
            visible_precedents=visible,
            scored_precedents=ranked,
        )


__all__ = ["FakeHearingPrecedentFixture", "FakeHearingPrecedentRetriever"]
