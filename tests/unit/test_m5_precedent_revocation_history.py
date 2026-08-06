from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from labcourt.adapters.storage._m5_precedent_revocation_history import (
    M5PrecedentRevocationHistoryError,
    M5PrecedentRevocationHistoryErrorCode,
    rebuild_m5_precedent_revocation_history,
)
from labcourt.application.m5_precedents import (
    create_m5_precedent_authority,
    revoke_m5_precedent,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
    M5PrecedentCausalEventSourceKind,
)
from labcourt.contracts.m5_precedents import (
    M5PrecedentAuthority,
    M5PrecedentCitationAuthority,
    M5PrecedentCitationSnapshot,
    M5PrecedentPolicy,
    M5PrecedentRevocationReceipt,
    M5PrecedentRevocationResult,
)

NOW = datetime(2026, 8, 3, 8, tzinfo=UTC)
RUN_ID = "run-revocation-history"
PRECEDENT_ID = "precedent-revocation-history"
MANIFEST_ID = "a" * 64
CONFIG_SHA256 = "b" * 64
REVOCATION_REF = "appeal-revocation-history"


@dataclass(frozen=True)
class _RevokedFacts:
    prior: M5PrecedentAuthority
    early: M5PrecedentCitationAuthority
    late: M5PrecedentCitationAuthority
    result: M5PrecedentRevocationResult


def _policy() -> M5PrecedentPolicy:
    return M5PrecedentPolicy(
        config_sha256=CONFIG_SHA256,
        text_weight=0.7,
        visual_weight=0.3,
        source_weights={
            PrecedentSource.PRESET: 1.0,
            PrecedentSource.AUTOMATIC: 0.75,
            PrecedentSource.HUMAN_REVIEW: 1.1,
            PrecedentSource.APPEAL_OVERTURN: 1.25,
        },
        source_priorities={
            PrecedentSource.AUTOMATIC: 100,
            PrecedentSource.PRESET: 200,
            PrecedentSource.HUMAN_REVIEW: 300,
            PrecedentSource.APPEAL_OVERTURN: 400,
        },
        conflict_similarity=0.8,
        automatic_activation_delay_seconds=3_600,
    )


def _authority(precedent_id: str = PRECEDENT_ID) -> M5PrecedentAuthority:
    return create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id=precedent_id,
        situation_text=f"Situation for {precedent_id}.",
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.OPEN_FLAME,
        rule_version="rules-v1",
        source_case_id=None,
        created_at=NOW,
        policy=_policy(),
    )


def _citation(
    authority: M5PrecedentAuthority,
    *,
    case_id: str,
    cited_at: datetime,
    query_digit: str,
) -> M5PrecedentCitationAuthority:
    return M5PrecedentCitationAuthority(
        run_id=RUN_ID,
        case_id=case_id,
        precedent_id=authority.precedent.precedent_id,
        precedent_authority_id=authority.authority_id,
        precedent_revision=authority.revision,
        query_id=query_digit * 64,
        score=0.9,
        cited_at=cited_at,
    )


def _receipt_document_sha256(receipt: M5PrecedentRevocationReceipt) -> str:
    raw = canonical_json(receipt.model_dump(mode="json"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _append_event(
    events: list[M5PrecedentCausalEvent],
    *,
    kind: M5PrecedentCausalEventKind,
    source_id: str,
    precedent_id: str | None,
    precedent_authority_id: str | None,
    precedent_revision: int | None,
    source_document_sha256: str = "c" * 64,
) -> M5PrecedentCausalEvent:
    event = M5PrecedentCausalEvent(
        run_id=RUN_ID,
        sequence=len(events) + 1,
        event_kind=kind,
        source_id=source_id,
        precedent_id=precedent_id,
        precedent_authority_id=precedent_authority_id,
        precedent_revision=precedent_revision,
        citation_kind=(
            M5PrecedentCausalEventSourceKind.DIRECT
            if kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED
            else None
        ),
        manifest_id=MANIFEST_ID,
        source_document_sha256=source_document_sha256,
        previous_event_sha256=(
            events[-1].event_sha256 if events else M5_PRECEDENT_CAUSAL_GENESIS_SHA256
        ),
    )
    events.append(event)
    return event


def _append_authority(
    events: list[M5PrecedentCausalEvent],
    authority: M5PrecedentAuthority,
) -> None:
    _append_event(
        events,
        kind=M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
        source_id=authority.authority_id,
        precedent_id=authority.precedent.precedent_id,
        precedent_authority_id=authority.authority_id,
        precedent_revision=authority.revision,
    )


def _append_citation(
    events: list[M5PrecedentCausalEvent],
    citation: M5PrecedentCitationAuthority,
) -> None:
    _append_event(
        events,
        kind=M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
        source_id=citation.citation_id,
        precedent_id=citation.precedent_id,
        precedent_authority_id=citation.precedent_authority_id,
        precedent_revision=citation.precedent_revision,
    )


def _append_revocation_marker(
    events: list[M5PrecedentCausalEvent],
    receipt: M5PrecedentRevocationReceipt,
    *,
    source_document_sha256: str | None = None,
) -> None:
    _append_event(
        events,
        kind=M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED,
        source_id=receipt.receipt_id,
        precedent_id=receipt.precedent_id,
        precedent_authority_id=receipt.resulting_authority_id,
        precedent_revision=receipt.resulting_revision,
        source_document_sha256=(source_document_sha256 or _receipt_document_sha256(receipt)),
    )


def _revoked_facts(
    *,
    snapshot_citations: tuple[M5PrecedentCitationAuthority, ...] | None = None,
) -> _RevokedFacts:
    prior = _authority()
    early = _citation(
        prior,
        case_id="case-before-cutoff",
        cited_at=NOW + timedelta(minutes=1),
        query_digit="1",
    )
    # Its semantic time is before revocation, but its causal append is after the marker.
    late = _citation(
        prior,
        case_id="case-after-cutoff",
        cited_at=NOW + timedelta(minutes=1),
        query_digit="2",
    )
    revoked_at = NOW + timedelta(minutes=2)
    claimed = (early,) if snapshot_citations is None else snapshot_citations
    snapshot = M5PrecedentCitationSnapshot(
        run_id=RUN_ID,
        precedent_id=PRECEDENT_ID,
        captured_at=revoked_at,
        citations=tuple(sorted(claimed, key=lambda item: (item.case_id, item.citation_id))),
    )
    result = revoke_m5_precedent(
        authority=prior,
        citation_snapshot=snapshot,
        revoked_by_ref=REVOCATION_REF,
        revoked_at=revoked_at,
    )
    return _RevokedFacts(prior=prior, early=early, late=late, result=result)


def _revoked_events(
    facts: _RevokedFacts,
    *,
    marker_receipt: M5PrecedentRevocationReceipt | None = None,
    marker_document_sha256: str | None = None,
    interloper: M5PrecedentAuthority | None = None,
    marker_count: int = 1,
) -> tuple[M5PrecedentCausalEvent, ...]:
    events: list[M5PrecedentCausalEvent] = []
    _append_authority(events, facts.prior)
    _append_citation(events, facts.early)
    _append_authority(events, facts.result.authority)
    if interloper is not None:
        _append_authority(events, interloper)
    receipt = marker_receipt or facts.result.receipt
    for _ in range(marker_count):
        _append_revocation_marker(
            events,
            receipt,
            source_document_sha256=marker_document_sha256,
        )
    _append_citation(events, facts.late)
    return tuple(events)


def _assert_history_error(
    code: M5PrecedentRevocationHistoryErrorCode,
    *,
    authorities: tuple[M5PrecedentAuthority, ...],
    citations: tuple[M5PrecedentCitationAuthority, ...],
    causal_events: tuple[M5PrecedentCausalEvent, ...],
    result: M5PrecedentRevocationResult,
) -> None:
    with pytest.raises(M5PrecedentRevocationHistoryError) as captured:
        rebuild_m5_precedent_revocation_history(
            authorities=authorities,
            citations=citations,
            causal_events=causal_events,
            receipt=result.receipt,
            citation_snapshot=result.citation_snapshot,
        )
    assert captured.value.code == code


def test_rebuild_revoked_history_uses_marker_cutoff_not_citation_time() -> None:
    facts = _revoked_facts()

    rebuilt = rebuild_m5_precedent_revocation_history(
        authorities=(facts.result.authority, facts.prior),
        citations=(facts.late, facts.early),
        causal_events=_revoked_events(facts),
        receipt=facts.result.receipt,
        citation_snapshot=facts.result.citation_snapshot,
    )

    assert rebuilt == facts.result
    assert rebuilt.citation_snapshot.citations == (facts.early,)
    assert facts.late.cited_at <= facts.result.receipt.revoked_at


def test_rebuild_already_revoked_history_has_no_result_authority_event() -> None:
    first = _revoked_facts()
    between = _citation(
        first.prior,
        case_id="case-between-revocations",
        cited_at=NOW + timedelta(minutes=3),
        query_digit="3",
    )
    second_time = NOW + timedelta(minutes=4)
    second_snapshot = M5PrecedentCitationSnapshot(
        run_id=RUN_ID,
        precedent_id=PRECEDENT_ID,
        captured_at=second_time,
        citations=tuple(
            sorted((first.early, between), key=lambda item: (item.case_id, item.citation_id))
        ),
    )
    already = revoke_m5_precedent(
        authority=first.result.authority,
        citation_snapshot=second_snapshot,
        revoked_by_ref=REVOCATION_REF,
        revoked_at=second_time,
    )
    events: list[M5PrecedentCausalEvent] = []
    _append_authority(events, first.prior)
    _append_citation(events, first.early)
    _append_authority(events, first.result.authority)
    _append_revocation_marker(events, first.result.receipt)
    _append_citation(events, between)
    _append_revocation_marker(events, already.receipt)

    rebuilt = rebuild_m5_precedent_revocation_history(
        authorities=(first.prior, first.result.authority),
        citations=(first.early, between),
        causal_events=tuple(events),
        receipt=already.receipt,
        citation_snapshot=already.citation_snapshot,
    )

    assert rebuilt == already
    assert events[-1].event_kind == M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED
    assert events[-2].event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED


@pytest.mark.parametrize("claim", ["omit_pre_cut", "include_post_cut"])
def test_rebuild_rejects_snapshot_that_differs_from_causal_cutoff(claim: str) -> None:
    base = _revoked_facts()
    claimed = () if claim == "omit_pre_cut" else (base.early, base.late)
    attacked = _revoked_facts(snapshot_citations=claimed)
    events = _revoked_events(
        base,
        marker_receipt=attacked.result.receipt,
    )

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.CITATION_SNAPSHOT_INVALID,
        authorities=(base.prior, base.result.authority),
        citations=(base.early, base.late),
        causal_events=events,
        result=attacked.result,
    )


def test_rebuild_rejects_non_adjacent_revoked_result_and_marker() -> None:
    facts = _revoked_facts()
    interloper = _authority("precedent-unrelated")

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.CAUSAL_INTERVAL_INVALID,
        authorities=(facts.prior, facts.result.authority, interloper),
        citations=(facts.early, facts.late),
        causal_events=_revoked_events(facts, interloper=interloper),
        result=facts.result,
    )


def test_rebuild_rejects_already_revoked_when_prior_is_not_head_at_cutoff() -> None:
    first = _revoked_facts()
    second_time = NOW + timedelta(minutes=4)
    second_snapshot = M5PrecedentCitationSnapshot(
        run_id=RUN_ID,
        precedent_id=PRECEDENT_ID,
        captured_at=second_time,
        citations=(first.early,),
    )
    already = revoke_m5_precedent(
        authority=first.result.authority,
        citation_snapshot=second_snapshot,
        revoked_by_ref=REVOCATION_REF,
        revoked_at=second_time,
    )
    later_authority = first.result.authority.model_copy(update={"revision": 3})
    events: list[M5PrecedentCausalEvent] = []
    _append_authority(events, first.prior)
    _append_citation(events, first.early)
    _append_authority(events, first.result.authority)
    _append_revocation_marker(events, first.result.receipt)
    _append_authority(events, later_authority)
    _append_revocation_marker(events, already.receipt)

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.CAUSAL_INTERVAL_INVALID,
        authorities=(first.prior, first.result.authority, later_authority),
        citations=(first.early,),
        causal_events=tuple(events),
        result=already,
    )


@pytest.mark.parametrize("marker_count", [0, 2])
def test_rebuild_rejects_missing_or_duplicate_marker(marker_count: int) -> None:
    facts = _revoked_facts()

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.COMMIT_MARKER_INVALID,
        authorities=(facts.prior, facts.result.authority),
        citations=(facts.early, facts.late),
        causal_events=_revoked_events(facts, marker_count=marker_count),
        result=facts.result,
    )


def test_rebuild_rejects_marker_with_wrong_receipt_document_hash() -> None:
    facts = _revoked_facts()

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.COMMIT_MARKER_INVALID,
        authorities=(facts.prior, facts.result.authority),
        citations=(facts.early, facts.late),
        causal_events=_revoked_events(facts, marker_document_sha256="f" * 64),
        result=facts.result,
    )


def test_rebuild_requires_complete_citation_source_event_inventory() -> None:
    facts = _revoked_facts()

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.CITATION_INVENTORY_INVALID,
        authorities=(facts.prior, facts.result.authority),
        citations=(facts.early,),
        causal_events=_revoked_events(facts),
        result=facts.result,
    )


def test_rebuild_rejects_citation_that_misstates_its_authority_revision() -> None:
    facts = _revoked_facts()
    forged_citation = facts.early.model_copy(update={"precedent_revision": 2})
    events: list[M5PrecedentCausalEvent] = []
    _append_authority(events, facts.prior)
    _append_citation(events, forged_citation)
    _append_authority(events, facts.result.authority)
    _append_revocation_marker(events, facts.result.receipt)
    _append_citation(events, facts.late)

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.CITATION_INVENTORY_INVALID,
        authorities=(facts.prior, facts.result.authority),
        citations=(forged_citation, facts.late),
        causal_events=tuple(events),
        result=facts.result,
    )


def test_rebuild_rejects_broken_causal_hash_chain() -> None:
    facts = _revoked_facts()
    events = list(_revoked_events(facts))
    events[1] = events[1].model_copy(update={"previous_event_sha256": "d" * 64})

    _assert_history_error(
        M5PrecedentRevocationHistoryErrorCode.CAUSAL_EVENT_INVENTORY_INVALID,
        authorities=(facts.prior, facts.result.authority),
        citations=(facts.early, facts.late),
        causal_events=tuple(events),
        result=facts.result,
    )
