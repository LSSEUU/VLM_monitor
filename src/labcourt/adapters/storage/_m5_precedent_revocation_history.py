"""Pure historical replay for one committed M5 precedent revocation."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn

from labcourt.application.m5_precedents import revoke_m5_precedent
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
)
from labcourt.contracts.m5_precedents import (
    M5PrecedentAuthority,
    M5PrecedentCitationAuthority,
    M5PrecedentCitationSnapshot,
    M5PrecedentRevocationOutcome,
    M5PrecedentRevocationReceipt,
    M5PrecedentRevocationResult,
)


class M5PrecedentRevocationHistoryErrorCode(StrEnum):
    """Stable failure classes shared by online replay and readonly validation."""

    AUTHORITY_INVENTORY_INVALID = "AUTHORITY_INVENTORY_INVALID"
    CITATION_INVENTORY_INVALID = "CITATION_INVENTORY_INVALID"
    CAUSAL_EVENT_INVENTORY_INVALID = "CAUSAL_EVENT_INVENTORY_INVALID"
    RECEIPT_CLOSURE_INVALID = "RECEIPT_CLOSURE_INVALID"
    COMMIT_MARKER_INVALID = "COMMIT_MARKER_INVALID"
    CAUSAL_INTERVAL_INVALID = "CAUSAL_INTERVAL_INVALID"
    RESULT_AUTHORITY_INVALID = "RESULT_AUTHORITY_INVALID"
    CITATION_SNAPSHOT_INVALID = "CITATION_SNAPSHOT_INVALID"
    REVOCATION_REPLAY_MISMATCH = "REVOCATION_REPLAY_MISMATCH"


class M5PrecedentRevocationHistoryError(RuntimeError):
    """Typed rejection of an internally inconsistent historical revocation."""

    def __init__(self, code: M5PrecedentRevocationHistoryErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def _fail(code: M5PrecedentRevocationHistoryErrorCode) -> NoReturn:
    raise M5PrecedentRevocationHistoryError(code)


def _require_inputs(
    *,
    authorities: tuple[M5PrecedentAuthority, ...],
    citations: tuple[M5PrecedentCitationAuthority, ...],
    causal_events: tuple[M5PrecedentCausalEvent, ...],
    receipt: M5PrecedentRevocationReceipt,
    citation_snapshot: M5PrecedentCitationSnapshot,
) -> None:
    if not isinstance(authorities, tuple) or any(
        not isinstance(item, M5PrecedentAuthority) for item in authorities
    ):
        raise TypeError("authorities must be a tuple of M5PrecedentAuthority values")
    if not isinstance(citations, tuple) or any(
        not isinstance(item, M5PrecedentCitationAuthority) for item in citations
    ):
        raise TypeError("citations must be a tuple of M5PrecedentCitationAuthority values")
    if not isinstance(causal_events, tuple) or any(
        not isinstance(item, M5PrecedentCausalEvent) for item in causal_events
    ):
        raise TypeError("causal_events must be a tuple of M5PrecedentCausalEvent values")
    if not isinstance(receipt, M5PrecedentRevocationReceipt):
        raise TypeError("receipt must be an M5PrecedentRevocationReceipt")
    if not isinstance(citation_snapshot, M5PrecedentCitationSnapshot):
        raise TypeError("citation_snapshot must be an M5PrecedentCitationSnapshot")


def rebuild_m5_precedent_revocation_history(
    *,
    authorities: tuple[M5PrecedentAuthority, ...],
    citations: tuple[M5PrecedentCitationAuthority, ...],
    causal_events: tuple[M5PrecedentCausalEvent, ...],
    receipt: M5PrecedentRevocationReceipt,
    citation_snapshot: M5PrecedentCitationSnapshot,
) -> M5PrecedentRevocationResult:
    """Rebuild one revocation solely from immutable authority/event history.

    The inventories must be complete for one run and their raw documents must
    already have passed storage-level parsing and index checks. This function
    independently closes each authority and citation to exactly one causal
    event, derives the pre-effect cutoff from the revocation marker, and ignores
    all later events when rebuilding the citation snapshot.
    """

    _require_inputs(
        authorities=authorities,
        citations=citations,
        causal_events=causal_events,
        receipt=receipt,
        citation_snapshot=citation_snapshot,
    )
    run_id = receipt.run_id
    if (
        citation_snapshot.run_id != run_id
        or citation_snapshot.precedent_id != receipt.precedent_id
        or citation_snapshot.snapshot_id != receipt.citation_snapshot_id
        or citation_snapshot.captured_at != receipt.revoked_at
    ):
        _fail(M5PrecedentRevocationHistoryErrorCode.RECEIPT_CLOSURE_INVALID)

    authority_by_revision: dict[tuple[str, int], M5PrecedentAuthority] = {}
    authority_by_id: dict[str, M5PrecedentAuthority] = {}
    for authority in authorities:
        key = (authority.precedent.precedent_id, authority.revision)
        if (
            authority.run_id != run_id
            or key in authority_by_revision
            or authority.authority_id in authority_by_id
        ):
            _fail(M5PrecedentRevocationHistoryErrorCode.AUTHORITY_INVENTORY_INVALID)
        authority_by_revision[key] = authority
        authority_by_id[authority.authority_id] = authority

    citation_by_id: dict[str, M5PrecedentCitationAuthority] = {}
    for citation in citations:
        if citation.run_id != run_id or citation.citation_id in citation_by_id:
            _fail(M5PrecedentRevocationHistoryErrorCode.CITATION_INVENTORY_INVALID)
        citation_by_id[citation.citation_id] = citation

    authority_event_by_id: dict[str, M5PrecedentCausalEvent] = {}
    citation_event_by_id: dict[str, M5PrecedentCausalEvent] = {}
    event_by_sequence: dict[int, M5PrecedentCausalEvent] = {}
    last_authority_revision: dict[str, int] = {}
    previous_event_sha256 = M5_PRECEDENT_CAUSAL_GENESIS_SHA256
    manifest_id: str | None = None
    for expected_sequence, event in enumerate(causal_events, start=1):
        if (
            event.run_id != run_id
            or event.sequence != expected_sequence
            or event.previous_event_sha256 != previous_event_sha256
            or (manifest_id is not None and event.manifest_id != manifest_id)
        ):
            _fail(M5PrecedentRevocationHistoryErrorCode.CAUSAL_EVENT_INVENTORY_INVALID)
        if manifest_id is None:
            manifest_id = event.manifest_id
        event_by_sequence[event.sequence] = event

        if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED:
            matched_authority = authority_by_id.get(event.source_id)
            precedent_id = event.precedent_id
            revision = event.precedent_revision
            if (
                matched_authority is None
                or precedent_id is None
                or revision is None
                or event.source_id in authority_event_by_id
                or matched_authority.precedent.precedent_id != precedent_id
                or matched_authority.authority_id != event.precedent_authority_id
                or matched_authority.revision != revision
                or revision != last_authority_revision.get(precedent_id, 0) + 1
            ):
                _fail(M5PrecedentRevocationHistoryErrorCode.AUTHORITY_INVENTORY_INVALID)
            authority_event_by_id[event.source_id] = event
            last_authority_revision[precedent_id] = revision
        elif event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED:
            matched_citation = citation_by_id.get(event.source_id)
            referenced_authority_event = (
                None
                if matched_citation is None
                else authority_event_by_id.get(matched_citation.precedent_authority_id)
            )
            if (
                matched_citation is None
                or event.source_id in citation_event_by_id
                or matched_citation.precedent_id != event.precedent_id
                or matched_citation.precedent_authority_id != event.precedent_authority_id
                or matched_citation.precedent_revision != event.precedent_revision
                or referenced_authority_event is None
                or referenced_authority_event.precedent_id != matched_citation.precedent_id
                or referenced_authority_event.precedent_revision
                != matched_citation.precedent_revision
                or referenced_authority_event.sequence >= event.sequence
            ):
                _fail(M5PrecedentRevocationHistoryErrorCode.CITATION_INVENTORY_INVALID)
            citation_event_by_id[event.source_id] = event
        previous_event_sha256 = event.event_sha256

    if set(authority_event_by_id) != set(authority_by_id):
        _fail(M5PrecedentRevocationHistoryErrorCode.AUTHORITY_INVENTORY_INVALID)
    if set(citation_event_by_id) != set(citation_by_id):
        _fail(M5PrecedentRevocationHistoryErrorCode.CITATION_INVENTORY_INVALID)

    prior_authority = authority_by_revision.get((receipt.precedent_id, receipt.prior_revision))
    resulting_authority = authority_by_revision.get(
        (receipt.precedent_id, receipt.resulting_revision)
    )
    if (
        prior_authority is None
        or prior_authority.authority_id != receipt.prior_authority_id
        or resulting_authority is None
        or resulting_authority.authority_id != receipt.resulting_authority_id
    ):
        _fail(M5PrecedentRevocationHistoryErrorCode.RESULT_AUTHORITY_INVALID)

    markers = tuple(
        event
        for event in causal_events
        if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED
        and event.source_id == receipt.receipt_id
    )
    if len(markers) != 1:
        _fail(M5PrecedentRevocationHistoryErrorCode.COMMIT_MARKER_INVALID)
    marker = markers[0]
    receipt_json = canonical_json(receipt.model_dump(mode="json"))
    receipt_document_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
    if (
        marker.precedent_id != receipt.precedent_id
        or marker.precedent_authority_id != receipt.resulting_authority_id
        or marker.precedent_revision != receipt.resulting_revision
        or marker.source_document_sha256 != receipt_document_sha256
    ):
        _fail(M5PrecedentRevocationHistoryErrorCode.COMMIT_MARKER_INVALID)

    prior_event = authority_event_by_id[prior_authority.authority_id]
    resulting_event = authority_event_by_id[resulting_authority.authority_id]
    if receipt.outcome == M5PrecedentRevocationOutcome.REVOKED:
        preceding = event_by_sequence.get(marker.sequence - 1)
        if preceding != resulting_event:
            _fail(M5PrecedentRevocationHistoryErrorCode.CAUSAL_INTERVAL_INVALID)
        cutoff_sequence = marker.sequence - 2
    else:
        if resulting_authority != prior_authority or resulting_event != prior_event:
            _fail(M5PrecedentRevocationHistoryErrorCode.RESULT_AUTHORITY_INVALID)
        cutoff_sequence = marker.sequence - 1

    target_head_event: M5PrecedentCausalEvent | None = None
    for event in causal_events:
        if event.sequence > cutoff_sequence:
            break
        if (
            event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
            and event.precedent_id == receipt.precedent_id
        ):
            target_head_event = event
    if target_head_event != prior_event:
        _fail(M5PrecedentRevocationHistoryErrorCode.CAUSAL_INTERVAL_INVALID)

    historical_citations = tuple(
        sorted(
            (
                citation_by_id[event.source_id]
                for event in causal_events
                if event.sequence <= cutoff_sequence
                and event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED
                and event.precedent_id == receipt.precedent_id
            ),
            key=lambda citation: (citation.case_id, citation.citation_id),
        )
    )
    try:
        rebuilt_snapshot = M5PrecedentCitationSnapshot(
            run_id=run_id,
            precedent_id=receipt.precedent_id,
            captured_at=receipt.revoked_at,
            citations=historical_citations,
        )
    except (TypeError, ValueError) as exc:
        raise M5PrecedentRevocationHistoryError(
            M5PrecedentRevocationHistoryErrorCode.CITATION_SNAPSHOT_INVALID
        ) from exc
    if rebuilt_snapshot != citation_snapshot:
        _fail(M5PrecedentRevocationHistoryErrorCode.CITATION_SNAPSHOT_INVALID)

    try:
        rebuilt = revoke_m5_precedent(
            authority=prior_authority,
            citation_snapshot=rebuilt_snapshot,
            revoked_by_ref=receipt.revoked_by_ref,
            revoked_at=receipt.revoked_at,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise M5PrecedentRevocationHistoryError(
            M5PrecedentRevocationHistoryErrorCode.REVOCATION_REPLAY_MISMATCH
        ) from exc
    if (
        rebuilt.receipt != receipt
        or rebuilt.authority != resulting_authority
        or rebuilt.citation_snapshot != citation_snapshot
    ):
        _fail(M5PrecedentRevocationHistoryErrorCode.REVOCATION_REPLAY_MISMATCH)
    return rebuilt


__all__ = [
    "M5PrecedentRevocationHistoryError",
    "M5PrecedentRevocationHistoryErrorCode",
    "rebuild_m5_precedent_revocation_history",
]
