"""Atomic append and strict replay helpers for M5 precedent causal events."""

from __future__ import annotations

import hashlib
import sqlite3
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_appeals import M5AppealResolutionCommitReceipt
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
    M5PrecedentCausalEventSourceKind,
)
from labcourt.contracts.m5_precedent_usage import M5PrecedentApplicationCitationCommit
from labcourt.contracts.m5_precedents import (
    M5PrecedentAuthority,
    M5PrecedentCitationAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentRevocationOutcome,
    M5PrecedentRevocationReceipt,
)

from ._m5_precedent_revocation_history import (
    M5PrecedentRevocationHistoryError,
    rebuild_m5_precedent_revocation_history,
)
from .sqlite_repository import (
    RepositoryIntegrityError,
    _contract_document,
    _row_int,
    _row_optional_int,
    _row_optional_str,
    _row_str,
    _verify_contract_document,
)


@dataclass(frozen=True, slots=True)
class M5PrecedentCausalSource:
    """Exact canonical source fields duplicated into one causal event."""

    run_id: str
    event_kind: M5PrecedentCausalEventKind
    source_id: str
    precedent_id: str | None
    precedent_authority_id: str | None
    precedent_revision: int | None
    citation_kind: M5PrecedentCausalEventSourceKind | None
    manifest_id: str
    source_document_sha256: str


def m5_precedent_authority_causal_source(
    authority: M5PrecedentAuthority,
    *,
    manifest_id: str,
    source_document_sha256: str,
) -> M5PrecedentCausalSource:
    return M5PrecedentCausalSource(
        run_id=authority.run_id,
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
        source_id=authority.authority_id,
        precedent_id=authority.precedent.precedent_id,
        precedent_authority_id=authority.authority_id,
        precedent_revision=authority.revision,
        citation_kind=None,
        manifest_id=manifest_id,
        source_document_sha256=source_document_sha256,
    )


def m5_precedent_citation_causal_source(
    citation: M5PrecedentCitationAuthority,
    *,
    citation_kind: M5PrecedentCausalEventSourceKind,
    manifest_id: str,
    source_document_sha256: str,
) -> M5PrecedentCausalSource:
    return M5PrecedentCausalSource(
        run_id=citation.run_id,
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
        source_id=citation.citation_id,
        precedent_id=citation.precedent_id,
        precedent_authority_id=citation.precedent_authority_id,
        precedent_revision=citation.precedent_revision,
        citation_kind=citation_kind,
        manifest_id=manifest_id,
        source_document_sha256=source_document_sha256,
    )


def m5_precedent_conflict_receipt_causal_source(
    receipt: M5PrecedentConflictBatchReceipt,
    *,
    manifest_id: str,
    source_document_sha256: str,
) -> M5PrecedentCausalSource:
    return M5PrecedentCausalSource(
        run_id=receipt.run_id,
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED,
        source_id=receipt.receipt_id,
        precedent_id=None,
        precedent_authority_id=None,
        precedent_revision=None,
        citation_kind=None,
        manifest_id=manifest_id,
        source_document_sha256=source_document_sha256,
    )


def m5_precedent_revocation_receipt_causal_source(
    receipt: M5PrecedentRevocationReceipt,
    *,
    manifest_id: str,
    source_document_sha256: str,
) -> M5PrecedentCausalSource:
    return M5PrecedentCausalSource(
        run_id=receipt.run_id,
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED,
        source_id=receipt.receipt_id,
        precedent_id=receipt.precedent_id,
        precedent_authority_id=receipt.resulting_authority_id,
        precedent_revision=receipt.resulting_revision,
        citation_kind=None,
        manifest_id=manifest_id,
        source_document_sha256=source_document_sha256,
    )


def m5_appeal_resolution_commit_causal_source(
    receipt: M5AppealResolutionCommitReceipt,
    *,
    source_document_sha256: str,
) -> M5PrecedentCausalSource:
    return M5PrecedentCausalSource(
        run_id=receipt.run_id,
        event_kind=M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED,
        source_id=receipt.receipt_id,
        precedent_id=None,
        precedent_authority_id=None,
        precedent_revision=None,
        citation_kind=None,
        manifest_id=receipt.manifest_id,
        source_document_sha256=source_document_sha256,
    )


def append_m5_precedent_causal_event(
    connection: sqlite3.Connection,
    *,
    source: M5PrecedentCausalSource,
    insert_source: Callable[[], None],
    fault_scope: str,
    fault: Callable[[str], None],
) -> M5PrecedentCausalEvent:
    """Validate, insert one source, and append its event as one transaction step."""

    if not isinstance(fault_scope, str) or not fault_scope:
        raise TypeError("M5 precedent causal fault scope must be a non-empty string")
    if not connection.in_transaction:
        raise RepositoryIntegrityError(
            "M5 precedent causal append requires a caller-owned transaction"
        )
    prior_events = _require_valid_causal_ledger(connection, source.run_id)
    if (
        _stored_source_count(connection, source) != 0
        or _stored_event_count(connection, source) != 0
    ):
        raise RepositoryIntegrityError("M5 precedent causal source already exists")
    insert_source()
    if not connection.in_transaction:
        raise RepositoryIntegrityError(
            "M5 precedent causal source callback ended the caller-owned transaction"
        )
    existing_events = _require_valid_causal_ledger(
        connection,
        source.run_id,
        pending_source=source,
    )
    if existing_events != prior_events:
        raise RepositoryIntegrityError(
            "M5 precedent causal source insert changed the prior event ledger"
        )
    if not existing_events:
        sequence = 1
        previous = M5_PRECEDENT_CAUSAL_GENESIS_SHA256
    else:
        tail = existing_events[-1]
        sequence = tail.sequence + 1
        previous = tail.event_sha256
    event = M5PrecedentCausalEvent(
        run_id=source.run_id,
        sequence=sequence,
        event_kind=source.event_kind,
        source_id=source.source_id,
        precedent_id=source.precedent_id,
        precedent_authority_id=source.precedent_authority_id,
        precedent_revision=source.precedent_revision,
        citation_kind=source.citation_kind,
        manifest_id=source.manifest_id,
        source_document_sha256=source.source_document_sha256,
        previous_event_sha256=previous,
    )
    event_json = _contract_document(event)
    fault(f"{fault_scope}.before_causal_event")
    try:
        connection.execute(
            """
            INSERT INTO m5_precedent_causal_events(
                run_id, sequence, event_id, source_identity_sha256,
                event_kind, source_id, precedent_id, precedent_authority_id,
                precedent_revision, citation_kind, manifest_id,
                source_document_sha256, previous_event_sha256, event_sha256,
                event_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.run_id,
                event.sequence,
                event.event_id,
                event.source_identity_sha256,
                event.event_kind.value,
                event.source_id,
                event.precedent_id,
                event.precedent_authority_id,
                event.precedent_revision,
                event.citation_kind.value if event.citation_kind is not None else None,
                event.manifest_id,
                event.source_document_sha256,
                event.previous_event_sha256,
                event.event_sha256,
                event_json,
                hashlib.sha256(event_json.encode("utf-8")).hexdigest(),
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise RepositoryIntegrityError("M5 precedent causal event could not be appended") from exc
    fault(f"{fault_scope}.after_causal_event")
    return require_m5_precedent_causal_event(connection, source=source)


def require_m5_precedent_causal_event(
    connection: sqlite3.Connection,
    *,
    source: M5PrecedentCausalSource,
) -> M5PrecedentCausalEvent:
    """Require exact replay evidence; a missing event is never repaired here."""

    events = _require_valid_causal_ledger(connection, source.run_id)
    matches = tuple(
        event
        for event in events
        if event.event_kind == source.event_kind and event.source_id == source.source_id
    )
    if len(matches) != 1:
        raise RepositoryIntegrityError("M5 precedent causal source does not have exactly one event")
    event = matches[0]
    expected = (
        source.run_id,
        source.event_kind,
        source.source_id,
        source.precedent_id,
        source.precedent_authority_id,
        source.precedent_revision,
        source.citation_kind,
        source.manifest_id,
        source.source_document_sha256,
    )
    actual = (
        event.run_id,
        event.event_kind,
        event.source_id,
        event.precedent_id,
        event.precedent_authority_id,
        event.precedent_revision,
        event.citation_kind,
        event.manifest_id,
        event.source_document_sha256,
    )
    if actual != expected:
        raise RepositoryIntegrityError("M5 precedent causal event differs from its source")
    return event


def load_m5_precedent_causal_events(
    connection: sqlite3.Connection,
    *,
    run_id: str,
) -> tuple[M5PrecedentCausalEvent, ...]:
    """Load a run only after full chain, ordering, and source replay succeeds."""

    return _require_valid_causal_ledger(connection, run_id)


def _event_from_row(
    row: sqlite3.Row,
) -> M5PrecedentCausalEvent:
    raw = _row_str(row, "event_json")
    try:
        event = M5PrecedentCausalEvent.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError("stored M5 precedent causal event is invalid") from exc
    _verify_contract_document(raw, event)
    citation_kind = event.citation_kind.value if event.citation_kind is not None else None
    indexed = (
        _row_str(row, "run_id") == event.run_id,
        _row_int(row, "sequence") == event.sequence,
        _row_str(row, "event_id") == event.event_id,
        _row_str(row, "source_identity_sha256") == event.source_identity_sha256,
        _row_str(row, "event_kind") == event.event_kind.value,
        _row_str(row, "source_id") == event.source_id,
        _row_optional_str(row, "precedent_id") == event.precedent_id,
        _row_optional_str(row, "precedent_authority_id") == event.precedent_authority_id,
        _row_optional_int(row, "precedent_revision") == event.precedent_revision,
        _row_optional_str(row, "citation_kind") == citation_kind,
        _row_str(row, "manifest_id") == event.manifest_id,
        _row_str(row, "source_document_sha256") == event.source_document_sha256,
        _row_str(row, "previous_event_sha256") == event.previous_event_sha256,
        _row_str(row, "event_sha256") == event.event_sha256,
        _row_str(row, "document_sha256") == hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        raw == canonical_json(event.model_dump(mode="json")),
    )
    if not all(indexed):
        raise RepositoryIntegrityError(
            "M5 precedent causal event indexes differ from canonical content"
        )
    return event


def _authority_source_from_row(
    row: sqlite3.Row,
) -> tuple[M5PrecedentCausalSource, M5PrecedentAuthority]:
    raw = _row_str(row, "authority_json")
    try:
        authority = M5PrecedentAuthority.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError(
            "stored M5 precedent causal authority source is invalid"
        ) from exc
    _verify_contract_document(raw, authority)
    precedent = authority.precedent
    document_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    indexed = (
        _row_str(row, "run_id") == authority.run_id,
        _row_str(row, "precedent_id") == precedent.precedent_id,
        _row_int(row, "revision") == authority.revision,
        _row_str(row, "authority_id") == authority.authority_id,
        _row_str(row, "document_sha256") == document_sha256,
    )
    if not all(indexed):
        raise RepositoryIntegrityError("M5 precedent causal authority source indexes are invalid")
    return (
        m5_precedent_authority_causal_source(
            authority,
            manifest_id=_row_str(row, "manifest_id"),
            source_document_sha256=document_sha256,
        ),
        authority,
    )


def _citation_source_from_row(
    row: sqlite3.Row,
) -> tuple[M5PrecedentCausalSource, M5PrecedentCitationAuthority]:
    commit_raw = _row_str(row, "commit_json")
    citation_raw = _row_str(row, "citation_json")
    citation_kind_raw = _row_str(row, "citation_kind")
    try:
        citation_kind = M5PrecedentCausalEventSourceKind(citation_kind_raw)
        commit: M5PrecedentCitationCommit | M5PrecedentApplicationCitationCommit
        if citation_kind == M5PrecedentCausalEventSourceKind.DIRECT:
            commit = M5PrecedentCitationCommit.model_validate_json(commit_raw)
        else:
            commit = M5PrecedentApplicationCitationCommit.model_validate_json(commit_raw)
        citation = M5PrecedentCitationAuthority.model_validate_json(citation_raw)
    except (ValidationError, ValueError) as exc:
        raise RepositoryIntegrityError(
            "stored M5 precedent causal citation source is invalid"
        ) from exc
    _verify_contract_document(commit_raw, commit)
    _verify_contract_document(citation_raw, citation)
    document_sha256 = hashlib.sha256(commit_raw.encode("utf-8")).hexdigest()
    indexed = (
        citation == commit.citation,
        _row_str(row, "run_id") == citation.run_id,
        _row_str(row, "citation_id") == citation.citation_id,
        _row_str(row, "commit_id") == commit.commit_id,
        _row_str(row, "precedent_id") == citation.precedent_id,
        _row_str(row, "precedent_authority_id") == citation.precedent_authority_id,
        _row_int(row, "precedent_revision") == citation.precedent_revision,
        _row_str(row, "document_sha256") == document_sha256,
    )
    if not all(indexed):
        raise RepositoryIntegrityError("M5 precedent causal citation source indexes are invalid")
    return (
        m5_precedent_citation_causal_source(
            citation,
            citation_kind=citation_kind,
            manifest_id=_row_str(row, "manifest_id"),
            source_document_sha256=document_sha256,
        ),
        citation,
    )


def _conflict_receipt_source_from_row(row: sqlite3.Row) -> M5PrecedentCausalSource:
    raw = _row_str(row, "receipt_json")
    try:
        receipt = M5PrecedentConflictBatchReceipt.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError(
            "stored M5 precedent conflict marker source is invalid"
        ) from exc
    _verify_contract_document(raw, receipt)
    document_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    changed_count = sum(
        item.resulting_authority_id != item.prior_authority_id for item in receipt.results
    )
    indexed = (
        _row_str(row, "run_id") == receipt.run_id,
        _row_str(row, "receipt_id") == receipt.receipt_id,
        _row_str(row, "batch_authority_id") == receipt.batch_authority_id,
        _row_str(row, "causal_cut_id") == receipt.causal_cut_id,
        _row_int(row, "result_count") == len(receipt.results),
        _row_int(row, "changed_count") == changed_count,
        _row_str(row, "document_sha256") == document_sha256,
    )
    if not all(indexed):
        raise RepositoryIntegrityError("M5 precedent conflict marker source indexes are invalid")
    return m5_precedent_conflict_receipt_causal_source(
        receipt,
        manifest_id=_row_str(row, "manifest_id"),
        source_document_sha256=document_sha256,
    )


def _revocation_receipt_source_from_row(
    row: sqlite3.Row,
) -> tuple[
    M5PrecedentCausalSource,
    M5PrecedentRevocationReceipt,
    M5PrecedentCitationSnapshot,
]:
    receipt_raw = _row_str(row, "receipt_json")
    context_raw = _row_str(row, "context_json")
    try:
        receipt = M5PrecedentRevocationReceipt.model_validate_json(receipt_raw)
        snapshot = M5PrecedentCitationSnapshot.model_validate_json(context_raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError(
            "stored M5 precedent revocation marker source is invalid"
        ) from exc
    _verify_contract_document(receipt_raw, receipt)
    _verify_contract_document(context_raw, snapshot)
    document_sha256 = hashlib.sha256(receipt_raw.encode("utf-8")).hexdigest()
    context_sha256 = hashlib.sha256(context_raw.encode("utf-8")).hexdigest()
    indexed = (
        _row_str(row, "receipt_kind") == "REVOCATION",
        _row_str(row, "run_id") == receipt.run_id,
        _row_str(row, "receipt_id") == receipt.receipt_id,
        _row_str(row, "outcome") == receipt.outcome.value,
        _row_str(row, "primary_precedent_id") == receipt.precedent_id,
        _row_str(row, "primary_prior_authority_id") == receipt.prior_authority_id,
        _row_int(row, "primary_prior_revision") == receipt.prior_revision,
        _row_str(row, "primary_resulting_authority_id") == receipt.resulting_authority_id,
        _row_int(row, "primary_resulting_revision") == receipt.resulting_revision,
        _row_optional_str(row, "secondary_precedent_id") is None,
        _row_optional_str(row, "secondary_prior_authority_id") is None,
        _row_optional_int(row, "secondary_prior_revision") is None,
        _row_optional_str(row, "secondary_resulting_authority_id") is None,
        _row_optional_int(row, "secondary_resulting_revision") is None,
        snapshot.snapshot_id == receipt.citation_snapshot_id,
        snapshot.run_id == receipt.run_id,
        snapshot.precedent_id == receipt.precedent_id,
        snapshot.captured_at == receipt.revoked_at,
        _row_str(row, "context_sha256") == context_sha256,
        _row_str(row, "document_sha256") == document_sha256,
    )
    if not all(indexed):
        raise RepositoryIntegrityError("M5 precedent revocation marker source indexes are invalid")
    return (
        m5_precedent_revocation_receipt_causal_source(
            receipt,
            manifest_id=_row_str(row, "manifest_id"),
            source_document_sha256=document_sha256,
        ),
        receipt,
        snapshot,
    )


def _appeal_resolution_commit_source_from_row(
    row: sqlite3.Row,
) -> tuple[M5PrecedentCausalSource, M5AppealResolutionCommitReceipt]:
    raw = _row_str(row, "receipt_json")
    try:
        receipt = M5AppealResolutionCommitReceipt.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError(
            "stored M5 appeal resolution commit marker source is invalid"
        ) from exc
    _verify_contract_document(raw, receipt)
    document_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    indexed = (
        _row_str(row, "run_id") == receipt.run_id,
        _row_str(row, "receipt_id") == receipt.receipt_id,
        _row_str(row, "effect_root_sha256") == receipt.effect_root_sha256,
        _row_str(row, "resolution_intent_id") == receipt.resolution_intent_id,
        _row_str(row, "resolution_document_sha256") == receipt.resolution_document_sha256,
        _row_str(row, "appeal_id") == receipt.appeal_id,
        _row_str(row, "appeal_authority_sha256") == receipt.appeal_authority_sha256,
        _row_str(row, "case_id") == receipt.case_id,
        _row_int(row, "source_case_revision") == receipt.source_case_revision,
        _row_int(row, "resulting_case_revision") == receipt.resulting_case_revision,
        _row_str(row, "resulting_case_document_sha256") == receipt.resulting_case_document_sha256,
        _row_str(row, "verdict_rescission_ids_json")
        == canonical_json(list(receipt.verdict_rescission_ids)),
        _row_str(row, "alert_rescission_ids_json")
        == canonical_json(list(receipt.alert_rescission_ids)),
        _row_str(row, "precedent_revocation_receipt_ids_json")
        == canonical_json(list(receipt.precedent_revocation_receipt_ids)),
        _row_optional_str(row, "replacement_precedent_authority_id")
        == receipt.replacement_precedent_authority_id,
        _row_str(row, "training_label_ids_json")
        == canonical_json(list(receipt.training_label_ids)),
        _row_str(row, "affected_citation_report_sha256") == receipt.affected_citation_report_sha256,
        _row_str(row, "manifest_id") == receipt.manifest_id,
        _row_str(row, "document_sha256") == document_sha256,
    )
    if not all(indexed):
        raise RepositoryIntegrityError(
            "M5 appeal resolution commit marker source indexes are invalid"
        )
    return (
        m5_appeal_resolution_commit_causal_source(
            receipt,
            source_document_sha256=document_sha256,
        ),
        receipt,
    )


def _source_key(
    source: M5PrecedentCausalSource,
) -> tuple[M5PrecedentCausalEventKind, str]:
    return source.event_kind, source.source_id


def _stored_source_count(
    connection: sqlite3.Connection,
    source: M5PrecedentCausalSource,
) -> int:
    source_queries = {
        M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED: (
            "SELECT COUNT(*) AS source_count FROM precedents WHERE run_id = ? AND authority_id = ?"
        ),
        M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED: (
            "SELECT COUNT(*) AS source_count FROM precedent_citations "
            "WHERE run_id = ? AND citation_id = ?"
        ),
        M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED: (
            "SELECT COUNT(*) AS source_count FROM precedent_conflict_batch_receipts "
            "WHERE run_id = ? AND receipt_id = ?"
        ),
        M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED: (
            "SELECT COUNT(*) AS source_count FROM precedent_lifecycle_receipts "
            "WHERE run_id = ? AND receipt_id = ? AND receipt_kind = 'REVOCATION'"
        ),
        M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED: (
            "SELECT COUNT(*) AS source_count FROM appeal_resolution_commit_receipts "
            "WHERE run_id = ? AND receipt_id = ?"
        ),
    }
    row = connection.execute(
        source_queries[source.event_kind],
        (source.run_id, source.source_id),
    ).fetchone()
    if row is None:
        raise RepositoryIntegrityError("M5 precedent causal source count is unavailable")
    return _row_int(row, "source_count")


def _stored_event_count(
    connection: sqlite3.Connection,
    source: M5PrecedentCausalSource,
) -> int:
    row = connection.execute(
        """
        SELECT COUNT(*) AS event_count
        FROM m5_precedent_causal_events
        WHERE run_id = ? AND event_kind = ? AND source_id = ?
        """,
        (source.run_id, source.event_kind.value, source.source_id),
    ).fetchone()
    if row is None:
        raise RepositoryIntegrityError("M5 precedent causal event count is unavailable")
    return _row_int(row, "event_count")


def _event_matches_source(
    event: M5PrecedentCausalEvent,
    source: M5PrecedentCausalSource,
) -> bool:
    return (
        event.run_id,
        event.event_kind,
        event.source_id,
        event.precedent_id,
        event.precedent_authority_id,
        event.precedent_revision,
        event.citation_kind,
        event.manifest_id,
        event.source_document_sha256,
    ) == (
        source.run_id,
        source.event_kind,
        source.source_id,
        source.precedent_id,
        source.precedent_authority_id,
        source.precedent_revision,
        source.citation_kind,
        source.manifest_id,
        source.source_document_sha256,
    )


def _require_valid_causal_ledger(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    pending_source: M5PrecedentCausalSource | None = None,
) -> tuple[M5PrecedentCausalEvent, ...]:
    """Validate the complete run chain and raw source/event bijection."""

    source_groups: dict[
        tuple[M5PrecedentCausalEventKind, str],
        list[M5PrecedentCausalSource],
    ] = defaultdict(list)
    authority_rows = connection.execute(
        "SELECT * FROM precedents WHERE run_id = ? ORDER BY precedent_id, revision",
        (run_id,),
    ).fetchall()
    citation_rows = connection.execute(
        "SELECT * FROM precedent_citations WHERE run_id = ? ORDER BY citation_id",
        (run_id,),
    ).fetchall()
    conflict_receipt_rows = connection.execute(
        "SELECT * FROM precedent_conflict_batch_receipts WHERE run_id = ? ORDER BY receipt_id",
        (run_id,),
    ).fetchall()
    revocation_receipt_rows = connection.execute(
        """
        SELECT * FROM precedent_lifecycle_receipts
        WHERE run_id = ? AND receipt_kind = 'REVOCATION'
        ORDER BY receipt_id
        """,
        (run_id,),
    ).fetchall()
    appeal_commit_rows = connection.execute(
        """
        SELECT * FROM appeal_resolution_commit_receipts
        WHERE run_id = ? ORDER BY receipt_id
        """,
        (run_id,),
    ).fetchall()
    revocation_receipts: dict[str, M5PrecedentRevocationReceipt] = {}
    revocation_snapshots: dict[str, M5PrecedentCitationSnapshot] = {}
    appeal_commits: dict[str, M5AppealResolutionCommitReceipt] = {}
    authorities: list[M5PrecedentAuthority] = []
    citations: list[M5PrecedentCitationAuthority] = []
    for row in authority_rows:
        source, authority = _authority_source_from_row(row)
        source_groups[_source_key(source)].append(source)
        authorities.append(authority)
    for row in citation_rows:
        source, citation = _citation_source_from_row(row)
        source_groups[_source_key(source)].append(source)
        citations.append(citation)
    for row in conflict_receipt_rows:
        source = _conflict_receipt_source_from_row(row)
        source_groups[_source_key(source)].append(source)
    for row in revocation_receipt_rows:
        revocation_source, revocation_receipt, _snapshot = _revocation_receipt_source_from_row(row)
        source_groups[_source_key(revocation_source)].append(revocation_source)
        if revocation_receipt.receipt_id in revocation_receipts:
            raise RepositoryIntegrityError("M5 revocation receipt identity is ambiguous")
        revocation_receipts[revocation_receipt.receipt_id] = revocation_receipt
        revocation_snapshots[revocation_receipt.receipt_id] = _snapshot
    for row in appeal_commit_rows:
        appeal_source, appeal_receipt = _appeal_resolution_commit_source_from_row(row)
        source_groups[_source_key(appeal_source)].append(appeal_source)
        if appeal_receipt.receipt_id in appeal_commits:
            raise RepositoryIntegrityError("M5 appeal commit receipt identity is ambiguous")
        appeal_commits[appeal_receipt.receipt_id] = appeal_receipt
    if any(len(sources) != 1 for sources in source_groups.values()):
        raise RepositoryIntegrityError(
            "M5 precedent causal source identity resolves to multiple rows"
        )

    pending_key: tuple[M5PrecedentCausalEventKind, str] | None = None
    if pending_source is not None:
        if pending_source.run_id != run_id:
            raise RepositoryIntegrityError("M5 precedent causal pending source run differs")
        pending_key = _source_key(pending_source)
        stored_pending = source_groups.get(pending_key)
        if stored_pending != [pending_source]:
            raise RepositoryIntegrityError(
                "M5 precedent causal pending source is not the exact stored source"
            )

    event_rows = connection.execute(
        """
        SELECT * FROM m5_precedent_causal_events
        WHERE run_id = ? ORDER BY sequence
        """,
        (run_id,),
    ).fetchall()
    events = tuple(_event_from_row(row) for row in event_rows)
    previous = M5_PRECEDENT_CAUSAL_GENESIS_SHA256
    last_authority_revision: dict[str, int] = {}
    authority_event_sequences: dict[tuple[str, str, int], int] = {}
    for ordinal, event in enumerate(events, start=1):
        if event.sequence != ordinal or event.previous_event_sha256 != previous:
            raise RepositoryIntegrityError("M5 precedent causal event chain is invalid")
        if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED:
            precedent_id = event.precedent_id
            authority_id = event.precedent_authority_id
            revision = event.precedent_revision
            if precedent_id is None or authority_id is None or revision is None:
                raise RepositoryIntegrityError("M5 precedent authority event shape is invalid")
            expected_revision = last_authority_revision.get(precedent_id, 0) + 1
            if revision != expected_revision:
                raise RepositoryIntegrityError(
                    "M5 precedent authority event revisions are not causally contiguous"
                )
            last_authority_revision[precedent_id] = revision
            authority_event_sequences[(precedent_id, authority_id, revision)] = event.sequence
        elif event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED:
            precedent_id = event.precedent_id
            authority_id = event.precedent_authority_id
            revision = event.precedent_revision
            authority_sequence = (
                None
                if precedent_id is None or authority_id is None or revision is None
                else authority_event_sequences.get((precedent_id, authority_id, revision))
            )
            if (
                precedent_id is None
                or authority_id is None
                or revision is None
                or authority_sequence is None
                or authority_sequence >= event.sequence
            ):
                raise RepositoryIntegrityError(
                    "M5 precedent citation event does not follow its authority event"
                )
        previous = event.event_sha256

    event_groups: dict[
        tuple[M5PrecedentCausalEventKind, str],
        list[M5PrecedentCausalEvent],
    ] = defaultdict(list)
    for event in events:
        event_groups[(event.event_kind, event.source_id)].append(event)
    if any(len(matches) != 1 for matches in event_groups.values()):
        raise RepositoryIntegrityError(
            "M5 precedent causal event identity resolves to multiple rows"
        )

    expected_keys = set(source_groups)
    if pending_key is not None:
        if pending_key in event_groups:
            raise RepositoryIntegrityError("M5 precedent causal source already has an event")
        expected_keys.remove(pending_key)
    observed_keys = set(event_groups)
    if expected_keys - observed_keys and not observed_keys - expected_keys:
        raise RepositoryIntegrityError("M5 precedent causal source does not have exactly one event")
    if observed_keys != expected_keys:
        raise RepositoryIntegrityError("M5 precedent causal source/event bijection is invalid")
    for key in expected_keys:
        if not _event_matches_source(event_groups[key][0], source_groups[key][0]):
            raise RepositoryIntegrityError("M5 precedent causal event differs from its source")
    replay_authorities = tuple(
        authority
        for authority in authorities
        if not (
            pending_source is not None
            and pending_source.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
            and authority.authority_id == pending_source.source_id
        )
    )
    replay_citations = tuple(
        citation
        for citation in citations
        if not (
            pending_source is not None
            and pending_source.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED
            and citation.citation_id == pending_source.source_id
        )
    )
    for receipt_id, revocation_receipt in revocation_receipts.items():
        marker_key = (
            M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED,
            receipt_id,
        )
        if marker_key == pending_key:
            continue
        marker = event_groups[marker_key][0]
        if revocation_receipt.outcome == M5PrecedentRevocationOutcome.REVOKED:
            if marker.sequence < 2:
                raise RepositoryIntegrityError(
                    "M5 precedent revocation marker lacks its resulting authority event"
                )
            authority_event = events[marker.sequence - 2]
            if (
                authority_event.event_kind
                != M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
                or authority_event.source_id != revocation_receipt.resulting_authority_id
                or authority_event.precedent_id != revocation_receipt.precedent_id
                or authority_event.precedent_authority_id
                != revocation_receipt.resulting_authority_id
                or authority_event.precedent_revision != revocation_receipt.resulting_revision
            ):
                raise RepositoryIntegrityError(
                    "M5 precedent revocation marker is not adjacent to its authority event"
                )
        else:
            authority_key = (
                M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
                revocation_receipt.resulting_authority_id,
            )
            authority_matches = event_groups.get(authority_key, ())
            if len(authority_matches) != 1 or authority_matches[0].sequence >= marker.sequence:
                raise RepositoryIntegrityError(
                    "idempotent M5 revocation marker does not follow its authority event"
                )
        try:
            rebuild_m5_precedent_revocation_history(
                authorities=replay_authorities,
                citations=replay_citations,
                causal_events=events,
                receipt=revocation_receipt,
                citation_snapshot=revocation_snapshots[receipt_id],
            )
        except M5PrecedentRevocationHistoryError as exc:
            raise RepositoryIntegrityError(
                f"M5 precedent revocation history is invalid: {exc.code.value}"
            ) from exc
    for receipt_id, appeal_receipt in appeal_commits.items():
        marker_key = (M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED, receipt_id)
        if marker_key == pending_key:
            continue
        marker = event_groups[marker_key][0]
        cursor = marker.sequence - 2
        if appeal_receipt.replacement_precedent_authority_id is not None:
            if cursor < 0:
                raise RepositoryIntegrityError(
                    "M5 appeal resolution marker lacks its replacement authority"
                )
            replacement = events[cursor]
            if (
                replacement.event_kind != M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
                or replacement.source_id != appeal_receipt.replacement_precedent_authority_id
                or replacement.precedent_authority_id
                != appeal_receipt.replacement_precedent_authority_id
            ):
                raise RepositoryIntegrityError(
                    "M5 appeal resolution marker does not follow its replacement authority"
                )
            cursor -= 1
        observed_revocation_ids: list[str] = []
        for _ in appeal_receipt.precedent_revocation_receipt_ids:
            if cursor < 1:
                raise RepositoryIntegrityError(
                    "M5 appeal resolution marker lacks its revocation event interval"
                )
            revocation_marker = events[cursor]
            authority_event = events[cursor - 1]
            if (
                revocation_marker.event_kind
                != M5PrecedentCausalEventKind.PRECEDENT_REVOCATION_COMMITTED
                or authority_event.event_kind
                != M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
                or authority_event.source_id != revocation_marker.precedent_authority_id
                or authority_event.precedent_id != revocation_marker.precedent_id
                or authority_event.precedent_revision != revocation_marker.precedent_revision
            ):
                raise RepositoryIntegrityError(
                    "M5 appeal resolution revocation interval is not exact"
                )
            child_receipt = revocation_receipts.get(revocation_marker.source_id)
            if (
                child_receipt is None
                or child_receipt.outcome != M5PrecedentRevocationOutcome.REVOKED
            ):
                raise RepositoryIntegrityError(
                    "M5 appeal resolution references a non-mutating revocation"
                )
            observed_revocation_ids.append(revocation_marker.source_id)
            cursor -= 2
        if (
            tuple(sorted(observed_revocation_ids))
            != appeal_receipt.precedent_revocation_receipt_ids
        ):
            raise RepositoryIntegrityError(
                "M5 appeal resolution marker revocation roots differ from its receipt"
            )
    return events


__all__ = [
    "M5PrecedentCausalSource",
    "append_m5_precedent_causal_event",
    "load_m5_precedent_causal_events",
    "m5_appeal_resolution_commit_causal_source",
    "m5_precedent_authority_causal_source",
    "m5_precedent_citation_causal_source",
    "m5_precedent_conflict_receipt_causal_source",
    "m5_precedent_revocation_receipt_causal_source",
    "require_m5_precedent_causal_event",
]
