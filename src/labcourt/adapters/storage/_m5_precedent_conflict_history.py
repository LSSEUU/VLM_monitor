"""Pure historical replay for one committed M5 precedent conflict batch."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn

from labcourt.application.m5_precedents import resolve_m5_precedent_conflict_batch
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import PrecedentStatus
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
)
from labcourt.contracts.m5_precedents import (
    M5PrecedentAuthority,
    M5PrecedentConflictBatchAuthority,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
)


class M5PrecedentConflictHistoryErrorCode(StrEnum):
    """Stable failure classes shared by online replay and readonly validation."""

    AUTHORITY_INVENTORY_INVALID = "AUTHORITY_INVENTORY_INVALID"
    CAUSAL_EVENT_INVENTORY_INVALID = "CAUSAL_EVENT_INVENTORY_INVALID"
    TRUSTED_POLICY_MISMATCH = "TRUSTED_POLICY_MISMATCH"
    RECEIPT_CLOSURE_INVALID = "RECEIPT_CLOSURE_INVALID"
    CAUSAL_CUT_ANCHOR_INVALID = "CAUSAL_CUT_ANCHOR_INVALID"
    ACTIVE_SNAPSHOT_INVALID = "ACTIVE_SNAPSHOT_INVALID"
    COMMIT_MARKER_INVALID = "COMMIT_MARKER_INVALID"
    AUTHORITY_INTERVAL_INVALID = "AUTHORITY_INTERVAL_INVALID"
    RESULT_AUTHORITY_INVALID = "RESULT_AUTHORITY_INVALID"
    RESOLVER_REPLAY_MISMATCH = "RESOLVER_REPLAY_MISMATCH"


class M5PrecedentConflictHistoryError(RuntimeError):
    """Typed rejection of an internally inconsistent historical conflict batch."""

    def __init__(self, code: M5PrecedentConflictHistoryErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def _fail(code: M5PrecedentConflictHistoryErrorCode) -> NoReturn:
    raise M5PrecedentConflictHistoryError(code)


def rebuild_m5_precedent_conflict_history(
    *,
    authorities: tuple[M5PrecedentAuthority, ...],
    causal_events: tuple[M5PrecedentCausalEvent, ...],
    trusted_policy: M5PrecedentPolicy,
    batch_authority: M5PrecedentConflictBatchAuthority,
    receipt: M5PrecedentConflictBatchReceipt,
) -> M5PrecedentConflictBatchResolution:
    """Rebuild one batch solely from its immutable authority/event history.

    ``causal_events`` must be the complete, already chain- and source-validated
    event inventory for the run. Events after the batch marker are deliberately
    ignored so an exact historical replay does not depend on current heads.
    """

    if not isinstance(authorities, tuple) or any(
        not isinstance(item, M5PrecedentAuthority) for item in authorities
    ):
        raise TypeError("authorities must be a tuple of M5PrecedentAuthority values")
    if not isinstance(causal_events, tuple) or any(
        not isinstance(item, M5PrecedentCausalEvent) for item in causal_events
    ):
        raise TypeError("causal_events must be a tuple of M5PrecedentCausalEvent values")
    if not isinstance(trusted_policy, M5PrecedentPolicy):
        raise TypeError("trusted_policy must be an M5PrecedentPolicy")
    if not isinstance(batch_authority, M5PrecedentConflictBatchAuthority):
        raise TypeError("batch_authority must be an M5PrecedentConflictBatchAuthority")
    if not isinstance(receipt, M5PrecedentConflictBatchReceipt):
        raise TypeError("receipt must be an M5PrecedentConflictBatchReceipt")

    run_id = batch_authority.run_id
    cut = batch_authority.causal_cut
    if (
        trusted_policy.config_sha256 != batch_authority.config_sha256
        or trusted_policy.policy_id != batch_authority.policy_id
        or cut.config_sha256 != trusted_policy.config_sha256
        or cut.policy_id != trusted_policy.policy_id
    ):
        _fail(M5PrecedentConflictHistoryErrorCode.TRUSTED_POLICY_MISMATCH)
    if (
        cut.run_id != run_id
        or receipt.run_id != run_id
        or receipt.config_sha256 != batch_authority.config_sha256
        or receipt.policy_id != batch_authority.policy_id
        or receipt.batch_authority_id != batch_authority.batch_authority_id
        or receipt.causal_cut_id != cut.cut_id
    ):
        _fail(M5PrecedentConflictHistoryErrorCode.RECEIPT_CLOSURE_INVALID)

    authority_by_revision: dict[tuple[str, int], M5PrecedentAuthority] = {}
    authority_ids: set[str] = set()
    for authority in authorities:
        key = (authority.precedent.precedent_id, authority.revision)
        if (
            authority.run_id != run_id
            or key in authority_by_revision
            or authority.authority_id in authority_ids
        ):
            _fail(M5PrecedentConflictHistoryErrorCode.AUTHORITY_INVENTORY_INVALID)
        authority_by_revision[key] = authority
        authority_ids.add(authority.authority_id)

    expected_sequences = tuple(range(1, len(causal_events) + 1))
    observed_sequences = tuple(event.sequence for event in causal_events)
    if observed_sequences != expected_sequences or any(
        event.run_id != run_id for event in causal_events
    ):
        _fail(M5PrecedentConflictHistoryErrorCode.CAUSAL_EVENT_INVENTORY_INVALID)
    event_by_sequence = {event.sequence: event for event in causal_events}

    if cut.authority_event_sequence == 0:
        if cut.authority_event_sha256 != M5_PRECEDENT_CAUSAL_GENESIS_SHA256:
            _fail(M5PrecedentConflictHistoryErrorCode.CAUSAL_CUT_ANCHOR_INVALID)
    else:
        anchor = event_by_sequence.get(cut.authority_event_sequence)
        if (
            anchor is None
            or anchor.event_kind != M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
            or anchor.event_sha256 != cut.authority_event_sha256
        ):
            _fail(M5PrecedentConflictHistoryErrorCode.CAUSAL_CUT_ANCHOR_INVALID)

    latest_at_cut: dict[str, M5PrecedentAuthority] = {}
    for event in causal_events:
        if event.sequence > cut.authority_event_sequence:
            break
        if event.event_kind != M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED:
            continue
        precedent_id = event.precedent_id
        revision = event.precedent_revision
        if precedent_id is None or revision is None:
            _fail(M5PrecedentConflictHistoryErrorCode.CAUSAL_EVENT_INVENTORY_INVALID)
        historical_authority = authority_by_revision.get((precedent_id, revision))
        if historical_authority is None or historical_authority.authority_id != event.source_id:
            _fail(M5PrecedentConflictHistoryErrorCode.AUTHORITY_INVENTORY_INVALID)
        latest_at_cut[precedent_id] = historical_authority

    active_at_cut = tuple(
        sorted(
            (
                authority
                for authority in latest_at_cut.values()
                if authority.precedent.status == PrecedentStatus.ACTIVE
            ),
            key=lambda authority: authority.precedent.precedent_id,
        )
    )
    try:
        snapshot = M5PrecedentConflictSnapshot(
            causal_cut=cut,
            authorities=active_at_cut,
        )
    except (TypeError, ValueError) as exc:
        raise M5PrecedentConflictHistoryError(
            M5PrecedentConflictHistoryErrorCode.ACTIVE_SNAPSHOT_INVALID
        ) from exc

    markers = tuple(
        event
        for event in causal_events
        if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED
        and event.source_id == receipt.receipt_id
    )
    receipt_json = canonical_json(receipt.model_dump(mode="json"))
    receipt_document_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
    if len(markers) != 1:
        _fail(M5PrecedentConflictHistoryErrorCode.COMMIT_MARKER_INVALID)
    marker = markers[0]
    if (
        marker.sequence <= cut.authority_event_sequence
        or marker.manifest_id != cut.manifest_id
        or marker.source_document_sha256 != receipt_document_sha256
    ):
        _fail(M5PrecedentConflictHistoryErrorCode.COMMIT_MARKER_INVALID)

    interval_authority_ids = tuple(
        event.source_id
        for event in causal_events
        if cut.authority_event_sequence < event.sequence < marker.sequence
        and event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
    )
    changed_result_ids = tuple(
        result.resulting_authority_id
        for result in receipt.results
        if result.resulting_authority_id != result.prior_authority_id
    )
    if interval_authority_ids != changed_result_ids:
        _fail(M5PrecedentConflictHistoryErrorCode.AUTHORITY_INTERVAL_INVALID)

    resulting_authorities: list[M5PrecedentAuthority] = []
    for result in receipt.results:
        resulting_authority = authority_by_revision.get(
            (result.precedent_id, result.resulting_revision)
        )
        if (
            resulting_authority is None
            or resulting_authority.authority_id != result.resulting_authority_id
        ):
            _fail(M5PrecedentConflictHistoryErrorCode.RESULT_AUTHORITY_INVALID)
        resulting_authorities.append(resulting_authority)

    try:
        rebuilt = resolve_m5_precedent_conflict_batch(
            snapshot=snapshot,
            policy=trusted_policy,
            scan_limit=batch_authority.scan_limit,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise M5PrecedentConflictHistoryError(
            M5PrecedentConflictHistoryErrorCode.RESOLVER_REPLAY_MISMATCH
        ) from exc
    if (
        rebuilt.batch_authority != batch_authority
        or rebuilt.receipt != receipt
        or rebuilt.prior_authorities != active_at_cut
        or rebuilt.resulting_authorities != tuple(resulting_authorities)
    ):
        _fail(M5PrecedentConflictHistoryErrorCode.RESOLVER_REPLAY_MISMATCH)
    return rebuilt


__all__ = [
    "M5PrecedentConflictHistoryError",
    "M5PrecedentConflictHistoryErrorCode",
    "rebuild_m5_precedent_conflict_history",
]
