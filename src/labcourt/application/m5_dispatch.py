"""Bounded restart-safe dispatch of persisted M5 alert outbox items."""

from __future__ import annotations

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
)
from labcourt.contracts.m5_operations import M5DispatchCommandReport
from labcourt.contracts.references import require_reference_token
from labcourt.ports.alert_outbox import AlertOutboxRepository
from labcourt.ports.alerts import AlertChannel
from labcourt.ports.evidence_repository import EvidenceRepository

from .alert_dispatch import AlertDispatcher

MAX_M5_DISPATCH_ITEMS = 256


def dispatch_pending_alerts(
    *,
    outbox: AlertOutboxRepository,
    cases: EvidenceRepository,
    channel: AlertChannel,
    channel_capability: AlertChannelCapabilityAuthority,
    run_id: str,
    worker_id: str,
    limit: int = MAX_M5_DISPATCH_ITEMS,
) -> M5DispatchCommandReport:
    controlled_run_id = require_reference_token(run_id, "M5 dispatch run_id")
    controlled_worker_id = require_reference_token(worker_id, "M5 dispatch worker_id")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 256:
        raise ValueError("M5 dispatch limit must be an integer in [1, 256]")

    if (
        not isinstance(channel_capability, AlertChannelCapabilityAuthority)
        or channel_capability.run_id != controlled_run_id
    ):
        raise ValueError("M5 dispatch capability must bind the selected run")
    dispatcher = AlertDispatcher(outbox, channel, channel_capability)
    pending = outbox.list_pending_outbox(controlled_run_id, limit)
    receipts = tuple(
        sorted(
            (
                dispatcher.dispatch(
                    item,
                    cases.load_case(controlled_run_id, item.case_id).case,
                    controlled_worker_id,
                )
                for item in pending
            ),
            key=lambda item: item.outbox_id,
        )
    )
    return M5DispatchCommandReport(
        run_id=controlled_run_id,
        selected_count=len(pending),
        succeeded_count=sum(
            item.disposition == AlertDispatchDisposition.SUCCEEDED for item in receipts
        ),
        retryable_failure_count=sum(
            item.disposition == AlertDispatchDisposition.RETRYABLE_FAILURE for item in receipts
        ),
        unknown_delivery_count=sum(
            item.disposition == AlertDispatchDisposition.UNKNOWN_DELIVERY for item in receipts
        ),
        attention_required_count=sum(
            item.continuation == AlertDispatchContinuation.ATTENTION_REQUIRED for item in receipts
        ),
        receipts=receipts,
    )


__all__ = ["MAX_M5_DISPATCH_ITEMS", "dispatch_pending_alerts"]
