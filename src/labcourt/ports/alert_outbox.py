"""Persistence boundary for serialized at-least-once alert dispatch."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertDispatchAttempt,
    AlertDispatchReceipt,
    AlertOutboxItem,
)


class AlertOutboxRepository(Protocol):
    """Own the attempt sequence and remember the first successful receipt."""

    def list_pending_outbox(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[AlertOutboxItem, ...]: ...

    def begin_dispatch(
        self,
        item: AlertOutboxItem,
        lease_owner_sha256: str,
        channel_capability: AlertChannelCapabilityAuthority,
    ) -> AlertDispatchAttempt | AlertDispatchReceipt: ...

    def complete_dispatch(
        self,
        attempt: AlertDispatchAttempt,
        receipt: AlertDispatchReceipt,
    ) -> AlertDispatchReceipt: ...


__all__ = ["AlertOutboxRepository"]
