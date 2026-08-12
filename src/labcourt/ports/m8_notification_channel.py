"""Port for bounded notification dispatch, delivery replay, and raw response access."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDeliveryReceiptV1,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
)
from labcourt.exceptions import ContractViolation


class M8NotificationChannelAdapterFailureCode(StrEnum):
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    DELIVERY_REPLAY_NOT_FOUND = "DELIVERY_REPLAY_NOT_FOUND"
    DISPATCH_REPLAY_NOT_FOUND = "DISPATCH_REPLAY_NOT_FOUND"
    DISPATCH_RESULT_MISMATCH = "DISPATCH_RESULT_MISMATCH"
    RENDERED_CARD_MISMATCH = "RENDERED_CARD_MISMATCH"
    REQUEST_MISMATCH = "REQUEST_MISMATCH"
    RESPONSE_NOT_FOUND = "RESPONSE_NOT_FOUND"


class M8NotificationChannelAdapterError(ContractViolation):
    """Typed, sanitized failure from a notification channel boundary."""

    def __init__(self, reason_code: M8NotificationChannelAdapterFailureCode) -> None:
        if not isinstance(reason_code, M8NotificationChannelAdapterFailureCode):
            raise TypeError("reason_code must be an M8NotificationChannelAdapterFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M8 notification channel failed: {reason_code.value}")


class M8NotificationChannelAdapter(Protocol):
    def capability_authority(self) -> M8NotificationChannelCapabilityAuthorityV1: ...

    def dispatch(
        self,
        request: M8NotificationDispatchRequestV1,
        rendered_card: bytes,
    ) -> M8NotificationDispatchResultV1: ...

    def confirm_simulated_delivery(
        self,
        dispatch_result: M8NotificationDispatchResultV1,
        occurred_at: datetime,
    ) -> M8NotificationDeliveryReceiptV1: ...

    def replay_dispatch(self, dispatch_request_id: str) -> M8NotificationDispatchResultV1: ...

    def replay_delivery(self, dispatch_result_id: str) -> M8NotificationDeliveryReceiptV1: ...

    def read_raw_response(self, raw_response_ref: str) -> bytes: ...


__all__ = [
    "M8NotificationChannelAdapter",
    "M8NotificationChannelAdapterError",
    "M8NotificationChannelAdapterFailureCode",
]
