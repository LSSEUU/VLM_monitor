"""Alert delivery port with explicit provider-side idempotency authority."""

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.alert_policy import AlertChannelCapabilityAuthority
from labcourt.contracts.alerts import AlertDecision, DeliveryReceipt
from labcourt.contracts.cases import Case
from labcourt.exceptions import ContractViolation


class AlertChannelDeliveryCertainty(StrEnum):
    DEFINITELY_NOT_SENT = "DEFINITELY_NOT_SENT"
    UNKNOWN = "UNKNOWN"


class AlertChannelFailureCode(StrEnum):
    CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"
    REQUEST_REJECTED_BEFORE_SEND = "REQUEST_REJECTED_BEFORE_SEND"


class AlertChannelError(ContractViolation):
    """Typed channel failure whose delivery certainty controls retry authority."""

    def __init__(
        self,
        reason_code: AlertChannelFailureCode,
        delivery_certainty: AlertChannelDeliveryCertainty,
    ) -> None:
        if not isinstance(reason_code, AlertChannelFailureCode):
            raise TypeError("reason_code must be an AlertChannelFailureCode")
        if not isinstance(delivery_certainty, AlertChannelDeliveryCertainty):
            raise TypeError("delivery_certainty must be an AlertChannelDeliveryCertainty")
        self.reason_code = reason_code
        self.delivery_certainty = delivery_certainty
        super().__init__(f"alert channel failed: {reason_code.value}")


class AlertChannel(Protocol):
    def capability_authority(
        self,
        *,
        run_id: str,
        manifest_id: str,
        config_sha256: str,
    ) -> AlertChannelCapabilityAuthority: ...

    def send(
        self,
        alert: AlertDecision,
        case: Case,
        idempotency_key: str,
    ) -> DeliveryReceipt: ...


__all__ = [
    "AlertChannel",
    "AlertChannelDeliveryCertainty",
    "AlertChannelError",
    "AlertChannelFailureCode",
]
