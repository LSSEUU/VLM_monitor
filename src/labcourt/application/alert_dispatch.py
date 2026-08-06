"""Fenced alert dispatcher with explicit unknown-delivery recovery semantics."""

from __future__ import annotations

from enum import StrEnum

from labcourt.contracts.alert_policy import (
    MAX_ALERT_DISPATCH_ATTEMPTS,
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
    AlertDispatchAttempt,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchFailureCode,
    AlertDispatchReceipt,
    AlertOutboxItem,
)
from labcourt.contracts.alerts import DeliveryReceipt
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus
from labcourt.exceptions import ContractViolation
from labcourt.ports.alert_outbox import AlertOutboxRepository
from labcourt.ports.alerts import (
    AlertChannel,
    AlertChannelDeliveryCertainty,
    AlertChannelError,
)


class AlertDispatchStateFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CASE_NOT_ATOMICALLY_CLOSED = "CASE_NOT_ATOMICALLY_CLOSED"
    BEGIN_AUTHORITY_INVALID = "BEGIN_AUTHORITY_INVALID"
    COMPLETION_AUTHORITY_INVALID = "COMPLETION_AUTHORITY_INVALID"


class AlertDispatchStateError(ContractViolation):
    def __init__(self, reason_code: AlertDispatchStateFailureCode) -> None:
        if not isinstance(reason_code, AlertDispatchStateFailureCode):
            raise TypeError("reason_code must be an AlertDispatchStateFailureCode")
        self.reason_code = reason_code
        super().__init__(f"alert dispatch state failed: {reason_code.value}")


class AlertDispatcher:
    """Send pending items; retry failures and never resend a recorded success."""

    def __init__(
        self,
        outbox: AlertOutboxRepository,
        channel: AlertChannel,
        channel_capability: AlertChannelCapabilityAuthority,
    ) -> None:
        for candidate, methods in (
            (outbox, ("begin_dispatch", "complete_dispatch")),
            (channel, ("send",)),
        ):
            if any(
                getattr(candidate, method, None) is None or not callable(getattr(candidate, method))
                for method in methods
            ):
                raise TypeError("alert dispatcher dependency does not implement its port")
        if not isinstance(channel_capability, AlertChannelCapabilityAuthority):
            raise TypeError("alert channel capability authority is invalid")
        self._outbox = outbox
        self._channel = channel
        self._channel_capability = AlertChannelCapabilityAuthority.model_validate(
            channel_capability.model_dump(mode="json")
        )

    @staticmethod
    def _validate_case(item: AlertOutboxItem, case: Case) -> None:
        if (
            case.status != CaseStatus.CLOSED
            or case.run_id != item.run_id
            or case.case_id != item.case_id
            or case.manifest_id != item.manifest_id
            or item.alert not in case.alerts
        ):
            raise AlertDispatchStateError(AlertDispatchStateFailureCode.CASE_NOT_ATOMICALLY_CLOSED)

    @staticmethod
    def _failure(
        attempt: AlertDispatchAttempt,
        code: AlertDispatchFailureCode,
        delivery: DeliveryReceipt | None = None,
    ) -> AlertDispatchReceipt:
        continuation = (
            AlertDispatchContinuation.ATTENTION_REQUIRED
            if attempt.attempt_number >= MAX_ALERT_DISPATCH_ATTEMPTS
            else AlertDispatchContinuation.RETRY_ALLOWED
        )
        return AlertDispatchReceipt(
            attempt_id=attempt.attempt_id,
            outbox_id=attempt.outbox_id,
            alert_id=attempt.alert_id,
            case_id=attempt.case_id,
            attempt_number=attempt.attempt_number,
            fence=attempt.fence,
            lease_owner_sha256=attempt.lease_owner_sha256,
            started_at=attempt.started_at,
            lease_expires_at=attempt.lease_expires_at,
            channel_capability=attempt.channel_capability,
            idempotency_key=attempt.alert_id,
            disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
            continuation=continuation,
            failure_code=code,
            delivery_receipt=delivery,
        )

    @staticmethod
    def _unknown(
        attempt: AlertDispatchAttempt,
        code: AlertDispatchFailureCode,
    ) -> AlertDispatchReceipt:
        retry_safe = (
            attempt.channel_capability.idempotency_guarantee
            == AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID
            and attempt.channel_capability.provider_idempotency_key == "alert_id"
            and attempt.attempt_number < MAX_ALERT_DISPATCH_ATTEMPTS
        )
        return AlertDispatchReceipt(
            attempt_id=attempt.attempt_id,
            outbox_id=attempt.outbox_id,
            alert_id=attempt.alert_id,
            case_id=attempt.case_id,
            attempt_number=attempt.attempt_number,
            fence=attempt.fence,
            lease_owner_sha256=attempt.lease_owner_sha256,
            started_at=attempt.started_at,
            lease_expires_at=attempt.lease_expires_at,
            channel_capability=attempt.channel_capability,
            idempotency_key=attempt.alert_id,
            disposition=AlertDispatchDisposition.UNKNOWN_DELIVERY,
            continuation=(
                AlertDispatchContinuation.RETRY_ALLOWED
                if retry_safe
                else AlertDispatchContinuation.ATTENTION_REQUIRED
            ),
            failure_code=code,
        )

    @staticmethod
    def _success(
        attempt: AlertDispatchAttempt,
        delivery: DeliveryReceipt,
    ) -> AlertDispatchReceipt:
        return AlertDispatchReceipt(
            attempt_id=attempt.attempt_id,
            outbox_id=attempt.outbox_id,
            alert_id=attempt.alert_id,
            case_id=attempt.case_id,
            attempt_number=attempt.attempt_number,
            fence=attempt.fence,
            lease_owner_sha256=attempt.lease_owner_sha256,
            started_at=attempt.started_at,
            lease_expires_at=attempt.lease_expires_at,
            channel_capability=attempt.channel_capability,
            idempotency_key=attempt.alert_id,
            disposition=AlertDispatchDisposition.SUCCEEDED,
            continuation=AlertDispatchContinuation.CLOSED,
            delivery_receipt=delivery,
        )

    def dispatch(
        self,
        item: AlertOutboxItem,
        case: Case,
        worker_id: str,
    ) -> AlertDispatchReceipt:
        if (
            not isinstance(item, AlertOutboxItem)
            or not isinstance(case, Case)
            or not isinstance(worker_id, str)
        ):
            raise AlertDispatchStateError(AlertDispatchStateFailureCode.INVALID_ARGUMENT)
        self._validate_case(item, case)
        lease_owner_sha256 = sha256_hex(["alert-dispatch-worker", 1, worker_id])
        prepared = self._outbox.begin_dispatch(
            item,
            lease_owner_sha256,
            self._channel_capability,
        )
        if isinstance(prepared, AlertDispatchReceipt):
            if (
                prepared.continuation
                not in {
                    AlertDispatchContinuation.CLOSED,
                    AlertDispatchContinuation.ATTENTION_REQUIRED,
                }
                or prepared.outbox_id != item.outbox_id
                or prepared.alert_id != item.alert.alert_id
                or prepared.channel_capability != self._channel_capability
            ):
                raise AlertDispatchStateError(AlertDispatchStateFailureCode.BEGIN_AUTHORITY_INVALID)
            return prepared
        if (
            not isinstance(prepared, AlertDispatchAttempt)
            or prepared.outbox_id != item.outbox_id
            or prepared.alert_id != item.alert.alert_id
            or prepared.case_id != item.case_id
            or prepared.idempotency_key != item.alert.alert_id
            or prepared.lease_owner_sha256 != lease_owner_sha256
            or prepared.channel_capability != self._channel_capability
        ):
            raise AlertDispatchStateError(AlertDispatchStateFailureCode.BEGIN_AUTHORITY_INVALID)

        try:
            delivery = self._channel.send(
                item.alert,
                case,
                idempotency_key=item.alert.alert_id,
            )
        except AlertChannelError as exc:
            if exc.delivery_certainty == AlertChannelDeliveryCertainty.DEFINITELY_NOT_SENT:
                candidate = self._failure(
                    prepared,
                    AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
                )
            else:
                candidate = self._unknown(
                    prepared,
                    AlertDispatchFailureCode.CHANNEL_EXCEPTION,
                )
        except Exception:  # external boundary: unknown delivery is persisted explicitly
            candidate = self._unknown(
                prepared,
                AlertDispatchFailureCode.CHANNEL_EXCEPTION,
            )
        else:
            exact_scope = (
                delivery.alert_id == item.alert.alert_id
                and delivery.idempotency_key == item.alert.alert_id
                and delivery.channel == self._channel_capability.channel
            )
            if not exact_scope:
                candidate = self._unknown(
                    prepared,
                    AlertDispatchFailureCode.RECEIPT_MISMATCH,
                )
            elif not delivery.accepted:
                candidate = self._failure(
                    prepared,
                    AlertDispatchFailureCode.CHANNEL_REJECTED,
                    delivery,
                )
            else:
                candidate = self._success(prepared, delivery)

        committed = self._outbox.complete_dispatch(prepared, candidate)
        if (
            not isinstance(committed, AlertDispatchReceipt)
            or committed.outbox_id != item.outbox_id
            or committed.alert_id != item.alert.alert_id
            or committed.idempotency_key != item.alert.alert_id
            or committed.attempt_id != prepared.attempt_id
            or committed.fence != prepared.fence
            or committed.lease_owner_sha256 != prepared.lease_owner_sha256
            or committed.channel_capability != prepared.channel_capability
        ):
            raise AlertDispatchStateError(
                AlertDispatchStateFailureCode.COMPLETION_AUTHORITY_INVALID
            )
        return committed


__all__ = [
    "AlertDispatchStateError",
    "AlertDispatchStateFailureCode",
    "AlertDispatcher",
]
