from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from labcourt.application.alert_dispatch import AlertDispatcher
from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
    AlertDispatchAttempt,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchFailureCode,
    AlertDispatchReceipt,
    AlertOutboxItem,
)
from labcourt.contracts.alerts import AlertDecision, DeliveryReceipt
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus
from labcourt.domain.alert_policy import plan_case_alert
from labcourt.ports.alerts import (
    AlertChannelDeliveryCertainty,
    AlertChannelError,
    AlertChannelFailureCode,
)
from tests.unit.test_m5_alert_policy import ROOT, _manifest_with_stream, _ready_case


class _Outbox:
    def __init__(self) -> None:
        self.attempt_count = 0
        self.success: AlertDispatchReceipt | None = None
        self.completed: list[AlertDispatchReceipt] = []

    def begin_dispatch(
        self,
        item: AlertOutboxItem,
        lease_owner_sha256: str,
        channel_capability: AlertChannelCapabilityAuthority,
    ) -> AlertDispatchAttempt | AlertDispatchReceipt:
        if self.success is not None:
            return self.success
        self.attempt_count += 1
        started_at = datetime(2026, 8, 2, 12, tzinfo=UTC)
        return AlertDispatchAttempt(
            outbox_id=item.outbox_id,
            alert_id=item.alert.alert_id,
            case_id=item.case_id,
            attempt_number=self.attempt_count,
            fence=self.attempt_count,
            lease_owner_sha256=lease_owner_sha256,
            started_at=started_at,
            lease_expires_at=started_at + timedelta(minutes=1),
            channel_capability=channel_capability,
            idempotency_key=item.alert.alert_id,
        )

    def complete_dispatch(
        self,
        attempt: AlertDispatchAttempt,
        receipt: AlertDispatchReceipt,
    ) -> AlertDispatchReceipt:
        assert receipt.attempt_id == attempt.attempt_id
        self.completed.append(receipt)
        if receipt.disposition == AlertDispatchDisposition.SUCCEEDED:
            self.success = receipt
        return receipt


class _Channel:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.reject_next = True

    def capability_authority(
        self,
        *,
        run_id: str,
        manifest_id: str,
        config_sha256: str,
    ) -> AlertChannelCapabilityAuthority:
        return AlertChannelCapabilityAuthority(
            run_id=run_id,
            manifest_id=manifest_id,
            config_sha256=config_sha256,
            channel="fake-alert-channel",
            capability_revision="fake-alert-channel-v1",
            idempotency_guarantee=AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID,
            provider_idempotency_key="alert_id",
        )

    def send(
        self,
        alert: AlertDecision,
        case: Case,
        idempotency_key: str,
    ) -> DeliveryReceipt:
        assert case.status == CaseStatus.CLOSED
        assert idempotency_key == alert.alert_id
        self.calls.append(idempotency_key)
        if self.reject_next:
            self.reject_next = False
            return DeliveryReceipt(
                alert_id=alert.alert_id,
                channel="fake-alert-channel",
                idempotency_key=idempotency_key,
                accepted=False,
            )
        return DeliveryReceipt(
            alert_id=alert.alert_id,
            channel="fake-alert-channel",
            idempotency_key=idempotency_key,
            accepted=True,
            provider_receipt_ref="provider-success-01",
        )


class _GenericFailureChannel(_Channel):
    def send(
        self,
        alert: AlertDecision,
        case: Case,
        idempotency_key: str,
    ) -> DeliveryReceipt:
        del alert, case, idempotency_key
        raise RuntimeError("simulated ambiguous transport failure")


class _MismatchChannel(_Channel):
    def send(
        self,
        alert: AlertDecision,
        case: Case,
        idempotency_key: str,
    ) -> DeliveryReceipt:
        del case
        return DeliveryReceipt(
            alert_id=alert.alert_id,
            channel="different-channel",
            idempotency_key=idempotency_key,
            accepted=True,
            provider_receipt_ref="mismatched-provider-receipt",
        )


class _DefinitelyNotSentChannel(_Channel):
    def send(
        self,
        alert: AlertDecision,
        case: Case,
        idempotency_key: str,
    ) -> DeliveryReceipt:
        del alert, case, idempotency_key
        raise AlertChannelError(
            AlertChannelFailureCode.REQUEST_REJECTED_BEFORE_SEND,
            AlertChannelDeliveryCertainty.DEFINITELY_NOT_SENT,
        )


def _closed_alert_case() -> tuple[AlertOutboxItem, Case]:
    manifest = _manifest_with_stream()
    ready = _ready_case(manifest)
    authority = plan_case_alert(ready, load_config(ROOT / "configs/demo.yaml"), manifest)
    assert authority.decision is not None
    assert authority.outbox_item is not None
    closed = ready.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": (authority.decision,),
            "final_decision": authority.final_decision,
        }
    )
    return authority.outbox_item, closed


def _capability(channel: _Channel, item: AlertOutboxItem) -> AlertChannelCapabilityAuthority:
    return channel.capability_authority(
        run_id=item.run_id,
        manifest_id=item.manifest_id,
        config_sha256="b" * 64,
    )


def test_dispatch_is_at_least_once_and_never_repeats_a_recorded_success() -> None:
    item, closed = _closed_alert_case()
    outbox = _Outbox()
    channel = _Channel()
    dispatcher = AlertDispatcher(outbox, channel, _capability(channel, item))

    failed = dispatcher.dispatch(item, closed, "worker-01")
    assert failed.disposition == AlertDispatchDisposition.RETRYABLE_FAILURE
    assert failed.failure_code == AlertDispatchFailureCode.CHANNEL_REJECTED

    succeeded = dispatcher.dispatch(item, closed, "worker-01")
    assert succeeded.disposition == AlertDispatchDisposition.SUCCEEDED
    assert channel.calls == [item.alert.alert_id, item.alert.alert_id]

    repeated = dispatcher.dispatch(item, closed, "worker-02")
    assert repeated == succeeded
    assert channel.calls == [item.alert.alert_id, item.alert.alert_id]


@pytest.mark.parametrize("channel", [_GenericFailureChannel(), _MismatchChannel()])
def test_ambiguous_exception_and_receipt_mismatch_are_unknown_delivery(
    channel: _Channel,
) -> None:
    item, closed = _closed_alert_case()
    result = AlertDispatcher(_Outbox(), channel, _capability(channel, item)).dispatch(
        item,
        closed,
        "worker-unknown",
    )

    assert result.disposition == AlertDispatchDisposition.UNKNOWN_DELIVERY
    assert result.continuation == AlertDispatchContinuation.RETRY_ALLOWED
    assert result.failure_code in {
        AlertDispatchFailureCode.CHANNEL_EXCEPTION,
        AlertDispatchFailureCode.RECEIPT_MISMATCH,
    }


def test_typed_definitely_not_sent_failure_is_the_only_exception_retry_path() -> None:
    item, closed = _closed_alert_case()
    channel = _DefinitelyNotSentChannel()
    result = AlertDispatcher(_Outbox(), channel, _capability(channel, item)).dispatch(
        item,
        closed,
        "worker-definite",
    )

    assert result.disposition == AlertDispatchDisposition.RETRYABLE_FAILURE
    assert result.continuation == AlertDispatchContinuation.RETRY_ALLOWED
    assert result.failure_code == AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT
