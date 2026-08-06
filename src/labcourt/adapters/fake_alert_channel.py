"""Offline deterministic alert channel with provider-style idempotent receipts."""

from __future__ import annotations

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
)
from labcourt.contracts.alerts import AlertDecision, DeliveryReceipt
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus


class DeterministicFakeAlertChannel:
    """Accept exact closed-Case alerts without network or external side effects."""

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
            channel="deterministic-fake-alert-v1",
            capability_revision="deterministic-fake-alert-capability-v1",
            idempotency_guarantee=AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID,
            provider_idempotency_key="alert_id",
        )

    def send(
        self,
        alert: AlertDecision,
        case: Case,
        idempotency_key: str,
    ) -> DeliveryReceipt:
        if not isinstance(alert, AlertDecision) or not isinstance(case, Case):
            raise TypeError("fake alert channel requires AlertDecision and Case")
        if (
            case.status != CaseStatus.CLOSED
            or alert not in case.alerts
            or alert.case_id != case.case_id
            or idempotency_key != alert.alert_id
        ):
            raise ValueError("fake alert channel received an invalid delivery authority")
        return DeliveryReceipt(
            alert_id=alert.alert_id,
            channel="deterministic-fake-alert-v1",
            idempotency_key=idempotency_key,
            accepted=True,
            provider_receipt_ref=sha256_hex(
                ["deterministic-fake-alert-receipt", 1, alert.alert_id]
            ),
        )


__all__ = ["DeterministicFakeAlertChannel"]
