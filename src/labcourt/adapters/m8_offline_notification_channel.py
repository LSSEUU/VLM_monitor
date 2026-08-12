"""Deterministic offline-only simulated notification channel for M8."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDeliveryDisposition,
    M8NotificationDeliveryReceiptV1,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
)
from labcourt.contracts.m8_notification_persistence import (
    MAX_M8_NOTIFICATION_RAW_ARTIFACT_BYTES,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind
from labcourt.ports.m8_notification_channel import (
    M8NotificationChannelAdapterError,
    M8NotificationChannelAdapterFailureCode,
)


def _canonical_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("M8 simulated notification time must be timezone-aware UTC")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class DeterministicOfflineNotificationChannel:
    """Simulate dispatch and delivery without network, GPU, wall clock, or sleeping."""

    def __init__(self, capability: M8NotificationChannelCapabilityAuthorityV1) -> None:
        if not isinstance(capability, M8NotificationChannelCapabilityAuthorityV1):
            raise TypeError("offline notification channel requires a typed capability")
        if (
            capability.channel != M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
            or capability.network_required
            or not capability.offline_capable
            or not capability.simulated
            or not capability.inbound_response_supported
        ):
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.CAPABILITY_MISMATCH
            )
        self._capability = capability
        self._dispatches: dict[str, M8NotificationDispatchResultV1] = {}
        self._dispatch_cards: dict[str, bytes] = {}
        self._idempotency_requests: dict[str, str] = {}
        self._deliveries: dict[str, M8NotificationDeliveryReceiptV1] = {}
        self._delivery_times: dict[str, datetime] = {}
        self._raw_responses: dict[str, bytes] = {}
        self._dispatch_generation_count = 0
        self._delivery_generation_count = 0

    def capability_authority(self) -> M8NotificationChannelCapabilityAuthorityV1:
        return self._capability

    def dispatch(
        self,
        request: M8NotificationDispatchRequestV1,
        rendered_card: bytes,
    ) -> M8NotificationDispatchResultV1:
        if not isinstance(request, M8NotificationDispatchRequestV1):
            raise TypeError("offline notification dispatch requires a typed request")
        if not isinstance(rendered_card, bytes):
            raise TypeError("offline notification rendered card must be exact bytes")
        if request.channel_capability != self._capability:
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.CAPABILITY_MISMATCH
            )
        if (
            request.plan.target.channel != M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
            or not request.plan.simulated
        ):
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.REQUEST_MISMATCH
            )
        if (
            not 1 <= len(rendered_card) <= MAX_M8_NOTIFICATION_RAW_ARTIFACT_BYTES
            or hashlib.sha256(rendered_card).hexdigest() != request.rendered_card_sha256
        ):
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.RENDERED_CARD_MISMATCH
            )

        request_id = request.dispatch_request_id
        prior_request_id = self._idempotency_requests.get(request.idempotency_key)
        if prior_request_id is not None and prior_request_id != request_id:
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.REQUEST_MISMATCH
            )
        cached = self._dispatches.get(request_id)
        if cached is not None:
            if self._dispatch_cards.get(request_id) != rendered_card:
                raise M8NotificationChannelAdapterError(
                    M8NotificationChannelAdapterFailureCode.RENDERED_CARD_MISMATCH
                )
            return cached

        raw_response_ref = f"m8-dispatch-response-{request_id[:40]}"
        raw_payload = {
            "adapter_id": self._capability.adapter_id,
            "adapter_manifest_id": self._capability.adapter_manifest_id,
            "channel": self._capability.channel,
            "dispatch_request_id": request_id,
            "disposition": M8NotificationDispatchDisposition.ACCEPTED,
            "external_delivery_confirmed": False,
            "notification_id": request.plan.notification_id,
            "schema_version": "m8-offline-notification-dispatch-response-v1",
            "simulated": True,
            "target_authority_id": request.plan.target.target_authority_id,
        }
        raw_response = (canonical_json(raw_payload) + "\n").encode("utf-8")
        result = M8NotificationDispatchResultV1(
            request=request,
            disposition=M8NotificationDispatchDisposition.ACCEPTED,
            provider_receipt_id=f"fake-dispatch-{request_id[:40]}",
            raw_response_ref=raw_response_ref,
            raw_response_sha256=hashlib.sha256(raw_response).hexdigest(),
            completed_at=request.dispatched_at,
            result_manifest_id=self._capability.adapter_manifest_id,
        )
        self._store_raw(raw_response_ref, raw_response)
        self._dispatch_cards[request_id] = rendered_card
        self._idempotency_requests[request.idempotency_key] = request_id
        self._dispatches[request_id] = result
        self._dispatch_generation_count += 1
        return result

    def confirm_simulated_delivery(
        self,
        dispatch_result: M8NotificationDispatchResultV1,
        occurred_at: datetime,
    ) -> M8NotificationDeliveryReceiptV1:
        if not isinstance(dispatch_result, M8NotificationDispatchResultV1):
            raise TypeError("offline notification delivery requires a typed dispatch result")
        _canonical_utc(occurred_at)
        request_id = dispatch_result.request.dispatch_request_id
        emitted = self._dispatches.get(request_id)
        if emitted != dispatch_result or not dispatch_result.accepted:
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.DISPATCH_RESULT_MISMATCH
            )
        dispatch_result_id = dispatch_result.dispatch_result_id
        cached = self._deliveries.get(dispatch_result_id)
        if cached is not None:
            if self._delivery_times.get(dispatch_result_id) != occurred_at:
                raise M8NotificationChannelAdapterError(
                    M8NotificationChannelAdapterFailureCode.REQUEST_MISMATCH
                )
            return cached

        request = dispatch_result.request
        raw_response_ref = f"m8-delivery-response-{dispatch_result_id[:40]}"
        raw_payload = {
            "adapter_id": self._capability.adapter_id,
            "adapter_manifest_id": self._capability.adapter_manifest_id,
            "channel": self._capability.channel,
            "dispatch_result_id": dispatch_result_id,
            "disposition": M8NotificationDeliveryDisposition.DELIVERED,
            "notification_id": request.plan.notification_id,
            "occurred_at": _canonical_utc(occurred_at),
            "real_delivery_confirmed": False,
            "schema_version": "m8-offline-notification-delivery-response-v1",
            "simulated": True,
            "target_authority_id": request.plan.target.target_authority_id,
        }
        raw_response = (canonical_json(raw_payload) + "\n").encode("utf-8")
        receipt = M8NotificationDeliveryReceiptV1(
            notification_id=request.plan.notification_id,
            dispatch_result_id=dispatch_result_id,
            target_authority_id=request.plan.target.target_authority_id,
            channel=self._capability.channel,
            disposition=M8NotificationDeliveryDisposition.DELIVERED,
            provider_delivery_id=f"fake-delivery-{dispatch_result_id[:40]}",
            occurred_at=occurred_at,
            raw_response_ref=raw_response_ref,
            raw_response_sha256=hashlib.sha256(raw_response).hexdigest(),
            simulated=True,
            receipt_manifest_id=self._capability.adapter_manifest_id,
        )
        self._store_raw(raw_response_ref, raw_response)
        self._delivery_times[dispatch_result_id] = occurred_at
        self._deliveries[dispatch_result_id] = receipt
        self._delivery_generation_count += 1
        return receipt

    def replay_dispatch(self, dispatch_request_id: str) -> M8NotificationDispatchResultV1:
        if not isinstance(dispatch_request_id, str):
            raise TypeError("M8 notification dispatch replay ID must be str")
        result = self._dispatches.get(dispatch_request_id)
        if result is None:
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.DISPATCH_REPLAY_NOT_FOUND
            )
        return result

    def replay_delivery(self, dispatch_result_id: str) -> M8NotificationDeliveryReceiptV1:
        if not isinstance(dispatch_result_id, str):
            raise TypeError("M8 notification delivery replay ID must be str")
        receipt = self._deliveries.get(dispatch_result_id)
        if receipt is None:
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.DELIVERY_REPLAY_NOT_FOUND
            )
        return receipt

    def read_raw_response(self, raw_response_ref: str) -> bytes:
        if not isinstance(raw_response_ref, str):
            raise TypeError("M8 notification raw response ref must be str")
        response = self._raw_responses.get(raw_response_ref)
        if response is None:
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.RESPONSE_NOT_FOUND
            )
        return response

    @property
    def generation_counts(self) -> tuple[int, int]:
        return self._dispatch_generation_count, self._delivery_generation_count

    def _store_raw(self, reference: str, raw_response: bytes) -> None:
        prior = self._raw_responses.setdefault(reference, raw_response)
        if prior != raw_response:  # pragma: no cover - content identity guards this branch
            raise M8NotificationChannelAdapterError(
                M8NotificationChannelAdapterFailureCode.RESPONSE_NOT_FOUND
            )


__all__ = ["DeterministicOfflineNotificationChannel"]
