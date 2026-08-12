"""Deterministic offline Feishu protocol conformance without network or credentials."""

from __future__ import annotations

import hashlib

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuCardDispatchPreflightV1,
    M8FeishuConformanceFailureCode,
    M8FeishuConformanceOutcome,
    M8FeishuConformanceResultV1,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.ports.m8_feishu_notification_adapter import (
    M8FeishuConformanceAdapterError,
    M8FeishuConformanceAdapterFailureCode,
)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu {name} must be lowercase SHA-256 hex")
    return value


class DeterministicOfflineFeishuConformanceAdapter:
    """Emit provider-shaped synthetic responses while making a real send impossible."""

    def __init__(
        self,
        profile: M8FeishuAdapterProfileV1,
        outcome: M8FeishuConformanceOutcome,
        conformance_manifest_id: Sha256Hex,
    ) -> None:
        if not isinstance(profile, M8FeishuAdapterProfileV1):
            raise TypeError("offline Feishu conformance requires a typed profile")
        if not isinstance(outcome, M8FeishuConformanceOutcome):
            raise TypeError("offline Feishu conformance requires a typed outcome")
        if profile.external_call_permitted:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.PROFILE_MISMATCH
            )
        self._profile = profile
        self._outcome = outcome
        self._manifest_id = _validate_sha256(
            conformance_manifest_id,
            "conformance manifest",
        )
        self._results: dict[str, M8FeishuConformanceResultV1] = {}
        self._cards: dict[str, bytes] = {}
        self._raw_responses: dict[str, bytes] = {}
        self._provider_requests: dict[str, tuple[str, str, str, str | None]] = {}
        self._provider_generation_count = 0

    def profile_authority(self) -> M8FeishuAdapterProfileV1:
        return self._profile

    def conform(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
    ) -> M8FeishuConformanceResultV1:
        if not isinstance(preflight, M8FeishuCardDispatchPreflightV1):
            raise TypeError("offline Feishu conformance requires a typed preflight")
        if not isinstance(rendered_card, bytes):
            raise TypeError("offline Feishu conformance card must be exact bytes")
        if preflight.profile != self._profile:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.PROFILE_MISMATCH
            )
        if preflight.external_call_permitted or preflight.notification_transition_permitted:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.PREFLIGHT_MISMATCH
            )
        self._validate_card(preflight, rendered_card)

        cached = self._results.get(preflight.preflight_id)
        if cached is not None:
            if self._cards.get(preflight.preflight_id) != rendered_card:
                raise M8FeishuConformanceAdapterError(
                    M8FeishuConformanceAdapterFailureCode.CARD_BYTES_MISMATCH
                )
            return cached

        request_fingerprint = (
            preflight.notification_request.plan.notification_id,
            preflight.recipient_binding.binding_authority_id,
            preflight.card.provider_content_sha256,
        )
        prior = self._provider_requests.get(preflight.provider_uuid)
        if prior is not None and prior[:3] != request_fingerprint:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.IDEMPOTENCY_CONFLICT
            )
        provider_message_id = (
            prior[3]
            if prior is not None
            else (
                f"om-simulated-{hashlib.sha256(preflight.provider_uuid.encode()).hexdigest()[:32]}"
                if self._outcome == M8FeishuConformanceOutcome.SUCCESS
                else None
            )
        )
        if prior is None:
            self._provider_requests[preflight.provider_uuid] = (
                *request_fingerprint,
                provider_message_id,
            )
            self._provider_generation_count += 1

        result, raw_response = self._build_result(preflight, provider_message_id)
        self._store_raw(result.raw_response_ref, raw_response)
        self._cards[preflight.preflight_id] = rendered_card
        self._results[preflight.preflight_id] = result
        return result

    def replay(self, preflight_id: str) -> M8FeishuConformanceResultV1:
        if not isinstance(preflight_id, str):
            raise TypeError("M8 Feishu preflight replay ID must be str")
        result = self._results.get(preflight_id)
        if result is None:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.PREFLIGHT_REPLAY_NOT_FOUND
            )
        return result

    def read_raw_response(self, raw_response_ref: str) -> bytes:
        if not isinstance(raw_response_ref, str):
            raise TypeError("M8 Feishu raw response reference must be str")
        response = self._raw_responses.get(raw_response_ref)
        if response is None:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.RAW_RESPONSE_NOT_FOUND
            )
        return response

    @property
    def provider_generation_count(self) -> int:
        return self._provider_generation_count

    @staticmethod
    def _validate_card(
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
    ) -> None:
        if (
            not 1 <= len(rendered_card) <= preflight.profile.max_card_content_bytes
            or hashlib.sha256(rendered_card).hexdigest() != preflight.card.provider_content_sha256
            or hashlib.sha256(rendered_card).hexdigest()
            != preflight.notification_request.rendered_card_sha256
        ):
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.CARD_BYTES_MISMATCH
            )
        try:
            decoded = rendered_card.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.CARD_BYTES_MISMATCH
            ) from error
        if decoded != preflight.card.provider_content_json:
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.CARD_BYTES_MISMATCH
            )

    def _build_result(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        provider_message_id: str | None,
    ) -> tuple[M8FeishuConformanceResultV1, bytes]:
        if self._outcome == M8FeishuConformanceOutcome.SUCCESS:
            disposition = M8NotificationDispatchDisposition.ACCEPTED
            http_status = 200
            provider_code = 0
            provider_log_id = f"log-simulated-{preflight.provider_uuid[-24:]}"
            failure_code = None
            raw_payload: dict[str, object] = {
                "code": 0,
                "data": {
                    "message_id": provider_message_id,
                    "msg_type": "interactive",
                },
                "msg": "success",
                "provider_uuid": preflight.provider_uuid,
                "simulated": True,
            }
        elif self._outcome == M8FeishuConformanceOutcome.PERMISSION_DENIED:
            disposition = M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
            http_status = 400
            provider_code = 230035
            provider_log_id = f"log-simulated-{preflight.provider_uuid[-24:]}"
            failure_code = M8FeishuConformanceFailureCode.PERMISSION_DENIED
            raw_payload = {
                "code": provider_code,
                "msg": "simulated permission denied",
                "provider_uuid": preflight.provider_uuid,
                "simulated": True,
            }
        elif self._outcome == M8FeishuConformanceOutcome.RATE_LIMITED:
            disposition = M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
            http_status = 400
            provider_code = 230020
            provider_log_id = f"log-simulated-{preflight.provider_uuid[-24:]}"
            failure_code = M8FeishuConformanceFailureCode.RATE_LIMITED
            raw_payload = {
                "code": provider_code,
                "msg": "simulated rate limited",
                "provider_uuid": preflight.provider_uuid,
                "simulated": True,
            }
        else:
            disposition = M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
            http_status = None
            provider_code = None
            provider_log_id = None
            failure_code = M8FeishuConformanceFailureCode.CHANNEL_TIMEOUT
            raw_payload = {
                "provider_response_received": False,
                "provider_uuid": preflight.provider_uuid,
                "schema_version": "m8-feishu-simulated-timeout-v1",
                "simulated": True,
            }
        raw_response = (canonical_json(raw_payload) + "\n").encode("utf-8")
        raw_sha256 = hashlib.sha256(raw_response).hexdigest()
        raw_response_ref = f"m8-feishu-response-{raw_sha256[:40]}"
        result = M8FeishuConformanceResultV1(
            preflight=preflight,
            outcome=self._outcome,
            disposition=disposition,
            provider_http_status=http_status,
            provider_code=provider_code,
            provider_message_id=provider_message_id,
            provider_log_id=provider_log_id,
            failure_code=failure_code,
            completed_at=preflight.notification_request.dispatched_at,
            raw_response_ref=raw_response_ref,
            raw_response_sha256=raw_sha256,
            raw_response_size_bytes=len(raw_response),
            conformance_manifest_id=self._manifest_id,
        )
        return result, raw_response

    def _store_raw(self, reference: str, raw_response: bytes) -> None:
        prior = self._raw_responses.setdefault(reference, raw_response)
        if prior != raw_response:  # pragma: no cover - SHA-256 identity guards this branch
            raise M8FeishuConformanceAdapterError(
                M8FeishuConformanceAdapterFailureCode.RAW_RESPONSE_NOT_FOUND
            )


__all__ = ["DeterministicOfflineFeishuConformanceAdapter"]
