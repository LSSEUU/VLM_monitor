"""Activated Feishu sandbox send orchestration with ephemeral secrets and token cache."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_feishu_notification import M8FeishuCardDispatchPreflightV1
from labcourt.contracts.m8_feishu_transport import (
    M8FeishuSandboxSendOutcome,
    M8FeishuSandboxSendReceiptV1,
    M8FeishuTokenAcquisitionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelFailureCode,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchResultV1,
)
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_feishu_activation_repository import M8FeishuActivationRepository
from labcourt.ports.m8_feishu_http import (
    M8FeishuHttpCallStage,
    M8FeishuHttpError,
    M8FeishuHttpFailureCode,
    M8FeishuHttpResponse,
    M8FeishuHttpTransport,
)
from labcourt.ports.m8_feishu_secrets import (
    M8FeishuResolvedSecrets,
    M8FeishuSecretResolver,
)

_TOKEN_EXPIRY_SKEW = timedelta(seconds=60)


class _TokenWire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    code: StrictInt
    msg: StrictStr | None = None
    tenant_access_token: StrictStr | None = None
    expire: StrictInt | None = None


@dataclass(slots=True)
class _CachedToken:
    token: bytearray
    receipt: M8FeishuTokenAcquisitionReceiptV1

    def close(self) -> None:
        self.token[:] = b"\x00" * len(self.token)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu {name} must be lowercase SHA-256 hex")
    return value


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu {name} must be timezone-aware UTC")
    return value


class M8FeishuSandboxSendService:
    """Perform one activated sandbox attempt without mutating notification state."""

    def __init__(
        self,
        activation_repository: M8FeishuActivationRepository,
        secret_resolver: M8FeishuSecretResolver,
        http_transport: M8FeishuHttpTransport,
        clock: Callable[[], datetime],
        token_manifest_id: Sha256Hex,
        dispatch_result_manifest_id: Sha256Hex,
        send_manifest_id: Sha256Hex,
    ) -> None:
        if activation_repository is None or secret_resolver is None or http_transport is None:
            raise TypeError("M8 Feishu sandbox send requires explicit ports")
        if not callable(clock):
            raise TypeError("M8 Feishu sandbox send requires a clock")
        self._activations = activation_repository
        self._secrets = secret_resolver
        self._http = http_transport
        self._clock = clock
        self._token_manifest_id = _validate_sha256(token_manifest_id, "token manifest")
        self._dispatch_manifest_id = _validate_sha256(
            dispatch_result_manifest_id,
            "dispatch result manifest",
        )
        self._send_manifest_id = _validate_sha256(send_manifest_id, "send manifest")
        self._token_cache: dict[str, _CachedToken] = {}
        self._raw_responses: dict[str, bytes] = {}
        self._lock = RLock()

    def send(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
    ) -> M8FeishuSandboxSendReceiptV1:
        return self._send(preflight, rendered_card, None)

    def send_authorized(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
        dispatch_authorization_id: str,
    ) -> M8FeishuSandboxSendReceiptV1:
        authorization = _validate_sha256(
            dispatch_authorization_id,
            "dispatch authorization",
        )
        return self._send(preflight, rendered_card, authorization)

    def _send(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
        dispatch_authorization_id: str | None,
    ) -> M8FeishuSandboxSendReceiptV1:
        if not isinstance(preflight, M8FeishuCardDispatchPreflightV1):
            raise TypeError("M8 Feishu sandbox send requires a typed preflight")
        if not isinstance(rendered_card, bytes):
            raise TypeError("M8 Feishu sandbox send card must be exact bytes")
        self._validate_card(preflight, rendered_card)
        started_at = _require_utc(self._clock(), "send started_at")
        candidate_id = preflight.profile.candidate.candidate_authority_id
        status = self._activations.get_current_status(candidate_id, started_at)
        runtime = status.activation_receipt.runtime_config
        if (
            not status.sandbox_external_call_permitted
            or runtime.profile != preflight.profile
            or preflight.recipient_binding not in runtime.recipient_allowlist
            or (
                dispatch_authorization_id is not None
                and status.activation_receipt.activation_commit_id != dispatch_authorization_id
            )
        ):
            raise ConcurrentModification("M8 Feishu sandbox activation is not current")

        with self._secrets.resolve(preflight.profile, preflight.recipient_binding) as secrets:
            self._validate_secrets(preflight, secrets)
            token, token_receipt, cache_hit, failure = self._resolve_token(
                preflight,
                secrets,
                started_at,
            )
            if failure is not None:
                outcome, response, raw_response = failure
                token_wire = self._parse_token_wire(response.body) if response is not None else None
                return self._build_send_receipt(
                    preflight,
                    status,
                    outcome,
                    None,
                    False,
                    False,
                    response,
                    raw_response,
                    _require_utc(self._clock(), "send completed_at"),
                    provider_code=token_wire.code if token_wire is not None else None,
                )
            if token is None or token_receipt is None:  # pragma: no cover - closed by tuple shape
                raise RuntimeError("M8 Feishu token resolution returned no authority")
            try:
                response = self._http.send_interactive_message(
                    preflight,
                    secrets,
                    token,
                    rendered_card,
                )
            except M8FeishuHttpError as error:
                if error.stage != M8FeishuHttpCallStage.MESSAGE:
                    raise ConcurrentModification("M8 Feishu HTTP stage mismatch") from error
                outcome = (
                    M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN
                    if error.failure_code == M8FeishuHttpFailureCode.TIMEOUT
                    else M8FeishuSandboxSendOutcome.MESSAGE_TRANSPORT_UNKNOWN
                )
                raw_response = self._transport_failure_raw(error)
                return self._build_send_receipt(
                    preflight,
                    status,
                    outcome,
                    token_receipt,
                    cache_hit,
                    True,
                    None,
                    raw_response,
                    _require_utc(self._clock(), "send completed_at"),
                )
            outcome, provider_code, provider_message_id = self._parse_message_response(response)
            return self._build_send_receipt(
                preflight,
                status,
                outcome,
                token_receipt,
                cache_hit,
                True,
                response,
                response.body,
                _require_utc(self._clock(), "send completed_at"),
                provider_code=provider_code,
                provider_message_id=provider_message_id,
            )

    def read_raw_response(self, raw_response_ref: str) -> bytes:
        if not isinstance(raw_response_ref, str):
            raise TypeError("M8 Feishu raw response reference must be str")
        with self._lock:
            raw = self._raw_responses.get(raw_response_ref)
        if raw is None:
            raise EvidenceMissing("M8 Feishu sandbox raw response was not found")
        return raw

    def close(self) -> None:
        with self._lock:
            entries = tuple(self._token_cache.values())
            self._token_cache.clear()
        for entry in entries:
            entry.close()

    def _resolve_token(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        secrets: M8FeishuResolvedSecrets,
        acquired_at: datetime,
    ) -> tuple[
        bytes | None,
        M8FeishuTokenAcquisitionReceiptV1 | None,
        bool,
        tuple[
            M8FeishuSandboxSendOutcome,
            M8FeishuHttpResponse | None,
            bytes,
        ]
        | None,
    ]:
        profile = preflight.profile
        with self._lock:
            cached = self._token_cache.get(profile.profile_id)
            if cached is not None and acquired_at + _TOKEN_EXPIRY_SKEW < cached.receipt.expires_at:
                return bytes(cached.token), cached.receipt, True, None
            if cached is not None:
                cached.close()
                self._token_cache.pop(profile.profile_id, None)

            try:
                response = self._http.acquire_tenant_access_token(profile, secrets)
            except M8FeishuHttpError as error:
                if error.stage != M8FeishuHttpCallStage.TOKEN:
                    raise ConcurrentModification("M8 Feishu HTTP stage mismatch") from error
                outcome = (
                    M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT
                    if error.failure_code == M8FeishuHttpFailureCode.TIMEOUT
                    else M8FeishuSandboxSendOutcome.TOKEN_UNAVAILABLE
                )
                return None, None, False, (outcome, None, self._transport_failure_raw(error))

            token_wire = self._parse_token_wire(response.body)
            redacted = self._redact_token_response(response.body, token_wire)
            if token_wire is None:
                return (
                    None,
                    None,
                    False,
                    (
                        M8FeishuSandboxSendOutcome.TOKEN_RESPONSE_INVALID,
                        response,
                        redacted,
                    ),
                )
            if token_wire.code != 0:
                return (
                    None,
                    None,
                    False,
                    (M8FeishuSandboxSendOutcome.TOKEN_REJECTED, response, redacted),
                )
            if (
                token_wire.tenant_access_token is None
                or token_wire.expire is None
                or not 60 <= token_wire.expire <= 86_400
                or response.status_code != 200
                or response.provider_log_id is None
            ):
                return (
                    None,
                    None,
                    False,
                    (
                        M8FeishuSandboxSendOutcome.TOKEN_RESPONSE_INVALID,
                        response,
                        redacted,
                    ),
                )
            token_bytes = token_wire.tenant_access_token.encode("utf-8")
            if not token_bytes or len(token_bytes) > 8_192:
                return (
                    None,
                    None,
                    False,
                    (
                        M8FeishuSandboxSendOutcome.TOKEN_RESPONSE_INVALID,
                        response,
                        redacted,
                    ),
                )
            raw_ref, raw_sha = self._store_raw(redacted, "token-redacted")
            receipt = M8FeishuTokenAcquisitionReceiptV1(
                profile_id=profile.profile_id,
                credential_bundle_reference_id=profile.credential_bundle_reference_id,
                app_id_sha256=profile.app_id_sha256,
                tenant_access_token_sha256=hashlib.sha256(token_bytes).hexdigest(),
                acquired_at=acquired_at,
                expires_at=acquired_at + timedelta(seconds=token_wire.expire),
                provider_log_id=response.provider_log_id,
                redacted_raw_response_ref=raw_ref,
                redacted_raw_response_sha256=raw_sha,
                redacted_raw_response_size_bytes=len(redacted),
                token_manifest_id=self._token_manifest_id,
            )
            self._token_cache[profile.profile_id] = _CachedToken(bytearray(token_bytes), receipt)
            return token_bytes, receipt, False, None

    def _build_send_receipt(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        status: M8FeishuSandboxActivationStatusV1,
        outcome: M8FeishuSandboxSendOutcome,
        token_receipt: M8FeishuTokenAcquisitionReceiptV1 | None,
        token_cache_hit: bool,
        message_request_attempted: bool,
        response: M8FeishuHttpResponse | None,
        raw_response: bytes,
        completed_at: datetime,
        *,
        provider_code: int | None = None,
        provider_message_id: str | None = None,
    ) -> M8FeishuSandboxSendReceiptV1:
        raw_ref, raw_sha = self._store_raw(raw_response, "send")
        disposition, failure_code = self._dispatch_shape(outcome)
        result = M8NotificationDispatchResultV1(
            request=preflight.notification_request,
            disposition=disposition,
            provider_receipt_id=provider_message_id,
            raw_response_ref=raw_ref,
            raw_response_sha256=raw_sha,
            failure_code=failure_code,
            completed_at=completed_at,
            result_manifest_id=self._dispatch_manifest_id,
        )
        return M8FeishuSandboxSendReceiptV1(
            preflight=preflight,
            activation_status=status,
            outcome=outcome,
            token_acquisition_receipt=token_receipt,
            token_cache_hit=token_cache_hit,
            message_request_attempted=message_request_attempted,
            provider_http_status=response.status_code if response is not None else None,
            provider_code=provider_code,
            provider_log_id=response.provider_log_id if response is not None else None,
            dispatch_result=result,
            raw_response_size_bytes=len(raw_response),
            send_manifest_id=self._send_manifest_id,
        )

    @staticmethod
    def _dispatch_shape(
        outcome: M8FeishuSandboxSendOutcome,
    ) -> tuple[M8NotificationDispatchDisposition, M8NotificationChannelFailureCode | None]:
        if outcome == M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED:
            return M8NotificationDispatchDisposition.ACCEPTED, None
        if outcome in {
            M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN,
            M8FeishuSandboxSendOutcome.MESSAGE_TRANSPORT_UNKNOWN,
        }:
            return (
                M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
                M8NotificationChannelFailureCode.UNKNOWN_DELIVERY,
            )
        if outcome == M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID:
            return (
                M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
                M8NotificationChannelFailureCode.RECEIPT_INVALID,
            )
        failure = {
            M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT: (
                M8NotificationChannelFailureCode.CHANNEL_TIMEOUT
            ),
            M8FeishuSandboxSendOutcome.TOKEN_UNAVAILABLE: (
                M8NotificationChannelFailureCode.CHANNEL_UNAVAILABLE
            ),
            M8FeishuSandboxSendOutcome.TOKEN_RESPONSE_INVALID: (
                M8NotificationChannelFailureCode.RECEIPT_INVALID
            ),
        }.get(outcome, M8NotificationChannelFailureCode.CHANNEL_REJECTED)
        return M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT, failure

    @staticmethod
    def _parse_token_wire(raw: bytes) -> _TokenWire | None:
        try:
            return _TokenWire.model_validate_json(raw)
        except ValidationError:
            return None

    @staticmethod
    def _redact_token_response(raw: bytes, wire: _TokenWire | None) -> bytes:
        payload: dict[str, object] = {
            "original_response_sha256": hashlib.sha256(raw).hexdigest(),
            "original_response_size_bytes": len(raw),
            "raw_response_redacted": True,
        }
        if wire is not None:
            payload["code"] = wire.code
            payload["msg"] = wire.msg
            payload["expire"] = wire.expire
            if wire.tenant_access_token is not None:
                payload["tenant_access_token_sha256"] = hashlib.sha256(
                    wire.tenant_access_token.encode("utf-8")
                ).hexdigest()
        return (canonical_json(payload) + "\n").encode("utf-8")

    @staticmethod
    def _parse_message_response(
        response: M8FeishuHttpResponse,
    ) -> tuple[M8FeishuSandboxSendOutcome, int | None, str | None]:
        try:
            payload = json.loads(response.body.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID, None, None
        if not isinstance(payload, dict) or set(payload) - {"code", "msg", "data"}:
            return M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID, None, None
        code = payload.get("code")
        if not isinstance(code, int) or isinstance(code, bool):
            return M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID, None, None
        if code == 0:
            data = payload.get("data")
            message_id = data.get("message_id") if isinstance(data, dict) else None
            if (
                response.status_code != 200
                or response.provider_log_id is None
                or not isinstance(message_id, str)
                or not message_id
            ):
                return M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID, code, None
            return M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED, code, message_id
        if code == 230035:
            if response.status_code != 400 or response.provider_log_id is None:
                return M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID, code, None
            return M8FeishuSandboxSendOutcome.MESSAGE_PERMISSION_DENIED, code, None
        if code == 230020:
            if response.status_code != 400 or response.provider_log_id is None:
                return M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID, code, None
            return M8FeishuSandboxSendOutcome.MESSAGE_RATE_LIMITED, code, None
        return M8FeishuSandboxSendOutcome.MESSAGE_REJECTED, code, None

    @staticmethod
    def _validate_card(
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
    ) -> None:
        if (
            rendered_card != preflight.card.provider_content_json.encode("utf-8")
            or hashlib.sha256(rendered_card).hexdigest() != preflight.card.provider_content_sha256
        ):
            raise ConcurrentModification("M8 Feishu sandbox card bytes changed after preflight")

    @staticmethod
    def _validate_secrets(
        preflight: M8FeishuCardDispatchPreflightV1,
        secrets: M8FeishuResolvedSecrets,
    ) -> None:
        if (
            secrets.profile_id != preflight.profile.profile_id
            or secrets.binding_authority_id != preflight.recipient_binding.binding_authority_id
            or secrets.credential_bundle_reference_id
            != preflight.profile.credential_bundle_reference_id
            or not hmac.compare_digest(
                hashlib.sha256(secrets.app_id_bytes()).hexdigest(),
                preflight.profile.app_id_sha256,
            )
            or not hmac.compare_digest(
                hashlib.sha256(secrets.open_id_bytes()).hexdigest(),
                preflight.recipient_binding.receive_id_sha256,
            )
        ):
            raise ConcurrentModification("M8 Feishu resolved secret authority mismatch")

    @staticmethod
    def _transport_failure_raw(error: M8FeishuHttpError) -> bytes:
        return (
            canonical_json(
                {
                    "delivery_certainty": error.delivery_certainty.value,
                    "failure_code": error.failure_code.value,
                    "provider_response_received": False,
                    "schema_version": "m8-feishu-http-failure-v1",
                    "stage": error.stage.value,
                }
            )
            + "\n"
        ).encode("utf-8")

    def _store_raw(self, raw: bytes, kind: str) -> tuple[str, str]:
        if not isinstance(raw, bytes) or not raw or len(raw) > 256 * 1024:
            raise ConcurrentModification("M8 Feishu raw response is outside its bound")
        sha = hashlib.sha256(raw).hexdigest()
        prefix = f"m8-feishu-{kind}-"
        ref = f"{prefix}{sha[: 64 - len(prefix)]}"
        with self._lock:
            prior = self._raw_responses.setdefault(ref, raw)
            if prior != raw:  # pragma: no cover - SHA-256 reference guards this branch
                raise ConcurrentModification("M8 Feishu raw response identity conflicts")
        return ref, sha


__all__ = ["M8FeishuSandboxSendService"]
