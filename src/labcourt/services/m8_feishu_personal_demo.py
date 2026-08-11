"""Isolated static-card connectivity probe for a Feishu enterprise app."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_personal_demo import (
    M8FeishuPersonalDemoOutcome,
    M8FeishuPersonalDemoProbeReceiptV1,
    M8FeishuPersonalDemoProbeV1,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m8_feishu_http import (
    M8FeishuHttpCallStage,
    M8FeishuHttpError,
    M8FeishuHttpResponse,
)
from labcourt.ports.m8_feishu_personal_demo import M8FeishuPersonalDemoHttpTransport


class _TokenWire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    code: StrictInt
    msg: StrictStr | None = None
    tenant_access_token: StrictStr | None = None
    expire: StrictInt | None = None


@dataclass(frozen=True, slots=True)
class M8FeishuPersonalDemoRun:
    receipt: M8FeishuPersonalDemoProbeReceiptV1
    raw_artifacts: tuple[tuple[str, bytes], ...]


def _raw_reference(kind: str, raw: bytes) -> str:
    return f"m8-feishu-personal-demo-{kind}-{hashlib.sha256(raw).hexdigest()[:40]}"


def _transport_raw(error: M8FeishuHttpError) -> bytes:
    return (
        canonical_json(
            {
                "delivery_certainty": error.delivery_certainty.value,
                "failure_code": error.failure_code.value,
                "stage": error.stage.value,
            }
        )
        + "\n"
    ).encode("utf-8")


def _parse_token(raw: bytes) -> _TokenWire | None:
    try:
        return _TokenWire.model_validate_json(raw)
    except (UnicodeDecodeError, ValidationError):
        return None


def _redact_token(raw: bytes, token: _TokenWire | None) -> bytes:
    payload: dict[str, object] = {
        "original_response_sha256": hashlib.sha256(raw).hexdigest(),
        "original_response_size_bytes": len(raw),
        "raw_response_redacted": True,
    }
    if token is not None:
        payload.update({"code": token.code, "expire": token.expire, "msg": token.msg})
        if token.tenant_access_token is not None:
            payload["tenant_access_token_sha256"] = hashlib.sha256(
                token.tenant_access_token.encode("utf-8")
            ).hexdigest()
    return (canonical_json(payload) + "\n").encode("utf-8")


def _parse_message(response: M8FeishuHttpResponse) -> tuple[int | None, str | None]:
    try:
        payload = json.loads(response.body.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None
    if not isinstance(payload, dict) or set(payload) - {"code", "msg", "data"}:
        return None, None
    code = payload.get("code")
    if not isinstance(code, int) or isinstance(code, bool):
        return None, None
    data = payload.get("data")
    message_id = data.get("message_id") if isinstance(data, dict) else None
    return code, message_id if isinstance(message_id, str) and message_id else None


class M8FeishuPersonalDemoService:
    def __init__(
        self,
        transport: M8FeishuPersonalDemoHttpTransport,
        clock: Callable[[], datetime],
    ) -> None:
        if transport is None or not callable(clock):
            raise TypeError("M8 Feishu personal demo requires explicit ports")
        self._transport = transport
        self._clock = clock

    def check(
        self,
        probe: M8FeishuPersonalDemoProbeV1,
        app_id: bytes,
        app_secret: bytes,
        open_id: bytes,
    ) -> M8FeishuPersonalDemoRun:
        self._validate_inputs(probe, app_id, app_secret, open_id)
        return M8FeishuPersonalDemoRun(
            M8FeishuPersonalDemoProbeReceiptV1(
                probe=probe,
                outcome=M8FeishuPersonalDemoOutcome.CHECKED,
                completed_at=self._clock(),
                token_call_attempted=False,
                message_call_attempted=False,
            ),
            (),
        )

    def send(
        self,
        probe: M8FeishuPersonalDemoProbeV1,
        app_id: bytes,
        app_secret: bytes,
        open_id: bytes,
    ) -> M8FeishuPersonalDemoRun:
        self._validate_inputs(probe, app_id, app_secret, open_id)
        try:
            token_response = self._transport.acquire_personal_demo_token(
                app_id,
                app_secret,
                probe.timeout_ms,
            )
        except M8FeishuHttpError as error:
            if error.stage != M8FeishuHttpCallStage.TOKEN:
                raise ConcurrentModification("Feishu personal demo HTTP stage mismatch") from error
            return self._token_only(
                probe,
                M8FeishuPersonalDemoOutcome.TOKEN_TRANSPORT_FAILED,
                _transport_raw(error),
            )

        token = _parse_token(token_response.body)
        redacted_token = _redact_token(token_response.body, token)
        if token is None:
            return self._token_only(
                probe,
                M8FeishuPersonalDemoOutcome.TOKEN_RESPONSE_INVALID,
                redacted_token,
                token_response,
            )
        if (
            token.code != 0
            or token_response.status_code != 200
            or not token.tenant_access_token
            or token.expire is None
            or token.expire < 60
        ):
            return self._token_only(
                probe,
                M8FeishuPersonalDemoOutcome.TOKEN_REJECTED,
                redacted_token,
                token_response,
                token.code,
            )

        token_bytes = bytearray(token.tenant_access_token.encode("utf-8"))
        try:
            try:
                message_response = self._transport.send_personal_demo_card(
                    open_id,
                    bytes(token_bytes),
                    probe.provider_uuid,
                    probe.provider_content_json.encode("utf-8"),
                    probe.timeout_ms,
                )
            except M8FeishuHttpError as error:
                if error.stage != M8FeishuHttpCallStage.MESSAGE:
                    raise ConcurrentModification(
                        "Feishu personal demo HTTP stage mismatch"
                    ) from error
                return self._message_result(
                    probe,
                    M8FeishuPersonalDemoOutcome.MESSAGE_TRANSPORT_FAILED,
                    redacted_token,
                    _transport_raw(error),
                )
        finally:
            token_bytes[:] = b"\x00" * len(token_bytes)

        code, message_id = _parse_message(message_response)
        if code is None:
            outcome = M8FeishuPersonalDemoOutcome.MESSAGE_RESPONSE_INVALID
        elif (
            code == 0
            and message_response.status_code == 200
            and message_id is not None
        ):
            outcome = M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED
        else:
            outcome = M8FeishuPersonalDemoOutcome.MESSAGE_REJECTED
        return self._message_result(
            probe,
            outcome,
            redacted_token,
            message_response.body,
            message_response,
            code,
            message_id,
        )

    def _token_only(
        self,
        probe: M8FeishuPersonalDemoProbeV1,
        outcome: M8FeishuPersonalDemoOutcome,
        raw: bytes,
        response: M8FeishuHttpResponse | None = None,
        provider_code: int | None = None,
    ) -> M8FeishuPersonalDemoRun:
        reference = _raw_reference("token-redacted", raw)
        return M8FeishuPersonalDemoRun(
            M8FeishuPersonalDemoProbeReceiptV1(
                probe=probe,
                outcome=outcome,
                completed_at=self._clock(),
                token_call_attempted=True,
                message_call_attempted=False,
                provider_http_status=(response.status_code if response else None),
                provider_code=provider_code,
                provider_log_id=(response.provider_log_id if response else None),
                token_raw_response_ref=reference,
                token_raw_response_sha256=hashlib.sha256(raw).hexdigest(),
            ),
            ((reference, raw),),
        )

    def _message_result(
        self,
        probe: M8FeishuPersonalDemoProbeV1,
        outcome: M8FeishuPersonalDemoOutcome,
        token_raw: bytes,
        message_raw: bytes,
        response: M8FeishuHttpResponse | None = None,
        provider_code: int | None = None,
        provider_message_id: str | None = None,
    ) -> M8FeishuPersonalDemoRun:
        token_ref = _raw_reference("token-redacted", token_raw)
        message_ref = _raw_reference("message", message_raw)
        return M8FeishuPersonalDemoRun(
            M8FeishuPersonalDemoProbeReceiptV1(
                probe=probe,
                outcome=outcome,
                completed_at=self._clock(),
                token_call_attempted=True,
                message_call_attempted=True,
                provider_http_status=(response.status_code if response else None),
                provider_code=provider_code,
                provider_log_id=(response.provider_log_id if response else None),
                provider_message_id=provider_message_id,
                token_raw_response_ref=token_ref,
                token_raw_response_sha256=hashlib.sha256(token_raw).hexdigest(),
                message_raw_response_ref=message_ref,
                message_raw_response_sha256=hashlib.sha256(message_raw).hexdigest(),
            ),
            ((message_ref, message_raw), (token_ref, token_raw)),
        )

    @staticmethod
    def _validate_inputs(
        probe: M8FeishuPersonalDemoProbeV1,
        app_id: bytes,
        app_secret: bytes,
        open_id: bytes,
    ) -> None:
        if not isinstance(probe, M8FeishuPersonalDemoProbeV1):
            raise TypeError("M8 Feishu personal demo requires a typed probe")
        for value in (app_id, app_secret, open_id):
            if not isinstance(value, bytes) or not value or any(byte <= 0x20 for byte in value):
                raise ValueError("M8 Feishu personal demo credential bytes are invalid")
        if (
            hashlib.sha256(app_id).hexdigest() != probe.app_id_sha256
            or hashlib.sha256(open_id).hexdigest() != probe.recipient_open_id_sha256
        ):
            raise ConcurrentModification("M8 Feishu personal demo credential hash changed")


__all__ = ["M8FeishuPersonalDemoRun", "M8FeishuPersonalDemoService"]
