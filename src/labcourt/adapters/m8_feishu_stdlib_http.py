"""Verified-TLS single-attempt stdlib HTTP transport for Feishu sandbox calls."""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Callable, Mapping
from types import TracebackType
from typing import Protocol, cast

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_notification import (
    MAX_M8_FEISHU_RAW_RESPONSE_BYTES,
    M8FeishuAdapterProfileV1,
    M8FeishuCardDispatchPreflightV1,
)
from labcourt.ports.m8_feishu_http import (
    M8FeishuHttpCallStage,
    M8FeishuHttpDeliveryCertainty,
    M8FeishuHttpError,
    M8FeishuHttpFailureCode,
    M8FeishuHttpResponse,
)
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets

_FEISHU_HOST = "open.feishu.cn"


class _HTTPSResponse(Protocol):
    status: int

    def read(self, amount: int) -> bytes: ...

    def getheader(self, name: str, default: str | None = None) -> str | None: ...


class _HTTPSConnection(Protocol):
    def request(
        self,
        method: str,
        target: str,
        body: bytes,
        headers: Mapping[str, str],
    ) -> None: ...

    def getresponse(self) -> _HTTPSResponse: ...

    def close(self) -> None: ...

    def __enter__(self) -> _HTTPSConnection: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


ConnectionFactory = Callable[..., _HTTPSConnection]


def _default_connection_factory(
    host: str,
    port: int | None,
    *,
    timeout: float,
    context: ssl.SSLContext,
) -> _HTTPSConnection:
    return cast(
        _HTTPSConnection,
        http.client.HTTPSConnection(host, port, timeout=timeout, context=context),
    )


def _decode_secret(value: bytes, stage: M8FeishuHttpCallStage) -> str:
    try:
        decoded = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise M8FeishuHttpError(
            stage,
            M8FeishuHttpFailureCode.TRANSPORT_UNAVAILABLE,
            _certainty(stage),
        ) from None
    if not decoded or any(character.isspace() or ord(character) < 0x20 for character in decoded):
        raise M8FeishuHttpError(
            stage,
            M8FeishuHttpFailureCode.TRANSPORT_UNAVAILABLE,
            _certainty(stage),
        )
    return decoded


def _certainty(stage: M8FeishuHttpCallStage) -> M8FeishuHttpDeliveryCertainty:
    return (
        M8FeishuHttpDeliveryCertainty.DEFINITELY_NOT_SENT
        if stage == M8FeishuHttpCallStage.TOKEN
        else M8FeishuHttpDeliveryCertainty.UNKNOWN
    )


class StdlibM8FeishuHttpTransport:
    """Perform exact pinned Feishu POSTs with verified TLS and no retries."""

    __slots__ = ("_connection_factory",)

    def __init__(self, connection_factory: ConnectionFactory | None = None) -> None:
        self._connection_factory = connection_factory or _default_connection_factory

    def __repr__(self) -> str:
        return "StdlibM8FeishuHttpTransport(host=open.feishu.cn, verified_tls=True, retry_count=0)"

    def acquire_tenant_access_token(
        self,
        profile: M8FeishuAdapterProfileV1,
        secrets: M8FeishuResolvedSecrets,
    ) -> M8FeishuHttpResponse:
        self._validate_profile(profile)
        body = (
            canonical_json(
                {
                    "app_id": _decode_secret(secrets.app_id_bytes(), M8FeishuHttpCallStage.TOKEN),
                    "app_secret": _decode_secret(
                        secrets.app_secret_bytes(), M8FeishuHttpCallStage.TOKEN
                    ),
                }
            )
            + "\n"
        ).encode("utf-8")
        return self._post(
            profile.token_path,
            body,
            {"Accept": "application/json", "Content-Type": "application/json"},
            profile.candidate.request_timeout_ms,
            M8FeishuHttpCallStage.TOKEN,
        )

    def send_interactive_message(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        secrets: M8FeishuResolvedSecrets,
        tenant_access_token: bytes,
        rendered_card: bytes,
    ) -> M8FeishuHttpResponse:
        if not isinstance(preflight, M8FeishuCardDispatchPreflightV1):
            raise TypeError("M8 Feishu HTTP message requires a typed preflight")
        if not isinstance(rendered_card, bytes):
            raise TypeError("M8 Feishu HTTP message card must be bytes")
        self._validate_profile(preflight.profile)
        token = _decode_secret(tenant_access_token, M8FeishuHttpCallStage.MESSAGE)
        open_id = _decode_secret(secrets.open_id_bytes(), M8FeishuHttpCallStage.MESSAGE)
        try:
            card_content = rendered_card.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise M8FeishuHttpError(
                M8FeishuHttpCallStage.MESSAGE,
                M8FeishuHttpFailureCode.TRANSPORT_UNAVAILABLE,
                M8FeishuHttpDeliveryCertainty.UNKNOWN,
            ) from None
        body = (
            canonical_json(
                {
                    "content": card_content,
                    "msg_type": "interactive",
                    "receive_id": open_id,
                    "uuid": preflight.provider_uuid,
                }
            )
            + "\n"
        ).encode("utf-8")
        target = (
            f"{preflight.profile.message_path}?receive_id_type={preflight.profile.receive_id_type}"
        )
        return self._post(
            target,
            body,
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            preflight.notification_request.timeout_ms,
            M8FeishuHttpCallStage.MESSAGE,
        )

    @staticmethod
    def _validate_profile(profile: M8FeishuAdapterProfileV1) -> None:
        if not isinstance(profile, M8FeishuAdapterProfileV1):
            raise TypeError("M8 Feishu HTTP requires a typed profile")
        if profile.api_origin != f"https://{_FEISHU_HOST}":
            raise M8FeishuHttpError(
                M8FeishuHttpCallStage.TOKEN,
                M8FeishuHttpFailureCode.TLS_FAILED,
                M8FeishuHttpDeliveryCertainty.DEFINITELY_NOT_SENT,
            )

    def _post(
        self,
        target: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_ms: int,
        stage: M8FeishuHttpCallStage,
    ) -> M8FeishuHttpResponse:
        certainty = _certainty(stage)
        context = ssl.create_default_context()
        connection: _HTTPSConnection | None = None
        try:
            connection = self._connection_factory(
                _FEISHU_HOST,
                443,
                timeout=timeout_ms / 1_000,
                context=context,
            )
            connection.request("POST", target, body, headers)
            response = connection.getresponse()
            response_body = response.read(MAX_M8_FEISHU_RAW_RESPONSE_BYTES + 1)
            if not isinstance(response_body, bytes):
                raise M8FeishuHttpError(
                    stage,
                    M8FeishuHttpFailureCode.TRANSPORT_UNAVAILABLE,
                    certainty,
                )
            if len(response_body) > MAX_M8_FEISHU_RAW_RESPONSE_BYTES:
                raise M8FeishuHttpError(
                    stage,
                    M8FeishuHttpFailureCode.RESPONSE_TOO_LARGE,
                    certainty,
                )
            log_id = response.getheader("x-tt-logid")
            return M8FeishuHttpResponse(response.status, response_body, log_id)
        except M8FeishuHttpError:
            raise
        except TimeoutError:
            raise M8FeishuHttpError(
                stage,
                M8FeishuHttpFailureCode.TIMEOUT,
                certainty,
            ) from None
        except ssl.SSLError:
            raise M8FeishuHttpError(
                stage,
                M8FeishuHttpFailureCode.TLS_FAILED,
                certainty,
            ) from None
        except (OSError, http.client.HTTPException, UnicodeError, ValueError):
            raise M8FeishuHttpError(
                stage,
                M8FeishuHttpFailureCode.TRANSPORT_UNAVAILABLE,
                certainty,
            ) from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except (OSError, http.client.HTTPException):
                    raise M8FeishuHttpError(
                        stage,
                        M8FeishuHttpFailureCode.TRANSPORT_UNAVAILABLE,
                        certainty,
                    ) from None


__all__ = ["ConnectionFactory", "StdlibM8FeishuHttpTransport"]
