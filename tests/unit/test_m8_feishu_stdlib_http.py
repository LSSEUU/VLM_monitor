from __future__ import annotations

import json
import ssl
from collections.abc import Mapping

import pytest

from labcourt.adapters.m8_feishu_stdlib_http import StdlibM8FeishuHttpTransport
from labcourt.contracts.m8_feishu_notification import MAX_M8_FEISHU_RAW_RESPONSE_BYTES
from labcourt.ports.m8_feishu_http import (
    M8FeishuHttpCallStage,
    M8FeishuHttpDeliveryCertainty,
    M8FeishuHttpError,
    M8FeishuHttpFailureCode,
)
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets
from tests.contract.test_m8_feishu_notification_contracts import (
    FAKE_FEISHU_APP_ID,
    FAKE_FEISHU_OPEN_ID,
    _preflight,
    _profile,
)

FAKE_APP_SECRET = b"fake_labcourt_feishu_app_secret"
FAKE_TOKEN = b"t-fake-labcourt-token"


class _Response:
    def __init__(
        self,
        body: bytes = b'{"code":0}\n',
        *,
        status: int = 200,
        log_id: str | None = "fake-provider-log-01",
    ) -> None:
        self.status = status
        self.body = body
        self.log_id = log_id
        self.read_amounts: list[int] = []

    def read(self, amount: int) -> bytes:
        self.read_amounts.append(amount)
        return self.body[:amount]

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.log_id if name.lower() == "x-tt-logid" else default


class _Connection:
    def __init__(
        self,
        response: _Response,
        *,
        request_error: BaseException | None = None,
    ) -> None:
        self.response = response
        self.request_error = request_error
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.close_count = 0

    def request(
        self,
        method: str,
        target: str,
        body: bytes,
        headers: Mapping[str, str],
    ) -> None:
        self.requests.append((method, target, body, dict(headers)))
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.close_count += 1


class _ConnectionFactory:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.calls: list[tuple[str, int | None, float, ssl.SSLContext]] = []

    def __call__(
        self,
        host: str,
        port: int | None,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _Connection:
        self.calls.append((host, port, timeout, context))
        return self.connection


def _secrets() -> M8FeishuResolvedSecrets:
    return M8FeishuResolvedSecrets(
        profile_id=_profile().profile_id,
        binding_authority_id=_preflight().recipient_binding.binding_authority_id,
        credential_bundle_reference_id=_profile().credential_bundle_reference_id,
        app_id=FAKE_FEISHU_APP_ID,
        app_secret=FAKE_APP_SECRET,
        open_id=FAKE_FEISHU_OPEN_ID,
    )


def test_token_call_is_pinned_to_verified_tls_and_exact_single_post() -> None:
    response = _Response()
    connection = _Connection(response)
    factory = _ConnectionFactory(connection)
    transport = StdlibM8FeishuHttpTransport(factory)

    with _secrets() as secrets:
        result = transport.acquire_tenant_access_token(_profile(), secrets)

    assert result.status_code == 200
    assert result.provider_log_id == "fake-provider-log-01"
    assert len(factory.calls) == 1
    host, port, timeout, context = factory.calls[0]
    assert (host, port, timeout) == ("open.feishu.cn", 443, 5.0)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert len(connection.requests) == 1
    method, target, body, headers = connection.requests[0]
    assert method == "POST"
    assert target == "/open-apis/auth/v3/tenant_access_token/internal"
    assert headers == {"Accept": "application/json", "Content-Type": "application/json"}
    assert json.loads(body) == {
        "app_id": FAKE_FEISHU_APP_ID.decode(),
        "app_secret": FAKE_APP_SECRET.decode(),
    }
    assert response.read_amounts == [MAX_M8_FEISHU_RAW_RESPONSE_BYTES + 1]
    assert connection.close_count == 1
    assert "retry_count=0" in repr(transport)
    assert "fake_" not in repr(transport)


def test_message_call_uses_open_id_card_and_notification_idempotency_key() -> None:
    response = _Response(b'{"code":0,"data":{"message_id":"om-fake"}}\n')
    connection = _Connection(response)
    factory = _ConnectionFactory(connection)
    transport = StdlibM8FeishuHttpTransport(factory)
    preflight = _preflight()

    with _secrets() as secrets:
        result = transport.send_interactive_message(
            preflight,
            secrets,
            FAKE_TOKEN,
            preflight.card.provider_content_json.encode(),
        )

    assert result.status_code == 200
    assert len(connection.requests) == 1
    method, target, body, headers = connection.requests[0]
    assert method == "POST"
    assert target == "/open-apis/im/v1/messages?receive_id_type=open_id"
    assert headers["Authorization"] == f"Bearer {FAKE_TOKEN.decode()}"
    assert json.loads(body) == {
        "content": preflight.card.provider_content_json,
        "msg_type": "interactive",
        "receive_id": FAKE_FEISHU_OPEN_ID.decode(),
        "uuid": preflight.provider_uuid,
    }
    assert factory.calls[0][2] == preflight.notification_request.timeout_ms / 1_000
    assert connection.close_count == 1


def test_agent_reply_uses_exact_inbound_message_and_single_text_post() -> None:
    connection = _Connection(_Response(b'{"code":0,"data":{"message_id":"om-reply"}}'))
    transport = StdlibM8FeishuHttpTransport(_ConnectionFactory(connection))

    result = transport.send_text_reply(
        _profile(),
        FAKE_TOKEN,
        "om-inbound-01",
        "reply-authority-01",
        "已根据平台可信工具完成查询。",
        10_000,
    )

    assert result.status_code == 200
    assert len(connection.requests) == 1
    method, target, body, headers = connection.requests[0]
    assert method == "POST"
    assert target == "/open-apis/im/v1/messages/om-inbound-01/reply"
    assert headers["Authorization"] == f"Bearer {FAKE_TOKEN.decode()}"
    payload = json.loads(body)
    assert payload["msg_type"] == "text"
    assert json.loads(payload["content"])["text"] == "已根据平台可信工具完成查询。"
    assert payload["uuid"] == "reply-authority-01"


@pytest.mark.parametrize(
    ("stage", "failure", "certainty"),
    [
        (
            M8FeishuHttpCallStage.TOKEN,
            TimeoutError(),
            M8FeishuHttpDeliveryCertainty.DEFINITELY_NOT_SENT,
        ),
        (
            M8FeishuHttpCallStage.MESSAGE,
            TimeoutError(),
            M8FeishuHttpDeliveryCertainty.UNKNOWN,
        ),
        (
            M8FeishuHttpCallStage.MESSAGE,
            ssl.SSLError("fake TLS failure"),
            M8FeishuHttpDeliveryCertainty.UNKNOWN,
        ),
    ],
)
def test_transport_maps_failure_without_retrying(
    stage: M8FeishuHttpCallStage,
    failure: BaseException,
    certainty: M8FeishuHttpDeliveryCertainty,
) -> None:
    connection = _Connection(_Response(), request_error=failure)
    factory = _ConnectionFactory(connection)
    transport = StdlibM8FeishuHttpTransport(factory)

    with _secrets() as secrets, pytest.raises(M8FeishuHttpError) as raised:
        if stage == M8FeishuHttpCallStage.TOKEN:
            transport.acquire_tenant_access_token(_profile(), secrets)
        else:
            preflight = _preflight()
            transport.send_interactive_message(
                preflight,
                secrets,
                FAKE_TOKEN,
                preflight.card.provider_content_json.encode(),
            )

    assert raised.value.stage == stage
    assert raised.value.failure_code == (
        M8FeishuHttpFailureCode.TLS_FAILED
        if isinstance(failure, ssl.SSLError)
        else M8FeishuHttpFailureCode.TIMEOUT
    )
    assert raised.value.delivery_certainty == certainty
    assert len(factory.calls) == 1
    assert len(connection.requests) == 1
    assert connection.close_count == 1


def test_transport_rejects_oversized_response_without_second_read_or_retry() -> None:
    response = _Response(b"x" * (MAX_M8_FEISHU_RAW_RESPONSE_BYTES + 1))
    connection = _Connection(response)
    factory = _ConnectionFactory(connection)
    transport = StdlibM8FeishuHttpTransport(factory)

    with _secrets() as secrets, pytest.raises(M8FeishuHttpError) as raised:
        transport.acquire_tenant_access_token(_profile(), secrets)

    assert raised.value.failure_code == M8FeishuHttpFailureCode.RESPONSE_TOO_LARGE
    assert raised.value.delivery_certainty == M8FeishuHttpDeliveryCertainty.DEFINITELY_NOT_SENT
    assert len(factory.calls) == 1
    assert len(connection.requests) == 1
    assert response.read_amounts == [MAX_M8_FEISHU_RAW_RESPONSE_BYTES + 1]


def test_message_encoding_failure_is_typed_and_never_opens_a_connection() -> None:
    connection = _Connection(_Response())
    factory = _ConnectionFactory(connection)
    transport = StdlibM8FeishuHttpTransport(factory)

    with _secrets() as secrets, pytest.raises(M8FeishuHttpError) as raised:
        transport.send_interactive_message(_preflight(), secrets, FAKE_TOKEN, b"\xff")

    assert raised.value.stage == M8FeishuHttpCallStage.MESSAGE
    assert raised.value.failure_code == M8FeishuHttpFailureCode.TRANSPORT_UNAVAILABLE
    assert raised.value.delivery_certainty == M8FeishuHttpDeliveryCertainty.UNKNOWN
    assert factory.calls == []
