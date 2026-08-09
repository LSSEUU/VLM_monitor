from __future__ import annotations

import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest

from labcourt.adapters.vlm import (
    OpenAICompatibleTransportRequest,
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.http_transport import (
    OpenAICompatibleTransportConfigurationCode,
    OpenAICompatibleTransportConfigurationError,
    StdlibOpenAICompatibleTransport,
    build_openai_compatible_transport,
)
from labcourt.config_loader import load_config
from labcourt.contracts.config import VlmProviderProfile


@dataclass(slots=True)
class _Response:
    status: int = 200
    body: bytes = b'{"choices":[],"usage":{}}'
    read_limits: list[int] = field(default_factory=list)

    def read(self, amount: int) -> bytes:
        self.read_limits.append(amount)
        return self.body[:amount]


@dataclass(slots=True)
class _Connection:
    response: _Response
    failure: Exception | None = None
    close_failure: Exception | None = None
    requests: list[tuple[str, str, bytes, Mapping[str, str]]] = field(default_factory=list)
    closed: bool = False

    def request(
        self,
        method: str,
        target: str,
        body: bytes,
        headers: Mapping[str, str],
    ) -> None:
        self.requests.append((method, target, body, dict(headers)))
        if self.failure is not None:
            raise self.failure

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True
        if self.close_failure is not None:
            raise self.close_failure


@dataclass(slots=True)
class _Factory:
    connection: _Connection
    calls: list[tuple[str, int | None, float, ssl.SSLContext]] = field(default_factory=list)

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


def _profile() -> VlmProviderProfile:
    base = load_config("configs/default.yaml").providers["fake-screening"]
    return VlmProviderProfile.model_validate(
        {
            **base.model_dump(mode="json"),
            "provider": "openai-compatible",
            "model": "vision-model",
            "revision": "2026-08-01",
            "execution_location": "EXTERNAL",
            "transport": "HTTP",
            "endpoint_env": "LABCOURT_TEST_ENDPOINT",
            "api_key_env": "LABCOURT_TEST_API_KEY",
            "timeout_seconds": 12.0,
            "input_cost_per_million_tokens": 1.0,
            "output_cost_per_million_tokens": 2.0,
        }
    )


def _request(*, max_response_bytes: int = 128) -> OpenAICompatibleTransportRequest:
    return OpenAICompatibleTransportRequest(
        body=b'{"request":"bounded"}',
        timeout_seconds=4.0,
        max_response_bytes=max_response_bytes,
    )


def test_real_transport_uses_verified_tls_one_post_and_bounded_read() -> None:
    response = _Response(body=b'{"ok":true}')
    connection = _Connection(response=response)
    factory = _Factory(connection)
    transport = build_openai_compatible_transport(
        _profile(),
        environment={
            "LABCOURT_TEST_ENDPOINT": "https://vlm.invalid/v1/chat/completions?api-version=1",
            "LABCOURT_TEST_API_KEY": "test-secret-key",
        },
        connection_factory=factory,
    )

    result = transport.send(_request(max_response_bytes=64))

    assert result.body == response.body
    assert len(factory.calls) == 1
    host, port, timeout, context = factory.calls[0]
    assert (host, port, timeout) == ("vlm.invalid", None, 4.0)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert connection.requests == [
        (
            "POST",
            "/v1/chat/completions?api-version=1",
            b'{"request":"bounded"}',
            {
                "Accept": "application/json",
                "Authorization": "Bearer test-secret-key",
                "Content-Type": "application/json",
            },
        )
    ]
    assert response.read_limits == [65]
    assert connection.closed is True
    assert "test-secret-key" not in repr(transport)
    assert "vlm.invalid" not in repr(transport)


@pytest.mark.parametrize("status", [300, 400, 401, 429, 500, 503])
def test_real_transport_maps_non_2xx_without_reading_upstream_body(status: int) -> None:
    response = _Response(status=status, body=b"secret upstream error")
    connection = _Connection(response=response)
    transport = StdlibOpenAICompatibleTransport(
        endpoint="https://vlm.invalid/v1/chat/completions",
        api_key="secret",
        connection_factory=_Factory(connection),
    )

    with pytest.raises(VLMProviderError) as captured:
        transport.send(_request())

    assert captured.value.reason_code == VLMProviderFailureCode.PROVIDER_OUTAGE
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.UNKNOWN
    assert "upstream" not in str(captured.value)
    assert response.read_limits == []
    assert len(connection.requests) == 1
    assert connection.closed is True


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (TimeoutError("secret timeout detail"), VLMProviderFailureCode.PROVIDER_TIMEOUT),
        (OSError("secret network detail"), VLMProviderFailureCode.TRANSPORT_UNAVAILABLE),
    ],
)
def test_real_transport_maps_wire_failures_without_retry_or_secret_detail(
    failure: Exception,
    reason: VLMProviderFailureCode,
) -> None:
    connection = _Connection(response=_Response(), failure=failure)
    transport = StdlibOpenAICompatibleTransport(
        endpoint="https://vlm.invalid/v1/chat/completions",
        api_key="secret",
        connection_factory=_Factory(connection),
    )

    with pytest.raises(VLMProviderError) as captured:
        transport.send(_request())

    assert captured.value.reason_code == reason
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.UNKNOWN
    assert "secret" not in str(captured.value)
    assert len(connection.requests) == 1
    assert connection.closed is True


def test_real_transport_rejects_oversized_body_after_bounded_read() -> None:
    response = _Response(body=b"x" * 65)
    connection = _Connection(response=response)
    transport = StdlibOpenAICompatibleTransport(
        endpoint="https://vlm.invalid/v1/chat/completions",
        api_key="secret",
        connection_factory=_Factory(connection),
    )

    with pytest.raises(VLMProviderError) as captured:
        transport.send(_request(max_response_bytes=64))

    assert captured.value.reason_code == VLMProviderFailureCode.RESPONSE_TOO_LARGE
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
    assert response.read_limits == [65]


def test_real_transport_converts_close_failure_instead_of_swallowing_or_exposing_it() -> None:
    connection = _Connection(
        response=_Response(body=b"{}"),
        close_failure=RuntimeError("secret close detail"),
    )
    transport = StdlibOpenAICompatibleTransport(
        endpoint="https://vlm.invalid/v1/chat/completions",
        api_key="secret",
        connection_factory=_Factory(connection),
    )

    with pytest.raises(VLMProviderError) as captured:
        transport.send(_request())

    assert captured.value.reason_code == VLMProviderFailureCode.TRANSPORT_UNAVAILABLE
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.UNKNOWN
    assert "close detail" not in str(captured.value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://vlm.invalid/v1/chat/completions",
        "https://user:password@vlm.invalid/v1/chat/completions",
        "https://vlm.invalid/v1/chat/completions#fragment",
        "https://vlm.invalid/with\nnewline",
    ],
)
def test_real_transport_rejects_unsafe_endpoint_without_echoing_it(endpoint: str) -> None:
    with pytest.raises(OpenAICompatibleTransportConfigurationError) as captured:
        StdlibOpenAICompatibleTransport(endpoint=endpoint, api_key="secret")
    assert captured.value.code == OpenAICompatibleTransportConfigurationCode.ENDPOINT_INVALID
    assert endpoint not in str(captured.value)


@pytest.mark.parametrize(
    ("environment", "code"),
    [
        (
            {"LABCOURT_TEST_API_KEY": "secret"},
            OpenAICompatibleTransportConfigurationCode.ENDPOINT_ENV_MISSING,
        ),
        (
            {"LABCOURT_TEST_ENDPOINT": "https://vlm.invalid/v1/chat/completions"},
            OpenAICompatibleTransportConfigurationCode.API_KEY_ENV_MISSING,
        ),
    ],
)
def test_transport_factory_requires_deployment_values_without_exposing_environment(
    environment: Mapping[str, str],
    code: OpenAICompatibleTransportConfigurationCode,
) -> None:
    with pytest.raises(OpenAICompatibleTransportConfigurationError) as captured:
        build_openai_compatible_transport(_profile(), environment=environment)
    assert captured.value.code == code
    assert "LABCOURT_TEST" not in str(captured.value)
