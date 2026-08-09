"""Single-attempt HTTPS transport for OpenAI-compatible model endpoints."""

from __future__ import annotations

import http.client
import os
import ssl
from collections.abc import Callable, Mapping
from enum import StrEnum
from time import perf_counter
from types import TracebackType
from typing import Protocol, cast
from urllib.parse import SplitResult, urlsplit, urlunsplit

from labcourt.adapters.vlm.openai_compatible import (
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
)
from labcourt.contracts.config import VlmProviderProfile
from labcourt.contracts.enums import ExecutionLocation, ProviderTransport
from labcourt.exceptions import LabCourtError
from labcourt.ports.vlm import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)

_MAX_ENDPOINT_CHARS = 4_096
_MAX_API_KEY_CHARS = 8_192


class OpenAICompatibleTransportConfigurationCode(StrEnum):
    """Secret-free deployment failure codes for the HTTP adapter factory."""

    PROFILE_UNSUPPORTED = "PROFILE_UNSUPPORTED"
    ENDPOINT_ENV_MISSING = "ENDPOINT_ENV_MISSING"
    API_KEY_ENV_MISSING = "API_KEY_ENV_MISSING"
    ENDPOINT_INVALID = "ENDPOINT_INVALID"
    API_KEY_INVALID = "API_KEY_INVALID"


class OpenAICompatibleTransportConfigurationError(LabCourtError):
    """A controlled configuration error that never echoes deployment values."""

    def __init__(self, code: OpenAICompatibleTransportConfigurationCode) -> None:
        if not isinstance(code, OpenAICompatibleTransportConfigurationCode):
            raise TypeError("code must be an OpenAICompatibleTransportConfigurationCode")
        self.code = code
        super().__init__(f"OpenAI-compatible transport configuration failed: {code.value}")


class _HTTPSResponse(Protocol):
    status: int

    def read(self, amount: int) -> bytes: ...


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


def _configuration_failure(
    code: OpenAICompatibleTransportConfigurationCode,
) -> OpenAICompatibleTransportConfigurationError:
    return OpenAICompatibleTransportConfigurationError(code)


def _has_unsafe_character(value: str) -> bool:
    return any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    )


def _validated_endpoint(endpoint: str) -> tuple[str, int | None, str]:
    if (
        not isinstance(endpoint, str)
        or not endpoint
        or len(endpoint) > _MAX_ENDPOINT_CHARS
        or _has_unsafe_character(endpoint)
    ):
        raise _configuration_failure(OpenAICompatibleTransportConfigurationCode.ENDPOINT_INVALID)
    try:
        parsed: SplitResult = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise _configuration_failure(
            OpenAICompatibleTransportConfigurationCode.ENDPOINT_INVALID
        ) from None
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise _configuration_failure(OpenAICompatibleTransportConfigurationCode.ENDPOINT_INVALID)
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return parsed.hostname, port, target


def _validated_api_key(api_key: str) -> str:
    if (
        not isinstance(api_key, str)
        or not api_key
        or len(api_key) > _MAX_API_KEY_CHARS
        or _has_unsafe_character(api_key)
    ):
        raise _configuration_failure(OpenAICompatibleTransportConfigurationCode.API_KEY_INVALID)
    return api_key


class StdlibOpenAICompatibleTransport:
    """Perform exactly one verified-TLS POST with bounded response reading."""

    __slots__ = (
        "_api_key",
        "_connection_factory",
        "_host",
        "_port",
        "_target",
    )

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        host, port, target = _validated_endpoint(endpoint)
        self._api_key = _validated_api_key(api_key)
        self._host = host
        self._port = port
        self._target = target
        self._connection_factory = connection_factory or _default_connection_factory

    def __repr__(self) -> str:
        return "StdlibOpenAICompatibleTransport(verified_tls=True, retry_count=0)"

    def send(
        self,
        request: OpenAICompatibleTransportRequest,
    ) -> OpenAICompatibleTransportResponse:
        if not isinstance(request, OpenAICompatibleTransportRequest):
            raise TypeError("request must be an OpenAICompatibleTransportRequest")
        context = ssl.create_default_context()
        started = perf_counter()
        connection: _HTTPSConnection | None = None
        try:
            active_connection = self._connection_factory(
                self._host,
                self._port,
                timeout=request.timeout_seconds,
                context=context,
            )
            connection = active_connection
            active_connection.request(
                "POST",
                self._target,
                request.body,
                {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
            )
            response = active_connection.getresponse()
            if not isinstance(response.status, int) or not 200 <= response.status < 300:
                raise VLMProviderError(
                    VLMProviderFailureCode.PROVIDER_OUTAGE,
                    VLMDeliveryCertainty.UNKNOWN,
                )
            body = response.read(request.max_response_bytes + 1)
            if not isinstance(body, bytes):
                raise VLMProviderError(
                    VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID,
                    VLMDeliveryCertainty.COMPLETED,
                )
            if len(body) > request.max_response_bytes:
                raise VLMProviderError(
                    VLMProviderFailureCode.RESPONSE_TOO_LARGE,
                    VLMDeliveryCertainty.COMPLETED,
                )
            latency_ms = max(0, int((perf_counter() - started) * 1_000))
            return OpenAICompatibleTransportResponse(body=body, latency_ms=latency_ms)
        except VLMProviderError:
            raise
        except TimeoutError:
            raise VLMProviderError(
                VLMProviderFailureCode.PROVIDER_TIMEOUT,
                VLMDeliveryCertainty.UNKNOWN,
            ) from None
        except (OSError, http.client.HTTPException):
            raise VLMProviderError(
                VLMProviderFailureCode.TRANSPORT_UNAVAILABLE,
                VLMDeliveryCertainty.UNKNOWN,
            ) from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    raise VLMProviderError(
                        VLMProviderFailureCode.TRANSPORT_UNAVAILABLE,
                        VLMDeliveryCertainty.UNKNOWN,
                    ) from None


def build_openai_compatible_transport(
    profile: VlmProviderProfile,
    *,
    environment: Mapping[str, str] | None = None,
    connection_factory: ConnectionFactory | None = None,
) -> StdlibOpenAICompatibleTransport:
    """Resolve the endpoint and API key once without persisting either value."""

    if not isinstance(profile, VlmProviderProfile):
        raise TypeError("profile must be a VlmProviderProfile")
    if (
        profile.transport != ProviderTransport.HTTP
        or profile.execution_location != ExecutionLocation.EXTERNAL
        or profile.endpoint_env is None
        or profile.api_key_env is None
    ):
        raise _configuration_failure(OpenAICompatibleTransportConfigurationCode.PROFILE_UNSUPPORTED)
    deployment = os.environ if environment is None else environment
    endpoint = deployment.get(profile.endpoint_env)
    if endpoint is None or endpoint == "":
        raise _configuration_failure(
            OpenAICompatibleTransportConfigurationCode.ENDPOINT_ENV_MISSING
        )
    api_key = deployment.get(profile.api_key_env)
    if api_key is None or api_key == "":
        raise _configuration_failure(OpenAICompatibleTransportConfigurationCode.API_KEY_ENV_MISSING)
    return StdlibOpenAICompatibleTransport(
        endpoint=endpoint,
        api_key=api_key,
        connection_factory=connection_factory,
    )


__all__ = [
    "OpenAICompatibleTransportConfigurationCode",
    "OpenAICompatibleTransportConfigurationError",
    "StdlibOpenAICompatibleTransport",
    "build_openai_compatible_transport",
]
