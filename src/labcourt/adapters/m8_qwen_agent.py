"""Single-attempt Qwen SSE client for the persistent M8 platform Agent."""

from __future__ import annotations

import http.client
import json
import os
import ssl
from collections.abc import Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol, cast
from urllib.parse import SplitResult, urlsplit, urlunsplit

from labcourt.contracts.m8_agent_chat import (
    M8AgentFailureCode,
    M8AgentModelProfileV1,
)
from labcourt.ports.m8_agent_chat import (
    M8AgentModelClient,
    M8AgentProviderDelta,
    M8AgentProviderDeltaKind,
    M8AgentProviderError,
    M8AgentProviderRequest,
)

_MAX_ENDPOINT_CHARS = 4_096
_MAX_API_KEY_CHARS = 8_192


class _HTTPSResponse(Protocol):
    status: int

    def readline(self, limit: int = -1) -> bytes: ...


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


class _ConnectionFactory(Protocol):
    def __call__(
        self,
        host: str,
        port: int | None,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _HTTPSConnection: ...


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


def _unsafe(value: str) -> bool:
    return any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    )


def _endpoint(value: str) -> tuple[str, int | None, str]:
    if not value or len(value) > _MAX_ENDPOINT_CHARS or _unsafe(value):
        raise M8AgentProviderError(M8AgentFailureCode.NOT_CONFIGURED)
    try:
        parsed: SplitResult = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise M8AgentProviderError(M8AgentFailureCode.NOT_CONFIGURED) from None
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.endswith("/compatible-mode/v1/chat/completions")
    ):
        raise M8AgentProviderError(M8AgentFailureCode.NOT_CONFIGURED)
    return parsed.hostname, port, urlunsplit(("", "", parsed.path, parsed.query, ""))


def _api_key(value: str) -> str:
    if not value or len(value) > _MAX_API_KEY_CHARS or _unsafe(value):
        raise M8AgentProviderError(M8AgentFailureCode.NOT_CONFIGURED)
    return value


class _DuplicateField(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateField
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> object:
    raise ValueError


@dataclass(frozen=True, slots=True)
class M8QwenAgentRuntime:
    profile: M8AgentModelProfileV1
    client: M8AgentModelClient | None
    endpoint_configured: bool
    api_key_configured: bool
    configuration_failure: M8AgentFailureCode | None = None


class StdlibM8QwenAgentClient:
    """Perform one bounded verified-TLS streaming Chat Completions request."""

    __slots__ = ("_api_key", "_connection_factory", "_host", "_port", "_target")

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        connection_factory: _ConnectionFactory | None = None,
    ) -> None:
        self._host, self._port, self._target = _endpoint(endpoint)
        self._api_key = _api_key(api_key)
        self._connection_factory = connection_factory or _default_connection_factory

    def __repr__(self) -> str:
        return "StdlibM8QwenAgentClient(verified_tls=True, retry_count=0)"

    def stream(self, request: M8AgentProviderRequest) -> Iterator[M8AgentProviderDelta]:
        if not isinstance(request, M8AgentProviderRequest):
            raise TypeError("M8 Agent provider request is invalid")
        context = ssl.create_default_context()
        connection: _HTTPSConnection | None = None
        observed_bytes = 0
        observed_done = False
        try:
            connection = self._connection_factory(
                self._host,
                self._port,
                timeout=request.timeout_seconds,
                context=context,
            )
            connection.request(
                "POST",
                self._target,
                request.body,
                {
                    "Accept": "text/event-stream",
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            if not isinstance(response.status, int) or not 200 <= response.status < 300:
                raise M8AgentProviderError(M8AgentFailureCode.PROVIDER_REJECTED)
            while True:
                line = response.readline(request.max_response_bytes + 1)
                if not isinstance(line, bytes):
                    raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
                if not line:
                    break
                observed_bytes += len(line)
                if observed_bytes > request.max_response_bytes:
                    raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_TOO_LARGE)
                stripped = line.strip()
                if not stripped or stripped.startswith(b":"):
                    yield M8AgentProviderDelta(
                        kind=M8AgentProviderDeltaKind.RAW,
                        raw_event=line,
                    )
                    continue
                if not stripped.startswith(b"data:"):
                    raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
                data = stripped[5:].lstrip()
                if data == b"[DONE]":
                    observed_done = True
                    yield M8AgentProviderDelta(
                        kind=M8AgentProviderDeltaKind.DONE,
                        raw_event=line,
                    )
                    break
                yield self._decode_data(line, data)
            if not observed_done:
                raise M8AgentProviderError(M8AgentFailureCode.STREAM_INTERRUPTED)
        except M8AgentProviderError:
            raise
        except TimeoutError:
            raise M8AgentProviderError(M8AgentFailureCode.PROVIDER_TIMEOUT) from None
        except (OSError, http.client.HTTPException):
            raise M8AgentProviderError(M8AgentFailureCode.TRANSPORT_UNAVAILABLE) from None
        finally:
            if connection is not None:
                with suppress(OSError, http.client.HTTPException):
                    connection.close()

    @staticmethod
    def _decode_data(raw_line: bytes, data: bytes) -> M8AgentProviderDelta:
        try:
            envelope = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID) from None
        if not isinstance(envelope, dict):
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
        choices = envelope.get("choices")
        usage = envelope.get("usage")
        if choices == [] and usage is not None:
            input_tokens, output_tokens = StdlibM8QwenAgentClient._usage(usage)
            return M8AgentProviderDelta(
                kind=M8AgentProviderDeltaKind.USAGE,
                raw_event=raw_line,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        if not isinstance(choices, list) or len(choices) != 1:
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
        choice = choices[0]
        if not isinstance(choice, dict) or choice.get("index", 0) != 0:
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
        content = delta.get("content")
        tool_calls = delta.get("tool_calls")
        if isinstance(content, str) and content:
            if tool_calls not in (None, []):
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            return M8AgentProviderDelta(
                kind=M8AgentProviderDeltaKind.TEXT,
                raw_event=raw_line,
                text=content,
            )
        if isinstance(tool_calls, list) and len(tool_calls) == 1:
            tool = tool_calls[0]
            if not isinstance(tool, dict):
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            function = tool.get("function", {})
            if not isinstance(function, dict):
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            index = tool.get("index")
            if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index > 15:
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            call_id = tool.get("id", "")
            name = function.get("name", "")
            arguments = function.get("arguments", "")
            if not all(isinstance(item, str) for item in (call_id, name, arguments)):
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            return M8AgentProviderDelta(
                kind=M8AgentProviderDeltaKind.TOOL,
                raw_event=raw_line,
                tool_index=index,
                tool_call_id=call_id,
                tool_name=name,
                tool_arguments_delta=arguments,
            )
        if content in (None, "") and tool_calls in (None, []):
            return M8AgentProviderDelta(
                kind=M8AgentProviderDeltaKind.RAW,
                raw_event=raw_line,
            )
        raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)

    @staticmethod
    def _usage(value: object) -> tuple[int, int]:
        if not isinstance(value, dict):
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
        input_tokens = value.get("prompt_tokens")
        output_tokens = value.get("completion_tokens")
        if any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in (input_tokens, output_tokens)
        ):
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
        return input_tokens, output_tokens  # type: ignore[return-value]


def build_m8_qwen_agent_runtime(
    profile: M8AgentModelProfileV1,
    *,
    environment: Mapping[str, str] | None = None,
    connection_factory: _ConnectionFactory | None = None,
) -> M8QwenAgentRuntime:
    if not isinstance(profile, M8AgentModelProfileV1):
        raise TypeError("M8 Qwen Agent runtime requires a typed profile")
    deployment = os.environ if environment is None else environment
    endpoint = deployment.get(profile.endpoint_env, "")
    api_key = deployment.get(profile.api_key_env, "")
    endpoint_configured = bool(endpoint)
    api_key_configured = bool(api_key)
    client: M8AgentModelClient | None = None
    configuration_failure: M8AgentFailureCode | None = None
    if endpoint_configured and api_key_configured:
        try:
            client = StdlibM8QwenAgentClient(
                endpoint=endpoint,
                api_key=api_key,
                connection_factory=connection_factory,
            )
        except M8AgentProviderError as error:
            configuration_failure = error.failure_code
    return M8QwenAgentRuntime(
        profile=profile,
        client=client,
        endpoint_configured=endpoint_configured,
        api_key_configured=api_key_configured,
        configuration_failure=configuration_failure,
    )


__all__ = [
    "M8QwenAgentRuntime",
    "StdlibM8QwenAgentClient",
    "build_m8_qwen_agent_runtime",
]
