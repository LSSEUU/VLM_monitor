"""Single-attempt OpenAI-compatible adapter for frozen M4 hearing requests."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot
from labcourt.adapters.vlm.errors import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.openai_compatible import (
    OpenAICompatibleTransport,
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import CropSource, ExecutionLocation, MediaAccess, VlmRole
from labcourt.contracts.hearing import HearingModelRequest, HearingModelResponse
from labcourt.exceptions import SecureWorkspaceError
from labcourt.ports.hearing_vlm import HearingModelResponsePublisher, HearingVLMClient


def _not_sent(code: VLMProviderFailureCode) -> VLMProviderError:
    return VLMProviderError(code, VLMDeliveryCertainty.DEFINITELY_NOT_SENT)


def _completed(code: VLMProviderFailureCode) -> VLMProviderError:
    return VLMProviderError(code, VLMDeliveryCertainty.COMPLETED)


class HearingPromptResolver(Protocol):
    def resolve(self, request: HearingModelRequest) -> bytes: ...


class HearingVerifiedMediaReader(Protocol):
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
    ) -> SecureFileSnapshot: ...


@dataclass(frozen=True, slots=True)
class HearingOpenAICompatibleIdentity:
    provider_profile: str
    provider: str
    model: str
    revision: str
    model_manifest_id: str
    execution_location: ExecutionLocation
    enable_thinking: bool | None = None


class _DuplicateEnvelopeField(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateEnvelopeField
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> object:
    raise ValueError


class OpenAICompatibleHearingVLMClient:
    """Call one exact configured role profile; never select a fixture fallback."""

    __slots__ = (
        "_identity",
        "_media_reader",
        "_prompt_resolver",
        "_response_store",
        "_transport",
    )

    def __init__(
        self,
        *,
        identity: HearingOpenAICompatibleIdentity,
        transport: OpenAICompatibleTransport,
        prompt_resolver: HearingPromptResolver,
        media_reader: HearingVerifiedMediaReader,
        response_store: HearingModelResponsePublisher,
    ) -> None:
        if not isinstance(identity, HearingOpenAICompatibleIdentity):
            raise TypeError("identity must be HearingOpenAICompatibleIdentity")
        for dependency, method in (
            (transport, "send"),
            (prompt_resolver, "resolve"),
            (media_reader, "read_verified"),
            (response_store, "publish"),
        ):
            if not callable(getattr(dependency, method, None)):
                raise TypeError(f"injected hearing dependency must implement {method}")
        self._identity = identity
        self._transport = transport
        self._prompt_resolver = prompt_resolver
        self._media_reader = media_reader
        self._response_store = response_store

    def __repr__(self) -> str:
        return (
            "OpenAICompatibleHearingVLMClient("
            f"provider_profile={self._identity.provider_profile!r}, "
            f"provider={self._identity.provider!r}, model={self._identity.model!r}, "
            f"revision={self._identity.revision!r})"
        )

    def complete(self, request: HearingModelRequest) -> HearingModelResponse:
        if not isinstance(request, HearingModelRequest):
            raise _not_sent(VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH)
        self._verify_request_identity(request)
        try:
            prompt_bytes = self._prompt_resolver.resolve(request)
        except VLMProviderError:
            raise
        except Exception:
            raise _not_sent(VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE) from None
        if (
            not isinstance(prompt_bytes, bytes)
            or hashlib.sha256(prompt_bytes).hexdigest() != request.rendered_prompt_sha256
        ):
            raise _not_sent(VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE)
        try:
            prompt_text = prompt_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise _not_sent(VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE) from None
        media_bytes = self._read_and_verify_media(request)
        transport_request = OpenAICompatibleTransportRequest(
            body=self._wire_payload(
                request,
                prompt_text,
                media_bytes,
                enable_thinking=self._identity.enable_thinking,
            ),
            timeout_seconds=float(request.budget.timeout_seconds),
            max_response_bytes=request.budget.max_response_bytes,
        )
        try:
            response = self._transport.send(transport_request)
        except VLMProviderError:
            raise
        except TimeoutError:
            raise VLMProviderError(VLMProviderFailureCode.PROVIDER_TIMEOUT) from None
        except Exception:
            raise VLMProviderError(VLMProviderFailureCode.TRANSPORT_UNAVAILABLE) from None
        raw, input_tokens, output_tokens, latency_ms = self._extract_content(request, response)
        try:
            return self._response_store.publish(
                request,
                raw,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
            )
        except Exception:
            raise _completed(VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE) from None

    def _verify_request_identity(self, request: HearingModelRequest) -> None:
        identity = self._identity
        if (
            request.provider_profile != identity.provider_profile
            or request.provider != identity.provider
            or request.model != identity.model
            or request.revision != identity.revision
            or request.model_manifest_id != identity.model_manifest_id
            or request.execution_location != identity.execution_location
        ):
            raise _not_sent(VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH)

    def _read_and_verify_media(self, request: HearingModelRequest) -> tuple[bytes, ...]:
        if request.attempt_index == 1:
            return ()
        values: list[bytes] = []
        for media in request.media:
            expected_path = f"{request.run_id}/frames/{media.media_sha256}.png"
            if media.local_path != expected_path:
                raise _not_sent(VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE)
            if request.execution_location == ExecutionLocation.EXTERNAL and (
                media.media_access != MediaAccess.CLOUD_ALLOWED
                or media.source == CropSource.PANORAMA
            ):
                raise _not_sent(VLMProviderFailureCode.MEDIA_POLICY_REJECTED)
            try:
                snapshot = self._media_reader.read_verified(
                    media.local_path,
                    media.media_sha256,
                )
            except SecureWorkspaceError:
                raise _not_sent(VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE) from None
            except Exception:
                raise _not_sent(VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE) from None
            if (
                not isinstance(snapshot, SecureFileSnapshot)
                or snapshot.relative_path != expected_path
                or snapshot.sha256 != media.media_sha256
                or hashlib.sha256(snapshot.bytes).hexdigest() != media.media_sha256
                or snapshot.size_bytes != len(snapshot.bytes)
            ):
                raise _not_sent(VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE)
            values.append(snapshot.bytes)
        return tuple(values)

    @staticmethod
    def _wire_payload(
        request: HearingModelRequest,
        prompt_text: str,
        media_bytes: tuple[bytes, ...],
        *,
        enable_thinking: bool | None,
    ) -> bytes:
        content: list[dict[str, object]] = [{"type": "text", "text": prompt_text}]
        content.extend(
            {
                "type": "image_url",
                "image_url": {
                    "url": "data:image/png;base64," + base64.b64encode(value).decode("ascii")
                },
            }
            for value in media_bytes
        )
        body: dict[str, object] = {
            "max_tokens": request.budget.max_output_tokens,
            "messages": [{"role": "user", "content": content}],
            "model": request.model,
            "response_format": {"type": "json_object"},
            "stream": False,
            "temperature": request.temperature,
        }
        if request.seed is not None:
            body["seed"] = request.seed
        if enable_thinking is not None:
            body["enable_thinking"] = enable_thinking
        return canonical_bytes(body)

    @staticmethod
    def _extract_content(
        request: HearingModelRequest,
        response: object,
    ) -> tuple[bytes, int, int, int]:
        if not isinstance(response, OpenAICompatibleTransportResponse):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        if len(response.body) > request.budget.max_response_bytes:
            raise _completed(VLMProviderFailureCode.RESPONSE_TOO_LARGE)
        try:
            envelope = json.loads(
                response.body.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID) from None
        if not isinstance(envelope, dict):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        choices = envelope.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        choice = choices[0]
        if (
            not isinstance(choice, dict)
            or ("index" in choice and choice["index"] != 0)
            or choice.get("finish_reason") not in {None, "stop"}
        ):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        message = choice.get("message")
        if not isinstance(message, dict) or ("role" in message and message["role"] != "assistant"):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        refusal = message.get("refusal")
        tool_calls = message.get("tool_calls")
        if (refusal is not None and refusal != "") or (tool_calls is not None and tool_calls != []):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        content = message.get("content")
        if not isinstance(content, str):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        try:
            raw = content.encode("utf-8")
        except UnicodeEncodeError:
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID) from None
        if len(raw) > request.budget.max_response_bytes:
            raise _completed(VLMProviderFailureCode.RESPONSE_TOO_LARGE)
        input_tokens, output_tokens = OpenAICompatibleHearingVLMClient._usage(envelope)
        if (
            input_tokens > request.budget.max_input_tokens
            or output_tokens > request.budget.max_output_tokens
        ):
            raise _completed(VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED)
        if not request.budget.allows_cost(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        ):
            raise _completed(VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED)
        return raw, input_tokens, output_tokens, response.latency_ms

    @staticmethod
    def _usage(envelope: dict[str, object]) -> tuple[int, int]:
        usage = envelope.get("usage")
        if not isinstance(usage, dict):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        values = (usage.get("prompt_tokens"), usage.get("completion_tokens"))
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values
        ):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        return values[0], values[1]  # type: ignore[return-value]


class RoutedHearingVLMClient:
    """Route only by the request's frozen role; missing roles never fall back."""

    __slots__ = ("_clients",)

    def __init__(self, clients: Mapping[VlmRole, HearingVLMClient]) -> None:
        expected = {VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE}
        if set(clients) != expected:
            raise ValueError("hearing role router requires exactly three role clients")
        self._clients = MappingProxyType(dict(clients))

    def complete(self, request: HearingModelRequest) -> HearingModelResponse:
        if not isinstance(request, HearingModelRequest):
            raise _not_sent(VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH)
        try:
            client = self._clients[request.role]
        except KeyError:
            raise _not_sent(VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH) from None
        return client.complete(request)


__all__ = [
    "HearingOpenAICompatibleIdentity",
    "HearingPromptResolver",
    "OpenAICompatibleHearingVLMClient",
    "RoutedHearingVLMClient",
]
