"""OpenAI-compatible VLM adapter with injected I/O and fail-closed envelopes."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Protocol

from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot
from labcourt.adapters.vlm.errors import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.protocols import (
    ModelResponsePublisher,
    RenderedPromptResolver,
    VerifiedMediaReader,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import CropSource, ExecutionLocation, MediaAccess
from labcourt.contracts.screening import (
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.exceptions import SecureWorkspaceError
from labcourt.ports.prompts import RenderedPrompt


def _not_sent(code: VLMProviderFailureCode) -> VLMProviderError:
    return VLMProviderError(code, VLMDeliveryCertainty.DEFINITELY_NOT_SENT)


def _completed(code: VLMProviderFailureCode) -> VLMProviderError:
    return VLMProviderError(code, VLMDeliveryCertainty.COMPLETED)


@dataclass(frozen=True, slots=True)
class OpenAICompatibleClientIdentity:
    """Public manifest identity expected by one injected transport."""

    provider_profile: str
    provider: str
    model: str
    revision: str
    model_manifest_id: str
    execution_location: ExecutionLocation


@dataclass(frozen=True, slots=True, repr=False)
class OpenAICompatibleTransportRequest:
    """Sensitive wire payload; endpoint and credentials belong to the transport."""

    body: bytes = field(repr=False)
    timeout_seconds: float
    max_response_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.body, bytes):
            raise TypeError("transport request body must be bytes")
        if (
            not isinstance(self.timeout_seconds, float)
            or self.timeout_seconds <= 0
            or not isinstance(self.max_response_bytes, int)
            or isinstance(self.max_response_bytes, bool)
            or self.max_response_bytes <= 0
        ):
            raise ValueError("transport request limits are invalid")

    def __repr__(self) -> str:
        digest = hashlib.sha256(self.body).hexdigest()
        return (
            "OpenAICompatibleTransportRequest("
            f"body_size={len(self.body)}, body_sha256={digest}, "
            f"timeout_seconds={self.timeout_seconds}, "
            f"max_response_bytes={self.max_response_bytes})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class OpenAICompatibleTransportResponse:
    body: bytes = field(repr=False)
    latency_ms: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.body, bytes):
            raise TypeError("transport response body must be bytes")
        if (
            not isinstance(self.latency_ms, int)
            or isinstance(self.latency_ms, bool)
            or self.latency_ms < 0
        ):
            raise ValueError("transport response latency must be a non-negative integer")

    def __repr__(self) -> str:
        return (
            "OpenAICompatibleTransportResponse("
            f"body_size={len(self.body)}, latency_ms={self.latency_ms})"
        )


class OpenAICompatibleTransport(Protocol):
    """A single-attempt transport configured with its own endpoint and credential."""

    def send(
        self,
        request: OpenAICompatibleTransportRequest,
    ) -> OpenAICompatibleTransportResponse: ...


@dataclass(frozen=True, slots=True, repr=False)
class _PromptEntry:
    manifest_id: str
    utf8_bytes: bytes = field(repr=False)


class ImmutableRenderedPromptRegistry:
    """Request-hash lookup for already rendered prompts, without implicit rerendering."""

    __slots__ = ("_entries",)

    def __init__(self, rendered_prompts: Iterable[RenderedPrompt]) -> None:
        entries: dict[str, _PromptEntry] = {}
        for prompt in rendered_prompts:
            if not isinstance(prompt, RenderedPrompt):
                raise TypeError("rendered_prompts must contain RenderedPrompt values")
            payload = prompt.utf8_bytes
            if hashlib.sha256(payload).hexdigest() != prompt.rendered_prompt_sha256:
                raise ValueError("rendered prompt bytes do not match their identity")
            entry = _PromptEntry(
                manifest_id=prompt.manifest.prompt_manifest_id,
                utf8_bytes=payload,
            )
            existing = entries.get(prompt.rendered_prompt_sha256)
            if existing is not None and existing != entry:
                raise ValueError("rendered prompt hash collision has conflicting content")
            entries[prompt.rendered_prompt_sha256] = entry
        self._entries: Mapping[str, _PromptEntry] = MappingProxyType(entries)

    def __repr__(self) -> str:
        return f"ImmutableRenderedPromptRegistry(prompt_count={len(self._entries)})"

    def resolve(self, request: VLMCallRequest) -> bytes:
        entry = self._entries.get(request.rendered_prompt_sha256)
        if entry is None:
            raise _not_sent(VLMProviderFailureCode.PROMPT_MISSING)
        if entry.manifest_id != request.prompt_manifest.prompt_manifest_id:
            raise _not_sent(VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE)
        if hashlib.sha256(entry.utf8_bytes).hexdigest() != request.rendered_prompt_sha256:
            raise _not_sent(VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE)
        return entry.utf8_bytes


class AppendOnlyRenderedPromptRegistry:
    """Thread-safe prompt registration for prompts rendered during orchestration."""

    __slots__ = ("_entries", "_lock")

    def __init__(self, rendered_prompts: Iterable[RenderedPrompt] = ()) -> None:
        self._entries: dict[str, _PromptEntry] = {}
        self._lock = RLock()
        for prompt in rendered_prompts:
            self.register(prompt)

    def __repr__(self) -> str:
        with self._lock:
            count = len(self._entries)
        return f"AppendOnlyRenderedPromptRegistry(prompt_count={count})"

    def register(self, prompt: RenderedPrompt) -> None:
        if not isinstance(prompt, RenderedPrompt):
            raise TypeError("prompt must be a RenderedPrompt")
        payload = prompt.utf8_bytes
        if hashlib.sha256(payload).hexdigest() != prompt.rendered_prompt_sha256:
            raise ValueError("rendered prompt bytes do not match their identity")
        entry = _PromptEntry(
            manifest_id=prompt.manifest.prompt_manifest_id,
            utf8_bytes=payload,
        )
        with self._lock:
            existing = self._entries.get(prompt.rendered_prompt_sha256)
            if existing is not None and existing != entry:
                raise ValueError("rendered prompt hash collision has conflicting content")
            if existing is None:
                self._entries[prompt.rendered_prompt_sha256] = entry

    def resolve(self, request: VLMCallRequest) -> bytes:
        with self._lock:
            entry = self._entries.get(request.rendered_prompt_sha256)
            if entry is None:
                raise _not_sent(VLMProviderFailureCode.PROMPT_MISSING)
            if entry.manifest_id != request.prompt_manifest.prompt_manifest_id:
                raise _not_sent(VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE)
            if hashlib.sha256(entry.utf8_bytes).hexdigest() != request.rendered_prompt_sha256:
                raise _not_sent(VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE)
            return entry.utf8_bytes


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


class OpenAICompatibleVLMClient:
    """Build one bounded request, call once, and persist exact selected content."""

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
        identity: OpenAICompatibleClientIdentity,
        transport: OpenAICompatibleTransport,
        prompt_resolver: RenderedPromptResolver,
        media_reader: VerifiedMediaReader,
        response_store: ModelResponsePublisher,
    ) -> None:
        if not isinstance(identity, OpenAICompatibleClientIdentity):
            raise TypeError("identity must be OpenAICompatibleClientIdentity")
        for dependency, method in (
            (transport, "send"),
            (prompt_resolver, "resolve"),
            (media_reader, "read_verified"),
            (response_store, "publish"),
        ):
            if not hasattr(dependency, method):
                raise TypeError(f"injected dependency must implement {method}")
        self._identity = identity
        self._transport = transport
        self._prompt_resolver = prompt_resolver
        self._media_reader = media_reader
        self._response_store = response_store

    def __repr__(self) -> str:
        return (
            "OpenAICompatibleVLMClient("
            f"provider_profile={self._identity.provider_profile!r}, "
            f"provider={self._identity.provider!r}, model={self._identity.model!r}, "
            f"revision={self._identity.revision!r})"
        )

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        if not isinstance(request, (VLMRequest, StructureRepairRequest)):
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
        payload = self._wire_payload(request, prompt_text, media_bytes)
        transport_request = OpenAICompatibleTransportRequest(
            body=payload,
            timeout_seconds=float(request.budget.timeout_seconds),
            max_response_bytes=request.budget.max_response_bytes,
        )
        try:
            transport_response = self._transport.send(transport_request)
        except TimeoutError:
            raise VLMProviderError(VLMProviderFailureCode.PROVIDER_TIMEOUT) from None
        except Exception:
            raise VLMProviderError(VLMProviderFailureCode.TRANSPORT_UNAVAILABLE) from None
        raw_content, input_tokens, output_tokens, latency_ms = self._extract_content(
            request,
            transport_response,
        )
        try:
            return self._response_store.publish(
                request,
                raw_content,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
            )
        except Exception:
            raise _completed(VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE) from None

    def _verify_request_identity(self, request: VLMCallRequest) -> None:
        expected = self._identity
        if (
            request.provider_profile != expected.provider_profile
            or request.provider != expected.provider
            or request.model != expected.model
            or request.revision != expected.revision
            or request.model_manifest_id != expected.model_manifest_id
            or request.execution_location != expected.execution_location
        ):
            raise _not_sent(VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH)

    def _read_and_verify_media(
        self,
        request: VLMCallRequest,
    ) -> tuple[bytes, ...]:
        if isinstance(request, StructureRepairRequest):
            return ()
        if not isinstance(request, VLMRequest):
            raise _not_sent(VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH)
        snapshots: list[bytes] = []
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
            self._verify_media_snapshot(snapshot, expected_path, media.media_sha256)
            snapshots.append(snapshot.bytes)
        return tuple(snapshots)

    @staticmethod
    def _verify_media_snapshot(
        snapshot: SecureFileSnapshot,
        expected_path: str,
        expected_sha256: str,
    ) -> None:
        if (
            not isinstance(snapshot, SecureFileSnapshot)
            or snapshot.relative_path != expected_path
            or snapshot.sha256 != expected_sha256
            or hashlib.sha256(snapshot.bytes).hexdigest() != expected_sha256
            or snapshot.size_bytes != len(snapshot.bytes)
        ):
            raise _not_sent(VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE)

    @staticmethod
    def _wire_payload(
        request: VLMCallRequest,
        prompt_text: str,
        media_bytes: tuple[bytes, ...],
    ) -> bytes:
        content: list[dict[str, object]] = [{"type": "text", "text": prompt_text}]
        content.extend(
            {
                "type": "image_url",
                "image_url": {
                    "url": ("data:image/png;base64," + base64.b64encode(payload).decode("ascii"))
                },
            }
            for payload in media_bytes
        )
        wire: dict[str, object] = {
            "max_tokens": request.budget.max_output_tokens,
            "messages": [{"role": "user", "content": content}],
            "model": request.model,
            "response_format": {"type": "json_object"},
            "stream": False,
            "temperature": request.temperature,
        }
        if request.seed is not None:
            wire["seed"] = request.seed
        return canonical_bytes(wire)

    @staticmethod
    def _extract_content(
        request: VLMCallRequest,
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
        if not isinstance(choice, dict):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        if "index" in choice and choice["index"] != 0:
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        if choice.get("finish_reason") not in {None, "stop"}:
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        message = choice.get("message")
        if not isinstance(message, dict):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        if "role" in message and message["role"] != "assistant":
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        refusal = message.get("refusal")
        tool_calls = message.get("tool_calls")
        if (refusal is not None and refusal != "") or (tool_calls is not None and tool_calls != []):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        content = message.get("content")
        if not isinstance(content, str):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        try:
            raw_content = content.encode("utf-8")
        except UnicodeEncodeError:
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID) from None
        if len(raw_content) > request.budget.max_response_bytes:
            raise _completed(VLMProviderFailureCode.RESPONSE_TOO_LARGE)
        input_tokens, output_tokens = OpenAICompatibleVLMClient._usage(envelope)
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
        return raw_content, input_tokens, output_tokens, response.latency_ms

    @staticmethod
    def _usage(envelope: dict[str, object]) -> tuple[int, int]:
        usage = envelope.get("usage")
        if not isinstance(usage, dict):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        if "prompt_tokens" not in usage or "completion_tokens" not in usage:
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        input_tokens = usage["prompt_tokens"]
        output_tokens = usage["completion_tokens"]
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in (input_tokens, output_tokens)
        ):
            raise _completed(VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID)
        return input_tokens, output_tokens


__all__ = [
    "AppendOnlyRenderedPromptRegistry",
    "ImmutableRenderedPromptRegistry",
    "OpenAICompatibleClientIdentity",
    "OpenAICompatibleTransport",
    "OpenAICompatibleTransportRequest",
    "OpenAICompatibleTransportResponse",
    "OpenAICompatibleVLMClient",
]
