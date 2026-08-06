"""Neutral runtime boundary for exact rendered prompts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from labcourt.contracts.m3_models import PromptManifest
from labcourt.contracts.screening import VLMCallRequest
from labcourt.exceptions import LabCourtError

MAX_PROMPT_VARIABLE_BYTES: Final = 524_288
MAX_PROMPT_STRING_CHARS: Final = 262_144


class PromptRenderFailureCode(StrEnum):
    TEMPLATE_NOT_FOUND = "TEMPLATE_NOT_FOUND"
    TEMPLATE_ROOT_INVALID = "TEMPLATE_ROOT_INVALID"
    TEMPLATE_EMPTY = "TEMPLATE_EMPTY"
    TEMPLATE_TOO_LARGE = "TEMPLATE_TOO_LARGE"
    TEMPLATE_ENCODING_INVALID = "TEMPLATE_ENCODING_INVALID"
    TEMPLATE_LINE_ENDING_INVALID = "TEMPLATE_LINE_ENDING_INVALID"
    TEMPLATE_SYNTAX_INVALID = "TEMPLATE_SYNTAX_INVALID"
    TEMPLATE_CONSTRUCT_FORBIDDEN = "TEMPLATE_CONSTRUCT_FORBIDDEN"
    TEMPLATE_VARIABLE_SET_INVALID = "TEMPLATE_VARIABLE_SET_INVALID"
    PROMPT_VARIABLE_SET_INVALID = "PROMPT_VARIABLE_SET_INVALID"
    PROMPT_VARIABLE_NOT_CANONICAL_JSON = "PROMPT_VARIABLE_NOT_CANONICAL_JSON"
    PROMPT_RENDER_FAILED = "PROMPT_RENDER_FAILED"
    PROMPT_RENDER_TOO_LARGE = "PROMPT_RENDER_TOO_LARGE"
    PROMPT_ID_UNKNOWN = "PROMPT_ID_UNKNOWN"
    PROMPT_SCHEMA_SET_INVALID = "PROMPT_SCHEMA_SET_INVALID"
    PROMPT_SCHEMA_NOT_CANONICAL_JSON = "PROMPT_SCHEMA_NOT_CANONICAL_JSON"
    PROMPT_BUNDLE_MISMATCH = "PROMPT_BUNDLE_MISMATCH"
    RENDERER_VERSION_MISMATCH = "RENDERER_VERSION_MISMATCH"


class PromptRenderError(LabCourtError):
    """Controlled prompt failure that never includes source, values, or host paths."""

    def __init__(self, reason_code: PromptRenderFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"prompt rendering failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class RenderedPrompt:
    """Exact prompt text and its immutable identity bindings."""

    manifest: PromptManifest
    rendered_prompt_sha256: str
    text: str = field(repr=False)

    @property
    def utf8_bytes(self) -> bytes:
        return self.text.encode("utf-8")


@runtime_checkable
class PromptCatalog(Protocol):
    """Immutable prompt manifests and deterministic rendering capability."""

    @property
    def bundle_sha256(self) -> str: ...

    def manifest(self, prompt_id: str) -> PromptManifest: ...

    def render(
        self,
        *,
        prompt_id: str,
        variables: Mapping[str, str],
    ) -> RenderedPrompt: ...


class RenderedPromptRegistrar(Protocol):
    """Append one already rendered prompt before its provider call."""

    def register(self, prompt: RenderedPrompt) -> None: ...


class RenderedPromptResolver(Protocol):
    """Resolve exact prompt bytes from a fully bound model request."""

    def resolve(self, request: VLMCallRequest) -> bytes: ...


__all__ = [
    "MAX_PROMPT_STRING_CHARS",
    "MAX_PROMPT_VARIABLE_BYTES",
    "PromptCatalog",
    "PromptRenderError",
    "PromptRenderFailureCode",
    "RenderedPrompt",
    "RenderedPromptRegistrar",
    "RenderedPromptResolver",
]
