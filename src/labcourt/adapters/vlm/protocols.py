"""Narrow injected boundaries shared by VLM adapters."""

from typing import Protocol

from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot
from labcourt.contracts.screening import VLMCallRequest, VLMResponse
from labcourt.ports.prompts import RenderedPromptResolver


class ModelResponsePublisher(Protocol):
    def publish(
        self,
        request: VLMCallRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> VLMResponse: ...


class VerifiedMediaReader(Protocol):
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
    ) -> SecureFileSnapshot: ...


__all__ = ["ModelResponsePublisher", "RenderedPromptResolver", "VerifiedMediaReader"]
