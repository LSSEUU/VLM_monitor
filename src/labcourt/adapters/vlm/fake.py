"""Explicit, deterministic, offline VLM fixtures selected only by cache key."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from labcourt.adapters.vlm.errors import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.protocols import ModelResponsePublisher
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.screening import (
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FakeFixtureDisposition(StrEnum):
    RESPONSE = "RESPONSE"
    OUTAGE = "OUTAGE"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True, slots=True, repr=False)
class FakeVLMFixture:
    """One immutable fake outcome; response bytes are intentionally not repr-visible."""

    disposition: FakeFixtureDisposition
    raw_response: bytes | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0

    def __post_init__(self) -> None:
        metrics = (self.input_tokens, self.output_tokens, self.latency_ms)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in metrics
        ):
            raise ValueError("fake fixture metrics must be non-negative integers")
        if self.disposition == FakeFixtureDisposition.RESPONSE:
            if not isinstance(self.raw_response, bytes):
                raise ValueError("response fixture requires exact bytes")
        elif self.raw_response is not None or any(metrics):
            raise ValueError("failure fixture cannot carry response bytes or metrics")

    @classmethod
    def response(
        cls,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> FakeVLMFixture:
        return cls(
            disposition=FakeFixtureDisposition.RESPONSE,
            raw_response=raw_response,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
        )

    def __repr__(self) -> str:
        if self.raw_response is None:
            return f"FakeVLMFixture(disposition={self.disposition.value})"
        digest = hashlib.sha256(self.raw_response).hexdigest()
        return (
            "FakeVLMFixture("
            f"disposition={self.disposition.value}, size_bytes={len(self.raw_response)}, "
            f"content_sha256={digest})"
        )


MALFORMED_RESPONSE_FIXTURE = FakeVLMFixture.response(b'{"violation_probability":')
EMPTY_RESPONSE_FIXTURE = FakeVLMFixture.response(b"")
UNKNOWN_REFERENCE_RESPONSE_FIXTURE = FakeVLMFixture.response(
    canonical_bytes(
        {
            "evidence_citations": [
                {
                    "bbox": None,
                    "coordinate_space": None,
                    "evidence_ref": {
                        "artifact_id": "f" * 64,
                        "kind": "CROP",
                    },
                }
            ],
            "evidence_class": "ABSENCE",
            "frame_observations": [
                {
                    "crop_id": "f" * 64,
                    "reason_summary": "Unknown crop fixture.",
                    "wear_status": "NOT_WORN",
                }
            ],
            "objective_claims": [],
            "prosecution_summary": "Unknown reference fixture.",
            "rationale_summary": "Exercises strict reference diagnostics.",
            "violation_probability": 0.9,
            "violation_type": "PPE_GOGGLES_MISSING",
        }
    )
)
OUTAGE_FIXTURE = FakeVLMFixture(disposition=FakeFixtureDisposition.OUTAGE)
TIMEOUT_FIXTURE = FakeVLMFixture(disposition=FakeFixtureDisposition.TIMEOUT)


class DeterministicFakeVLMClient:
    """No network, clock, randomness, retry, mutation, or implicit fallback."""

    __slots__ = ("_fixtures", "_response_store")

    def __init__(
        self,
        fixtures_by_cache_key: Mapping[str, FakeVLMFixture],
        response_store: ModelResponsePublisher,
    ) -> None:
        if not isinstance(fixtures_by_cache_key, Mapping):
            raise TypeError("fixtures_by_cache_key must be a mapping")
        copied: dict[str, FakeVLMFixture] = {}
        for cache_key, fixture in fixtures_by_cache_key.items():
            if not isinstance(cache_key, str) or _SHA256.fullmatch(cache_key) is None:
                raise ValueError("fake fixture cache keys must be lowercase SHA-256 digests")
            if not isinstance(fixture, FakeVLMFixture):
                raise TypeError("fake fixture mapping values must be FakeVLMFixture")
            copied[cache_key] = fixture
        if not hasattr(response_store, "publish"):
            raise TypeError("response_store must publish model responses")
        self._fixtures: Mapping[str, FakeVLMFixture] = MappingProxyType(copied)
        self._response_store = response_store

    def __repr__(self) -> str:
        return f"DeterministicFakeVLMClient(fixture_count={len(self._fixtures)})"

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        if not isinstance(request, (VLMRequest, StructureRepairRequest)):
            raise VLMProviderError(
                VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH,
                VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            )
        fixture = self._fixtures.get(request.cache_key)
        if fixture is None:
            raise VLMProviderError(
                VLMProviderFailureCode.FIXTURE_MISSING,
                VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            )
        if fixture.disposition == FakeFixtureDisposition.OUTAGE:
            raise VLMProviderError(
                VLMProviderFailureCode.PROVIDER_OUTAGE,
                VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            )
        if fixture.disposition == FakeFixtureDisposition.TIMEOUT:
            raise VLMProviderError(
                VLMProviderFailureCode.PROVIDER_TIMEOUT,
                VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            )
        raw_response = fixture.raw_response
        if raw_response is None:
            raise AssertionError("validated response fixture lost its bytes")
        if len(raw_response) > request.budget.max_response_bytes:
            raise VLMProviderError(
                VLMProviderFailureCode.RESPONSE_TOO_LARGE,
                VLMDeliveryCertainty.COMPLETED,
            )
        if (
            fixture.input_tokens > request.budget.max_input_tokens
            or fixture.output_tokens > request.budget.max_output_tokens
        ):
            raise VLMProviderError(
                VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
                VLMDeliveryCertainty.COMPLETED,
            )
        if not request.budget.allows_cost(
            input_tokens=fixture.input_tokens,
            output_tokens=fixture.output_tokens,
        ):
            raise VLMProviderError(
                VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
                VLMDeliveryCertainty.COMPLETED,
            )
        try:
            return self._response_store.publish(
                request,
                raw_response,
                input_tokens=fixture.input_tokens,
                output_tokens=fixture.output_tokens,
                latency_ms=fixture.latency_ms,
            )
        except Exception:
            raise VLMProviderError(
                VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE,
                VLMDeliveryCertainty.COMPLETED,
            ) from None


__all__ = [
    "EMPTY_RESPONSE_FIXTURE",
    "MALFORMED_RESPONSE_FIXTURE",
    "OUTAGE_FIXTURE",
    "TIMEOUT_FIXTURE",
    "UNKNOWN_REFERENCE_RESPONSE_FIXTURE",
    "DeterministicFakeVLMClient",
    "FakeFixtureDisposition",
    "FakeVLMFixture",
]
