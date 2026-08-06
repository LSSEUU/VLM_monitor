"""Explicit, deterministic, offline fixtures for M4 hearing roles."""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType

from labcourt.adapters.vlm.errors import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.fake import FakeFixtureDisposition, FakeVLMFixture
from labcourt.contracts.hearing import HearingModelRequest, HearingModelResponse
from labcourt.ports.hearing_vlm import HearingModelResponsePublisher

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DeterministicFakeHearingVLMClient:
    """Resolve an M4 result by cache key with no fallback or hidden retry."""

    __slots__ = ("_fixtures", "_response_store")

    def __init__(
        self,
        fixtures_by_cache_key: Mapping[str, FakeVLMFixture],
        response_store: HearingModelResponsePublisher,
    ) -> None:
        if not isinstance(fixtures_by_cache_key, Mapping):
            raise TypeError("fixtures_by_cache_key must be a mapping")
        copied: dict[str, FakeVLMFixture] = {}
        for cache_key, fixture in fixtures_by_cache_key.items():
            if not isinstance(cache_key, str) or _SHA256.fullmatch(cache_key) is None:
                raise ValueError("hearing fixture keys must be lowercase SHA-256 digests")
            if not isinstance(fixture, FakeVLMFixture):
                raise TypeError("hearing fixture values must be FakeVLMFixture")
            copied[cache_key] = fixture
        if not hasattr(response_store, "publish"):
            raise TypeError("response_store must publish hearing responses")
        self._fixtures: Mapping[str, FakeVLMFixture] = MappingProxyType(copied)
        self._response_store = response_store

    def __repr__(self) -> str:
        return f"DeterministicFakeHearingVLMClient(fixture_count={len(self._fixtures)})"

    def complete(self, request: HearingModelRequest) -> HearingModelResponse:
        if not isinstance(request, HearingModelRequest):
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
            raise AssertionError("validated hearing response fixture lost its bytes")
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


__all__ = ["DeterministicFakeHearingVLMClient"]
