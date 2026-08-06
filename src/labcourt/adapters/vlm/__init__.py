"""Offline fake and injected-transport VLM adapters."""

from labcourt.adapters.vlm.errors import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.fake import (
    EMPTY_RESPONSE_FIXTURE,
    MALFORMED_RESPONSE_FIXTURE,
    OUTAGE_FIXTURE,
    TIMEOUT_FIXTURE,
    UNKNOWN_REFERENCE_RESPONSE_FIXTURE,
    DeterministicFakeVLMClient,
    FakeFixtureDisposition,
    FakeVLMFixture,
)
from labcourt.adapters.vlm.hearing_fake import DeterministicFakeHearingVLMClient
from labcourt.adapters.vlm.openai_compatible import (
    AppendOnlyRenderedPromptRegistry,
    ImmutableRenderedPromptRegistry,
    OpenAICompatibleClientIdentity,
    OpenAICompatibleTransport,
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
    OpenAICompatibleVLMClient,
)

__all__ = [
    "EMPTY_RESPONSE_FIXTURE",
    "MALFORMED_RESPONSE_FIXTURE",
    "OUTAGE_FIXTURE",
    "TIMEOUT_FIXTURE",
    "UNKNOWN_REFERENCE_RESPONSE_FIXTURE",
    "AppendOnlyRenderedPromptRegistry",
    "DeterministicFakeHearingVLMClient",
    "DeterministicFakeVLMClient",
    "FakeFixtureDisposition",
    "FakeVLMFixture",
    "ImmutableRenderedPromptRegistry",
    "OpenAICompatibleClientIdentity",
    "OpenAICompatibleTransport",
    "OpenAICompatibleTransportRequest",
    "OpenAICompatibleTransportResponse",
    "OpenAICompatibleVLMClient",
    "VLMDeliveryCertainty",
    "VLMProviderError",
    "VLMProviderFailureCode",
]
