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
from labcourt.adapters.vlm.http_transport import (
    OpenAICompatibleTransportConfigurationCode,
    OpenAICompatibleTransportConfigurationError,
    StdlibOpenAICompatibleTransport,
    build_openai_compatible_transport,
)
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
    "OpenAICompatibleTransportConfigurationCode",
    "OpenAICompatibleTransportConfigurationError",
    "OpenAICompatibleTransportRequest",
    "OpenAICompatibleTransportResponse",
    "OpenAICompatibleVLMClient",
    "StdlibOpenAICompatibleTransport",
    "VLMDeliveryCertainty",
    "VLMProviderError",
    "VLMProviderFailureCode",
    "build_openai_compatible_transport",
]
