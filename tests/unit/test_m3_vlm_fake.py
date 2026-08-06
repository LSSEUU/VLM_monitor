from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from labcourt.adapters.vlm import (
    EMPTY_RESPONSE_FIXTURE,
    MALFORMED_RESPONSE_FIXTURE,
    OUTAGE_FIXTURE,
    TIMEOUT_FIXTURE,
    UNKNOWN_REFERENCE_RESPONSE_FIXTURE,
    DeterministicFakeVLMClient,
    FakeVLMFixture,
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    PrivacyPolicy,
    ViolationType,
    VlmCallPurpose,
    VlmRole,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import (
    VLMCallRequest,
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import LabCourtError

SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64


def _request(case_id: str = "case-01", *, max_response_bytes: int = 4096) -> VLMRequest:
    media = VLMMediaRef(
        crop_id=SHA_4,
        media_sha256=SHA_5,
        local_path=f"run-01/frames/{SHA_5}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=8,
        height=8,
    )
    return VLMRequest(
        run_id="run-01",
        case_id=case_id,
        evidence_pack_id=SHA_6,
        evidence_pack_version=1,
        provider_profile="fake-v1",
        provider="fixture",
        model="fixture-vlm",
        revision="1",
        model_manifest_id=SHA_7,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id="screening-v1",
            role=VlmRole.SCREENING,
            template_sha256=SHA_1,
            output_schema_sha256=SHA_2,
            prompt_bundle_sha256=SHA_3,
            renderer_version="jinja-3-1",
        ),
        rendered_prompt_sha256=SHA_1,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Apply the configured rule.",
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id),),
        objective_summary={},
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=64,
            max_output_tokens=128,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=max_response_bytes,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=1024,
            timeout_seconds=5.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=SHA_2,
    )


@dataclass(slots=True)
class _RecordingPublisher:
    calls: list[tuple[VLMCallRequest, bytes, int, int, int]] = field(default_factory=list)

    def publish(
        self,
        request: VLMCallRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> VLMResponse:
        self.calls.append((request, raw_response, input_tokens, output_tokens, latency_ms))
        import hashlib

        content_sha256 = hashlib.sha256(raw_response).hexdigest()
        response_id = derive_model_response_id(
            request.run_id,
            request.request_id,
            content_sha256,
        )
        return VLMResponse(
            run_id=request.run_id,
            case_id=request.case_id,
            evidence_pack_id=request.evidence_pack_id,
            evidence_pack_version=request.evidence_pack_version,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            cache_key=request.cache_key,
            purpose=request.purpose,
            attempt_index=(0 if request.purpose == VlmCallPurpose.SCREENING else 1),
            raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
            content_sha256=content_sha256,
            size_bytes=len(raw_response),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            model_manifest_id=request.model_manifest_id,
            manifest_id=request.manifest_id,
        )


class _FailingPublisher:
    def publish(
        self,
        request: VLMCallRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> VLMResponse:
        del request, raw_response, input_tokens, output_tokens, latency_ms
        raise LabCourtError("controlled persistence failure")


def test_fake_selection_is_explicit_immutable_and_byte_deterministic() -> None:
    request = _request()
    fixture = FakeVLMFixture.response(
        b'{"exact":"bytes"}',
        input_tokens=2,
        output_tokens=3,
        latency_ms=4,
    )
    configured = {request.cache_key: fixture}
    publisher = _RecordingPublisher()
    client = DeterministicFakeVLMClient(configured, publisher)
    configured.clear()

    first = client.complete(request)
    second = client.complete(request)

    assert first == second
    assert publisher.calls == [
        (request, b'{"exact":"bytes"}', 2, 3, 4),
        (request, b'{"exact":"bytes"}', 2, 3, 4),
    ]
    assert "exact" not in repr(fixture)
    assert repr(client) == "DeterministicFakeVLMClient(fixture_count=1)"


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (MALFORMED_RESPONSE_FIXTURE, b'{"violation_probability":'),
        (EMPTY_RESPONSE_FIXTURE, b""),
        (
            UNKNOWN_REFERENCE_RESPONSE_FIXTURE,
            UNKNOWN_REFERENCE_RESPONSE_FIXTURE.raw_response,
        ),
    ],
)
def test_fake_exposes_malformed_empty_and_unknown_reference_bytes_for_later_parser_gates(
    fixture: FakeVLMFixture,
    expected: bytes | None,
) -> None:
    request = _request()
    publisher = _RecordingPublisher()
    response = DeterministicFakeVLMClient(
        {request.cache_key: fixture},
        publisher,
    ).complete(request)

    assert expected is not None
    assert publisher.calls[0][1] == expected
    assert response.size_bytes == len(expected)


@pytest.mark.parametrize(
    ("fixture", "reason"),
    [
        (OUTAGE_FIXTURE, VLMProviderFailureCode.PROVIDER_OUTAGE),
        (TIMEOUT_FIXTURE, VLMProviderFailureCode.PROVIDER_TIMEOUT),
    ],
)
def test_fake_outage_and_timeout_are_controlled_without_store_calls(
    fixture: FakeVLMFixture,
    reason: VLMProviderFailureCode,
) -> None:
    request = _request()
    publisher = _RecordingPublisher()
    client = DeterministicFakeVLMClient({request.cache_key: fixture}, publisher)

    with pytest.raises(VLMProviderError) as captured:
        client.complete(request)

    assert captured.value.reason_code == reason
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert publisher.calls == []


def test_fake_missing_fixture_and_budgets_fail_without_hidden_fallback() -> None:
    request = _request()
    publisher = _RecordingPublisher()
    missing = DeterministicFakeVLMClient({}, publisher)
    with pytest.raises(VLMProviderError) as absent:
        missing.complete(request)
    assert absent.value.reason_code == VLMProviderFailureCode.FIXTURE_MISSING
    assert absent.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT

    constrained = _request(case_id="case-02", max_response_bytes=1)
    oversized = DeterministicFakeVLMClient(
        {constrained.cache_key: FakeVLMFixture.response(b"xx")},
        publisher,
    )
    with pytest.raises(VLMProviderError) as boundary:
        oversized.complete(constrained)
    assert boundary.value.reason_code == VLMProviderFailureCode.RESPONSE_TOO_LARGE
    assert boundary.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
    assert publisher.calls == []


def test_fake_failures_after_fixture_response_are_completed() -> None:
    base = _request()
    token_request = base.model_copy(
        update={"budget": base.budget.model_copy(update={"max_output_tokens": 1})}
    )
    cost_request = base.model_copy(
        update={
            "budget": base.budget.model_copy(
                update={
                    "input_cost_per_million_tokens": 1.0,
                    "max_estimated_cost": 0.0,
                }
            )
        }
    )
    cases = (
        (
            token_request,
            FakeVLMFixture.response(b"{}", output_tokens=2),
            _RecordingPublisher(),
            VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
        ),
        (
            cost_request,
            FakeVLMFixture.response(b"{}", input_tokens=1),
            _RecordingPublisher(),
            VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
        ),
        (
            base,
            FakeVLMFixture.response(b"{}"),
            _FailingPublisher(),
            VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE,
        ),
    )

    for request, fixture, publisher, reason in cases:
        with pytest.raises(VLMProviderError) as captured:
            DeterministicFakeVLMClient({request.cache_key: fixture}, publisher).complete(request)
        assert captured.value.reason_code == reason
        assert captured.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
