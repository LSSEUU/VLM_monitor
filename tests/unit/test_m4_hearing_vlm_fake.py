from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import pytest

from labcourt.adapters.vlm import (
    DeterministicFakeHearingVLMClient,
    DeterministicFakeVLMClient,
    FakeVLMFixture,
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.fake import OUTAGE_FIXTURE, TIMEOUT_FIXTURE
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    PrivacyPolicy,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.hearing import (
    HearingModelRequest,
    HearingModelResponse,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import VLMMediaRef, VLMRequest
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import LabCourtError

SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64
SHA_8 = "8" * 64
SHA_9 = "9" * 64


def _request(
    role: VlmRole = VlmRole.PROSECUTOR,
    *,
    max_response_bytes: int = 4_096,
) -> HearingModelRequest:
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
    upstream = ArtifactRef(kind=ArtifactKind.PARSED_MODEL_OUTPUT, artifact_id=SHA_8)
    return HearingModelRequest(
        run_id="run-01",
        case_id="case-01",
        hearing_session_id=SHA_9,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=SHA_6,
        current_evidence_pack_version=1,
        screening_ref=ArtifactRef(kind=ArtifactKind.SCREENING_RESULT, artifact_id=SHA_7),
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        role=role,
        provider_profile=f"fake-{role.value.lower()}",
        provider="fake",
        model=f"deterministic-{role.value.lower()}",
        revision="1.0.0",
        model_manifest_id=SHA_1,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id=f"hearing_{role.value.lower()}_v1",
            role=role,
            template_sha256=SHA_2,
            output_schema_sha256=SHA_3,
            prompt_bundle_sha256=SHA_4,
            renderer_version="jinja-3-1",
        ),
        hearing_prompt_bundle_sha256=SHA_4,
        rendered_prompt_sha256=SHA_5,
        hearing_context_sha256=SHA_6,
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id),),
        prosecutor_output_ref=(upstream if role in {VlmRole.DEFENDER, VlmRole.JUDGE} else None),
        defender_output_ref=upstream if role == VlmRole.JUDGE else None,
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id=SHA_2,
        precedent_retrieval_receipt_sha256=SHA_3,
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
            max_string_chars=1_024,
            timeout_seconds=5.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=SHA_7,
    )


@dataclass(slots=True)
class _RecordingPublisher:
    calls: list[tuple[HearingModelRequest, bytes, int, int, int]] = field(default_factory=list)

    def publish(
        self,
        request: HearingModelRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> HearingModelResponse:
        self.calls.append((request, raw_response, input_tokens, output_tokens, latency_ms))
        content_sha256 = hashlib.sha256(raw_response).hexdigest()
        response_id = derive_hearing_model_response_id(
            request.run_id,
            request.request_id,
            content_sha256,
        )
        return HearingModelResponse(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            round_index=request.round_index,
            prior_acquisition_rounds=request.prior_acquisition_rounds,
            prior_rework_rounds=request.prior_rework_rounds,
            current_evidence_pack_id=request.current_evidence_pack_id,
            current_evidence_pack_version=request.current_evidence_pack_version,
            role=request.role,
            attempt_index=request.attempt_index,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            cache_key=request.cache_key,
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
        request: HearingModelRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> HearingModelResponse:
        del request, raw_response, input_tokens, output_tokens, latency_ms
        raise LabCourtError("controlled persistence failure")


def test_three_roles_use_independent_explicit_fixture_maps() -> None:
    requests = tuple(
        _request(role)
        for role in (
            VlmRole.PROSECUTOR,
            VlmRole.DEFENDER,
            VlmRole.JUDGE,
        )
    )
    publishers = tuple(_RecordingPublisher() for _ in requests)
    fixtures = tuple(
        FakeVLMFixture.response(
            f'{{"role":"{request.role.value}"}}'.encode(),
            input_tokens=index,
            output_tokens=index + 1,
            latency_ms=index + 2,
        )
        for index, request in enumerate(requests, start=1)
    )
    clients = tuple(
        DeterministicFakeHearingVLMClient(
            {request.cache_key: fixture},
            publisher,
        )
        for request, fixture, publisher in zip(requests, fixtures, publishers, strict=True)
    )

    responses = tuple(
        client.complete(request) for client, request in zip(clients, requests, strict=True)
    )

    assert tuple(response.role for response in responses) == tuple(
        request.role for request in requests
    )
    assert all(len(publisher.calls) == 1 for publisher in publishers)
    assert (
        tuple(repr(client) for client in clients)
        == ("DeterministicFakeHearingVLMClient(fixture_count=1)",) * 3
    )


@pytest.mark.parametrize(
    ("fixture", "reason"),
    [
        (OUTAGE_FIXTURE, VLMProviderFailureCode.PROVIDER_OUTAGE),
        (TIMEOUT_FIXTURE, VLMProviderFailureCode.PROVIDER_TIMEOUT),
    ],
)
def test_hearing_fake_outage_and_timeout_never_publish(
    fixture: FakeVLMFixture,
    reason: VLMProviderFailureCode,
) -> None:
    request = _request()
    publisher = _RecordingPublisher()

    with pytest.raises(VLMProviderError) as captured:
        DeterministicFakeHearingVLMClient(
            {request.cache_key: fixture},
            publisher,
        ).complete(request)

    assert captured.value.reason_code == reason
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert publisher.calls == []


def test_hearing_fake_has_no_missing_fixture_or_screening_request_fallback() -> None:
    request = _request()
    publisher = _RecordingPublisher()
    client = DeterministicFakeHearingVLMClient({}, publisher)

    with pytest.raises(VLMProviderError) as missing:
        client.complete(request)
    assert missing.value.reason_code == VLMProviderFailureCode.FIXTURE_MISSING

    with pytest.raises(VLMProviderError) as wrong_contract:
        client.complete(object())  # type: ignore[arg-type]
    assert wrong_contract.value.reason_code == VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH
    assert publisher.calls == []


def test_hearing_fake_enforces_response_token_cost_and_persistence_boundaries() -> None:
    base = _request()
    oversized = _request(max_response_bytes=1)
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
            oversized,
            FakeVLMFixture.response(b"xx"),
            _RecordingPublisher(),
            VLMProviderFailureCode.RESPONSE_TOO_LARGE,
        ),
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
            DeterministicFakeHearingVLMClient(
                {request.cache_key: fixture},
                publisher,
            ).complete(request)
        assert captured.value.reason_code == reason
        assert captured.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED


def test_m3_fake_still_rejects_the_independent_m4_request_contract() -> None:
    request = _request()
    publisher = _RecordingPublisher()
    client = DeterministicFakeVLMClient(
        {request.cache_key: FakeVLMFixture.response(b"{}")},
        publisher,  # type: ignore[arg-type]
    )

    with pytest.raises(VLMProviderError) as captured:
        client.complete(request)  # type: ignore[arg-type]

    assert captured.value.reason_code == VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert publisher.calls == []
    assert not issubclass(HearingModelRequest, VLMRequest)
