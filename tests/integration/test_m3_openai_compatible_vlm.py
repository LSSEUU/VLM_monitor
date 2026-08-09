from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from labcourt.adapters.jinja_prompt_renderer import RenderedPrompt
from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.vlm import (
    DeterministicFakeVLMClient,
    FakeVLMFixture,
    ImmutableRenderedPromptRegistry,
    OpenAICompatibleClientIdentity,
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
    OpenAICompatibleVLMClient,
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
    ProceduralDefectCode,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import (
    StructureRepairRequest,
    VLMCallRequest,
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import LabCourtError

RUN_ID = "run-01"
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
MODEL_MANIFEST_ID = "7" * 64
PROMPT_TEXT = "Return exactly one JSON object."
PROMPT_SHA256 = hashlib.sha256(PROMPT_TEXT.encode("utf-8")).hexdigest()
MEDIA_BYTES = b"\x89PNG\r\n\x1a\ncontrolled-test-media"
MEDIA_SHA256 = hashlib.sha256(MEDIA_BYTES).hexdigest()


def _manifest(role: VlmRole = VlmRole.SCREENING) -> PromptManifest:
    return PromptManifest(
        prompt_id=f"{role.value.lower()}-v1",
        role=role,
        template_sha256=SHA_1,
        output_schema_sha256=SHA_2,
        prompt_bundle_sha256=SHA_3,
        renderer_version="jinja-3-1",
    )


def _prompt_registry() -> ImmutableRenderedPromptRegistry:
    return ImmutableRenderedPromptRegistry(
        (
            RenderedPrompt(
                manifest=_manifest(),
                rendered_prompt_sha256=PROMPT_SHA256,
                text=PROMPT_TEXT,
            ),
        )
    )


def _request(
    *,
    max_response_bytes: int = 4096,
    max_input_tokens: int = 256,
    max_output_tokens: int = 128,
    input_cost_per_million_tokens: float = 2.0,
    output_cost_per_million_tokens: float = 4.0,
    max_estimated_cost: float = 1.0,
) -> VLMRequest:
    media = VLMMediaRef(
        crop_id=SHA_4,
        media_sha256=MEDIA_SHA256,
        local_path=f"{RUN_ID}/frames/{MEDIA_SHA256}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.CLOUD_ALLOWED,
        privacy_policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
        privacy_transform_version="privacy-v1",
        width=8,
        height=8,
    )
    return VLMRequest(
        run_id=RUN_ID,
        case_id="case-01",
        evidence_pack_id=SHA_5,
        evidence_pack_version=1,
        provider_profile="openai-compatible-v1",
        provider="compatible-test",
        model="vlm-test",
        revision="2026-01",
        model_manifest_id=MODEL_MANIFEST_ID,
        execution_location=ExecutionLocation.EXTERNAL,
        prompt_manifest=_manifest(),
        rendered_prompt_sha256=PROMPT_SHA256,
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
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
            pricing_currency="USD",
            input_cost_per_million_tokens=input_cost_per_million_tokens,
            output_cost_per_million_tokens=output_cost_per_million_tokens,
            max_estimated_cost=max_estimated_cost,
            max_response_bytes=max_response_bytes,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=1024,
            timeout_seconds=5.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=SHA_2,
    )


def _identity() -> OpenAICompatibleClientIdentity:
    return OpenAICompatibleClientIdentity(
        provider_profile="openai-compatible-v1",
        provider="compatible-test",
        model="vlm-test",
        revision="2026-01",
        model_manifest_id=MODEL_MANIFEST_ID,
        execution_location=ExecutionLocation.EXTERNAL,
    )


def _envelope(
    content: str,
    *,
    choices: list[object] | None = None,
    prompt_tokens: int = 3,
    completion_tokens: int = 4,
) -> bytes:
    document = {
        "choices": choices
        if choices is not None
        else [
            {
                "finish_reason": "stop",
                "index": 0,
                "message": {"content": content, "role": "assistant"},
            }
        ],
        "usage": {
            "completion_tokens": completion_tokens,
            "prompt_tokens": prompt_tokens,
        },
    }
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


@dataclass(slots=True)
class _Transport:
    response: OpenAICompatibleTransportResponse | None = None
    failure: Exception | None = None
    secret: str = field(default="secret-key", repr=True)
    calls: list[OpenAICompatibleTransportRequest] = field(default_factory=list)

    def send(
        self,
        request: OpenAICompatibleTransportRequest,
    ) -> OpenAICompatibleTransportResponse:
        self.calls.append(request)
        if self.failure is not None:
            raise self.failure
        if self.response is None:
            raise AssertionError("transport fixture has no result")
        return self.response


@dataclass(slots=True)
class _FailingPublisher:
    failure: Exception

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
        raise self.failure


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir(parents=True)
    return root


def _prepare_media(workspace: SecureWorkspace, payload: bytes = MEDIA_BYTES) -> None:
    workspace.ensure_private_directory(RUN_ID)
    workspace.ensure_private_directory(f"{RUN_ID}/frames")
    workspace.create_new(
        f"{RUN_ID}/frames/{MEDIA_SHA256}.png",
        payload,
        hashlib.sha256(payload).hexdigest(),
    )


def _client(
    workspace: SecureWorkspace,
    transport: _Transport,
) -> OpenAICompatibleVLMClient:
    return OpenAICompatibleVLMClient(
        identity=_identity(),
        transport=transport,
        prompt_resolver=_prompt_registry(),
        media_reader=workspace,
        response_store=SecureModelResponseStore(workspace),
    )


@pytest.mark.parametrize("adapter_kind", ["fake", "openai-compatible"])
def test_fake_and_openai_adapters_share_the_same_response_receipt_contract(
    tmp_path: Path,
    adapter_kind: str,
) -> None:
    root = _root(tmp_path)
    request = _request()
    content = b'{"shared":"contract"}'
    transport = _Transport(
        response=OpenAICompatibleTransportResponse(
            body=_envelope(content.decode("utf-8")),
            latency_ms=5,
        )
    )
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        store = SecureModelResponseStore(workspace)
        if adapter_kind == "fake":
            client = DeterministicFakeVLMClient(
                {
                    request.cache_key: FakeVLMFixture.response(
                        content,
                        input_tokens=3,
                        output_tokens=4,
                        latency_ms=5,
                    )
                },
                store,
            )
        else:
            client = _client(workspace, transport)
        first = client.complete(request)
        retry = client.complete(request)

        assert first == retry
        assert store.verify(RUN_ID, first) == first
        assert store.read_json(RUN_ID, first, len(content)) == content.decode("utf-8")
        assert first.request_id == request.request_id
        assert first.request_sha256 == request.request_sha256
        assert first.cache_key == request.cache_key
        assert first.manifest_id == request.manifest_id
        assert first.model_manifest_id == request.model_manifest_id
        assert first.size_bytes == len(content)


def test_openai_adapter_revalidates_media_calls_once_and_persists_exact_content(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    content = ' \n{"provider":"content"}\n '
    transport = _Transport(
        response=OpenAICompatibleTransportResponse(
            body=_envelope(content),
            latency_ms=9,
        )
    )
    request = _request()
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        client = _client(workspace, transport)
        response = client.complete(request)
        assert (
            SecureModelResponseStore(workspace).read_json(
                RUN_ID,
                response,
                request.budget.max_response_bytes,
            )
            == content
        )

    assert len(transport.calls) == 1
    wire = json.loads(transport.calls[0].body.decode("utf-8"))
    assert wire["messages"][0]["content"][0] == {
        "text": PROMPT_TEXT,
        "type": "text",
    }
    assert wire["messages"][0]["content"][1] == {
        "image_url": {
            "url": "data:image/png;base64," + base64.b64encode(MEDIA_BYTES).decode("ascii")
        },
        "type": "image_url",
    }
    assert RUN_ID not in transport.calls[0].body.decode("utf-8")
    assert response.input_tokens == 3
    assert response.output_tokens == 4
    assert response.latency_ms == 9
    assert (root / Path(response.raw_response_ref)).read_bytes() == content.encode("utf-8")


@pytest.mark.parametrize("content", ["", '{"malformed":'])
def test_valid_single_choice_can_carry_empty_or_malformed_model_output_for_strict_parser(
    tmp_path: Path,
    content: str,
) -> None:
    root = _root(tmp_path)
    transport = _Transport(response=OpenAICompatibleTransportResponse(body=_envelope(content)))
    request = _request()
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        response = _client(workspace, transport).complete(request)
    assert (root / Path(response.raw_response_ref)).read_bytes() == content.encode("utf-8")


def test_structure_repair_call_is_media_free_and_publishes_attempt_one(tmp_path: Path) -> None:
    root = _root(tmp_path)
    request = _request()
    repair_text = "Repair structure only."
    repair_sha = hashlib.sha256(repair_text.encode("utf-8")).hexdigest()
    transport = _Transport(response=OpenAICompatibleTransportResponse(body=_envelope("{}")))
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        original = SecureModelResponseStore(workspace).publish(request, b'{"malformed":')
        repair = StructureRepairRequest(
            run_id=request.run_id,
            case_id=request.case_id,
            evidence_pack_id=request.evidence_pack_id,
            evidence_pack_version=request.evidence_pack_version,
            provider_profile=request.provider_profile,
            provider=request.provider,
            model=request.model,
            revision=request.revision,
            model_manifest_id=request.model_manifest_id,
            execution_location=request.execution_location,
            prompt_manifest=_manifest(VlmRole.STRUCTURE_REPAIR),
            rendered_prompt_sha256=repair_sha,
            original_request_id=request.request_id,
            original_request_sha256=request.request_sha256,
            original_response_id=original.response_id,
            original_response_sha256=original.content_sha256,
            parse_defect_codes=(ProceduralDefectCode.MALFORMED_STRUCTURE,),
            temperature=0.0,
            seed=7,
            budget=VlmCallBudget(
                max_images=0,
                max_input_pixels=0,
                max_output_tokens=128,
                pricing_currency=request.budget.pricing_currency,
                input_cost_per_million_tokens=(request.budget.input_cost_per_million_tokens),
                output_cost_per_million_tokens=(request.budget.output_cost_per_million_tokens),
                max_estimated_cost=request.budget.max_estimated_cost,
                max_response_bytes=4096,
                max_json_depth=8,
                max_json_fields=128,
                max_string_chars=1024,
                timeout_seconds=5.0,
                claim_completion_grace_seconds=5.0,
            ),
            manifest_id=request.manifest_id,
        )
        repair_registry = ImmutableRenderedPromptRegistry(
            (
                RenderedPrompt(
                    manifest=repair.prompt_manifest,
                    rendered_prompt_sha256=repair_sha,
                    text=repair_text,
                ),
            )
        )
        client = OpenAICompatibleVLMClient(
            identity=_identity(),
            transport=transport,
            prompt_resolver=repair_registry,
            media_reader=workspace,
            response_store=SecureModelResponseStore(workspace),
        )
        response = client.complete(repair)

    wire = json.loads(transport.calls[0].body.decode("utf-8"))
    assert wire["messages"][0]["content"] == [{"text": repair_text, "type": "text"}]
    assert response.attempt_index == 1
    assert response.purpose.value == "STRUCTURE_REPAIR"


@pytest.mark.parametrize(
    "body",
    [
        _envelope(
            "{}",
            choices=[
                {"message": {"content": "{}"}},
                {"message": {"content": "{}"}},
            ],
        ),
        b'{"choices":[],"choices":[]}',
        b'{"choices":[{"message":{"content":[]}}]}',
        b'{"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}',
        b'{"choices":[{"message":{"content":"{}"}}]}',
        b'{"choices":[{"message":{"content":"{}"}}],"usage":{"prompt_tokens":3}}',
        b'{"choices":[{"message":{"content":"{}"}}],"usage":{"completion_tokens":4}}',
        b"not-json",
    ],
)
def test_openai_adapter_rejects_non_single_or_invalid_envelopes_without_publishing(
    tmp_path: Path,
    body: bytes,
) -> None:
    root = _root(tmp_path)
    transport = _Transport(response=OpenAICompatibleTransportResponse(body=body))
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        with pytest.raises(VLMProviderError) as captured:
            _client(workspace, transport).complete(_request())
    assert captured.value.reason_code == VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
    assert len(transport.calls) == 1
    assert not (root / RUN_ID / "model_responses").exists()


def test_openai_adapter_enforces_wire_and_token_budgets(tmp_path: Path) -> None:
    root = _root(tmp_path)
    oversized = _Transport(response=OpenAICompatibleTransportResponse(body=b"x" * 257))
    token_overrun = _Transport(
        response=OpenAICompatibleTransportResponse(body=_envelope("{}", completion_tokens=129))
    )
    input_token_overrun = _Transport(
        response=OpenAICompatibleTransportResponse(body=_envelope("{}", prompt_tokens=257))
    )
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        with pytest.raises(VLMProviderError) as too_large:
            _client(workspace, oversized).complete(_request(max_response_bytes=256))
        with pytest.raises(VLMProviderError) as too_many_tokens:
            _client(workspace, token_overrun).complete(_request(max_output_tokens=128))
        with pytest.raises(VLMProviderError) as too_many_input_tokens:
            _client(workspace, input_token_overrun).complete(_request(max_input_tokens=256))
    assert too_large.value.reason_code == VLMProviderFailureCode.RESPONSE_TOO_LARGE
    assert too_many_tokens.value.reason_code == (
        VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED
    )
    assert too_many_input_tokens.value.reason_code == (
        VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED
    )
    assert too_large.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
    assert too_many_tokens.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
    assert too_many_input_tokens.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED


def test_openai_adapter_enforces_request_bound_cost_before_publish(tmp_path: Path) -> None:
    root = _root(tmp_path)
    transport = _Transport(
        response=OpenAICompatibleTransportResponse(
            body=_envelope("{}", prompt_tokens=3, completion_tokens=4)
        )
    )
    request = _request(max_estimated_cost=0.000021)

    assert request.budget.estimate_cost(input_tokens=3, output_tokens=4) == 0.000022
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        with pytest.raises(VLMProviderError) as captured:
            _client(workspace, transport).complete(request)

    assert captured.value.reason_code == (VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED)
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
    assert len(transport.calls) == 1
    assert not (root / RUN_ID / "model_responses").exists()


def test_openai_adapter_fails_before_transport_on_media_hash_or_cloud_policy_change(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    transport = _Transport(response=OpenAICompatibleTransportResponse(body=_envelope("{}")))
    request = _request()
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace, payload=b"tampered-media")
        with pytest.raises(VLMProviderError) as tamper:
            _client(workspace, transport).complete(request)
    assert tamper.value.reason_code == VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE
    assert tamper.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert transport.calls == []

    policy_root = _root(tmp_path / "policy")
    bad_media = request.media[0].model_copy(update={"media_access": MediaAccess.LOCAL_ONLY})
    unchecked_payload = dict(request.__dict__)
    unchecked_payload["media"] = (bad_media,)
    # Deliberately bypass Pydantic to prove the adapter repeats this security check
    # immediately before transport, even if an unsafe caller forges an object.
    bypassed = VLMRequest.model_construct(**unchecked_payload)
    with SecureWorkspace(policy_root, 16384) as workspace:
        _prepare_media(workspace)
        with pytest.raises(VLMProviderError) as policy:
            _client(workspace, transport).complete(bypassed)
    assert policy.value.reason_code == VLMProviderFailureCode.MEDIA_POLICY_REJECTED
    assert policy.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert transport.calls == []


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (TimeoutError("secret endpoint"), VLMProviderFailureCode.PROVIDER_TIMEOUT),
        (RuntimeError("secret endpoint"), VLMProviderFailureCode.TRANSPORT_UNAVAILABLE),
    ],
)
def test_openai_transport_failure_is_single_attempt_and_redacted(
    tmp_path: Path,
    failure: Exception,
    reason: VLMProviderFailureCode,
) -> None:
    root = _root(tmp_path)
    transport = _Transport(failure=failure, secret="do-not-leak")
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        client = _client(workspace, transport)
        with pytest.raises(VLMProviderError) as captured:
            client.complete(_request())
    assert captured.value.reason_code == reason
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.UNKNOWN
    assert len(transport.calls) == 1
    assert "do-not-leak" not in repr(client)
    assert "do-not-leak" not in str(captured.value)
    assert "secret endpoint" not in str(captured.value)


def test_openai_client_preserves_typed_transport_failure(tmp_path: Path) -> None:
    typed = VLMProviderError(
        VLMProviderFailureCode.PROVIDER_OUTAGE,
        VLMDeliveryCertainty.UNKNOWN,
    )
    transport = _Transport(failure=typed)
    with SecureWorkspace(_root(tmp_path), 16384) as workspace:
        _prepare_media(workspace)
        with pytest.raises(VLMProviderError) as captured:
            _client(workspace, transport).complete(_request())
    assert captured.value is typed


def test_prompt_registry_missing_or_manifest_mismatch_fails_before_transport(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    transport = _Transport(response=OpenAICompatibleTransportResponse(body=_envelope("{}")))
    request = _request()
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        missing = OpenAICompatibleVLMClient(
            identity=_identity(),
            transport=transport,
            prompt_resolver=ImmutableRenderedPromptRegistry(()),
            media_reader=workspace,
            response_store=SecureModelResponseStore(workspace),
        )
        with pytest.raises(VLMProviderError) as captured:
            missing.complete(request)
    assert captured.value.reason_code == VLMProviderFailureCode.PROMPT_MISSING
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert transport.calls == []


@pytest.mark.parametrize(
    "failure",
    [LabCourtError("journal not created"), RuntimeError("unexpected storage failure")],
)
def test_openai_publish_failure_after_transport_is_completed(
    tmp_path: Path,
    failure: Exception,
) -> None:
    root = _root(tmp_path)
    transport = _Transport(response=OpenAICompatibleTransportResponse(body=_envelope("{}")))
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        client = OpenAICompatibleVLMClient(
            identity=_identity(),
            transport=transport,
            prompt_resolver=_prompt_registry(),
            media_reader=workspace,
            response_store=_FailingPublisher(failure),
        )
        with pytest.raises(VLMProviderError) as captured:
            client.complete(_request())

    assert captured.value.reason_code == VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.COMPLETED
    assert len(transport.calls) == 1


def test_openai_identity_mismatch_is_definitely_not_sent(tmp_path: Path) -> None:
    root = _root(tmp_path)
    transport = _Transport(response=OpenAICompatibleTransportResponse(body=_envelope("{}")))
    with SecureWorkspace(root, 16384) as workspace:
        _prepare_media(workspace)
        mismatched = _request().model_copy(update={"revision": "unexpected"})
        with pytest.raises(VLMProviderError) as captured:
            _client(workspace, transport).complete(mismatched)

    assert captured.value.reason_code == VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH
    assert captured.value.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT
    assert transport.calls == []
