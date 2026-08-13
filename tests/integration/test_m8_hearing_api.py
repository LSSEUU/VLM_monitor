from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
from labcourt.adapters.storage.m8_hearing_session_locator import (
    SQLiteM8HearingSessionLocator,
)
from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, SQLiteEvidenceRepository
from labcourt.adapters.vlm import DeterministicFakeHearingVLMClient
from labcourt.adapters.vlm.errors import (
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.adapters.vlm.hearing_openai_compatible import (
    HearingOpenAICompatibleIdentity,
    OpenAICompatibleHearingVLMClient,
    RoutedHearingVLMClient,
)
from labcourt.adapters.vlm.openai_compatible import (
    AppendOnlyRenderedPromptRegistry,
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
)
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.m8_platform_demo_api import _pilot_config
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.config_loader import load_config
from labcourt.contracts.enums import (
    CaseStatus,
    MediaAccess,
    PrivacyReasonCode,
    VlmRole,
)
from labcourt.contracts.m8_hearing_api import (
    M8HearingEligibility,
    M8HearingL5Status,
    M8HearingModelMode,
    M8HearingProviderSelectionV1,
    M8HearingStartRequestV1,
    M8HearingViewV1,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.ports.pixels import rgb8_pixel_sha256
from labcourt.services.m8_hearing_api import M4HearingApiRuntime, M8HearingApiService
from labcourt.services.m8_hearing_runtime import open_m8_hearing_runtime
from labcourt.services.m8_operations_api import M8ApiServiceError
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    ROOT,
    RUN_ID,
    _clock,
    _complete_call,
    _detection,
    _draft,
    _event,
    _frame,
    _manifest,
    _parsed,
    _parsed_receipt,
    _RawVerifier,
    _response,
    _screening_for,
    _Verifier,
)
from tests.integration.test_m3_sqlite_repository import (
    _request as _screening_request,
)
from tests.integration.test_m4_hearing_coordinator import (
    _digest,
    _escalated_case,
    _fixtures_for_terminal_hearing,
    _NeverAcquisitionExecutor,
    _PromptRegistrar,
)
from tests.integration.test_m8_api_server import (
    TOKENS,
)
from tests.integration.test_m8_api_server import (
    _request as _http_request,
)
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents

pytest_plugins = ("tests.integration.test_m8_api_server",)


def _provider_selections(config, manifest) -> tuple[M8HearingProviderSelectionV1, ...]:
    bindings = (
        (VlmRole.PROSECUTOR, "prosecutor", config.hearing.prosecutor_profile),
        (VlmRole.DEFENDER, "defender", config.hearing.defender_profile),
        (VlmRole.JUDGE, "judge", config.hearing.judge_profile),
    )
    return tuple(
        M8HearingProviderSelectionV1(
            role=role,
            provider_profile=profile_name,
            provider=config.providers[profile_name].provider,
            model=config.providers[profile_name].model,
            revision=config.providers[profile_name].revision,
            model_manifest_id=manifest.models[component].model_manifest_id,
            execution_location=config.providers[profile_name].execution_location,
            transport=config.providers[profile_name].transport,
        )
        for role, component, profile_name in bindings
    )


def _qwen_config_and_manifest():
    source_config = load_config(ROOT / "configs" / "demo.yaml")
    payload = source_config.model_dump(mode="json")
    payload.pop("config_sha256")
    profile_names: dict[str, str] = {}
    for role in ("prosecutor", "defender", "judge"):
        profile_name = f"qwen-{role}"
        profile_names[role] = profile_name
        profile = dict(payload["providers"][f"fake-{role}"])
        profile.update(
            {
                "provider": "openai-compatible",
                "model": "qwen3.7-plus-2026-05-26",
                "revision": "2026-05-26",
                "execution_location": "EXTERNAL",
                "transport": "HTTP",
                "endpoint_env": f"LABCOURT_QWEN_{role.upper()}_ENDPOINT",
                "api_key_env": f"LABCOURT_QWEN_{role.upper()}_API_KEY",
                "enable_thinking": False,
                "pricing_currency": "CNY",
                "input_cost_per_million_tokens": 1.0,
                "output_cost_per_million_tokens": 2.0,
            }
        )
        payload["providers"][profile_name] = profile
    payload["hearing"].update(
        {
            "prosecutor_profile": profile_names["prosecutor"],
            "defender_profile": profile_names["defender"],
            "judge_profile": profile_names["judge"],
        }
    )
    config = type(source_config).model_validate(payload)
    base_manifest = _manifest()
    models = dict(base_manifest.models)
    for component in ("prosecutor", "defender", "judge"):
        profile = config.providers[profile_names[component]]
        models[component] = models[component].model_copy(
            update={
                "provider": profile.provider,
                "model": profile.model,
                "revision": profile.revision,
                "quantization": profile.quantization,
            }
        )
    manifest = RunManifest.model_validate(
        base_manifest.model_copy(
            update={"config_sha256": config.config_sha256, "models": models}
        ).model_dump(mode="json")
    )
    assert isinstance(manifest, RunManifest)
    return config, manifest


def _real_escalated_case(
    tmp_path: Path,
    config,
    manifest: RunManifest,
    media: bytes,
    *,
    pixel_sha256: str | None = None,
):
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
    )
    evidence.register_run(RUN_ID, manifest)
    evidence.register_frame(RUN_ID, _frame())
    evidence.register_detection(RUN_ID, _detection())
    event = _event().model_copy(update={"manifest_id": manifest.manifest_id})
    evidence.create_or_get_case(RUN_ID, event)
    draft = _draft(version=1, complete=True)
    source_crop = draft.focus_crops[0]
    media_sha256 = hashlib.sha256(media).hexdigest()
    privacy = source_crop.privacy_receipt.model_copy(
        update={
            "media_access": MediaAccess.CLOUD_ALLOWED,
            "reason_code": PrivacyReasonCode.SUBJECT_FULL_REDACTION,
        }
    )
    crop = source_crop.model_copy(
        update={
            "local_path": f"{RUN_ID}/frames/{media_sha256}.png",
            "media_sha256": media_sha256,
            "pixel_sha256": pixel_sha256 or source_crop.pixel_sha256,
            "size_bytes": len(media),
            "privacy_receipt": privacy,
        }
    )
    draft = draft.model_copy(
        update={
            "event": event,
            "focus_crops": (crop,),
            "manifest_id": manifest.manifest_id,
        }
    )
    published = evidence.publish_pack(RUN_ID, 1, draft)
    pack = published.pack
    closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    m3 = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
        procedural_review_verifier=DeterministicProceduralReviewVerifier(config, evidence),
    )
    request = _screening_request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    output = _parsed(request, response, violation_probability=0.5)
    receipt = _parsed_receipt(request, response, output)
    _complete_call(m3, request, response)
    m3.append_parse_receipt(receipt, output)
    committed = m3.commit_screening(
        RUN_ID,
        published.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        _screening_for(pack, output),
    )
    assert committed.case.case.status == CaseStatus.ESCALATED
    return database, evidence, pack, committed.case


class _MemoryMediaReader:
    def __init__(self, media: bytes) -> None:
        self._media = media

    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
    ) -> SecureFileSnapshot:
        digest = hashlib.sha256(self._media).hexdigest()
        assert expected_sha256 == digest
        return SecureFileSnapshot(
            relative_path=relative_path,
            size_bytes=len(self._media),
            sha256=digest,
            bytes=self._media,
        )


class _DefinitelyNotSentQwenTransport:
    def __init__(self) -> None:
        self.calls: list[OpenAICompatibleTransportRequest] = []

    def send(
        self,
        request: OpenAICompatibleTransportRequest,
    ) -> OpenAICompatibleTransportResponse:
        self.calls.append(request)
        raise VLMProviderError(
            VLMProviderFailureCode.PROVIDER_OUTAGE,
            VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        )


class _IneligibleRuntime:
    run_id = RUN_ID

    def __init__(self, config, manifest: RunManifest) -> None:
        self.started = False
        self._view = M8HearingViewV1(
            run_id=RUN_ID,
            case_id="case-clear-terminal",
            case_location_id="room-chem-301",
            model_mode=M8HearingModelMode.OFFLINE_FIXTURE,
            provider_selections=_provider_selections(config, manifest),
            case_revision=3,
            case_status=CaseStatus.READY_FOR_ALERT_POLICY,
            eligibility=M8HearingEligibility.NOT_ELIGIBLE,
            request_manifest_id=manifest.manifest_id,
            screening_id="a" * 64,
            screening_decision="ESTABLISHED",
            current_evidence_pack_id="b" * 64,
            current_evidence_pack_version=1,
            l5_status=M8HearingL5Status.NOT_RUN,
        )

    def view(self, case_id: str) -> M8HearingViewV1:
        assert case_id == self._view.case_id
        return self._view

    def start(self, _request: M8HearingStartRequestV1) -> M8HearingViewV1:
        self.started = True
        raise AssertionError("ineligible runtime must not be started")


def test_authenticated_api_runs_offline_hearing_and_recovers_terminal_projection(
    tmp_path: Path,
    api_server,
) -> None:
    hearing_root = tmp_path / "hearing-authority"
    hearing_root.mkdir()
    database, repository, pack, escalated = _escalated_case(hearing_root)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = repository.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_digest("fake-hearing-precedents"),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    workspace_root = tmp_path / "hearing-workspace"
    workspace_root.mkdir()
    with SecureWorkspace(workspace_root, 256 * 1024) as workspace:
        response_store = SecureHearingModelResponseStore(workspace)
        role_calls = HearingRoleCallService(
            repository=repository,
            response_store=response_store,
            vlm_client=DeterministicFakeHearingVLMClient(fixtures, response_store),
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "m" * 43,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=repository,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(config, repository),
        )
        runtime = M4HearingApiRuntime(
            run_id=RUN_ID,
            location_by_zone={pack.event.zone_id: "room-chem-301"},
            model_mode=M8HearingModelMode.OFFLINE_FIXTURE,
            provider_selections=_provider_selections(config, manifest),
            evidence_repository=repository,
            hearing_repository=repository,
            session_locator=SQLiteM8HearingSessionLocator(database, repository),
            coordinator=coordinator,
        )
        server, _operational_case, operations = api_server
        server.hearing_service = M8HearingApiService(operations, {RUN_ID: runtime})
        path = f"/api/m8/runs/{RUN_ID}/cases/{pack.case_id}/hearing"

        initial_status, initial = _http_request(
            server,
            "GET",
            path,
            token=TOKENS["safety"],
        )
        assert initial_status == 200
        assert initial["eligibility"] == M8HearingEligibility.ELIGIBLE_ESCALATED.value

        request = M8HearingStartRequestV1(
            run_id=RUN_ID,
            case_id=pack.case_id,
            source_status=CaseStatus.ESCALATED,
            source_screening_id=escalated.case.screening_results[-1].screening_id,
            source_evidence_pack_id=pack.pack_id,
            source_evidence_pack_version=pack.version,
            model_mode=M8HearingModelMode.OFFLINE_FIXTURE,
            request_manifest_id=manifest.manifest_id,
        )
        post_status, posted = _http_request(
            server,
            "POST",
            path,
            token=TOKENS["safety"],
            payload=request.model_dump(mode="json"),
        )
        assert post_status == 200
        assert posted["case_status"] == CaseStatus.READY_FOR_ALERT_POLICY.value
        assert posted["eligibility"] == M8HearingEligibility.COMPLETED.value
        assert posted["l5_status"] == M8HearingL5Status.PASSED.value
        assert posted["start_request_id"] == request.start_request_id
        assert len(posted["rounds"]) == 1
        assert [item["role"] for item in posted["role_outputs"]] == [
            VlmRole.PROSECUTOR.value,
            VlmRole.DEFENDER.value,
            VlmRole.JUDGE.value,
        ]
        assert len(posted["model_responses"]) == 3
        assert posted["typed_failures"] == []
        assert posted["cited_evidence_refs"]
        assert posted["raw_model_response_content_exposed"] is False

        get_status, recovered = _http_request(
            server,
            "GET",
            path,
            token=TOKENS["safety"],
        )
        assert get_status == 200
        assert recovered["hearing_session_id"] == posted["hearing_session_id"]
        assert recovered["final_verdict"] == posted["final_verdict"]
        assert recovered["procedural_reviews"] == posted["procedural_reviews"]
        assert recovered["start_request_id"] is None

        leader_status, leader_view = _http_request(
            server,
            "GET",
            path,
            token=TOKENS["leader"],
        )
        assert leader_status == 200
        assert leader_view["final_verdict"] == posted["final_verdict"]
        assert leader_view["eligibility"] == M8HearingEligibility.COMPLETED.value

        repeated_status, repeated = _http_request(
            server,
            "POST",
            path,
            token=TOKENS["safety"],
            payload=request.model_dump(mode="json"),
        )
        assert repeated_status == 200
        assert repeated["hearing_session_id"] == posted["hearing_session_id"]
        assert (
            len(
                repository.list_hearing_model_responses(
                    RUN_ID,
                    posted["hearing_session_id"],
                )
            )
            == 3
        )


def test_explicit_qwen_mode_persists_auditable_definitely_not_sent_failure(
    tmp_path: Path,
    api_server,
) -> None:
    config, manifest = _qwen_config_and_manifest()
    media = b"controlled-redacted-media-for-qwen-boundary"
    hearing_root = tmp_path / "qwen-hearing-authority"
    hearing_root.mkdir()
    database, repository, pack, escalated = _real_escalated_case(
        hearing_root,
        config,
        manifest,
        media,
    )
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_digest("fake-hearing-precedents"),
    )
    prompt_registry = AppendOnlyRenderedPromptRegistry()
    transport = _DefinitelyNotSentQwenTransport()
    workspace_root = tmp_path / "qwen-hearing-workspace"
    workspace_root.mkdir()
    with SecureWorkspace(workspace_root, 256 * 1024) as workspace:
        response_store = SecureHearingModelResponseStore(workspace)
        clients = {}
        bindings = (
            (VlmRole.PROSECUTOR, "prosecutor", config.hearing.prosecutor_profile),
            (VlmRole.DEFENDER, "defender", config.hearing.defender_profile),
            (VlmRole.JUDGE, "judge", config.hearing.judge_profile),
        )
        for role, component, profile_name in bindings:
            profile = config.providers[profile_name]
            clients[role] = OpenAICompatibleHearingVLMClient(
                identity=HearingOpenAICompatibleIdentity(
                    provider_profile=profile_name,
                    provider=profile.provider,
                    model=profile.model,
                    revision=profile.revision,
                    model_manifest_id=manifest.models[component].model_manifest_id,
                    execution_location=profile.execution_location,
                    enable_thinking=profile.enable_thinking,
                ),
                transport=transport,
                prompt_resolver=prompt_registry,
                media_reader=_MemoryMediaReader(media),
                response_store=response_store,
            )
        role_calls = HearingRoleCallService(
            repository=repository,
            response_store=response_store,
            vlm_client=RoutedHearingVLMClient(clients),
            prompt_registrar=prompt_registry,
            owner_token_factory=lambda: "q" * 43,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=repository,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(config, repository),
        )
        runtime = M4HearingApiRuntime(
            run_id=RUN_ID,
            location_by_zone={pack.event.zone_id: "room-chem-301"},
            model_mode=M8HearingModelMode.OPENAI_COMPATIBLE_QWEN,
            provider_selections=_provider_selections(config, manifest),
            evidence_repository=repository,
            hearing_repository=repository,
            session_locator=SQLiteM8HearingSessionLocator(database, repository),
            coordinator=coordinator,
        )
        server, _operational_case, operations = api_server
        server.hearing_service = M8HearingApiService(operations, {RUN_ID: runtime})
        path = f"/api/m8/runs/{RUN_ID}/cases/{pack.case_id}/hearing"
        request = M8HearingStartRequestV1(
            run_id=RUN_ID,
            case_id=pack.case_id,
            source_status=CaseStatus.ESCALATED,
            source_screening_id=escalated.case.screening_results[-1].screening_id,
            source_evidence_pack_id=pack.pack_id,
            source_evidence_pack_version=pack.version,
            model_mode=M8HearingModelMode.OPENAI_COMPATIBLE_QWEN,
            request_manifest_id=manifest.manifest_id,
        )
        status, body = _http_request(
            server,
            "POST",
            path,
            token=TOKENS["safety"],
            payload=request.model_dump(mode="json"),
        )

        assert status == 200
        assert body["case_status"] == CaseStatus.BACKLOGGED.value
        assert body["eligibility"] == M8HearingEligibility.BACKLOGGED.value
        assert body["model_mode"] == M8HearingModelMode.OPENAI_COMPATIBLE_QWEN.value
        assert len(body["typed_failures"]) == 1
        failure = body["typed_failures"][0]
        assert failure["role"] == VlmRole.PROSECUTOR.value
        assert failure["failure_code"] == VLMProviderFailureCode.PROVIDER_OUTAGE.value
        assert failure["delivery_certainty"] == VLMDeliveryCertainty.DEFINITELY_NOT_SENT.value
        assert failure["backlog_item_id"] == body["current_backlog_item_id"]
        assert body["model_responses"] == []
        assert body["role_outputs"] == []
        assert body["raw_model_response_content_exposed"] is False
        assert len(transport.calls) == 1
        wire = json.loads(transport.calls[0].body)
        assert wire["enable_thinking"] is False
        assert wire["response_format"] == {"type": "json_object"}
        assert wire["model"] == "qwen3.7-plus-2026-05-26"
        assert all(
            item["provider"] == "openai-compatible" and "qwen" in item["model"].lower()
            for item in body["provider_selections"]
        )


def test_ineligible_case_refuses_start_and_crops_non_safety_roles(api_server) -> None:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = _manifest()
    runtime = _IneligibleRuntime(config, manifest)
    server, _operational_case, operations = api_server
    server.hearing_service = M8HearingApiService(operations, {RUN_ID: runtime})
    path = f"/api/m8/runs/{RUN_ID}/cases/{runtime._view.case_id}/hearing"

    safety_status, safety_view = _http_request(
        server,
        "GET",
        path,
        token=TOKENS["safety"],
    )
    assert safety_status == 200
    assert safety_view["eligibility"] == M8HearingEligibility.NOT_ELIGIBLE.value

    request = M8HearingStartRequestV1(
        run_id=RUN_ID,
        case_id=runtime._view.case_id,
        source_status=CaseStatus.ESCALATED,
        source_screening_id=runtime._view.screening_id,
        source_evidence_pack_id=runtime._view.current_evidence_pack_id,
        source_evidence_pack_version=runtime._view.current_evidence_pack_version,
        model_mode=runtime._view.model_mode,
        request_manifest_id=runtime._view.request_manifest_id,
    )
    rejected_status, rejected = _http_request(
        server,
        "POST",
        path,
        token=TOKENS["safety"],
        payload=request.model_dump(mode="json"),
    )
    assert rejected_status == 400
    assert rejected["reason_code"] == "INVALID_REQUEST"
    assert runtime.started is False

    for token in (TOKENS["leader"], TOKENS["student"], TOKENS["operations"]):
        cropped_status, cropped = _http_request(server, "GET", path, token=token)
        assert cropped_status == 403
        assert cropped["reason_code"] == "FORBIDDEN"


def test_persisted_runtime_resolver_closes_offline_demo_and_recovers_after_reopen(
    tmp_path: Path,
    api_server,
) -> None:
    hearing_root = tmp_path / "persisted-platform-hearing"
    hearing_root.mkdir()
    config = _pilot_config(ROOT, fixture=True)
    base_manifest = _manifest()
    models = dict(base_manifest.models)
    for component, profile_name in (
        ("prosecutor", config.hearing.prosecutor_profile),
        ("defender", config.hearing.defender_profile),
        ("judge", config.hearing.judge_profile),
    ):
        profile = config.providers[profile_name]
        models[component] = models[component].model_copy(
            update={
                "provider": profile.provider,
                "model": profile.model,
                "revision": profile.revision,
                "quantization": profile.quantization,
            }
        )
    platform_manifest = RunManifest.model_validate(
        base_manifest.model_copy(
            update={"config_sha256": config.config_sha256, "models": models}
        ).model_dump(mode="json")
    )
    assert config.perception.provider == "local-worker"
    pixels = bytes(100 * 200 * 3)
    media = encode_rgb_png(100, 200, pixels)
    database, repository, pack, escalated = _real_escalated_case(
        hearing_root,
        config,
        platform_manifest,
        media,
        pixel_sha256=rgb8_pixel_sha256(100, 200, pixels),
    )
    with SecureWorkspace(hearing_root, config.storage.max_media_bytes) as workspace:
        workspace.ensure_private_directory(".staging")
        workspace.ensure_private_directory(f".staging/{RUN_ID}")
        workspace.ensure_private_directory(RUN_ID)
        workspace.ensure_private_directory(f"{RUN_ID}/frames")
        workspace.ensure_private_directory(f"{RUN_ID}/model_responses")
        workspace.create_new(pack.crops[0].local_path, media, hashlib.sha256(media).hexdigest())
    manifest = repository.load_run_manifest(RUN_ID)

    def resolve_runtime(run_id: str):
        assert run_id == RUN_ID
        return open_m8_hearing_runtime(
            config=config,
            run_id=run_id,
            workspace_root=hearing_root,
            database_path=database,
            location_by_zone={pack.event.zone_id: "room-chem-301"},
            model_mode=M8HearingModelMode.OFFLINE_FIXTURE,
            synthetic_demo_fixture=True,
        )

    server, _operational_case, operations = api_server
    hearing_service = M8HearingApiService(
        operations,
        {},
        runtime_resolver=resolve_runtime,
    )
    server.hearing_service = hearing_service
    request = M8HearingStartRequestV1(
        run_id=RUN_ID,
        case_id=pack.case_id,
        source_status=CaseStatus.ESCALATED,
        source_screening_id=escalated.case.screening_results[-1].screening_id,
        source_evidence_pack_id=pack.pack_id,
        source_evidence_pack_version=pack.version,
        model_mode=M8HearingModelMode.OFFLINE_FIXTURE,
        request_manifest_id=manifest.manifest_id,
    )

    safety = server.api_authenticator.authenticate(f"Bearer {TOKENS['safety']}")
    posted = hearing_service.start(
        safety,
        RUN_ID,
        pack.case_id,
        request,
    )
    assert posted.eligibility == M8HearingEligibility.COMPLETED
    assert posted.l5_status == M8HearingL5Status.PASSED
    assert [item.role for item in posted.role_outputs] == [
        VlmRole.PROSECUTOR,
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
    ]

    recovered = hearing_service.status(safety, RUN_ID, pack.case_id)
    assert recovered.hearing_session_id == posted.hearing_session_id
    assert recovered.final_verdict == posted.final_verdict

    student = server.api_authenticator.authenticate(f"Bearer {TOKENS['student']}")
    with pytest.raises(M8ApiServiceError, match="FORBIDDEN"):
        hearing_service.status(student, RUN_ID, pack.case_id)
