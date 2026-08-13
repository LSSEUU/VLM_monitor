"""Composition root for explicit offline or OpenAI-compatible Qwen M8 hearings."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.hearing_model_response_store import (
    SecureHearingModelResponseStore,
)
from labcourt.adapters.storage.m8_hearing_evidence_repository import (
    SQLiteM8HearingEvidenceRepository,
)
from labcourt.adapters.storage.m8_hearing_session_locator import (
    SQLiteM8HearingSessionLocator,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_m5_precedent_usage import (
    SQLiteM5PrecedentExposureCommitter,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.adapters.vlm.hearing_fake import DeterministicFakeHearingVLMClient
from labcourt.adapters.vlm.hearing_openai_compatible import (
    HearingOpenAICompatibleIdentity,
    HearingPromptResolver,
    OpenAICompatibleHearingVLMClient,
    RoutedHearingVLMClient,
)
from labcourt.adapters.vlm.hearing_synthetic_demo import (
    DeterministicSyntheticDemoHearingVLMClient,
)
from labcourt.adapters.vlm.http_transport import build_openai_compatible_transport
from labcourt.adapters.vlm.openai_compatible import (
    AppendOnlyRenderedPromptRegistry,
    OpenAICompatibleTransport,
)
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_request import FROZEN_M4_PROMPT_BUNDLE_SHA256
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    M5HearingPrecedentRetriever,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import ExecutionLocation, ProviderTransport, VlmRole
from labcourt.contracts.m4_operations import M4FakeVLMFixtureBundle
from labcourt.contracts.m8_hearing_api import (
    M8HearingModelMode,
    M8HearingProviderSelectionV1,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import LabCourtError
from labcourt.ports.hearing_acquisition import HearingAcquisitionExecutor
from labcourt.ports.hearing_repository import HearingRepository
from labcourt.ports.hearing_vlm import HearingVLMClient
from labcourt.services.m4_operations import (
    _fake_acquisition_executor,
    _fixture_mapping,
    build_hearing_prompt_catalog,
)
from labcourt.services.m8_hearing_api import M4HearingApiRuntime


class M8HearingRuntimeFailureCode(StrEnum):
    DEPLOYMENT_UNSUPPORTED = "DEPLOYMENT_UNSUPPORTED"
    MODEL_MANIFEST_MISMATCH = "MODEL_MANIFEST_MISMATCH"
    OFFLINE_FIXTURE_REQUIRED = "OFFLINE_FIXTURE_REQUIRED"
    REAL_MODE_FIXTURE_FORBIDDEN = "REAL_MODE_FIXTURE_FORBIDDEN"


class M8HearingRuntimeError(LabCourtError):
    def __init__(self, reason_code: M8HearingRuntimeFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"M8 hearing runtime failed: {reason_code.value}")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _hearing_prompt_bundle_for_run(database: Path, run_id: str) -> str:
    """Reuse a persisted run's single M4 bundle, or select the current bundle."""

    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            """
            SELECT DISTINCT hearing_prompt_bundle_sha256
            FROM m4_hearings
            WHERE run_id = ?
            ORDER BY hearing_prompt_bundle_sha256
            """,
            (run_id,),
        ).fetchall()
    finally:
        connection.close()
    if not rows:
        return FROZEN_M4_PROMPT_BUNDLE_SHA256
    if len(rows) != 1 or not isinstance(rows[0][0], str):
        raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.DEPLOYMENT_UNSUPPORTED)
    return rows[0][0]


@contextmanager
def open_m8_hearing_runtime(
    *,
    config: AppConfig,
    run_id: str,
    workspace_root: str | Path,
    database_path: str | Path,
    location_by_zone: Mapping[str, str],
    model_mode: M8HearingModelMode = M8HearingModelMode.OFFLINE_FIXTURE,
    fixture_bundle: M4FakeVLMFixtureBundle | None = None,
    synthetic_demo_fixture: bool = False,
    environment: Mapping[str, str] | None = None,
    transports: Mapping[str, OpenAICompatibleTransport] | None = None,
    acquisition_executor_factory: (
        Callable[[SecureWorkspace, RunManifest], HearingAcquisitionExecutor] | None
    ) = None,
    clock: Callable[[], datetime] | None = None,
) -> Iterator[M4HearingApiRuntime]:
    """Open one run with exactly one selected model mode and no fallback path."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    if not isinstance(model_mode, M8HearingModelMode):
        raise TypeError("model_mode must be an M8HearingModelMode")
    if not isinstance(synthetic_demo_fixture, bool):
        raise TypeError("synthetic_demo_fixture must be a bool")
    controlled_run_id = require_reference_token(run_id, "M8 hearing runtime run reference")
    root = Path(workspace_root).absolute()
    database = Path(database_path).absolute()
    permitted_databases = {
        root / config.storage.database_filename,
        root / controlled_run_id / config.storage.database_filename,
    }
    if database not in permitted_databases:
        raise ValueError("database_path must match the configured run workspace database")
    if set(location_by_zone) != {zone.zone_id for zone in config.zones}:
        raise ValueError("location_by_zone must cover exactly every configured zone")

    role_bindings = (
        (VlmRole.PROSECUTOR, "prosecutor", config.hearing.prosecutor_profile),
        (VlmRole.DEFENDER, "defender", config.hearing.defender_profile),
        (VlmRole.JUDGE, "judge", config.hearing.judge_profile),
    )
    profile_names = tuple(item[2] for item in role_bindings)
    profiles = tuple(config.providers[name] for name in profile_names)
    if (
        config.perception.provider not in {"precomputed", "local-worker"}
        or len(set(profile_names)) != 3
    ):
        raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.DEPLOYMENT_UNSUPPORTED)
    if model_mode == M8HearingModelMode.OFFLINE_FIXTURE:
        if fixture_bundle is None and not synthetic_demo_fixture:
            raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.OFFLINE_FIXTURE_REQUIRED)
        if transports is not None or any(
            profile.provider != "fake"
            or profile.transport != ProviderTransport.IN_PROCESS
            or profile.execution_location != ExecutionLocation.LOCAL
            for profile in profiles
        ):
            raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.DEPLOYMENT_UNSUPPORTED)
    else:
        if synthetic_demo_fixture:
            raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.REAL_MODE_FIXTURE_FORBIDDEN)
        if fixture_bundle is not None and fixture_bundle.fixtures:
            raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.REAL_MODE_FIXTURE_FORBIDDEN)
        if any(
            profile.provider != "openai-compatible"
            or profile.transport != ProviderTransport.HTTP
            or profile.execution_location != ExecutionLocation.EXTERNAL
            or "qwen" not in profile.model.lower()
            for profile in profiles
        ):
            raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.DEPLOYMENT_UNSUPPORTED)
        if transports is not None and set(transports) != set(profile_names):
            raise ValueError("real hearing transports must cover exactly three profiles")

    acquisition_bundle = fixture_bundle or M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(),
    )
    effective_clock = clock or _utc_now
    if not callable(effective_clock):
        raise TypeError("clock must be callable")

    with SecureWorkspace(root, max_file_bytes=config.storage.max_media_bytes) as workspace:
        verifier = StoredPngVerifier(
            run_id=controlled_run_id,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        evidence = SQLiteM8HearingEvidenceRepository(
            database,
            config.storage.busy_timeout_ms,
            verifier=verifier,
            clock=effective_clock,
        )
        hearings = SQLiteHearingRepository(evidence)
        hearing_authority = cast(HearingRepository, hearings)
        manifest = evidence.load_run_manifest(controlled_run_id)
        if manifest.config_sha256 != config.config_sha256:
            raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.MODEL_MANIFEST_MISMATCH)
        for _role, component, profile_name in role_bindings:
            profile = config.providers[profile_name]
            model_manifest = manifest.models[component]
            if (
                model_manifest.provider,
                model_manifest.model,
                model_manifest.revision,
                model_manifest.quantization,
            ) != (
                profile.provider,
                profile.model,
                profile.revision,
                profile.quantization,
            ):
                raise M8HearingRuntimeError(M8HearingRuntimeFailureCode.MODEL_MANIFEST_MISMATCH)

        selections = tuple(
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
            for role, component, profile_name in role_bindings
        )
        policy_verifier = ConfiguredM5PrecedentPolicyVerifier(config)
        m5_repository = SQLiteM5Repository(
            database,
            config.storage.busy_timeout_ms,
            clock=effective_clock,
            m5_precedent_policy_verifier=policy_verifier,
        )
        embeddings = DeterministicFakePrecedentEmbeddingProvider()
        response_store = SecureHearingModelResponseStore(workspace)
        prompt_registry = AppendOnlyRenderedPromptRegistry()
        if model_mode == M8HearingModelMode.OFFLINE_FIXTURE:
            vlm_client: HearingVLMClient
            if synthetic_demo_fixture:
                vlm_client = DeterministicSyntheticDemoHearingVLMClient(response_store)
            else:
                assert fixture_bundle is not None
                vlm_client = DeterministicFakeHearingVLMClient(
                    _fixture_mapping(fixture_bundle),
                    response_store,
                )
        else:
            role_clients = {}
            for role, component, profile_name in role_bindings:
                profile = config.providers[profile_name]
                active_transport = (
                    transports[profile_name]
                    if transports is not None
                    else build_openai_compatible_transport(profile, environment=environment)
                )
                role_clients[role] = OpenAICompatibleHearingVLMClient(
                    identity=HearingOpenAICompatibleIdentity(
                        provider_profile=profile_name,
                        provider=profile.provider,
                        model=profile.model,
                        revision=profile.revision,
                        model_manifest_id=manifest.models[component].model_manifest_id,
                        execution_location=profile.execution_location,
                        enable_thinking=profile.enable_thinking,
                    ),
                    transport=active_transport,
                    prompt_resolver=cast(HearingPromptResolver, prompt_registry),
                    media_reader=workspace,
                    response_store=response_store,
                )
            vlm_client = RoutedHearingVLMClient(role_clients)

        catalog = build_hearing_prompt_catalog(
            _hearing_prompt_bundle_for_run(database, controlled_run_id)
        )
        role_calls = HearingRoleCallService(
            repository=hearing_authority,
            response_store=response_store,
            vlm_client=vlm_client,
            prompt_registrar=prompt_registry,
        )
        precedents = HearingPrecedentRetrievalService(
            M5HearingPrecedentRetriever(
                repository=m5_repository,
                manifest=manifest,
                policy=policy_verifier.expected_policy(manifest),
                run_mode=policy_verifier.run_mode,
                embedding_provider=embeddings,
            ),
            retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
            retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=evidence,
            hearing_repository=hearing_authority,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=hearing_authority,
                executor=(
                    acquisition_executor_factory(workspace, manifest)
                    if acquisition_executor_factory is not None
                    else _fake_acquisition_executor(manifest, acquisition_bundle)
                ),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(config, evidence),
            precedent_outcome_committer=SQLiteM5PrecedentExposureCommitter(
                repository=m5_repository,
                hearing_repository=hearings,
                embedding_provider=embeddings,
            ),
        )
        yield M4HearingApiRuntime(
            run_id=controlled_run_id,
            location_by_zone=location_by_zone,
            model_mode=model_mode,
            provider_selections=selections,
            evidence_repository=evidence,
            hearing_repository=hearing_authority,
            session_locator=SQLiteM8HearingSessionLocator(database, hearing_authority),
            coordinator=coordinator,
        )


__all__ = [
    "M8HearingRuntimeError",
    "M8HearingRuntimeFailureCode",
    "open_m8_hearing_runtime",
]
