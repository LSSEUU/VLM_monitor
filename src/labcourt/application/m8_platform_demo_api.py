"""Assemble the authenticated same-origin campus platform Demo."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from labcourt.adapters.m8_hashed_bearer_authenticator import M8HashedBearerAuthenticator
from labcourt.adapters.m8_qwen_agent import build_m8_qwen_agent_runtime
from labcourt.adapters.storage.sqlite_m8_adapter_commissioning_repository import (
    SQLiteM8AdapterCommissioningRepository,
)
from labcourt.adapters.storage.sqlite_m8_agent_conversation_repository import (
    SQLiteM8AgentConversationRepository,
)
from labcourt.adapters.storage.sqlite_m8_feishu_activation_repository import (
    SQLiteM8FeishuActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_feishu_inbound_activation_repository import (
    SQLiteM8FeishuInboundActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_knowledge_repository import SQLiteM8KnowledgeRepository
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_m8_sensor_persistence_repository import (
    SQLiteM8SensorPersistenceRepository,
)
from labcourt.application.m8_platform_bootstrap import (
    PLATFORM_ACCESS_NAME,
    PLATFORM_CAMPUS_ID,
    PLATFORM_LOCATION_ID,
    bootstrap_m8_platform_demo,
    load_m8_platform_bootstrap,
    platform_manifest,
)
from labcourt.application.m8_sensor_demo import build_offline_smoke_demo_bundle
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_agent_chat import M8AgentModelProfileV1
from labcourt.contracts.m8_api import (
    M8ApiCredentialAuthorityV1,
    M8ApiCredentialCatalogAuthorityV1,
)
from labcourt.m8_platform_server import M8PlatformHttpServer, build_m8_platform_server
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_agent_chat import M8AgentChatService
from labcourt.services.m8_agent_tools import M8PlatformAgentToolService
from labcourt.services.m8_case_memory import M8ScopedOperationalCaseMemoryAdapter
from labcourt.services.m8_commissioning_api import M8CommissioningApiService
from labcourt.services.m8_feishu_platform import M8FeishuPlatformService
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_knowledge_projection import M8KnowledgeProjectionService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_operations_api import M8OperationsApiService
from labcourt.services.m8_operations_projection import M8OperationsProjectionService
from labcourt.services.m8_platform_agent import M8PlatformAgentService
from labcourt.services.m8_platform_demo import M8PlatformDemoService
from labcourt.services.m8_projection_api import M8ProjectionApiService
from labcourt.services.m8_recorded_media_api import M8RecordedMediaApiService
from labcourt.services.m8_rule_config_api import M8RuleConfigApiService
from labcourt.services.m8_user_permission_api import M8UserPermissionApiService
from labcourt.services.pilot_ui import PilotUiService

_BUSY_TIMEOUT_MS = 5_000
M8_PLATFORM_ROLE_TOKENS = {
    M8ActorRole.LEADER: "labcourt-platform-leader-token",
    M8ActorRole.SAFETY_OFFICER: "labcourt-platform-safety-token",
    M8ActorRole.STUDENT: "labcourt-platform-student-token",
    M8ActorRole.OPERATIONS: "labcourt-platform-operations-token",
}
_ROLE_ACTORS = {
    M8ActorRole.LEADER: "leader-demo",
    M8ActorRole.SAFETY_OFFICER: "safety-officer-demo",
    M8ActorRole.STUDENT: "student-demo",
    M8ActorRole.OPERATIONS: "operations-demo",
}


def _credential_catalog() -> M8ApiCredentialCatalogAuthorityV1:
    credentials = tuple(
        M8ApiCredentialAuthorityV1(
            credential_id=f"credential-platform-{role.value.casefold()}",
            actor_id=_ROLE_ACTORS[role],
            bearer_token_sha256=hashlib.sha256(token.encode("ascii")).hexdigest(),
            active=True,
            manifest_id=platform_manifest("platform-api-credential-v1"),
        )
        for role, token in sorted(M8_PLATFORM_ROLE_TOKENS.items(), key=lambda item: item[0].value)
    )
    return M8ApiCredentialCatalogAuthorityV1(
        revision=1,
        credentials=credentials,
        authentication_manifest_id=platform_manifest("platform-api-authentication-v1"),
    )


def _pilot_config(project_root: Path, *, fixture: bool) -> AppConfig:
    """Compose the Pilot scope while retaining an explicit model/fixture choice."""

    demo = load_config(project_root / "configs/demo.yaml")
    pilot = load_config(project_root / "configs/pilot.yaml")
    payload = demo.model_dump(mode="python", exclude_computed_fields=True)
    pilot_payload = pilot.model_dump(mode="python", exclude_computed_fields=True)
    payload["zones"] = pilot_payload["zones"]
    payload["pilot"] = pilot_payload["pilot"]
    payload["perception"] = pilot_payload["perception"]
    if fixture:
        screening = dict(payload["screening"])
        providers = dict(payload["providers"])
        profile = dict(pilot_payload["providers"]["pilot-screening"])
        profile.update(
            {
                "provider": "labcourt-fixture",
                "model": "offline-structured-ppe-screening",
                "revision": "1.0.0",
                "endpoint_env": "LABCOURT_PLATFORM_FIXTURE_ENDPOINT",
                "api_key_env": "LABCOURT_PLATFORM_FIXTURE_API_KEY",
                "input_cost_per_million_tokens": 0.0,
                "output_cost_per_million_tokens": 0.0,
            }
        )
        providers["platform-fixture-screening"] = profile
        payload["providers"] = providers
        screening["provider_profile"] = "platform-fixture-screening"
        screening["timeout_seconds"] = 15.0
    else:
        # FULL_MODEL is a Pilot execution, not a Demo-fixture execution. Copy
        # the complete Pilot budget; replacing only the provider profile kept
        # the Demo's 15 second timeout and truncated normal multi-image calls.
        screening = dict(pilot_payload["screening"])
        providers = dict(payload["providers"])
        providers["pilot-screening"] = pilot_payload["providers"]["pilot-screening"]
        payload["providers"] = providers
        screening["provider_profile"] = "pilot-screening"
    payload["screening"] = screening
    return AppConfig.model_validate(payload)


@dataclass(frozen=True, slots=True)
class M8PlatformDemoApiAssembly:
    server: M8PlatformHttpServer
    database_path: Path
    artifact_root: Path
    input_media_path: Path

    def local_access_document(self) -> dict[str, object]:
        receipt = load_m8_platform_bootstrap(self.artifact_root)
        return {
            "schema_version": "m8-platform-local-access-v1",
            "base_url": f"http://127.0.0.1:{self.server.server_port}",
            "session_id": receipt.session_id,
            "personal_demo_only": True,
            "production_ready": False,
            "roles": [role.value for role in M8ActorRole],
        }

    def write_local_access(self) -> Path:
        path = self.artifact_root / PLATFORM_ACCESS_NAME
        path.write_text(canonical_json(self.local_access_document()), encoding="utf-8")
        return path


def assemble_m8_platform_demo_api(
    *,
    project_root: Path,
    database_path: Path,
    input_media_path: Path,
    port: int,
) -> M8PlatformDemoApiAssembly:
    root = project_root.absolute()
    database = database_path.absolute()
    if not database.exists():
        bootstrap_m8_platform_demo(database, input_media_path)
    else:
        load_m8_platform_bootstrap(database.parent)
    repository_manifest_id = platform_manifest("labcourt-platform-sqlite-repository-v1")
    inventory = SQLiteM8InventoryRepository(database, _BUSY_TIMEOUT_MS, repository_manifest_id)
    operations = SQLiteM8OperationsRepository(database, _BUSY_TIMEOUT_MS, repository_manifest_id)
    sensors = SQLiteM8SensorPersistenceRepository(
        database, _BUSY_TIMEOUT_MS, repository_manifest_id
    )
    notifications = SQLiteM8NotificationRepository(
        database, _BUSY_TIMEOUT_MS, repository_manifest_id
    )
    knowledge = SQLiteM8KnowledgeRepository(
        database,
        _BUSY_TIMEOUT_MS,
        # The platform baseline intentionally reuses the frozen personal-Demo
        # knowledge bootstrap, whose append-only receipts bind this repository
        # manifest. Other platform repositories retain their platform manifest.
        platform_manifest("labcourt-personal-demo-sqlite-repository-v1"),
    )
    commissioning = SQLiteM8AdapterCommissioningRepository(
        database, _BUSY_TIMEOUT_MS, repository_manifest_id
    )
    feishu_activations = SQLiteM8FeishuActivationRepository(
        database,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
        platform_manifest("platform-readiness-assessment-v1"),
    )
    feishu_inbound_activations = SQLiteM8FeishuInboundActivationRepository(
        database,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
        platform_manifest("platform-readiness-assessment-v1"),
    )
    projection_reader = M8OperationsProjectionService(
        inventory,
        operations,
        sensors,
        notifications,
        platform_manifest("platform-operations-projection-v1"),
    )
    operations_api = M8OperationsApiService(
        inventory,
        operations,
        sensors,
        platform_manifest("platform-case-authority-v1"),
        platform_manifest("platform-case-audit-v1"),
    )
    knowledge_api = M8KnowledgeApiService(
        knowledge,
        operations,
        platform_manifest("platform-knowledge-query-v1"),
        platform_manifest("platform-knowledge-adapter-v1"),
    )
    notification_api = M8NotificationApiService(notifications, operations)
    knowledge_projection = M8KnowledgeProjectionService(
        knowledge_api,
        M8ScopedOperationalCaseMemoryAdapter(operations_api),
    )
    projection_api = M8ProjectionApiService(operations, projection_reader)
    readiness_service = M8AdapterReadinessService(
        commissioning,
        operations,
        platform_manifest("platform-readiness-assessment-v1"),
    )

    def clock() -> datetime:
        return datetime.now(UTC)

    feishu_platform = M8FeishuPlatformService(
        commissioning,
        readiness_service,
        feishu_activations,
        feishu_inbound_activations,
        notifications,
        _ROLE_ACTORS[M8ActorRole.OPERATIONS],
        clock,
        platform_manifest("platform-feishu-test-card-probe-v1"),
    )
    platform_agent = M8PlatformAgentService(
        operations_api,
        notification_api,
        knowledge_projection,
        clock,
        PLATFORM_CAMPUS_ID,
    )
    fixture_pilot_service = PilotUiService(
        project_root=root,
        config_path=root / "configs/demo.yaml",
        config_override=_pilot_config(root, fixture=True),
    )
    model_pilot_service = PilotUiService(
        project_root=root,
        config_path=root / "configs/pilot.yaml",
        config_override=_pilot_config(root, fixture=False),
    )
    platform_service = M8PlatformDemoService(
        project_root=root,
        database_path=database,
        input_media_path=input_media_path,
        api_service=operations_api,
        notification_service=notification_api,
        knowledge_service=knowledge_api,
        knowledge_projection_service=knowledge_projection,
        feishu_platform_service=feishu_platform,
        agent_service=platform_agent,
        fixture_pilot_service=fixture_pilot_service,
        model_pilot_service=model_pilot_service,
    )
    agent_repository = SQLiteM8AgentConversationRepository.initialize(
        database,
        _BUSY_TIMEOUT_MS,
        platform_manifest("platform-agent-conversation-repository-v1"),
        clock,
    )
    agent_profile = M8AgentModelProfileV1(
        profile_id=platform_manifest("platform-qwen-agent-profile-v2"),
        model_manifest_id=platform_manifest("platform-qwen-agent-model-v1"),
        prompt_manifest_id=platform_manifest("platform-qwen-agent-system-prompt-v2"),
        tool_schema_manifest_id=platform_manifest("platform-qwen-agent-tools-v2"),
    )
    agent_chat = M8AgentChatService(
        operations_api,
        agent_repository,
        M8PlatformAgentToolService(
            operations_api,
            notification_api,
            projection_api,
            knowledge_projection,
            PLATFORM_CAMPUS_ID,
            clock,
        ),
        build_m8_qwen_agent_runtime(agent_profile),
        platform_service.agent_query,
        clock,
    )
    catalog = inventory.get_current_source_catalog(PLATFORM_CAMPUS_ID)
    smoke_policy = build_offline_smoke_demo_bundle(
        source_catalog_id=catalog.catalog.catalog_id,
        location_id=PLATFORM_LOCATION_ID,
        adapter_manifest_id=platform_manifest("platform-sensor-adapter-v1"),
        fixture_manifest_id=platform_manifest("platform-smoke-fixture-v1"),
        policy_manifest_id=platform_manifest("platform-smoke-policy-v1"),
    ).risk_policy
    server = build_m8_platform_server(
        port=port,
        service=operations_api,
        knowledge_service=knowledge_api,
        notification_service=notification_api,
        projection_service=projection_api,
        commissioning_service=M8CommissioningApiService(
            readiness_service,
            operations,
            clock=clock,
        ),
        authenticator=M8HashedBearerAuthenticator(_credential_catalog()),
        recorded_media_service=M8RecordedMediaApiService(
            database.parent,
            inventory,
            operations,
            platform_manifest("platform-camera-view-v1"),
        ),
        user_permission_service=M8UserPermissionApiService(
            operations, tuple(sorted(_ROLE_ACTORS.values()))
        ),
        rule_config_service=M8RuleConfigApiService(operations, smoke_policy),
        platform_service=platform_service,
        agent_chat_service=agent_chat,
        role_tokens=M8_PLATFORM_ROLE_TOKENS,
    )
    assembly = M8PlatformDemoApiAssembly(
        server=server,
        database_path=database,
        artifact_root=database.parent,
        input_media_path=input_media_path.absolute(),
    )
    assembly.write_local_access()
    return assembly


__all__ = [
    "M8_PLATFORM_ROLE_TOKENS",
    "M8PlatformDemoApiAssembly",
    "assemble_m8_platform_demo_api",
]
