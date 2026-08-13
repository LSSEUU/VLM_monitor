"""Assemble the authenticated same-origin campus platform Demo."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from labcourt.adapters.m8_hashed_bearer_authenticator import M8HashedBearerAuthenticator
from labcourt.adapters.storage.sqlite_m8_adapter_commissioning_repository import (
    SQLiteM8AdapterCommissioningRepository,
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
from labcourt.contracts.m8_api import (
    M8ApiCredentialAuthorityV1,
    M8ApiCredentialCatalogAuthorityV1,
)
from labcourt.m8_platform_server import M8PlatformHttpServer, build_m8_platform_server
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_commissioning_api import M8CommissioningApiService
from labcourt.services.m8_hearing_api import M8HearingApiService
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_operations_api import M8OperationsApiService
from labcourt.services.m8_operations_projection import M8OperationsProjectionService
from labcourt.services.m8_platform_demo import M8PlatformDemoService
from labcourt.services.m8_projection_api import M8ProjectionApiService
from labcourt.services.m8_qwen_hearing_demo import build_m8_qwen_hearing_demo_config
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
    # These sections form one decision authority.  Mixing the Pilot
    # observability threshold with the Demo procedural gate makes a valid
    # absence fast verdict fail L5 and incorrectly become hearing-eligible.
    for section in (
        "zones",
        "pilot",
        "perception",
        "absence",
        "presence",
        "procedural_gate",
    ):
        payload[section] = pilot_payload[section]
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
    config = AppConfig.model_validate(payload)
    return config if fixture else build_m8_qwen_hearing_demo_config(config)


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
    inventory = SQLiteM8InventoryRepository(
        database, _BUSY_TIMEOUT_MS, repository_manifest_id
    )
    operations = SQLiteM8OperationsRepository(
        database, _BUSY_TIMEOUT_MS, repository_manifest_id
    )
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
        knowledge_service=knowledge_api,
        fixture_pilot_service=fixture_pilot_service,
        model_pilot_service=model_pilot_service,
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
        notification_service=M8NotificationApiService(notifications, operations),
        projection_service=M8ProjectionApiService(operations, projection_reader),
        commissioning_service=M8CommissioningApiService(
            M8AdapterReadinessService(
                commissioning,
                operations,
                platform_manifest("platform-readiness-assessment-v1"),
            ),
            operations,
            clock=lambda: datetime.now(UTC),
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
        hearing_service=M8HearingApiService(
            operations,
            {},
            runtime_resolver=platform_service.open_hearing_runtime,
        ),
        platform_service=platform_service,
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
