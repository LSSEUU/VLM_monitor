"""Explicit assembly of the authenticated loopback API over Demo authority."""

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
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.application.m8_personal_demo_knowledge import (
    bootstrap_m8_personal_demo_knowledge,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_api import (
    M8ApiCredentialAuthorityV1,
    M8ApiCredentialCatalogAuthorityV1,
)
from labcourt.contracts.m8_personal_demo import M8PersonalDemoKnowledgeReceiptV1
from labcourt.contracts.m8_personal_demo_api import (
    M8PersonalDemoApiProfileV1,
    M8PersonalDemoLocalAccessV1,
)
from labcourt.m8_api_server import M8ApiHttpServer, build_m8_api_server
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_commissioning_api import M8CommissioningApiService
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_operations_api import M8OperationsApiService
from labcourt.services.m8_operations_projection import M8OperationsProjectionService
from labcourt.services.m8_projection_api import M8ProjectionApiService

_BUSY_TIMEOUT_MS = 5_000
M8_PERSONAL_DEMO_ROLE_TOKENS = {
    "leader": "labcourt-personal-demo-leader-token",
    "operations": "labcourt-personal-demo-operations-token",
    "safety": "labcourt-personal-demo-safety-token",
    "student": "labcourt-personal-demo-student-token",
}


def _manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _credential_catalog() -> M8ApiCredentialCatalogAuthorityV1:
    actors = {
        "leader": "leader-demo",
        "operations": "operations-demo",
        "safety": "safety-officer-demo",
        "student": "student-demo",
    }
    credentials = tuple(
        M8ApiCredentialAuthorityV1(
            credential_id=f"credential-{name}-demo",
            actor_id=actors[name],
            bearer_token_sha256=hashlib.sha256(token.encode("ascii")).hexdigest(),
            active=True,
            manifest_id=_manifest("labcourt-personal-demo-api-credential-v1"),
        )
        for name, token in sorted(M8_PERSONAL_DEMO_ROLE_TOKENS.items())
    )
    return M8ApiCredentialCatalogAuthorityV1(
        revision=1,
        credentials=credentials,
        authentication_manifest_id=_manifest("labcourt-personal-demo-api-authentication-v1"),
    )


@dataclass(frozen=True, slots=True)
class M8PersonalDemoApiAssembly:
    server: M8ApiHttpServer
    profile: M8PersonalDemoApiProfileV1
    knowledge_receipt: M8PersonalDemoKnowledgeReceiptV1

    def local_access_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": "m8-personal-demo-local-access-v1",
            "base_url": self.profile.base_url,
            "knowledge_catalog_id": self.knowledge_receipt.catalog_id,
            "personal_demo_only": True,
            "production_ready": False,
            "tokens": dict(sorted(M8_PERSONAL_DEMO_ROLE_TOKENS.items())),
        }
        M8PersonalDemoLocalAccessV1.model_validate(document)
        return document


def assemble_m8_personal_demo_api(
    database_path: Path,
    port: int,
) -> M8PersonalDemoApiAssembly:
    """Bootstrap exact data and bind, but do not start, one loopback server."""

    bootstrap = bootstrap_m8_personal_demo(database_path)
    knowledge_receipt = bootstrap_m8_personal_demo_knowledge(database_path)
    repository_manifest_id = _manifest("labcourt-personal-demo-sqlite-repository-v1")
    inventory = SQLiteM8InventoryRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    operations = SQLiteM8OperationsRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    sensors = SQLiteM8SensorPersistenceRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    notifications = SQLiteM8NotificationRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    projection_reader = M8OperationsProjectionService(
        inventory,
        operations,
        sensors,
        notifications,
        _manifest("labcourt-personal-demo-operations-projection-v1"),
    )
    knowledge = SQLiteM8KnowledgeRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    commissioning = SQLiteM8AdapterCommissioningRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    server = build_m8_api_server(
        port=port,
        service=M8OperationsApiService(
            inventory,
            operations,
            sensors,
            _manifest("labcourt-personal-demo-case-authority-v1"),
            _manifest("labcourt-personal-demo-case-audit-v1"),
        ),
        knowledge_service=M8KnowledgeApiService(
            knowledge,
            operations,
            _manifest("labcourt-personal-demo-knowledge-query-v1"),
            _manifest("labcourt-personal-demo-knowledge-adapter-v1"),
        ),
        projection_service=M8ProjectionApiService(operations, projection_reader),
        commissioning_service=M8CommissioningApiService(
            M8AdapterReadinessService(
                commissioning,
                operations,
                _manifest("labcourt-personal-demo-readiness-assessment-v1"),
            ),
            operations,
            clock=lambda: datetime.now(UTC),
        ),
        authenticator=M8HashedBearerAuthenticator(_credential_catalog()),
    )
    profile = M8PersonalDemoApiProfileV1(
        bind_port=server.server_port,
        bootstrap_receipt_id=bootstrap.receipt.bootstrap_receipt_id,
        credential_catalog=_credential_catalog(),
        server_manifest_id=_manifest("labcourt-personal-demo-api-server-v1"),
    )
    return M8PersonalDemoApiAssembly(
        server=server,
        profile=profile,
        knowledge_receipt=knowledge_receipt,
    )


__all__ = [
    "M8_PERSONAL_DEMO_ROLE_TOKENS",
    "M8PersonalDemoApiAssembly",
    "assemble_m8_personal_demo_api",
]
