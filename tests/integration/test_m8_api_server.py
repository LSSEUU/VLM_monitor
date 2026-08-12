from __future__ import annotations

import hashlib
import http.client
import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from labcourt.adapters.m8_hashed_bearer_authenticator import M8HashedBearerAuthenticator
from labcourt.adapters.storage.sqlite_m8_adapter_commissioning_repository import (
    SQLiteM8AdapterCommissioningRepository,
)
from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_knowledge_repository import (
    SQLiteM8KnowledgeRepository,
)
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import SQLiteM8OperationsRepository
from labcourt.adapters.storage.sqlite_m8_sensor_persistence_repository import (
    SQLiteM8SensorPersistenceRepository,
)
from labcourt.application.m8_knowledge_demo import build_offline_knowledge_demo_bundle
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseAction,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseReasonCode,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_adapter_commissioning import (
    M8ExternalIdempotencyKey,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_api import (
    M8ApiCaseTransitionRequestV1,
    M8ApiCredentialAuthorityV1,
    M8ApiCredentialCatalogAuthorityV1,
    M8ApiKnowledgeQueryRequestV1,
)
from labcourt.contracts.m8_case_persistence import M8OperationalCaseCommitReceiptV1
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_operations import (
    M8CampusLocation,
    M8CampusLocationKind,
    M8CampusTopologyAuthorityV1,
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
    M8OperationalSourceMode,
    M8SensorType,
)
from labcourt.m8_api_server import M8ApiHttpServer, build_m8_api_server
from labcourt.ports.m8_api_authentication import M8AuthenticationError, M8RequestAuthenticator
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_commissioning_api import M8CommissioningApiService
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_operations_api import M8OperationsApiService
from labcourt.services.m8_operations_projection import M8OperationsProjectionService
from labcourt.services.m8_projection_api import M8ProjectionApiService

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BUSY_TIMEOUT_MS = 5_000
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
TOKENS = {
    "leader": "labcourt-test-leader-token",
    "operations": "labcourt-test-operations-token",
    "safety": "labcourt-test-safety-token",
    "student": "labcourt-test-student-token",
}


def _topology() -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=1,
        locations=(
            M8CampusLocation(
                location_id="campus-main",
                kind=M8CampusLocationKind.CAMPUS,
                parent_location_id=None,
                display_name="主校区",
            ),
            M8CampusLocation(
                location_id="building-chem",
                kind=M8CampusLocationKind.BUILDING,
                parent_location_id="campus-main",
                display_name="化学楼",
            ),
            M8CampusLocation(
                location_id="floor-chem-03",
                kind=M8CampusLocationKind.FLOOR,
                parent_location_id="building-chem",
                display_name="三层",
            ),
            M8CampusLocation(
                location_id="room-chem-301",
                kind=M8CampusLocationKind.ROOM,
                parent_location_id="floor-chem-03",
                display_name="实验室 301",
            ),
        ),
        manifest_id=SHA_A,
    )


def _source() -> M8OperationalSource:
    return M8OperationalSource(
        source_id="sensor-simulated-smoke-01",
        device_id="sensor-smoke-01",
        location_id="room-chem-301",
        mode=M8OperationalSourceMode.SIMULATED_SENSOR,
        sensor_type=M8SensorType.SMOKE,
        adapter_id="m8-offline-sensor-simulator",
        manifest_id=SHA_B,
    )


def _adapter_candidate() -> M8ProductionAdapterCandidateAuthorityV1:
    return M8ProductionAdapterCandidateAuthorityV1(
        adapter_id="notification-adapter-candidate-01",
        adapter_revision="revision-01",
        adapter_kind=M8ProductionAdapterKind.EXTERNAL_NOTIFICATION,
        provider_id="provider-not-yet-selected",
        product_revision="product-not-yet-selected",
        campus_id="campus-main",
        scope_kind=M8ActorScopeKind.CAMPUS_WIDE,
        scope_location_ids=(),
        declared_license_id="license-review-required",
        request_timeout_ms=5_000,
        idempotency_key=M8ExternalIdempotencyKey.NOTIFICATION_ID,
        network_required=True,
        offline_fallback_adapter_id="local-offline-notification-fake",
        offline_fallback_revision="offline-revision-01",
        adapter_manifest_id=SHA_C,
        offline_fallback_manifest_id=SHA_D,
    )


def _actor(role: M8ActorRole, *, revision: int = 1, active: bool = True) -> M8ActorAuthorityV1:
    actor_id = {
        M8ActorRole.LEADER: "leader-01",
        M8ActorRole.SAFETY_OFFICER: "safety-officer-01",
        M8ActorRole.STUDENT: "student-01",
        M8ActorRole.OPERATIONS: "operations-01",
    }[role]
    if role == M8ActorRole.STUDENT:
        scope_kind = M8ActorScopeKind.SELF_ONLY
        locations: tuple[str, ...] = ()
    elif role == M8ActorRole.SAFETY_OFFICER:
        scope_kind = M8ActorScopeKind.LOCATIONS
        locations = ("room-chem-301",)
    else:
        scope_kind = M8ActorScopeKind.CAMPUS_WIDE
        locations = ()
    return M8ActorAuthorityV1(
        actor_id=actor_id,
        role=role,
        scope_kind=scope_kind,
        scope_location_ids=locations,
        identity_provider_id="campus-idp",
        subject_binding_sha256=hashlib.sha256(actor_id.encode()).hexdigest(),
        authority_revision=revision,
        active=active,
        manifest_id=SHA_C,
    )


def _credentials() -> M8ApiCredentialCatalogAuthorityV1:
    credentials = tuple(
        M8ApiCredentialAuthorityV1(
            credential_id=f"credential-{name}",
            actor_id={
                "leader": "leader-01",
                "operations": "operations-01",
                "safety": "safety-officer-01",
                "student": "student-01",
            }[name],
            bearer_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            active=True,
            manifest_id=SHA_D,
        )
        for name, token in sorted(TOKENS.items())
    )
    return M8ApiCredentialCatalogAuthorityV1(
        revision=1,
        credentials=credentials,
        authentication_manifest_id=SHA_E,
    )


def _create_case(
    repository: SQLiteM8OperationsRepository,
    *,
    risk_level: M8OperationalRiskLevel = M8OperationalRiskLevel.EMERGENCY,
) -> M8OperationalCaseCommitReceiptV1:
    command = M8OperationalCaseCreateCommandV1(
        source_catalog_id=SHA_A,
        location_id="room-chem-301",
        risk_level=risk_level,
        policy_rule_id="simulated-smoke-active-emergency-v1",
        policy_manifest_id=SHA_B,
        source_ids=("sensor-simulated-smoke-01",),
        simulated_source_ids=("sensor-simulated-smoke-01",),
        trigger_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                authority_id="smoke-sample-01",
                document_sha256=SHA_C,
            ),
        ),
        automation_component_id="m8-offline-sensor-simulator",
        automation_manifest_id=SHA_D,
    )
    return repository.create_operational_case(command, "student-01", SHA_D, SHA_E)


@pytest.fixture
def api_server(
    tmp_path: Path,
    socket_enabled: None,
) -> Iterator[
    tuple[M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository]
]:
    root = tmp_path / "operations"
    root.mkdir()
    database = root / "labcourt.sqlite3"
    inventory = SQLiteM8InventoryRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_A)
    inventory.publish_topology(_topology(), None)
    inventory.publish_source_catalog(
        M8OperationalSourceCatalogAuthorityV1(
            revision=1,
            topology=_topology(),
            sources=(_source(),),
            catalog_manifest_id=SHA_C,
        ),
        None,
    )
    operations = SQLiteM8OperationsRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    for role in M8ActorRole:
        operations.publish_actor_authority(_actor(role), None)
    commissioning_repository = SQLiteM8AdapterCommissioningRepository(
        database,
        BUSY_TIMEOUT_MS,
        SHA_A,
    )
    commissioning_repository.register_candidate(_adapter_candidate(), "operations-01")
    case = _create_case(operations)
    sensors = SQLiteM8SensorPersistenceRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    service = M8OperationsApiService(inventory, operations, sensors, SHA_D, SHA_E)
    bundle = build_offline_knowledge_demo_bundle(
        generated_at=BASE_TIME,
        document_manifest_id=SHA_A,
        catalog_manifest_id=SHA_B,
        adapter_manifest_id=SHA_C,
    )
    knowledge_repository = SQLiteM8KnowledgeRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    contents = bundle.content_map()
    knowledge_repository.publish_catalog(
        bundle.catalog,
        tuple(contents[document.content_ref] for document in bundle.catalog.documents),
        None,
        SHA_D,
    )
    knowledge_service = M8KnowledgeApiService(
        knowledge_repository,
        operations,
        SHA_E,
        bundle.adapter_manifest_id,
    )
    notification_repository = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_A)
    projection_reader = M8OperationsProjectionService(
        inventory,
        operations,
        sensors,
        notification_repository,
        SHA_C,
    )
    projection_service = M8ProjectionApiService(operations, projection_reader)
    commissioning_service = M8CommissioningApiService(
        M8AdapterReadinessService(commissioning_repository, operations, SHA_D),
        operations,
        clock=lambda: BASE_TIME + timedelta(hours=1),
    )
    server = build_m8_api_server(
        port=0,
        service=service,
        knowledge_service=knowledge_service,
        notification_service=M8NotificationApiService(notification_repository, operations),
        projection_service=projection_service,
        commissioning_service=commissioning_service,
        authenticator=M8HashedBearerAuthenticator(_credentials()),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, case, operations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(
    server: M8ApiHttpServer,
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: object | None = None,
    host: str | None = None,
) -> tuple[int, dict[str, object] | list[object]]:
    body = None if payload is None else canonical_json(payload).encode()
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if host is not None:
        headers["Host"] = host
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = json.loads(response.read())
    connection.close()
    return response.status, data


def _transition_payload(
    case: M8OperationalCaseCommitReceiptV1,
    action: M8OperationalCaseAction = M8OperationalCaseAction.CONFIRM,
) -> dict[str, object]:
    reason = {
        M8OperationalCaseAction.CONFIRM: M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
        M8OperationalCaseAction.REJECT: M8OperationalCaseReasonCode.FALSE_POSITIVE,
        M8OperationalCaseAction.SUBMIT_APPEAL: M8OperationalCaseReasonCode.SUBJECT_DISPUTE,
    }[action]
    request = M8ApiCaseTransitionRequestV1(
        source_case_version=case.case_version,
        source_case_authority_sha256=case.case_document_sha256,
        source_status=case.status,
        case_location_id=case.audit_event.case_authority.location_id,
        subject_actor_id=case.audit_event.case_authority.subject_actor_id,
        action=action,
        reason_code=reason,
        reason_summary="用户已明确确认并提供支持材料。",
        supporting_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.USER_STATEMENT,
                authority_id="statement-api-01",
                document_sha256=SHA_D,
            ),
        ),
        explicit_human_confirmation=True,
        command_manifest_id=SHA_E,
    )
    return request.model_dump(mode="json")


def _knowledge_query_payload() -> dict[str, object]:
    return M8ApiKnowledgeQueryRequestV1(
        query_text="\u62a4\u76ee\u955c \u4f69\u6234",
        locale="zh-CN",
        as_of=BASE_TIME,
        allowed_document_types=tuple(sorted(M8KnowledgeDocumentType, key=lambda item: item.value)),
        max_citations=3,
    ).model_dump(mode="json")


def test_hashed_authenticator_fails_closed_and_server_binds_loopback(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, _case, _operations = api_server
    assert server.server_address[0] == "127.0.0.1"
    with pytest.raises(M8AuthenticationError):
        M8HashedBearerAuthenticator(_credentials()).authenticate(None)
    with pytest.raises(TypeError, match="explicit authenticator"):
        build_m8_api_server(
            port=0,
            service=server.api_service,
            knowledge_service=server.knowledge_service,
            notification_service=server.notification_service,
            projection_service=server.projection_service,
            commissioning_service=server.commissioning_service,
            authenticator=cast(M8RequestAuthenticator, None),
        )
    with pytest.raises(TypeError, match="knowledge service"):
        build_m8_api_server(
            port=0,
            service=server.api_service,
            knowledge_service=cast(M8KnowledgeApiService, None),
            notification_service=server.notification_service,
            projection_service=server.projection_service,
            commissioning_service=server.commissioning_service,
            authenticator=server.api_authenticator,
        )
    with pytest.raises(TypeError, match="projection service"):
        build_m8_api_server(
            port=0,
            service=server.api_service,
            knowledge_service=server.knowledge_service,
            notification_service=server.notification_service,
            projection_service=cast(M8ProjectionApiService, None),
            commissioning_service=server.commissioning_service,
            authenticator=server.api_authenticator,
        )
    with pytest.raises(TypeError, match="notification service"):
        build_m8_api_server(
            port=0,
            service=server.api_service,
            knowledge_service=server.knowledge_service,
            notification_service=cast(M8NotificationApiService, None),
            projection_service=server.projection_service,
            commissioning_service=server.commissioning_service,
            authenticator=server.api_authenticator,
        )
    with pytest.raises(TypeError, match="commissioning service"):
        build_m8_api_server(
            port=0,
            service=server.api_service,
            knowledge_service=server.knowledge_service,
            notification_service=server.notification_service,
            projection_service=server.projection_service,
            commissioning_service=cast(M8CommissioningApiService, None),
            authenticator=server.api_authenticator,
        )

    status, body = _request(server, "GET", "/api/m8/campuses/campus-main/topology")
    assert status == 401
    assert body["reason_code"] == "AUTHENTICATION_REQUIRED"  # type: ignore[index]
    status, body = _request(
        server,
        "GET",
        "/api/m8/campuses/campus-main/topology",
        token="wrong-token",
    )
    assert status == 401
    assert body["reason_code"] == "INVALID_CREDENTIAL"  # type: ignore[index]
    status, body = _request(
        server,
        "GET",
        "/api/m8/campuses/campus-main/topology",
        token=TOKENS["leader"],
        host="campus.example",
    )
    assert status == 403
    assert body["reason_code"] == "LOCAL_HOST_REQUIRED"  # type: ignore[index]


@pytest.mark.parametrize(
    ("role", "topology_status", "case_status", "audit_status"),
    (
        ("leader", 200, 200, 200),
        ("safety", 200, 200, 200),
        ("student", 403, 200, 403),
        ("operations", 200, 403, 403),
    ),
)
def test_http_read_rbac_uses_persisted_actor_authority(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
    role: str,
    topology_status: int,
    case_status: int,
    audit_status: int,
) -> None:
    server, case, _operations = api_server
    status, _ = _request(
        server,
        "GET",
        "/api/m8/campuses/campus-main/topology",
        token=TOKENS[role],
    )
    assert status == topology_status
    status, _ = _request(
        server,
        "GET",
        f"/api/m8/cases/{case.case_id}",
        token=TOKENS[role],
    )
    assert status == case_status
    status, _ = _request(
        server,
        "GET",
        f"/api/m8/cases/{case.case_id}/audit",
        token=TOKENS[role],
    )
    assert status == audit_status


def test_leader_cannot_read_non_major_case(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, _case, operations = api_server
    general_case = _create_case(operations, risk_level=M8OperationalRiskLevel.GENERAL)
    status, body = _request(
        server,
        "GET",
        f"/api/m8/cases/{general_case.case_id}",
        token=TOKENS["leader"],
    )
    assert status == 403
    assert body["reason_code"] == "FORBIDDEN"  # type: ignore[index]


def test_operations_projection_endpoint_applies_role_scope_server_side(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, emergency_case, operations = api_server
    general_case = _create_case(operations, risk_level=M8OperationalRiskLevel.GENERAL)
    path = "/api/m8/campuses/campus-main/operations-projection"

    status, safety = _request(server, "GET", path, token=TOKENS["safety"])
    assert status == 200
    assert safety["view_kind"] == "SAFETY_FULL"  # type: ignore[index]
    assert len(safety["visible_projection"]["current_cases"]) == 2  # type: ignore[arg-type,index]

    status, leader = _request(server, "GET", path, token=TOKENS["leader"])
    assert status == 200
    assert leader["view_kind"] == "LEADER_GLOBAL_MAJOR"  # type: ignore[index]
    leader_cases = leader["visible_projection"]["current_cases"]  # type: ignore[index]
    assert len(leader_cases) == 1  # type: ignore[arg-type]
    assert leader_cases[0]["case_id"] == emergency_case.case_id  # type: ignore[index]

    status, device_view = _request(server, "GET", path, token=TOKENS["operations"])
    assert status == 200
    assert device_view["view_kind"] == "OPERATIONS_DEVICES"  # type: ignore[index]
    visible = device_view["visible_projection"]  # type: ignore[index]
    assert visible["current_cases"] == []  # type: ignore[index]
    assert visible["case_audit_events"] == []  # type: ignore[index]
    assert visible["current_notifications"] == []  # type: ignore[index]
    assert visible["notification_audit_events"] == []  # type: ignore[index]
    assert visible["sources"][0]["display_badge"] == "SIMULATED · SENSOR"  # type: ignore[index]
    assert visible["sources"][0]["simulated"] is True  # type: ignore[index]

    status, denied = _request(server, "GET", path, token=TOKENS["student"])
    assert status == 403
    assert denied["reason_code"] == "FORBIDDEN"  # type: ignore[index]
    assert operations.get_current_operational_case(emergency_case.case_id) == emergency_case
    assert operations.get_current_operational_case(general_case.case_id) == general_case


def test_commissioning_readiness_endpoint_is_operations_only_and_read_only(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, emergency_case, operations = api_server
    candidate = _adapter_candidate()
    path = f"/api/m8/adapter-candidates/{candidate.candidate_authority_id}/readiness"

    status, readiness = _request(server, "GET", path, token=TOKENS["operations"])
    assert status == 200
    assert readiness["candidate"]["candidate_authority_id"] == candidate.candidate_authority_id  # type: ignore[index]
    assert readiness["assessed_at"] == "2026-08-10T10:00:00Z"  # type: ignore[index]
    assert readiness["readiness"] == "BLOCKED"  # type: ignore[index]
    assert readiness["missing_evidence_kinds"] == [  # type: ignore[index]
        "LICENSE_REVIEW",
        "OFFLINE_FALLBACK_DRILL",
        "SAFETY_REVIEW",
        "SECURITY_REVIEW",
        "SITE_ACCEPTANCE",
    ]
    assert readiness["production_activation_permitted"] is False  # type: ignore[index]
    assert "artifact_bytes" not in str(readiness)

    for role in ("leader", "safety", "student"):
        status, denied = _request(server, "GET", path, token=TOKENS[role])
        assert status == 403
        assert denied["reason_code"] == "FORBIDDEN"  # type: ignore[index]

    missing_path = f"/api/m8/adapter-candidates/{'f' * 64}/readiness"
    status, missing = _request(server, "GET", missing_path, token=TOKENS["operations"])
    assert status == 404
    assert missing["reason_code"] == "RESOURCE_NOT_FOUND"  # type: ignore[index]
    status, invalid_time = _request(
        server,
        "GET",
        f"{path}?assessed_at=2026-08-10T09%3A00%3A00Z",
        token=TOKENS["operations"],
    )
    assert status == 400
    assert invalid_time["reason_code"] == "INVALID_REQUEST"  # type: ignore[index]
    assert operations.get_current_operational_case(emergency_case.case_id) == emergency_case


def test_http_transition_allows_safety_only_and_returns_concurrency_conflict(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, case, _operations = api_server
    payload = _transition_payload(case)
    status, _ = _request(
        server,
        "POST",
        f"/api/m8/cases/{case.case_id}/transitions",
        token=TOKENS["leader"],
        payload=payload,
    )
    assert status == 403
    status, body = _request(
        server,
        "POST",
        f"/api/m8/cases/{case.case_id}/transitions",
        token=TOKENS["safety"],
        payload=payload,
    )
    assert status == 200
    assert body["status"] == "CONFIRMED"  # type: ignore[index]

    losing = _transition_payload(case, M8OperationalCaseAction.REJECT)
    status, body = _request(
        server,
        "POST",
        f"/api/m8/cases/{case.case_id}/transitions",
        token=TOKENS["safety"],
        payload=losing,
    )
    assert status == 409
    assert body["reason_code"] == "CONCURRENT_MODIFICATION"  # type: ignore[index]


def test_http_student_can_only_submit_own_case_appeal(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, case, _operations = api_server
    status, body = _request(
        server,
        "POST",
        f"/api/m8/cases/{case.case_id}/transitions",
        token=TOKENS["safety"],
        payload=_transition_payload(case),
    )
    assert status == 200
    confirmed = M8OperationalCaseCommitReceiptV1.model_validate(body)

    status, body = _request(
        server,
        "POST",
        f"/api/m8/cases/{case.case_id}/transitions",
        token=TOKENS["student"],
        payload=_transition_payload(confirmed, M8OperationalCaseAction.SUBMIT_APPEAL),
    )
    assert status == 200
    assert body["status"] == "APPEALED"  # type: ignore[index]


def test_http_rejects_actor_authority_graft_and_inactive_persisted_actor(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, case, operations = api_server
    payload = _transition_payload(case)
    payload["actor_authority"] = _actor(M8ActorRole.SAFETY_OFFICER).model_dump(mode="json")
    status, body = _request(
        server,
        "POST",
        f"/api/m8/cases/{case.case_id}/transitions",
        token=TOKENS["safety"],
        payload=payload,
    )
    assert status == 400
    assert body["reason_code"] == "INVALID_REQUEST"  # type: ignore[index]

    operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER, revision=2, active=False),
        1,
    )
    status, body = _request(
        server,
        "GET",
        "/api/m8/campuses/campus-main/topology",
        token=TOKENS["safety"],
    )
    assert status == 403
    assert body["reason_code"] == "FORBIDDEN"  # type: ignore[index]
    status, body = _request(
        server,
        "GET",
        "/api/m8/campuses/campus-main/operations-projection",
        token=TOKENS["safety"],
    )
    assert status == 403
    assert body["reason_code"] == "FORBIDDEN"  # type: ignore[index]


def test_sensor_poll_endpoint_denies_leader_but_allows_operations_lookup(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, _case, _operations = api_server
    request_id = "f" * 64
    status, _ = _request(
        server,
        "GET",
        f"/api/m8/sensor-polls/{request_id}",
        token=TOKENS["leader"],
    )
    assert status == 403
    status, body = _request(
        server,
        "GET",
        f"/api/m8/sensor-polls/{request_id}",
        token=TOKENS["operations"],
    )
    assert status == 404
    assert body["reason_code"] == "RESOURCE_NOT_FOUND"  # type: ignore[index]


def test_knowledge_api_resolves_current_authorities_and_replays_own_answer(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, case, _operations = api_server
    catalog_id = "campus-safety-knowledge"
    status, body = _request(
        server,
        "GET",
        f"/api/m8/knowledge/catalogs/{catalog_id}",
        token=TOKENS["student"],
    )
    assert status == 200
    assert body["catalog"]["catalog_revision"] == 1  # type: ignore[index]

    status, body = _request(
        server,
        "POST",
        f"/api/m8/knowledge/catalogs/{catalog_id}/queries",
        token=TOKENS["student"],
        payload=_knowledge_query_payload(),
    )
    assert status == 200
    answer = body["answer"]  # type: ignore[index]
    assert answer["query"]["requester_actor_id"] == "student-01"  # type: ignore[index]
    assert answer["network_used"] is False  # type: ignore[index]
    assert answer["model_used"] is False  # type: ignore[index]
    assert answer["case_transition_permitted"] is False  # type: ignore[index]
    assert len(answer["citations"]) >= 1  # type: ignore[arg-type,index]
    query_id = str(body["query_id"])  # type: ignore[index]

    status, replay = _request(
        server,
        "GET",
        f"/api/m8/knowledge/answers/{query_id}",
        token=TOKENS["student"],
    )
    assert status == 200
    assert replay == body
    status, denied = _request(
        server,
        "GET",
        f"/api/m8/knowledge/answers/{query_id}",
        token=TOKENS["safety"],
    )
    assert status == 403
    assert denied["reason_code"] == "FORBIDDEN"  # type: ignore[index]
    assert _operations.get_current_operational_case(case.case_id) == case


def test_knowledge_api_rejects_authority_grafts_missing_catalog_and_inactive_actor(
    api_server: tuple[
        M8ApiHttpServer, M8OperationalCaseCommitReceiptV1, SQLiteM8OperationsRepository
    ],
) -> None:
    server, _case, operations = api_server
    payload = _knowledge_query_payload()
    payload["requester_actor_id"] = "leader-01"
    status, body = _request(
        server,
        "POST",
        "/api/m8/knowledge/catalogs/campus-safety-knowledge/queries",
        token=TOKENS["student"],
        payload=payload,
    )
    assert status == 400
    assert body["reason_code"] == "INVALID_REQUEST"  # type: ignore[index]

    status, body = _request(
        server,
        "GET",
        "/api/m8/knowledge/catalogs/missing-catalog",
        token=TOKENS["student"],
    )
    assert status == 404
    assert body["reason_code"] == "RESOURCE_NOT_FOUND"  # type: ignore[index]

    operations.publish_actor_authority(_actor(M8ActorRole.STUDENT, revision=2, active=False), 1)
    status, body = _request(
        server,
        "POST",
        "/api/m8/knowledge/catalogs/campus-safety-knowledge/queries",
        token=TOKENS["student"],
        payload=_knowledge_query_payload(),
    )
    assert status == 403
    assert body["reason_code"] == "FORBIDDEN"  # type: ignore[index]
