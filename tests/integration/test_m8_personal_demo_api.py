from __future__ import annotations

import http.client
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_personal_demo_api import (
    M8_PERSONAL_DEMO_ROLE_TOKENS,
    assemble_m8_personal_demo_api,
)
from labcourt.application.m8_personal_demo_camera import register_m8_personal_demo_camera
from labcourt.application.m8_personal_demo_knowledge import (
    bootstrap_m8_personal_demo_knowledge,
)
from labcourt.application.m8_personal_demo_notification import (
    acknowledge_m8_personal_demo_notification,
    deliver_m8_personal_demo_notification,
    route_m8_personal_demo_notification,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_access_cases import (
    M8OperationalCaseAction,
    M8OperationalCaseReasonCode,
)
from labcourt.contracts.m8_api import (
    M8ApiCaseTransitionRequestV1,
    M8ApiKnowledgeQueryRequestV1,
)
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType

BUSY_TIMEOUT_MS = 5_000


def _request(
    port: int,
    method: str,
    path: str,
    role: str,
    payload: object | None = None,
) -> tuple[int, object]:
    body = None if payload is None else canonical_json(payload).encode("utf-8")
    headers = {"Authorization": f"Bearer {M8_PERSONAL_DEMO_ROLE_TOKENS[role]}"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = json.loads(response.read())
    connection.close()
    return response.status, result


def test_demo_api_enforces_leader_read_only_and_safety_human_transition(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    database = tmp_path / "demo" / "labcourt.sqlite3"
    assembly = assemble_m8_personal_demo_api(database, 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        projection_status, projection = _request(
            server.server_port,
            "GET",
            "/api/m8/campuses/campus-demo/operations-projection",
            "leader",
        )
        assert projection_status == 200
        assert isinstance(projection, dict)
        case_id = projection["visible_projection"]["current_cases"][0]["case_id"]
        case_status, case_payload = _request(
            server.server_port,
            "GET",
            f"/api/m8/cases/{case_id}",
            "leader",
        )
        assert case_status == 200
        assert isinstance(case_payload, dict)
        repository = SQLiteM8OperationsRepository(
            database,
            BUSY_TIMEOUT_MS,
            case_payload["repository_manifest_id"],
        )
        case = repository.get_current_operational_case(str(case_id))
        request = M8ApiCaseTransitionRequestV1(
            source_case_version=case.case_version,
            source_case_authority_sha256=case.case_document_sha256,
            source_status=case.status,
            case_location_id=case.audit_event.case_authority.location_id,
            subject_actor_id=case.audit_event.case_authority.subject_actor_id,
            action=M8OperationalCaseAction.CONFIRM,
            reason_code=M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
            reason_summary="安全负责人已明确确认模拟演示案件。",
            supporting_authorities=(
                case.audit_event.case_authority.create_command.trigger_authorities[0],
            ),
            explicit_human_confirmation=True,
            command_manifest_id="5" * 64,
        ).model_dump(mode="json")

        leader_status, _leader_result = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{case_id}/transitions",
            "leader",
            request,
        )
        safety_status, safety_result = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{case_id}/transitions",
            "safety",
            request,
        )
        assert leader_status == 403
        assert safety_status == 200
        assert isinstance(safety_result, dict)
        assert safety_result["status"] == "CONFIRMED"
        assert len(repository.list_operational_case_audit(str(case_id))) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_api_check_assembly_exposes_tokens_only_in_local_document(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = assemble_m8_personal_demo_api(tmp_path / "labcourt.sqlite3", 0)
    try:
        access = assembly.local_access_document()
        assert access["personal_demo_only"] is True
        assert access["production_ready"] is False
        assert access["tokens"] == dict(sorted(M8_PERSONAL_DEMO_ROLE_TOKENS.items()))
        assert all(
            token not in assembly.profile.model_dump_json()
            for token in M8_PERSONAL_DEMO_ROLE_TOKENS.values()
        )
    finally:
        assembly.server.server_close()


def test_demo_api_session_resolves_each_current_role_without_frontend_claims(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = assemble_m8_personal_demo_api(tmp_path / "session" / "labcourt.sqlite3", 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        expected = {
            "leader": ("leader-demo", "LEADER"),
            "operations": ("operations-demo", "OPERATIONS"),
            "safety": ("safety-officer-demo", "SAFETY_OFFICER"),
            "student": ("student-demo", "STUDENT"),
        }
        for token_role, (actor_id, actor_role) in expected.items():
            status, payload = _request(
                server.server_port,
                "GET",
                "/api/m8/session",
                token_role,
            )
            assert status == 200
            assert isinstance(payload, dict)
            authority = payload["authority"]
            assert authority["actor_id"] == actor_id
            assert authority["role"] == actor_role
            assert authority["active"] is True
            assert authority["capabilities"]
            assert "bearer" not in canonical_json(payload).lower()
            assert all(
                token not in canonical_json(payload)
                for token in M8_PERSONAL_DEMO_ROLE_TOKENS.values()
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_api_case_list_is_server_filtered_by_current_role(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = assemble_m8_personal_demo_api(tmp_path / "case-list" / "labcourt.sqlite3", 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        visible_case_id: str | None = None
        for role in ("safety", "leader"):
            status, payload = _request(server.server_port, "GET", "/api/m8/cases", role)
            assert status == 200
            assert isinstance(payload, list)
            assert len(payload) == 1
            assert payload[0]["status"] == "PENDING_VERIFICATION"
            assert payload[0]["audit_event"]["case_authority"]["risk_level"] == "EMERGENCY"
            visible_case_id = payload[0]["case_id"]
        assert visible_case_id is not None

        for role in ("operations", "student"):
            status, payload = _request(server.server_port, "GET", "/api/m8/cases", role)
            assert status == 200
            assert payload == []

        status, payload = _request(
            server.server_port,
            "GET",
            "/api/m8/cases?limit=999999",
            "safety",
        )
        assert status == 400
        assert isinstance(payload, dict)
        assert payload["reason_code"] == "INVALID_REQUEST"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_api_answers_from_versioned_offline_knowledge_with_citations(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    database = tmp_path / "knowledge" / "labcourt.sqlite3"
    assembly = assemble_m8_personal_demo_api(database, 0)
    assert bootstrap_m8_personal_demo_knowledge(database) == assembly.knowledge_receipt
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = M8ApiKnowledgeQueryRequestV1(
            query_text="护目镜 佩戴",
            locale="zh-CN",
            as_of=datetime(2026, 8, 10, 9, 0, tzinfo=UTC),
            allowed_document_types=tuple(
                sorted(M8KnowledgeDocumentType, key=lambda item: item.value)
            ),
            max_citations=3,
        ).model_dump(mode="json")
        status, payload = _request(
            server.server_port,
            "POST",
            "/api/m8/knowledge/catalogs/campus-safety-knowledge/queries",
            "safety",
            request,
        )
        assert status == 200
        assert isinstance(payload, dict)
        answer = payload["answer"]
        assert answer["outcome"] == "ANSWERED"
        assert answer["network_used"] is False
        assert answer["model_used"] is False
        assert answer["ordinary_document_used_as_case_rule"] is False
        assert answer["citations"]
        assert all(citation["source_version"] == 1 for citation in answer["citations"])
        assert all(citation["source_effective_at"] for citation in answer["citations"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_api_projection_exposes_routed_notification_by_role(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    database = tmp_path / "notification-api" / "labcourt.sqlite3"
    routed = route_m8_personal_demo_notification(database)
    deliver_m8_personal_demo_notification(database, routed.receipt)
    acknowledged = acknowledge_m8_personal_demo_notification(
        database,
        routed.receipt,
        confirmed=True,
    )
    assembly = assemble_m8_personal_demo_api(database, 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for role in ("safety", "leader"):
            status, payload = _request(
                server.server_port,
                "GET",
                "/api/m8/campuses/campus-demo/operations-projection",
                role,
            )
            assert status == 200
            assert isinstance(payload, dict)
            visible = payload["visible_projection"]
            assert visible["overview"]["current_notification_count"] == 1
            assert visible["current_notifications"][0]["notification_id"] == (
                routed.receipt.notification_id
            )
            assert visible["current_notifications"][0]["status"] == "ACKNOWLEDGED"
            assert visible["current_notifications"][0]["commit_receipt_id"] == (
                acknowledged.commit_receipt_id
            )
            assert visible["overview"]["unresolved_notification_count"] == 0

        status, payload = _request(
            server.server_port,
            "GET",
            "/api/m8/campuses/campus-demo/operations-projection",
            "operations",
        )
        assert status == 200
        assert isinstance(payload, dict)
        assert payload["visible_projection"]["overview"]["current_notification_count"] == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_api_notification_center_is_role_scoped_and_audited(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    database = tmp_path / "notification-center" / "labcourt.sqlite3"
    routed = route_m8_personal_demo_notification(database)
    deliver_m8_personal_demo_notification(database, routed.receipt)
    acknowledged = acknowledge_m8_personal_demo_notification(
        database,
        routed.receipt,
        confirmed=True,
    )
    assembly = assemble_m8_personal_demo_api(database, 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for role in ("safety", "leader"):
            status, payload = _request(
                server.server_port,
                "GET",
                "/api/m8/notifications",
                role,
            )
            assert status == 200
            assert isinstance(payload, list)
            assert len(payload) == 1
            assert payload[0]["commit_receipt_id"] == acknowledged.commit_receipt_id

            status, detail = _request(
                server.server_port,
                "GET",
                f"/api/m8/notifications/{routed.receipt.notification_id}",
                role,
            )
            assert status == 200
            assert isinstance(detail, dict)
            assert detail["status"] == "ACKNOWLEDGED"

            status, audit = _request(
                server.server_port,
                "GET",
                f"/api/m8/notifications/{routed.receipt.notification_id}/audit",
                role,
            )
            assert status == 200
            assert isinstance(audit, list)
            assert [item["event_sequence"] for item in audit] == [1, 2, 3, 4, 5]

        for role in ("operations", "student"):
            status, payload = _request(
                server.server_port,
                "GET",
                "/api/m8/notifications",
                role,
            )
            assert status == 200
            assert payload == []
            status, detail = _request(
                server.server_port,
                "GET",
                f"/api/m8/notifications/{routed.receipt.notification_id}",
                role,
            )
            assert status == 403
            assert isinstance(detail, dict)
            assert detail["reason_code"] == "FORBIDDEN"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_api_projection_exposes_simulated_recorded_camera(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    database = tmp_path / "camera-api" / "labcourt.sqlite3"
    camera = register_m8_personal_demo_camera(database)
    assembly = assemble_m8_personal_demo_api(database, 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, payload = _request(
            server.server_port,
            "GET",
            "/api/m8/campuses/campus-demo/operations-projection",
            "operations",
        )
        assert status == 200
        assert isinstance(payload, dict)
        visible = payload["visible_projection"]
        assert visible["overview"]["source_count"] == 2
        assert visible["overview"]["camera_count"] == 1
        assert visible["overview"]["simulated_source_count"] == 2
        camera_source = next(
            item for item in visible["sources"] if item["source"]["source_id"] == camera.source_id
        )
        assert camera_source["observation_state"] == "SOURCE_CATALOG_ONLY"
        assert camera_source["display_badge"] == "SIMULATED · RECORDED VIDEO"
        assert camera_source["simulated"] is True
        assert camera_source["live_observation_confirmed"] is False
        assert camera_source["certified_fire_detection_claim_permitted"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
