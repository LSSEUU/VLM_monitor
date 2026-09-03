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
from labcourt.application.m8_personal_demo_media import bind_m8_personal_demo_recorded_media
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


def test_demo_user_permission_list_is_current_typed_and_read_only(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = assemble_m8_personal_demo_api(tmp_path / "users" / "labcourt.sqlite3", 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for role in ("leader", "safety"):
            status, payload = _request(server.server_port, "GET", "/api/m8/users", role)
            assert status == 200
            assert isinstance(payload, list)
            assert [item["authority"]["actor_id"] for item in payload] == [
                "leader-demo",
                "operations-demo",
                "safety-officer-demo",
                "student-demo",
            ]
            assert all(item["authority"]["active"] is True for item in payload)
            assert all(item["authority"]["capabilities"] for item in payload)
        for role in ("operations", "student"):
            status, _payload = _request(server.server_port, "GET", "/api/m8/users", role)
            assert status == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_sensor_discovery_and_device_health_reuse_role_scoped_projection(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = assemble_m8_personal_demo_api(tmp_path / "health" / "labcourt.sqlite3", 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for role in ("leader", "safety", "operations"):
            health_status, health = _request(
                server.server_port,
                "GET",
                "/api/m8/campuses/campus-demo/device-health",
                role,
            )
            sensor_status, sensors = _request(
                server.server_port,
                "GET",
                "/api/m8/campuses/campus-demo/sensors",
                role,
            )
            assert health_status == sensor_status == 200
            assert isinstance(health, list)
            assert isinstance(sensors, list)
            assert len(sensors) >= 1
            assert len(health) >= len(sensors)
            assert all(item["source"]["source_kind"] == "SENSOR" for item in sensors)
            assert all(item["source"]["simulated"] is True for item in sensors)
            assert all(item["observation_state"] for item in health)
            assert all(
                item["certified_fire_detection_claim_permitted"] is False for item in sensors
            )
        for path in (
            "/api/m8/campuses/campus-demo/device-health",
            "/api/m8/campuses/campus-demo/sensors",
        ):
            status, _payload = _request(server.server_port, "GET", path, "student")
            assert status == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_rule_config_returns_typed_policy_without_document_rule_power(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = assemble_m8_personal_demo_api(tmp_path / "rules" / "labcourt.sqlite3", 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for role in ("leader", "safety"):
            status, policy = _request(server.server_port, "GET", "/api/m8/rules", role)
            assert status == 200
            assert isinstance(policy, dict)
            assert policy["schema_version"] == "m8-sensor-risk-policy-authority-v1"
            assert policy["revision"] == 1
            assert policy["purpose"] == "DEMONSTRATION"
            assert policy["rules"][0]["rule_id"] == "simulated-smoke-active-emergency-v1"
            assert policy["rules"][0]["risk_level"] == "EMERGENCY"
            assert policy["rules"][0]["create_pending_case"] is True
        for role in ("operations", "student"):
            status, _payload = _request(server.server_port, "GET", "/api/m8/rules", role)
            assert status == 403
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

        status, cameras = _request(server.server_port, "GET", "/api/m8/cameras", "operations")
        assert status == 200
        assert isinstance(cameras, list)
        assert len(cameras) == 1
        assert cameras[0]["source"]["source_id"] == camera.source_id
        assert cameras[0]["media_attached"] is False
        assert cameras[0]["media_binding"] is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_demo_api_streams_verified_recorded_media_with_role_scoped_ranges(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    output = tmp_path / "recorded-media-api"
    database = output / "labcourt.sqlite3"
    input_media = tmp_path / "authorized-camera.mp4"
    media_bytes = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2\x00\x00\x00\x10mdat12345678"
    input_media.write_bytes(media_bytes)
    binding = bind_m8_personal_demo_recorded_media(database, input_media, output)
    (output / "camera-media-receipt.json").write_text(
        binding.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    assembly = assemble_m8_personal_demo_api(database, 0)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, metadata = _request(
            server.server_port,
            "GET",
            "/api/m8/cameras/camera-recorded-demo-01/media-metadata",
            "operations",
        )
        assert status == 200
        assert isinstance(metadata, dict)
        assert metadata["media_binding_receipt_id"] == binding.media_binding_receipt_id
        assert metadata["display_badge"] == "SIMULATED · RECORDED VIDEO"
        assert metadata["live_camera_claim_permitted"] is False

        for role in ("operations", "safety"):
            status, cameras = _request(
                server.server_port,
                "GET",
                "/api/m8/cameras",
                role,
            )
            assert status == 200
            assert isinstance(cameras, list)
            assert len(cameras) == 1
            assert cameras[0]["media_attached"] is True
            assert cameras[0]["media_binding"]["media_binding_receipt_id"] == (
                binding.media_binding_receipt_id
            )

        for role in ("leader", "student"):
            status, cameras = _request(
                server.server_port,
                "GET",
                "/api/m8/cameras",
                role,
            )
            assert status == 200
            assert cameras == []
            status, payload = _request(
                server.server_port,
                "GET",
                "/api/m8/cameras/camera-recorded-demo-01/media-metadata",
                role,
            )
            assert status == 403
            assert isinstance(payload, dict)
            assert payload["reason_code"] == "FORBIDDEN"

        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request(
            "GET",
            "/api/m8/cameras/camera-recorded-demo-01/media",
            headers={
                "Authorization": f"Bearer {M8_PERSONAL_DEMO_ROLE_TOKENS['safety']}",
                "Range": "bytes=4-11",
            },
        )
        response = connection.getresponse()
        body = response.read()
        assert response.status == 206
        assert response.getheader("Content-Type") == "video/mp4"
        assert response.getheader("Accept-Ranges") == "bytes"
        assert response.getheader("Content-Range") == f"bytes 4-11/{len(media_bytes)}"
        assert body == media_bytes[4:12]
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request(
            "GET",
            "/api/m8/cameras/camera-recorded-demo-01/media",
            headers={
                "Authorization": f"Bearer {M8_PERSONAL_DEMO_ROLE_TOKENS['operations']}",
                "Range": "bytes=999-1000",
            },
        )
        response = connection.getresponse()
        assert response.status == 416
        assert response.getheader("Content-Range") == f"bytes */{len(media_bytes)}"
        assert json.loads(response.read())["reason_code"] == "INVALID_REQUEST"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
