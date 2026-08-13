from __future__ import annotations

import http.client
import json
import threading
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME, platform_manifest
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_platform import (
    M8FeishuPlatformDisplayStatus,
    M8FeishuTestCardCheckRequestV1,
)
from labcourt.exceptions import EvidenceMissing
from labcourt.services.m8_feishu_platform import M8FeishuPlatformService
from tests.contract.test_m8_feishu_transport_contracts import _activation_status
from tests.integration.test_m8_platform_demo_api import _transition_payload
from tests.integration.test_m8_sqlite_notification_repository import _create_command


def _request(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: object | None = None,
) -> tuple[int, object]:
    body = None if payload is None else canonical_json(payload).encode()
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    return response.status, json.loads(raw) if raw else None


def _login(port: int, role: str) -> str:
    status, payload = _request(port, "POST", "/api/m8/demo/login", payload={"role": role})
    assert status == 200 and isinstance(payload, dict)
    return str(payload["bearer_token"])


def _minimal_mp4(path: Path) -> None:
    path.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + b"\x00" * 40)


def test_platform_exposes_explainable_knowledge_modular_agent_and_offline_feishu(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    root = Path(__file__).parents[2]
    media = tmp_path / "fixture.mp4"
    _minimal_mp4(media)
    assembly = assemble_m8_platform_demo_api(
        project_root=root,
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=media,
        port=0,
    )
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        operations = _login(server.server_port, "OPERATIONS")
        leader = _login(server.server_port, "LEADER")
        safety = _login(server.server_port, "SAFETY_OFFICER")
        status_code, feishu = _request(
            server.server_port,
            "GET",
            "/api/m8/integrations/feishu/status",
            token=operations,
        )
        assert status_code == 200 and isinstance(feishu, dict)
        assert feishu["display_status"] == "NOT_CONFIGURED"
        assert feishu["default_channel"] == "LOCAL_OFFLINE_FAKE"
        assert feishu["real_delivery_confirmed"] is False

        base_query = {
            "locale": "zh-CN",
            "as_of": "2026-08-13T04:00:00Z",
            "allowed_document_types": [
                "DEVICE_MANUAL",
                "EMERGENCY_PLAN",
                "FAQ",
                "HISTORICAL_PRECEDENT",
                "POLICY",
                "SOP",
            ],
            "max_citations": 3,
        }
        answered_code, answered = _request(
            server.server_port,
            "POST",
            "/api/m8/knowledge/catalogs/campus-safety-knowledge/query-projections",
            token=operations,
            payload=base_query | {"query_text": "护目镜操作规程"},
        )
        assert answered_code == 200 and isinstance(answered, dict)
        assert answered["outcome"] == "ANSWERED"
        assert answered["normalized_intent"] == "SOP"
        assert answered["document_hits"][0]["source_ref"]
        assert answered["document_hits"][0]["citation_id"]
        assert answered["similarity_score_reported"] is False

        no_match_code, no_match = _request(
            server.server_port,
            "POST",
            "/api/m8/knowledge/catalogs/campus-safety-knowledge/query-projections",
            token=operations,
            payload=base_query | {"query_text": "zzzxqv unmatched token"},
        )
        assert no_match_code == 200 and isinstance(no_match, dict)
        assert no_match["outcome"] == "NO_MATCH"
        assert no_match["document_hits"] == []

        agent_code, action = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=operations,
            payload={"query": "触发烟雾与温度场景"},
        )
        assert agent_code == 200 and isinstance(action, dict)
        assert action["normalized_intent"] == "SCENARIO_ACTION"
        assert action["proposed_action"]["action_kind"] == "RUN_SCENARIO"
        assert len(action["proposed_action"]["current_fence"]) == 64
        assert action["proposed_action"]["requires_confirmation"] is True
        assert "action_kind" not in action["proposed_action"]["request_payload"]
        scenario_code, scenario_run = _request(
            server.server_port,
            "POST",
            action["proposed_action"]["endpoint_path"],
            token=operations,
            payload=action["proposed_action"]["request_payload"],
        )
        assert scenario_code == 202 and isinstance(scenario_run, dict)

        reset_code, reset_action = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=operations,
            payload={"query": "复位演示"},
        )
        assert reset_code == 200 and isinstance(reset_action, dict)
        reset_receipt_code, reset_receipt = _request(
            server.server_port,
            "POST",
            reset_action["proposed_action"]["endpoint_path"],
            token=operations,
            payload=reset_action["proposed_action"]["request_payload"],
        )
        assert reset_receipt_code == 200 and isinstance(reset_receipt, dict)

        for query_text, expected_intent in (
            ("查看设备状态", "DEVICE_QUERY"),
            ("查看传感器状态", "SENSOR_QUERY"),
            ("查看校园地图", "MAP_QUERY"),
        ):
            query_code, query_result = _request(
                server.server_port,
                "POST",
                "/api/m8/agent/queries",
                token=operations,
                payload={"query": query_text},
            )
            assert query_code == 200 and isinstance(query_result, dict)
            assert query_result["normalized_intent"] == expected_intent
            assert query_result["source_refs"]

        trimmed_code, trimmed = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=leader,
            payload={"query": "触发烟雾与温度场景"},
        )
        assert trimmed_code == 200 and isinstance(trimmed, dict)
        assert trimmed["proposed_action"] is None

        created = assembly.server.platform_service._operations().create_operational_case(
            _create_command(),
            "student-demo",
            platform_manifest("platform-agent-case-fixture-v1"),
            platform_manifest("platform-agent-case-audit-fixture-v1"),
        )
        case_action_code, case_action = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=safety,
            payload={"query": "确认当前待核实案件"},
        )
        assert case_action_code == 200 and isinstance(case_action, dict)
        assert case_action["proposed_action"]["current_fence"] == created.case_document_sha256
        confirmed_code, confirmed = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{created.case_id}/transitions",
            token=safety,
            payload=_transition_payload(
                created.model_dump(mode="json"),
                action="CONFIRM",
                reason_code="VERIFIED_VIOLATION",
            ),
        )
        assert confirmed_code == 200 and isinstance(confirmed, dict)
        notification_action_code, notification_action = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=safety,
            payload={"query": "发送当前案件通知"},
        )
        assert notification_action_code == 200 and isinstance(notification_action, dict)
        proposed_notification = notification_action["proposed_action"]
        assert proposed_notification["action_kind"] == "NOTIFICATION_SEND"
        request_payload = dict(proposed_notification["request_payload"])
        request_payload.pop("action_kind", None)
        sent_code, sent = _request(
            server.server_port,
            "POST",
            proposed_notification["endpoint_path"],
            token=safety,
            payload=request_payload,
        )
        assert sent_code == 200 and isinstance(sent, dict)
        assert sent["audit_event"]["notification_authority"]["plan"]["target"]["channel"] == (
            "LOCAL_OFFLINE_FAKE"
        )
        resolved_code, resolved = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{created.case_id}/transitions",
            token=safety,
            payload=_transition_payload(
                confirmed,
                action="RESOLVE",
                reason_code="HAZARD_CLEARED",
            ),
        )
        assert resolved_code == 200 and isinstance(resolved, dict)
        stale_code, stale = _request(
            server.server_port,
            "POST",
            proposed_notification["endpoint_path"],
            token=safety,
            payload=request_payload,
        )
        assert stale_code == 409 and isinstance(stale, dict)
        assert stale["reason_code"] == "CONCURRENT_MODIFICATION"
        memory_code, memory = _request(
            server.server_port,
            "POST",
            "/api/m8/knowledge/catalogs/campus-safety-knowledge/query-projections",
            token=safety,
            payload=base_query | {"query_text": "历史案件案例"},
        )
        assert memory_code == 200 and isinstance(memory, dict)
        assert memory["normalized_intent"] == "CASE_MEMORY"
        assert memory["case_memory"]["availability"] == "AVAILABLE"
        assert memory["case_memory"]["entries"][0]["case_id"] == created.case_id
        assert memory["case_memory"]["entries"][0]["current_rule_rewrite_permitted"] is False

        unavailable_code, unavailable = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=operations,
            payload={"query": "发送飞书测试卡"},
        )
        assert unavailable_code == 200 and isinstance(unavailable, dict)
        assert unavailable["proposed_action"] is None
        assert "NOT_CONFIGURED" in unavailable["answer"]

        operations_principal = server.api_authenticator.authenticate(f"Bearer {operations}")
        operations_actor = assembly.server.platform_service._actor(operations_principal)
        formable = assembly.server.platform_service.agent_service.query(
            operations_principal,
            operations_actor,
            "发送飞书测试卡",
            _feishu_service(active=True).status(),
        )
        assert formable.proposed_action is not None
        assert formable.proposed_action.action_kind.value == "FEISHU_TEST_CARD_CHECK"
        assert formable.proposed_action.requires_confirmation is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class _Candidates:
    def __init__(self, candidate) -> None:
        self.candidate = candidate

    def list_candidates(self, limit: int):
        assert limit == 1_000
        return (SimpleNamespace(candidate=self.candidate),)


class _Readiness:
    def __init__(self, assessment) -> None:
        self.assessment = assessment

    def assess(self, candidate_id: str, actor_id: str, assessed_at):
        assert candidate_id == self.assessment.candidate.candidate_authority_id
        assert actor_id == "operations-demo"
        return self.assessment.model_copy(update={"assessed_at": assessed_at})


class _Activation:
    def __init__(self, status=None) -> None:
        self.status = status

    def get_current_status(self, candidate_id: str, assessed_at):
        if self.status is None:
            raise EvidenceMissing("not active")
        readiness = self.status.current_readiness_assessment
        return self.status.model_copy(
            update={
                "assessed_at": assessed_at,
                "current_readiness_assessment": (
                    None
                    if readiness is None
                    else readiness.model_copy(update={"assessed_at": assessed_at})
                ),
            }
        )


class _NoInbound:
    def get_current_inbound_status(self, candidate_id: str, assessed_at):
        raise EvidenceMissing("not active")


class _NoNotifications:
    def list_current_notifications(self, limit: int):
        return ()


def _feishu_service(active: bool) -> M8FeishuPlatformService:
    status = _activation_status()
    assessment = status.current_readiness_assessment
    assert assessment is not None
    return M8FeishuPlatformService(
        _Candidates(assessment.candidate),
        _Readiness(assessment),
        _Activation(status if active else None),
        _NoInbound(),
        _NoNotifications(),
        "operations-demo",
        lambda: status.assessed_at,
        "a" * 64,
    )


def test_feishu_platform_projects_ready_and_active_without_network() -> None:
    ready = _feishu_service(active=False).status()
    assert ready.display_status == M8FeishuPlatformDisplayStatus.READY_NOT_ACTIVE
    assert ready.external_call_permitted is False

    service = _feishu_service(active=True)
    active = service.status()
    assert active.display_status == M8FeishuPlatformDisplayStatus.ACTIVE
    assert active.recipient_binding_count == 1
    receipt = service.check_test_card(
        M8FeishuTestCardCheckRequestV1(
            activation_revision=active.activation_revision,
            activation_status_id=active.activation_status_id,
            explicit_human_confirmation=True,
        )
    )
    assert receipt.external_call_attempted is False
    assert receipt.probe_receipt.token_call_attempted is False
    assert receipt.probe_receipt.message_call_attempted is False
    assert receipt.real_delivery_confirmed is False


def test_feishu_platform_exposes_stable_activation_fence_across_assessments() -> None:
    activation = _activation_status()
    assessment = activation.current_readiness_assessment
    assert assessment is not None
    times = iter((activation.assessed_at, activation.assessed_at + timedelta(seconds=1)))
    service = M8FeishuPlatformService(
        _Candidates(assessment.candidate),
        _Readiness(assessment),
        _Activation(activation),
        _NoInbound(),
        _NoNotifications(),
        "operations-demo",
        lambda: next(times),
        "a" * 64,
    )

    first = service.status()
    second = service.status()

    assert first.activation_status_id == second.activation_status_id
    assert (
        first.activation_status_id
        == activation.activation_receipt.activation_commit_id
    )
