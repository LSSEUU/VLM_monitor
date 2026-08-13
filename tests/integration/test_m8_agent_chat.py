from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from labcourt.adapters.m8_qwen_agent import M8QwenAgentRuntime
from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME
from labcourt.application.m8_platform_demo_api import (
    M8_PLATFORM_ROLE_TOKENS,
    assemble_m8_platform_demo_api,
)
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_agent_chat import (
    M8AgentExecutionMode,
    M8AgentFailureCode,
    M8AgentTurnOutcome,
    M8AgentTurnRequestV1,
)
from labcourt.contracts.m8_platform_agent import M8PlatformAgentIntentV2
from labcourt.ports.m8_agent_chat import (
    M8AgentProviderDelta,
    M8AgentProviderDeltaKind,
    M8AgentProviderError,
    M8AgentProviderRequest,
)
from labcourt.services.m8_platform_agent import M8PlatformAgentIntentRouter

_MP4_HEADER = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"


class _ToolCallingModel:
    def __init__(
        self,
        tool_name: str,
        arguments: dict[str, object],
        *,
        tool_preamble: str = "",
    ) -> None:
        self.tool_name = tool_name
        self.arguments = arguments
        self.tool_preamble = tool_preamble
        self.calls = 0
        self.requests: list[dict[str, object]] = []

    def stream(self, request: M8AgentProviderRequest) -> Iterator[M8AgentProviderDelta]:
        self.calls += 1
        document = json.loads(request.body)
        self.requests.append(document)
        messages = document["messages"]
        if messages[-1]["role"] == "tool":
            yield M8AgentProviderDelta(
                kind=M8AgentProviderDeltaKind.TEXT,
                raw_event=b"final-text\n",
                text="这是基于平台可信工具回执形成的回答。",
            )
        else:
            if self.tool_preamble:
                yield M8AgentProviderDelta(
                    kind=M8AgentProviderDeltaKind.TEXT,
                    raw_event=b"tool-preamble\n",
                    text=self.tool_preamble,
                )
            arguments = json.dumps(self.arguments, ensure_ascii=False, separators=(",", ":"))
            split = max(1, len(arguments) // 2)
            yield M8AgentProviderDelta(
                kind=M8AgentProviderDeltaKind.TOOL,
                raw_event=b"tool-1\n",
                tool_index=0,
                tool_call_id="call-1",
                tool_name=self.tool_name,
                tool_arguments_delta=arguments[:split],
            )
            yield M8AgentProviderDelta(
                kind=M8AgentProviderDeltaKind.TOOL,
                raw_event=b"tool-2\n",
                tool_index=0,
                tool_arguments_delta=arguments[split:],
            )
        yield M8AgentProviderDelta(
            kind=M8AgentProviderDeltaKind.USAGE,
            raw_event=b"usage\n",
            input_tokens=12,
            output_tokens=6,
        )
        yield M8AgentProviderDelta(
            kind=M8AgentProviderDeltaKind.DONE,
            raw_event=b"done\n",
        )


def _assembly(tmp_path: Path):
    media = tmp_path / "agent-demo.mp4"
    media.write_bytes(_MP4_HEADER)
    return assemble_m8_platform_demo_api(
        project_root=Path.cwd(),
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=media,
        port=0,
    )


def _principal(assembly, role: M8ActorRole):
    token = M8_PLATFORM_ROLE_TOKENS[role]
    return assembly.server.api_authenticator.authenticate(f"Bearer {token}")


def _install_model(service, model: _ToolCallingModel) -> None:
    runtime = service._runtime
    service._runtime = M8QwenAgentRuntime(
        profile=runtime.profile,
        client=model,
        endpoint_configured=True,
        api_key_configured=True,
    )


def _http_json(
    base_url: str,
    method: str,
    path: str,
    *,
    token: str,
    body: dict[str, object] | None = None,
    accept: str = "application/json",
) -> tuple[int, bytes]:
    payload = None if body is None else json.dumps(body).encode()
    headers = {"Accept": accept, "Authorization": f"Bearer {token}"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    with urlopen(
        Request(base_url + path, data=payload, headers=headers, method=method),
        timeout=10,
    ) as response:
        return response.status, response.read()


def test_agent_http_api_reports_live_only_and_fails_without_configuration(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    thread = threading.Thread(target=assembly.server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{assembly.server.server_port}"
        token = M8_PLATFORM_ROLE_TOKENS[M8ActorRole.SAFETY_OFFICER]
        status_code, status_body = _http_json(base_url, "GET", "/api/m8/agent/status", token=token)
        assert status_code == 200
        status = json.loads(status_body)
        assert status["availability"] == "NOT_CONFIGURED"
        assert status["reply_policy"] == "LIVE_ONLY"
        assert status["cache_enabled"] is False
        assert status["default_execution_mode"] == "LIVE_QWEN"
        create_code, create_body = _http_json(
            base_url,
            "POST",
            "/api/m8/agent/conversations",
            token=token,
            body={},
        )
        assert create_code == 201
        conversation_id = json.loads(create_body)["conversation_id"]
        stream_code, stream_body = _http_json(
            base_url,
            "POST",
            f"/api/m8/agent/conversations/{conversation_id}/turns",
            token=token,
            body={"query": "护目镜有什么要求?"},
            accept="text/event-stream",
        )
        assert stream_code == 200
        assert b"event: turn.accepted" in stream_body
        assert b"event: turn.failed" in stream_body
        assert b'"failure_code":"NOT_CONFIGURED"' in stream_body
        assert b"event: message.completed" not in stream_body
        detail_code, detail_body = _http_json(
            base_url,
            "GET",
            f"/api/m8/agent/conversations/{conversation_id}",
            token=token,
        )
        assert detail_code == 200
        turn = json.loads(detail_body)["turns"][0]
        assert turn["state"] == "FAILED"
        assert turn["failure_code"] == "NOT_CONFIGURED"
    finally:
        assembly.server.shutdown()
        assembly.server.server_close()
        thread.join(timeout=5)


def test_agent_http_api_removes_conversation_from_active_history_but_retains_audit(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    thread = threading.Thread(target=assembly.server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{assembly.server.server_port}"
        token = M8_PLATFORM_ROLE_TOKENS[M8ActorRole.SAFETY_OFFICER]
        _, create_body = _http_json(
            base_url,
            "POST",
            "/api/m8/agent/conversations",
            token=token,
            body={},
        )
        conversation_id = json.loads(create_body)["conversation_id"]

        delete_code, delete_body = _http_json(
            base_url,
            "DELETE",
            f"/api/m8/agent/conversations/{conversation_id}",
            token=token,
        )
        receipt = json.loads(delete_body)
        assert delete_code == 200
        assert receipt["conversation_id"] == conversation_id
        assert receipt["retained_for_audit"] is True

        _, list_body = _http_json(
            base_url,
            "GET",
            "/api/m8/agent/conversations",
            token=token,
        )
        assert all(
            item["conversation_id"] != conversation_id for item in json.loads(list_body)
        )
        with pytest.raises(HTTPError) as missing:
            _http_json(
                base_url,
                "GET",
                f"/api/m8/agent/conversations/{conversation_id}",
                token=token,
            )
        assert missing.value.code == 404

        database = tmp_path / PLATFORM_DATABASE_NAME
        with sqlite3.connect(database) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM m8_agent_conversations WHERE conversation_id = ?",
                (conversation_id,),
            ).fetchone() == (1,)
            assert connection.execute(
                "SELECT COUNT(*) FROM m8_agent_conversation_removals WHERE conversation_id = ?",
                (conversation_id,),
            ).fetchone() == (1,)
    finally:
        assembly.server.shutdown()
        assembly.server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    ("query", "tool_name", "arguments", "expected_count"),
    [
        ("列出我能看到的待核实案件, 并说明风险等级。", "read_cases", {"limit": 10}, 0),
        ("查看最近通知", "read_notifications", {"limit": 10}, 0),
        ("查看设备状态", "read_operations_projection", {"focus": "DEVICES"}, 1),
        ("当前温度和烟雾传感器状态如何?", "read_operations_projection", {"focus": "SENSORS"}, 1),
        ("查看校园地图", "read_operations_projection", {"focus": "MAP"}, 1),
        ("护目镜有什么要求?", "query_knowledge", {"query": "护目镜有什么要求?"}, 1),
    ],
)
def test_live_agent_uses_role_scoped_read_only_tools_and_persists_receipts(
    tmp_path: Path,
    socket_enabled: None,
    query: str,
    tool_name: str,
    arguments: dict[str, object],
    expected_count: int,
) -> None:
    assembly = _assembly(tmp_path)
    try:
        service = assembly.server.agent_chat_service
        model = _ToolCallingModel(tool_name, arguments)
        _install_model(service, model)
        principal = _principal(assembly, M8ActorRole.SAFETY_OFFICER)
        conversation = service.create_conversation(principal)
        completion = service.complete_turn(
            principal,
            conversation.conversation_id,
            M8AgentTurnRequestV1(query=query),
        )
        assert completion.execution_mode == M8AgentExecutionMode.LIVE_QWEN
        assert completion.tool_receipts[0].result_count >= expected_count
        if expected_count:
            assert completion.source_refs
        assert len(completion.model_call_receipts) == 2
        restored = service.conversation(principal, conversation.conversation_id)
        assert restored.turns[0].completion == completion
        assert model.calls == 2
    finally:
        assembly.server.server_close()


def test_live_only_calls_model_again_instead_of_replaying_cache(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    try:
        service = assembly.server.agent_chat_service
        model = _ToolCallingModel("read_cases", {"limit": 10})
        _install_model(service, model)
        principal = _principal(assembly, M8ActorRole.SAFETY_OFFICER)
        first_conversation = service.create_conversation(principal)
        second_conversation = service.create_conversation(principal)

        first = service.complete_turn(
            principal,
            first_conversation.conversation_id,
            M8AgentTurnRequestV1(query="查看当前案件"),
        )
        second = service.complete_turn(
            principal,
            second_conversation.conversation_id,
            M8AgentTurnRequestV1(query="查看当前案件"),
        )

        assert first.execution_mode == M8AgentExecutionMode.LIVE_QWEN
        assert second.execution_mode == M8AgentExecutionMode.LIVE_QWEN
        assert all(not item.cache_hit for item in first.model_call_receipts)
        assert all(not item.cache_hit for item in second.model_call_receipts)
        assert model.calls == 4
    finally:
        assembly.server.server_close()


def test_live_agent_accepts_non_terminal_text_before_a_read_only_tool_call(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    try:
        service = assembly.server.agent_chat_service
        preamble = "我先查询设备投影, 再根据可信结果回答."
        model = _ToolCallingModel(
            "read_operations_projection",
            {"focus": "ALL", "location_id": "room-chem-301"},
            tool_preamble=preamble,
        )
        _install_model(service, model)
        principal = _principal(assembly, M8ActorRole.SAFETY_OFFICER)
        conversation = service.create_conversation(principal)

        completion = service.complete_turn(
            principal,
            conversation.conversation_id,
            M8AgentTurnRequestV1(query="查看化学楼 301 的设备状态"),
        )

        assert completion.execution_mode == M8AgentExecutionMode.LIVE_QWEN
        assert completion.answer == "这是基于平台可信工具回执形成的回答。"
        assert preamble not in completion.answer
        assert len(completion.tool_receipts) == 1
        assert len(completion.model_call_receipts) == 2
        second_round_messages = model.requests[1]["messages"]
        assert isinstance(second_round_messages, list)
        assert second_round_messages[-2]["role"] == "assistant"
        assert second_round_messages[-2]["content"] == preamble
        assert second_round_messages[-2]["tool_calls"][0]["function"]["name"] == (
            "read_operations_projection"
        )
        assert second_round_messages[-1]["role"] == "tool"
        tool_result = json.loads(second_round_messages[-1]["content"])
        assert tool_result["requested_location_id"] == "room-chem-301"
        assert tool_result["location_filter_matched"] is True
        assert tool_result["overview_scope"] == "ROLE_SCOPED_CAMPUS"
        assert tool_result["map_nodes"][0]["parent_location_id"] == "floor-chem-03"
    finally:
        assembly.server.server_close()


def test_agent_router_keeps_summary_queries_separate_from_confirmed_actions() -> None:
    router = M8PlatformAgentIntentRouter()

    assert router.classify("结合当前案件和知识库, 整理一份处置摘要.") == (
        M8PlatformAgentIntentV2.CASE_QUERY
    )
    assert router.classify("确认当前待核实案件") == (
        M8PlatformAgentIntentV2.CASE_TRANSITION_ACTION
    )


@pytest.mark.parametrize(
    ("role", "query"),
    [
        (M8ActorRole.STUDENT, "查看设备状态"),
        (M8ActorRole.OPERATIONS, "列出当前案件"),
    ],
)
def test_live_agent_denies_unavailable_required_tools_before_calling_model(
    tmp_path: Path,
    socket_enabled: None,
    role: M8ActorRole,
    query: str,
) -> None:
    assembly = _assembly(tmp_path)
    try:
        service = assembly.server.agent_chat_service
        model = _ToolCallingModel("query_knowledge", {"query": query})
        _install_model(service, model)
        principal = _principal(assembly, role)
        conversation = service.create_conversation(principal)

        with pytest.raises(M8AgentProviderError) as captured:
            service.complete_turn(
                principal,
                conversation.conversation_id,
                M8AgentTurnRequestV1(query=query),
            )

        assert captured.value.failure_code == M8AgentFailureCode.TOOL_FORBIDDEN
        assert model.calls == 0
    finally:
        assembly.server.server_close()


def test_agent_no_match_role_denial_and_deterministic_action_bypass_model(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    try:
        service = assembly.server.agent_chat_service
        model = _ToolCallingModel("query_knowledge", {"query": "zzzxqv unmatched token"})
        _install_model(service, model)
        safety = _principal(assembly, M8ActorRole.SAFETY_OFFICER)
        conversation = service.create_conversation(safety)
        no_match = service.complete_turn(
            safety,
            conversation.conversation_id,
            M8AgentTurnRequestV1(query="火星传送门校规是什么?"),
        )
        assert no_match.outcome == M8AgentTurnOutcome.NO_MATCH
        assert no_match.knowledge_projection is not None
        assert no_match.answer == no_match.knowledge_projection.answer_receipt.answer.answer_text

        forbidden_model = _ToolCallingModel("read_operations_projection", {"focus": "DEVICES"})
        _install_model(service, forbidden_model)
        student = _principal(assembly, M8ActorRole.STUDENT)
        student_conversation = service.create_conversation(student)
        with pytest.raises(M8AgentProviderError) as captured:
            service.complete_turn(
                student,
                student_conversation.conversation_id,
                M8AgentTurnRequestV1(query="查看设备状态"),
            )
        assert captured.value.failure_code == M8AgentFailureCode.TOOL_FORBIDDEN
        assert (
            service.conversation(student, student_conversation.conversation_id)
            .turns[0]
            .failure_code
            == M8AgentFailureCode.TOOL_FORBIDDEN
        )

        write_model = _ToolCallingModel(
            "transition_case", {"case_id": "case-demo", "status": "CONFIRMED"}
        )
        _install_model(service, write_model)
        write_conversation = service.create_conversation(safety)
        with pytest.raises(M8AgentProviderError) as write_failure:
            service.complete_turn(
                safety,
                write_conversation.conversation_id,
                M8AgentTurnRequestV1(query="查看当前案件"),
            )
        assert write_failure.value.failure_code == M8AgentFailureCode.TOOL_FORBIDDEN

        action_model = _ToolCallingModel("read_cases", {"limit": 1})
        _install_model(service, action_model)
        operations = _principal(assembly, M8ActorRole.OPERATIONS)
        action_conversation = service.create_conversation(operations)
        action = service.complete_turn(
            operations,
            action_conversation.conversation_id,
            M8AgentTurnRequestV1(query="触发烟雾与温度场景"),
        )
        assert action.execution_mode == M8AgentExecutionMode.DETERMINISTIC_ACTION
        assert action.proposed_action is not None
        assert action.proposed_action.requires_confirmation
        assert action_model.calls == 0
    finally:
        assembly.server.server_close()
