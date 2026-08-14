from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME, platform_manifest
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_agent_chat import (
    M8AgentExecutionMode,
    M8AgentToolKind,
    M8AgentTurnRequestV1,
)
from labcourt.contracts.m8_api import M8ApiKnowledgeQueryRequestV1
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_platform_agent import (
    M8PlatformAgentIntentV2,
    M8PlatformAgentQueryResponseV2,
)
from labcourt.contracts.m8_platform_demo import (
    M8PlatformRecognitionMode,
    M8PlatformScenarioKind,
    M8PlatformScenarioRunV1,
    M8PlatformScenarioStage,
    M8PlatformScenarioStageV1,
    M8PlatformStageState,
)
from labcourt.services.m8_agent_chat import M8AgentChatService
from labcourt.services.m8_evaluation import M8EvaluationService
from labcourt.services.m8_hearing_api import M8HearingApiService
from tests.integration.test_m8_agent_chat import (
    _install_model,
    _principal,
    _ToolCallingModel,
)
from tests.integration.test_m8_sqlite_notification_repository import _create_command

_MP4_HEADER = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"


def test_final_assembly_preserves_hearing_mapping_and_grounded_agent_v2(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    media = tmp_path / "capability-union.mp4"
    media.write_bytes(_MP4_HEADER + b"\x00" * 40)
    assembly = assemble_m8_platform_demo_api(
        project_root=Path(__file__).parents[2],
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=media,
        port=0,
    )
    try:
        server = assembly.server
        platform = server.platform_service
        assert isinstance(server.agent_chat_service, M8AgentChatService)
        assert isinstance(server.hearing_service, M8HearingApiService)
        assert isinstance(server.evaluation_service, M8EvaluationService)
        assert server.feishu_live_service is assembly.feishu_live.api

        safety = _principal(assembly, M8ActorRole.SAFETY_OFFICER)
        created = platform._operations().create_operational_case(
            _create_command(),
            "student-demo",
            platform_manifest("combined-regression-case-v1"),
            platform_manifest("combined-regression-case-audit-v1"),
        )
        run = M8PlatformScenarioRunV1(
            run_id="combined-regression-hearing-map",
            scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
            state="RUNNING",
            stages=tuple(
                M8PlatformScenarioStageV1(
                    stage=stage,
                    state=M8PlatformStageState.PENDING,
                    summary="Awaiting the persisted offline run.",
                )
                for stage in M8PlatformScenarioStage
            ),
            case_id=created.case_id,
            hearing_case_id="m4-combined-regression-case",
            case_status=created.status,
            recognition_mode=M8PlatformRecognitionMode.DEMO_FIXTURE,
        )
        platform._write_run(run)
        assert platform.resolve_hearing_case_id(run.run_id, created.case_id) == (
            run.hearing_case_id
        )

        deterministic = platform.agent_query(safety, "\u67e5\u770b\u6848\u4ef6")
        assert isinstance(deterministic, M8PlatformAgentQueryResponseV2)
        assert deterministic.schema_version == "m8-platform-agent-query-response-v2"
        assert deterministic.normalized_intent == M8PlatformAgentIntentV2.CASE_QUERY
        assert created.case_id in deterministic.source_refs

        model = _ToolCallingModel("read_cases", {"case_id": created.case_id, "limit": 10})
        _install_model(server.agent_chat_service, model)
        conversation = server.agent_chat_service.create_conversation(safety)
        completion = server.agent_chat_service.complete_turn(
            safety,
            conversation.conversation_id,
            M8AgentTurnRequestV1(query="\u67e5\u770b\u4f1a\u5ba1\u6620\u5c04\u6848\u4ef6"),
        )
        assert completion.execution_mode == M8AgentExecutionMode.LIVE_QWEN
        assert created.case_id in completion.source_refs
        assert len(completion.tool_receipts) == 1
        assert completion.tool_receipts[0].tool_kind == M8AgentToolKind.READ_CASES
        assert created.case_id in completion.tool_receipts[0].source_refs
        assert len(completion.model_call_receipts) == 2
        assert all(item.raw_response_ref for item in completion.model_call_receipts)

        knowledge = platform.knowledge_query_projection(
            safety,
            "campus-safety-knowledge",
            M8ApiKnowledgeQueryRequestV1(
                query_text="\u62a4\u76ee\u955c\u64cd\u4f5c\u89c4\u7a0b",
                locale="zh-CN",
                as_of=datetime(2026, 8, 14, tzinfo=UTC),
                allowed_document_types=tuple(
                    sorted(M8KnowledgeDocumentType, key=lambda item: item.value)
                ),
                max_citations=3,
            ),
        )
        assert knowledge.outcome.value == "ANSWERED"
        assert knowledge.document_hits
        assert knowledge.document_hits[0].source_ref
        assert knowledge.document_hits[0].citation_id

        feishu = platform.feishu_status(safety)
        assert feishu.schema_version == "m8-feishu-platform-status-v1"
        assert feishu.default_channel.value == "LOCAL_OFFLINE_FAKE"
        assert feishu.real_delivery_confirmed is False

        dashboard = server.evaluation_service.dashboard(safety)
        assert dashboard.schema_version == "m8-evaluation-dashboard-v1"
    finally:
        assembly.server.server_close()
