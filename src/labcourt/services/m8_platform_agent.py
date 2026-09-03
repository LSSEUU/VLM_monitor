"""Deterministic, modular intent routing and proposal-only orchestration for M8."""

# ruff: noqa: RUF001 - Chinese product copy intentionally uses full-width punctuation.

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8OperationalCaseStatus,
)
from labcourt.contracts.m8_api import M8ApiKnowledgeQueryRequestV1, M8ApiPrincipalV1
from labcourt.contracts.m8_feishu_platform import (
    M8FeishuPlatformDisplayStatus,
    M8FeishuPlatformStatusV1,
)
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_platform_agent import (
    M8AgentCaseTransitionPayloadV2,
    M8AgentFeishuTestCardPayloadV2,
    M8AgentNotificationSendPayloadV2,
    M8AgentResetPayloadV2,
    M8AgentRunScenarioPayloadV2,
    M8PlatformAgentActionKindV2,
    M8PlatformAgentIntentV2,
    M8PlatformAgentQueryResponseV2,
    M8PlatformProposedActionV2,
)
from labcourt.contracts.references import require_reference_token
from labcourt.services.m8_knowledge_projection import M8KnowledgeProjectionService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_operations_api import M8OperationsApiService


def normalize_agent_query(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("M8 Agent query must be text")
    normalized = re.sub(r"\s+", " ", value.strip()).casefold()
    if not normalized:
        raise ValueError("M8 Agent query cannot normalize to empty text")
    return normalized


class M8PlatformAgentIntentRouter:
    """Closed lexical router. It never parses free-form JSON or model output."""

    def classify(self, query: str) -> M8PlatformAgentIntentV2:
        text = normalize_agent_query(query)

        def has(*terms: str) -> bool:
            return any(term in text for term in terms)

        if has("飞书", "feishu") and has("测试", "测试卡", "test card"):
            return M8PlatformAgentIntentV2.FEISHU_TEST_CARD_ACTION
        if has("飞书", "feishu") and has("送达", "失败", "最近", "delivery"):
            return M8PlatformAgentIntentV2.DELIVERY_STATUS_QUERY
        if has("飞书", "feishu"):
            return M8PlatformAgentIntentV2.FEISHU_STATUS_QUERY
        if has("复位", "重置", "reset"):
            return M8PlatformAgentIntentV2.RESET_ACTION
        if has("触发", "运行场景", "启动场景", "run scenario"):
            return M8PlatformAgentIntentV2.SCENARIO_ACTION
        if has("通知", "消息") and has("发送", "下发", "send"):
            return M8PlatformAgentIntentV2.NOTIFICATION_SEND_ACTION
        case_query_cue = has(
            "查看",
            "查询",
            "列出",
            "哪些",
            "多少",
            "状态",
            "详情",
            "说明",
            "风险",
            "摘要",
            "整理",
            "结合",
            "分析",
            "概述",
            "汇总",
        )
        if has("案件", "事件") and has("确认", "处置", "核实", "confirm") and not case_query_cue:
            return M8PlatformAgentIntentV2.CASE_TRANSITION_ACTION
        if has("通知", "消息"):
            return M8PlatformAgentIntentV2.NOTIFICATION_QUERY
        if has("案件", "事件"):
            return M8PlatformAgentIntentV2.CASE_QUERY
        if has("传感器", "sensor"):
            return M8PlatformAgentIntentV2.SENSOR_QUERY
        if has("设备", "摄像头", "device"):
            return M8PlatformAgentIntentV2.DEVICE_QUERY
        if has("地图", "位置", "校区", "map"):
            return M8PlatformAgentIntentV2.MAP_QUERY
        if has("知识", "规程", "制度", "应急", "护目镜", "案例", "先例", "knowledge"):
            return M8PlatformAgentIntentV2.KNOWLEDGE_QUERY
        return M8PlatformAgentIntentV2.UNKNOWN


class M8PlatformAgentService:
    def __init__(
        self,
        operations_api: M8OperationsApiService,
        notification_api: M8NotificationApiService,
        knowledge_projection: M8KnowledgeProjectionService,
        clock: Callable[[], datetime],
        campus_id: str,
    ) -> None:
        if (
            not isinstance(operations_api, M8OperationsApiService)
            or not isinstance(notification_api, M8NotificationApiService)
            or not isinstance(knowledge_projection, M8KnowledgeProjectionService)
            or not callable(clock)
        ):
            raise TypeError("M8 Agent service requires existing typed APIs and a clock")
        self._operations = operations_api
        self._notifications = notification_api
        self._knowledge = knowledge_projection
        self._clock = clock
        self._campus_id = require_reference_token(campus_id, "M8 Agent campus")
        self._router = M8PlatformAgentIntentRouter()

    def query(
        self,
        principal: M8ApiPrincipalV1,
        actor: M8ActorAuthorityV1,
        query: str,
        feishu: M8FeishuPlatformStatusV1,
    ) -> M8PlatformAgentQueryResponseV2:
        intent = self._router.classify(query)
        cases = self._operations.cases(principal)
        if intent == M8PlatformAgentIntentV2.FEISHU_TEST_CARD_ACTION:
            return self._feishu_test_card(actor, feishu)
        if intent == M8PlatformAgentIntentV2.FEISHU_STATUS_QUERY:
            return self._feishu_status(feishu)
        if intent == M8PlatformAgentIntentV2.DELIVERY_STATUS_QUERY:
            return self._delivery_status(feishu)
        if intent == M8PlatformAgentIntentV2.RESET_ACTION:
            if actor.role == M8ActorRole.OPERATIONS:
                fence = sha256_hex(["m8-platform-demo-reset-fence", 1])
                return M8PlatformAgentQueryResponseV2(
                    outcome="ANSWERED",
                    normalized_intent=intent,
                    answer="已按当前 Demo 基线生成复位操作卡；确认后仍由复位接口重新校验角色。",
                    source_refs=("platform-demo",),
                    proposed_action=M8PlatformProposedActionV2(
                        action_kind=M8PlatformAgentActionKindV2.RESET_DEMO,
                        target_ref="platform-demo",
                        endpoint_path="/api/m8/demo/reset",
                        current_version=1,
                        current_fence=fence,
                        impact_summary="归档当前 Demo 会话并恢复无案件、无通知基线",
                        request_payload=M8AgentResetPayloadV2(
                            explicit_human_confirmation=True,
                        ),
                    ),
                )
            return self._query_only_role(intent)
        if intent == M8PlatformAgentIntentV2.SCENARIO_ACTION:
            if actor.role == M8ActorRole.OPERATIONS:
                fence = sha256_hex(["m8-platform-scenario-fence", 1, "smoke-temperature"])
                return M8PlatformAgentQueryResponseV2(
                    outcome="ANSWERED",
                    normalized_intent=intent,
                    answer="可形成烟雾与温度联动场景操作卡；它只写入既有离线模拟流程。",
                    source_refs=("smoke-temperature-emergency",),
                    proposed_action=M8PlatformProposedActionV2(
                        action_kind=M8PlatformAgentActionKindV2.RUN_SCENARIO,
                        target_ref="smoke-temperature-emergency",
                        endpoint_path="/api/m8/demo/scenario-runs",
                        current_version=1,
                        current_fence=fence,
                        impact_summary="写入两路离线模拟信号并按既有服务建立紧急案件",
                        request_payload=M8AgentRunScenarioPayloadV2(
                            scenario_kind="SMOKE_TEMPERATURE_EMERGENCY",
                            explicit_human_confirmation=True,
                        ),
                    ),
                )
            return self._query_only_role(intent)
        if intent == M8PlatformAgentIntentV2.CASE_TRANSITION_ACTION:
            if actor.role != M8ActorRole.SAFETY_OFFICER:
                return self._query_only_role(intent)
            pending = next(
                (
                    item
                    for item in cases
                    if item.status == M8OperationalCaseStatus.PENDING_VERIFICATION
                ),
                None,
            )
            if pending is None:
                return M8PlatformAgentQueryResponseV2(
                    outcome="ANSWERED",
                    normalized_intent=intent,
                    answer="当前可见范围内没有待核实案件，不能形成处置操作卡。",
                    source_refs=tuple(item.case_id for item in cases),
                )
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=intent,
                answer=(
                    "已绑定案件当前版本与文档 fence；确认时案件接口仍会重新执行 RBAC 和版本校验。"
                ),
                source_refs=(pending.case_id, pending.audit_event_id),
                proposed_action=M8PlatformProposedActionV2(
                    action_kind=M8PlatformAgentActionKindV2.CASE_TRANSITION,
                    target_ref=pending.case_id,
                    endpoint_path=f"/api/m8/cases/{pending.case_id}/transitions",
                    current_version=pending.case_version,
                    current_fence=pending.case_document_sha256,
                    impact_summary="把当前待核实案件提交为已确认，后续通知仍需独立确认",
                    request_payload=M8AgentCaseTransitionPayloadV2(
                        action="CONFIRM",
                        source_case_version=pending.case_version,
                        source_case_authority_sha256=pending.case_document_sha256,
                        source_status=M8OperationalCaseStatus.PENDING_VERIFICATION,
                        explicit_human_confirmation=True,
                    ),
                ),
            )
        if intent == M8PlatformAgentIntentV2.NOTIFICATION_SEND_ACTION:
            if actor.role != M8ActorRole.SAFETY_OFFICER:
                return self._query_only_role(intent)
            current = next(
                (
                    item
                    for item in cases
                    if item.status
                    in {
                        M8OperationalCaseStatus.CONFIRMED,
                        M8OperationalCaseStatus.RESOLVED,
                    }
                    and item.audit_event.case_authority.subject_actor_id is not None
                ),
                None,
            )
            if current is None:
                return M8PlatformAgentQueryResponseV2(
                    outcome="ANSWERED",
                    normalized_intent=intent,
                    answer="当前没有具备学生 target 的已确认案件，不能形成通知操作卡。",
                    source_refs=tuple(item.case_id for item in cases),
                )
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=intent,
                answer="已生成本地默认通道通知操作卡；确认时通知服务会复核案件版本，不会改写旧通知。",
                source_refs=(current.case_id, current.case_document_sha256),
                proposed_action=M8PlatformProposedActionV2(
                    action_kind=M8PlatformAgentActionKindV2.NOTIFICATION_SEND,
                    target_ref=current.case_id,
                    endpoint_path=f"/api/m8/cases/{current.case_id}/notification-dispatches",
                    current_version=current.case_version,
                    current_fence=current.case_document_sha256,
                    impact_summary="为当前案件新增一条 LOCAL_OFFLINE_FAKE 更新通知",
                    request_payload=M8AgentNotificationSendPayloadV2(
                        kind="CASE_UPDATED",
                        source_case_version=current.case_version,
                        source_case_authority_sha256=current.case_document_sha256,
                        explicit_human_confirmation=True,
                    ),
                ),
            )
        if intent == M8PlatformAgentIntentV2.CASE_QUERY:
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=intent,
                answer=f"当前角色可见 {len(cases)} 个案件；数量来自角色裁剪后的案件 API。",
                source_refs=tuple(item.case_id for item in cases),
            )
        if intent == M8PlatformAgentIntentV2.NOTIFICATION_QUERY:
            notifications = self._notifications.notifications(principal)
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=intent,
                answer=(
                    f"当前角色可见 {len(notifications)} 条通知；"
                    "每条通道与送达声明均来自通知 authority。"
                ),
                source_refs=tuple(item.notification_id for item in notifications),
            )
        if intent in {
            M8PlatformAgentIntentV2.DEVICE_QUERY,
            M8PlatformAgentIntentV2.SENSOR_QUERY,
            M8PlatformAgentIntentV2.MAP_QUERY,
        }:
            if actor.role == M8ActorRole.STUDENT:
                return M8PlatformAgentQueryResponseV2(
                    outcome="ANSWERED",
                    normalized_intent=intent,
                    answer="学生角色不具备设备与全局地图 inventory 权限；Agent 未扩大可见范围。",
                )
            catalog = self._operations.source_catalog(principal, self._campus_id)
            noun = {
                M8PlatformAgentIntentV2.DEVICE_QUERY: "设备",
                M8PlatformAgentIntentV2.SENSOR_QUERY: "传感器",
                M8PlatformAgentIntentV2.MAP_QUERY: "地图数据源",
            }[intent]
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=intent,
                answer=(
                    f"当前校区登记 {len(catalog.catalog.sources)} 个{noun}来源，"
                    "状态来自运营 source catalog。"
                ),
                source_refs=tuple(item.source_id for item in catalog.catalog.sources),
            )
        return self._knowledge_fallback(principal, query)

    @staticmethod
    def _query_only_role(intent: M8PlatformAgentIntentV2) -> M8PlatformAgentQueryResponseV2:
        return M8PlatformAgentQueryResponseV2(
            outcome="ANSWERED",
            normalized_intent=intent,
            answer="当前角色仅可查询与读取知识，不能形成该操作卡；Agent 未执行任何写入。",
        )

    @staticmethod
    def _feishu_status(feishu: M8FeishuPlatformStatusV1) -> M8PlatformAgentQueryResponseV2:
        refs = tuple(
            item
            for item in (feishu.candidate_authority_id, feishu.activation_status_id)
            if item is not None
        )
        return M8PlatformAgentQueryResponseV2(
            outcome="ANSWERED",
            normalized_intent=M8PlatformAgentIntentV2.FEISHU_STATUS_QUERY,
            answer=(
                f"飞书状态为 {feishu.display_status.value}；默认通知通道仍是 "
                f"{feishu.default_channel.value}，"
                f"recipient binding={feishu.recipient_binding_count}。"
            ),
            source_refs=refs,
        )

    @staticmethod
    def _delivery_status(feishu: M8FeishuPlatformStatusV1) -> M8PlatformAgentQueryResponseV2:
        attempt = feishu.last_audited_attempt
        if attempt is None:
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=M8PlatformAgentIntentV2.DELIVERY_STATUS_QUERY,
                answer="当前没有可见的飞书 audited dispatch attempt；Agent 不会推断送达。",
                source_refs=tuple(
                    item for item in (feishu.activation_status_id,) if item is not None
                ),
            )
        return M8PlatformAgentQueryResponseV2(
            outcome="ANSWERED",
            normalized_intent=M8PlatformAgentIntentV2.DELIVERY_STATUS_QUERY,
            answer=(
                f"最近一次飞书发送审计结果为 {attempt.disposition.value}；"
                "real_delivery_confirmed=false，UNKNOWN 不会自动重试。"
            ),
            source_refs=(
                attempt.notification_id,
                attempt.dispatch_result_id,
                attempt.audit_event_id,
            ),
        )

    @staticmethod
    def _feishu_test_card(
        actor: M8ActorAuthorityV1,
        feishu: M8FeishuPlatformStatusV1,
    ) -> M8PlatformAgentQueryResponseV2:
        if actor.role != M8ActorRole.OPERATIONS:
            return M8PlatformAgentService._query_only_role(
                M8PlatformAgentIntentV2.FEISHU_TEST_CARD_ACTION
            )
        if (
            feishu.display_status != M8FeishuPlatformDisplayStatus.ACTIVE
            or feishu.activation_revision is None
            or feishu.activation_status_id is None
        ):
            refs = tuple(
                item
                for item in (feishu.candidate_authority_id, feishu.readiness_assessment_id)
                if item is not None
            )
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=M8PlatformAgentIntentV2.FEISHU_TEST_CARD_ACTION,
                answer=(
                    f"当前飞书为 {feishu.display_status.value}，缺少可用 activation authority，"
                    "不能形成测试卡操作。"
                ),
                source_refs=refs,
            )
        return M8PlatformAgentQueryResponseV2(
            outcome="ANSWERED",
            normalized_intent=M8PlatformAgentIntentV2.FEISHU_TEST_CARD_ACTION,
            answer="已形成 CHECK_ONLY 测试卡检查操作；确认后仍不联网、不发送真实消息。",
            source_refs=(feishu.activation_status_id,),
            proposed_action=M8PlatformProposedActionV2(
                action_kind=M8PlatformAgentActionKindV2.FEISHU_TEST_CARD_CHECK,
                target_ref="feishu-test-card",
                endpoint_path="/api/m8/integrations/feishu/test-card-checks",
                current_version=feishu.activation_revision,
                current_fence=feishu.activation_status_id,
                impact_summary="复核当前 activation 与 recipient，生成不联网的 CHECK_ONLY 收据",
                request_payload=M8AgentFeishuTestCardPayloadV2(
                    activation_revision=feishu.activation_revision,
                    activation_status_id=feishu.activation_status_id,
                    explicit_human_confirmation=True,
                ),
            ),
        )

    def _knowledge_fallback(
        self,
        principal: M8ApiPrincipalV1,
        query: str,
    ) -> M8PlatformAgentQueryResponseV2:
        projection = self._knowledge.query(
            principal,
            "campus-safety-knowledge",
            M8ApiKnowledgeQueryRequestV1(
                query_text=query,
                locale="zh-CN",
                as_of=self._clock(),
                allowed_document_types=tuple(
                    sorted(M8KnowledgeDocumentType, key=lambda item: item.value)
                ),
                max_citations=3,
            ),
        )
        memory_entries = projection.case_memory.entries
        if memory_entries and projection.outcome.value == "NO_MATCH":
            return M8PlatformAgentQueryResponseV2(
                outcome="ANSWERED",
                normalized_intent=M8PlatformAgentIntentV2.KNOWLEDGE_QUERY,
                answer="普通文档未命中；已在隔离的案例记忆分区找到可引用的历史案件。",
                source_refs=tuple(item.case_id for item in memory_entries),
                knowledge_projection=projection,
            )
        return M8PlatformAgentQueryResponseV2(
            outcome=projection.outcome.value,
            normalized_intent=(
                M8PlatformAgentIntentV2.KNOWLEDGE_QUERY
                if projection.outcome.value == "ANSWERED"
                else M8PlatformAgentIntentV2.UNKNOWN
            ),
            answer=projection.answer_receipt.answer.answer_text,
            source_refs=tuple(item.citation_id for item in projection.document_hits),
            knowledge_projection=projection,
        )


__all__ = [
    "M8PlatformAgentIntentRouter",
    "M8PlatformAgentService",
    "normalize_agent_query",
]
