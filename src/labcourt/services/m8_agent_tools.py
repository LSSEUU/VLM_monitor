"""Role-scoped read-only tools exposed to the M8 platform Agent model."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import TypeAlias

from pydantic import Field, ValidationError

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m8_access_cases import M8ActorRole, M8OperationalCaseStatus
from labcourt.contracts.m8_agent_chat import (
    M8AgentFailureCode,
    M8AgentToolKind,
    M8AgentToolReceiptV1,
)
from labcourt.contracts.m8_api import M8ApiKnowledgeQueryRequestV1, M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_knowledge_projection import M8KnowledgeQueryProjectionV1
from labcourt.ports.m8_agent_chat import (
    M8AgentProviderError,
    M8AgentToolExecution,
)
from labcourt.services.m8_knowledge_projection import M8KnowledgeProjectionService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_operations_api import M8OperationsApiService
from labcourt.services.m8_projection_api import M8ProjectionApiService


class M8AgentProjectionFocus(StrEnum):
    ALL = "ALL"
    DEVICES = "DEVICES"
    SENSORS = "SENSORS"
    MAP = "MAP"


class M8AgentReadCasesArguments(FrozenContractModel):
    case_id: str | None = Field(default=None, min_length=1, max_length=64)
    status: M8OperationalCaseStatus | None = None
    location_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description=(
            "Exact stable platform location_id such as room-chem-301; "
            "omit when only a human-readable place name is known."
        ),
    )
    limit: int = Field(default=10, ge=1, le=10, strict=True)


class M8AgentReadNotificationsArguments(FrozenContractModel):
    limit: int = Field(default=10, ge=1, le=10, strict=True)


class M8AgentReadProjectionArguments(FrozenContractModel):
    focus: M8AgentProjectionFocus = M8AgentProjectionFocus.ALL
    location_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description=(
            "Exact stable platform location_id such as room-chem-301; "
            "omit display names and use returned map_nodes to resolve them."
        ),
    )
    limit: int = Field(default=16, ge=1, le=32, strict=True)


class M8AgentKnowledgeArguments(FrozenContractModel):
    query: str = Field(min_length=1, max_length=512)
    max_citations: int = Field(default=3, ge=1, le=8, strict=True)


_AgentArgumentModel: TypeAlias = (
    type[M8AgentReadCasesArguments]
    | type[M8AgentReadNotificationsArguments]
    | type[M8AgentReadProjectionArguments]
    | type[M8AgentKnowledgeArguments]
)

_TOOL_MODELS: dict[str, tuple[M8AgentToolKind, _AgentArgumentModel]] = {
    "read_cases": (M8AgentToolKind.READ_CASES, M8AgentReadCasesArguments),
    "read_notifications": (
        M8AgentToolKind.READ_NOTIFICATIONS,
        M8AgentReadNotificationsArguments,
    ),
    "read_operations_projection": (
        M8AgentToolKind.READ_OPERATIONS_PROJECTION,
        M8AgentReadProjectionArguments,
    ),
    "query_knowledge": (M8AgentToolKind.QUERY_KNOWLEDGE, M8AgentKnowledgeArguments),
}

_DESCRIPTIONS = {
    "read_cases": "读取当前登录角色有权查看的案件; 不能修改案件。",
    "read_notifications": "读取当前登录角色有权查看的通知和送达声明。",
    "read_operations_projection": (
        "读取当前角色裁剪后的设备、传感器和地图投影。目录登记不等于设备在线。"
    ),
    "query_knowledge": "查询本地权威知识目录, 返回精确引用或明确 NO_MATCH。",
}


class M8PlatformAgentToolService:
    def __init__(
        self,
        operations: M8OperationsApiService,
        notifications: M8NotificationApiService,
        projection: M8ProjectionApiService,
        knowledge: M8KnowledgeProjectionService,
        campus_id: str,
        clock: Callable[[], datetime],
    ) -> None:
        self._operations = operations
        self._notifications = notifications
        self._projection = projection
        self._knowledge = knowledge
        self._campus_id = campus_id
        self._clock = clock

    def tool_schemas(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> tuple[dict[str, object], ...]:
        role = actor_receipt.authority.role
        names = ["read_notifications", "query_knowledge"]
        if role != M8ActorRole.OPERATIONS:
            names.insert(0, "read_cases")
        if role != M8ActorRole.STUDENT:
            names.insert(-1, "read_operations_projection")
        return tuple(self._tool_schema(name) for name in names)

    @staticmethod
    def _tool_schema(name: str) -> dict[str, object]:
        _kind, model = _TOOL_MODELS[name]
        schema = model.model_json_schema(mode="validation")
        schema["additionalProperties"] = False
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": _DESCRIPTIONS[name],
                "parameters": schema,
            },
        }

    def execute(
        self,
        principal: M8ApiPrincipalV1,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        tool_call_id: str,
        tool_name: str,
        arguments_json: str,
    ) -> M8AgentToolExecution:
        available = {
            item["function"]["name"]  # type: ignore[index]
            for item in self.tool_schemas(actor_receipt)
        }
        if tool_name not in available or tool_name not in _TOOL_MODELS:
            raise M8AgentProviderError(M8AgentFailureCode.TOOL_FORBIDDEN)
        kind, model = _TOOL_MODELS[tool_name]
        try:
            arguments = model.model_validate_json(arguments_json or "{}")
        except ValidationError:
            raise M8AgentProviderError(M8AgentFailureCode.TOOL_ARGUMENT_INVALID) from None
        if isinstance(arguments, M8AgentReadCasesArguments):
            document, refs, count, knowledge = self._cases(principal, arguments)
        elif isinstance(arguments, M8AgentReadNotificationsArguments):
            document, refs, count, knowledge = self._notifications_result(principal, arguments)
        elif isinstance(arguments, M8AgentReadProjectionArguments):
            document, refs, count, knowledge = self._projection_result(principal, arguments)
        elif isinstance(arguments, M8AgentKnowledgeArguments):
            document, refs, count, knowledge = self._knowledge_result(principal, arguments)
        else:
            raise M8AgentProviderError(M8AgentFailureCode.TOOL_ARGUMENT_INVALID)
        content = canonical_json(document)
        receipt = M8AgentToolReceiptV1(
            tool_call_id=sha256_hex(["m8-agent-tool-call", 1, tool_call_id]),
            tool_kind=kind,
            arguments_sha256=sha256_hex(arguments.model_dump(mode="json")),
            result_sha256=sha256_hex(document),
            source_refs=tuple(refs[:32]),
            result_count=count,
            knowledge_projection=knowledge,
        )
        return M8AgentToolExecution(receipt=receipt, model_content=content)

    def _cases(
        self,
        principal: M8ApiPrincipalV1,
        arguments: M8AgentReadCasesArguments,
    ) -> tuple[dict[str, object], list[str], int, None]:
        items = self._operations.cases(principal)
        if arguments.case_id is not None:
            items = tuple(item for item in items if item.case_id == arguments.case_id)
        if arguments.status is not None:
            items = tuple(item for item in items if item.status == arguments.status)
        if arguments.location_id is not None:
            items = tuple(
                item
                for item in items
                if item.audit_event.case_authority.location_id == arguments.location_id
            )
        selected = items[: arguments.limit]
        values = []
        refs: list[str] = []
        for item in selected:
            authority = item.audit_event.case_authority
            refs.extend((item.case_id, item.audit_event_id))
            values.append(
                {
                    "case_id": item.case_id,
                    "case_version": item.case_version,
                    "status": item.status.value,
                    "risk_level": authority.risk_level.value,
                    "location_id": authority.location_id,
                    "subject_actor_id": authority.subject_actor_id,
                    "source_ids": authority.source_ids,
                    "case_document_sha256": item.case_document_sha256,
                    "audit_event_id": item.audit_event_id,
                }
            )
        return (
            {
                "kind": "ROLE_SCOPED_CASES",
                "count": len(values),
                "cases": values,
                "write_permitted": False,
            },
            refs,
            len(values),
            None,
        )

    def _notifications_result(
        self,
        principal: M8ApiPrincipalV1,
        arguments: M8AgentReadNotificationsArguments,
    ) -> tuple[dict[str, object], list[str], int, None]:
        selected = self._notifications.notifications(principal)[: arguments.limit]
        values = []
        refs: list[str] = []
        for item in selected:
            plan = item.audit_event.notification_authority.plan
            refs.extend((item.notification_id, item.audit_event_id))
            values.append(
                {
                    "notification_id": item.notification_id,
                    "notification_version": item.notification_version,
                    "status": item.status.value,
                    "case_id": plan.case_id,
                    "channel": plan.target.channel.value,
                    "location_id": plan.location_id,
                    "audience": plan.audience.value,
                    "external_delivery_claim_permitted": plan.external_delivery_claim_permitted,
                    "audit_event_id": item.audit_event_id,
                }
            )
        return (
            {
                "kind": "ROLE_SCOPED_NOTIFICATIONS",
                "count": len(values),
                "notifications": values,
                "write_permitted": False,
            },
            refs,
            len(values),
            None,
        )

    def _projection_result(
        self,
        principal: M8ApiPrincipalV1,
        arguments: M8AgentReadProjectionArguments,
    ) -> tuple[dict[str, object], list[str], int, None]:
        view = self._projection.projection(principal, self._campus_id)
        projection = view.visible_projection
        sources = projection.sources
        if arguments.location_id is not None:
            sources = tuple(
                item for item in sources if item.source.location_id == arguments.location_id
            )
        if arguments.focus == M8AgentProjectionFocus.SENSORS:
            sources = tuple(item for item in sources if item.source.source_kind.value == "SENSOR")
        elif arguments.focus == M8AgentProjectionFocus.DEVICES:
            sources = tuple(item for item in sources if item.source.source_kind.value == "CAMERA")
        selected = sources[: arguments.limit]
        values = [
            {
                "source_id": item.source.source_id,
                "device_id": item.source.device_id,
                "location_id": item.source.location_id,
                "source_kind": item.source.source_kind.value,
                "mode": item.source.mode.value,
                "display_badge": item.display_badge,
                "observation_state": item.observation_state.value,
                "simulated": item.simulated,
                "live_observation_confirmed": item.live_observation_confirmed,
                "latest_sample": (
                    item.latest_sample_receipt.sample.model_dump(mode="json")
                    if item.latest_sample_receipt is not None
                    else None
                ),
            }
            for item in selected
        ]
        maps = []
        if arguments.focus in {M8AgentProjectionFocus.ALL, M8AgentProjectionFocus.MAP}:
            maps = [
                {
                    "location_id": node.location.location_id,
                    "name": node.location.display_name,
                    "kind": node.location.kind.value,
                    "parent_location_id": node.location.parent_location_id,
                    "source_ids": node.source_ids,
                    "current_case_ids": node.current_case_ids,
                }
                for node in projection.map_nodes[: arguments.limit]
                if arguments.location_id is None
                or node.location.location_id == arguments.location_id
            ]
        refs = [view.view_id, *(item.source.source_id for item in selected)]
        return (
            {
                "kind": "ROLE_SCOPED_OPERATIONS_PROJECTION",
                "view_kind": view.view_kind.value,
                "source_projection_id": view.source_projection_id,
                "requested_location_id": arguments.location_id,
                "location_filter_matched": (
                    arguments.location_id is None
                    or any(
                        node.location.location_id == arguments.location_id
                        for node in projection.map_nodes
                    )
                ),
                "overview_scope": "ROLE_SCOPED_CAMPUS",
                "overview": projection.overview.model_dump(mode="json"),
                "sources": values,
                "map_nodes": maps,
                "read_only": True,
            },
            refs,
            len(values) + len(maps),
            None,
        )

    def _knowledge_result(
        self,
        principal: M8ApiPrincipalV1,
        arguments: M8AgentKnowledgeArguments,
    ) -> tuple[dict[str, object], list[str], int, M8KnowledgeQueryProjectionV1]:
        projection = self._knowledge.query(
            principal,
            "campus-safety-knowledge",
            M8ApiKnowledgeQueryRequestV1(
                query_text=arguments.query,
                locale="zh-CN",
                as_of=self._clock(),
                allowed_document_types=tuple(
                    sorted(M8KnowledgeDocumentType, key=lambda item: item.value)
                ),
                max_citations=arguments.max_citations,
            ),
        )
        refs = [item.citation_id for item in projection.document_hits]
        refs.extend(item.case_id for item in projection.case_memory.entries)
        document: dict[str, object] = {
            "kind": "EXACT_KNOWLEDGE_PROJECTION",
            "outcome": projection.outcome.value,
            "answer": projection.answer_receipt.answer.answer_text,
            "normalized_intent": projection.normalized_intent.value,
            "applied_document_types": [item.value for item in projection.applied_document_types],
            "document_hits": [item.model_dump(mode="json") for item in projection.document_hits],
            "case_memory": projection.case_memory.model_dump(mode="json"),
            "exact_citations_only": True,
            "current_rule_rewrite_permitted": False,
        }
        return document, refs, len(refs), projection


__all__ = [
    "M8AgentKnowledgeArguments",
    "M8AgentProjectionFocus",
    "M8AgentReadCasesArguments",
    "M8AgentReadNotificationsArguments",
    "M8AgentReadProjectionArguments",
    "M8PlatformAgentToolService",
]
