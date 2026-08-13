"""Persistent, streaming, tool-grounded Agent orchestration for the M8 platform."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime
from typing import TypedDict

from labcourt.adapters.m8_qwen_agent import M8QwenAgentRuntime
from labcourt.contracts.canonical import canonical_bytes, sha256_hex
from labcourt.contracts.m8_agent_chat import (
    M8AgentConversationRemovalReceiptV1,
    M8AgentConversationSummaryV1,
    M8AgentConversationV1,
    M8AgentExecutionMode,
    M8AgentFailureCode,
    M8AgentModelAvailability,
    M8AgentModelCallReceiptV1,
    M8AgentModelStatusV1,
    M8AgentStreamEventKind,
    M8AgentStreamEventV1,
    M8AgentToolKind,
    M8AgentToolReceiptV1,
    M8AgentTurnCompletionV1,
    M8AgentTurnOutcome,
    M8AgentTurnRequestV1,
)
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_knowledge import M8KnowledgeAnswerOutcome
from labcourt.contracts.m8_platform_agent import (
    M8PlatformAgentIntentV2,
    M8PlatformAgentQueryResponseV2,
)
from labcourt.ports.m8_agent_chat import (
    M8AgentConversationRepository,
    M8AgentProviderDeltaKind,
    M8AgentProviderError,
    M8AgentProviderRequest,
    M8AgentToolExecutor,
)
from labcourt.services.m8_operations_api import M8OperationsApiService
from labcourt.services.m8_platform_agent import M8PlatformAgentIntentRouter

_SYSTEM_PROMPT = """你是 LabCourt 校园安全运营平台的对话助手。
你可以自然聊天, 但回答任何当前案件、通知、设备、传感器、地图或本地知识事实时必须调用提供的只读工具。
工具结果已经按当前登录角色裁剪; 不得要求或推断更高权限数据。
SOURCE_CATALOG_ONLY 只表示来源已登记, 不表示设备在线。模拟来源必须明确标注为模拟。
工具参数 location_id 只能填写稳定平台 ID。
只有中文位置名时应省略该参数, 再从 map_nodes 的名称与父级关系匹配。
overview_scope 为 ROLE_SCOPED_CAMPUS 时概览是角色可见的全局计数, 不得写成某个房间的计数。
location_filter_matched 为 false 时不得用全局概览代替该位置明细, 应省略位置过滤后重新查询。
知识工具返回 NO_MATCH 时必须明确说当前知识库没有匹配, 不得用模型常识补成制度或规则。
案例记忆不是当前规则, 机器弱标签不是事实。不得生成写操作或声称已经执行操作。
不要使用联网搜索、外部工具、代码执行或任何未列出的能力。回答简洁, 并让界面显示服务端提供的引用。"""

_ACTION_INTENTS = frozenset(
    {
        M8PlatformAgentIntentV2.CASE_TRANSITION_ACTION,
        M8PlatformAgentIntentV2.FEISHU_TEST_CARD_ACTION,
        M8PlatformAgentIntentV2.NOTIFICATION_SEND_ACTION,
        M8PlatformAgentIntentV2.RESET_ACTION,
        M8PlatformAgentIntentV2.SCENARIO_ACTION,
    }
)

_PLATFORM_QUERY_INTENTS = frozenset(
    {
        M8PlatformAgentIntentV2.CASE_QUERY,
        M8PlatformAgentIntentV2.DELIVERY_STATUS_QUERY,
        M8PlatformAgentIntentV2.DEVICE_QUERY,
        M8PlatformAgentIntentV2.FEISHU_STATUS_QUERY,
        M8PlatformAgentIntentV2.KNOWLEDGE_QUERY,
        M8PlatformAgentIntentV2.MAP_QUERY,
        M8PlatformAgentIntentV2.NOTIFICATION_QUERY,
        M8PlatformAgentIntentV2.SENSOR_QUERY,
    }
)

_REQUIRED_TOOL_BY_INTENT = {
    M8PlatformAgentIntentV2.CASE_QUERY: M8AgentToolKind.READ_CASES,
    M8PlatformAgentIntentV2.DELIVERY_STATUS_QUERY: M8AgentToolKind.READ_NOTIFICATIONS,
    M8PlatformAgentIntentV2.DEVICE_QUERY: M8AgentToolKind.READ_OPERATIONS_PROJECTION,
    M8PlatformAgentIntentV2.KNOWLEDGE_QUERY: M8AgentToolKind.QUERY_KNOWLEDGE,
    M8PlatformAgentIntentV2.MAP_QUERY: M8AgentToolKind.READ_OPERATIONS_PROJECTION,
    M8PlatformAgentIntentV2.NOTIFICATION_QUERY: M8AgentToolKind.READ_NOTIFICATIONS,
    M8PlatformAgentIntentV2.SENSOR_QUERY: M8AgentToolKind.READ_OPERATIONS_PROJECTION,
}


class _ToolCallBuffer:
    __slots__ = ("arguments", "call_id", "name")

    def __init__(self) -> None:
        self.call_id = ""
        self.name = ""
        self.arguments = ""

    def append(self, call_id: str, name: str, arguments: str) -> None:
        if call_id:
            if self.call_id and self.call_id != call_id:
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            self.call_id = call_id
        if name:
            if self.name and self.name != name:
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            self.name = name
        self.arguments += arguments
        if len(self.arguments.encode("utf-8")) > 16 * 1024:
            raise M8AgentProviderError(M8AgentFailureCode.TOOL_ARGUMENT_INVALID)

    def complete(self) -> tuple[str, str, str]:
        if not self.call_id or not self.name or not self.arguments:
            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
        return self.call_id, self.name, self.arguments


class _FunctionCall(TypedDict):
    name: str
    arguments: str


class _ToolCall(TypedDict):
    id: str
    type: str
    function: _FunctionCall


class M8AgentChatService:
    def __init__(
        self,
        operations: M8OperationsApiService,
        repository: M8AgentConversationRepository,
        tools: M8AgentToolExecutor,
        runtime: M8QwenAgentRuntime,
        deterministic_action_query: Callable[
            [M8ApiPrincipalV1, str], M8PlatformAgentQueryResponseV2
        ],
        clock: Callable[[], datetime],
    ) -> None:
        self._operations = operations
        self._repository = repository
        self._tools = tools
        self._runtime = runtime
        self._deterministic_action_query = deterministic_action_query
        self._clock = clock
        self._router = M8PlatformAgentIntentRouter()

    def status(self, principal: M8ApiPrincipalV1) -> M8AgentModelStatusV1:
        actor = self._operations.session(principal)
        last = self._repository.last_model_call(actor)
        configured = self._runtime.client is not None
        availability = (
            M8AgentModelAvailability.DEGRADED
            if self._runtime.configuration_failure is not None
            else M8AgentModelAvailability.DEGRADED
            if last is not None and not last.completed
            else M8AgentModelAvailability.AVAILABLE
            if last is not None and last.completed
            else M8AgentModelAvailability.CONFIGURED_NOT_PROBED
            if configured
            else M8AgentModelAvailability.NOT_CONFIGURED
        )
        return M8AgentModelStatusV1(
            availability=availability,
            default_execution_mode=M8AgentExecutionMode.LIVE_QWEN,
            provider=self._runtime.profile.provider,
            model=self._runtime.profile.model,
            revision=self._runtime.profile.revision,
            endpoint_env=self._runtime.profile.endpoint_env,
            api_key_env=self._runtime.profile.api_key_env,
            endpoint_configured=self._runtime.endpoint_configured,
            api_key_configured=self._runtime.api_key_configured,
            last_model_call_ref=last.model_call_id if last is not None else None,
            last_failure_code=(
                last.failure_code if last is not None else self._runtime.configuration_failure
            ),
        )

    def create_conversation(self, principal: M8ApiPrincipalV1) -> M8AgentConversationSummaryV1:
        return self._repository.create_conversation(self._operations.session(principal))

    def conversations(
        self, principal: M8ApiPrincipalV1
    ) -> tuple[M8AgentConversationSummaryV1, ...]:
        return self._repository.list_conversations(self._operations.session(principal))

    def conversation(
        self, principal: M8ApiPrincipalV1, conversation_id: str
    ) -> M8AgentConversationV1:
        return self._repository.get_conversation(
            self._operations.session(principal), conversation_id
        )

    def remove_conversation(
        self, principal: M8ApiPrincipalV1, conversation_id: str
    ) -> M8AgentConversationRemovalReceiptV1:
        return self._repository.remove_conversation(
            self._operations.session(principal), conversation_id
        )

    def complete_turn(
        self,
        principal: M8ApiPrincipalV1,
        conversation_id: str,
        request: M8AgentTurnRequestV1,
    ) -> M8AgentTurnCompletionV1:
        completion: M8AgentTurnCompletionV1 | None = None
        for event in self.stream_turn(principal, conversation_id, request):
            if event.completion is not None:
                completion = event.completion
            if event.failure_code is not None:
                raise M8AgentProviderError(event.failure_code)
        if completion is None:
            raise M8AgentProviderError(M8AgentFailureCode.STREAM_INTERRUPTED)
        return completion

    def stream_turn(
        self,
        principal: M8ApiPrincipalV1,
        conversation_id: str,
        request: M8AgentTurnRequestV1,
    ) -> Iterator[M8AgentStreamEventV1]:
        if not isinstance(request, M8AgentTurnRequestV1):
            raise TypeError("M8 Agent chat requires a typed turn request")
        query = request.query.strip()
        if query != request.query:
            request = M8AgentTurnRequestV1(query=query)
        actor = self._operations.session(principal)
        prior = self._repository.get_conversation(actor, conversation_id)
        turn = self._repository.begin_turn(actor, conversation_id, query)
        event_index = [1]
        yield M8AgentStreamEventV1(
            event_kind=M8AgentStreamEventKind.TURN_ACCEPTED,
            conversation_id=conversation_id,
            turn_id=turn.turn_id,
            event_index=event_index[0],
        )
        intent = self._router.classify(query)
        if intent in _ACTION_INTENTS:
            yield from self._deterministic_action_events(
                principal,
                actor,
                conversation_id,
                turn.turn_id,
                query,
                event_index,
            )
            return
        if self._runtime.client is None:
            failure_code = M8AgentFailureCode.NOT_CONFIGURED
            self._repository.fail_turn(
                actor,
                conversation_id,
                turn.turn_id,
                failure_code,
            )
            event_index[0] += 1
            yield M8AgentStreamEventV1(
                event_kind=M8AgentStreamEventKind.TURN_FAILED,
                conversation_id=conversation_id,
                turn_id=turn.turn_id,
                event_index=event_index[0],
                failure_code=failure_code,
            )
            return
        messages = self._messages(prior, query)
        schemas = self._tools.tool_schemas(actor)
        required_tool = _REQUIRED_TOOL_BY_INTENT.get(intent)
        required_tool_name = (
            None
            if required_tool is None
            else {
                M8AgentToolKind.READ_CASES: "read_cases",
                M8AgentToolKind.READ_NOTIFICATIONS: "read_notifications",
                M8AgentToolKind.READ_OPERATIONS_PROJECTION: "read_operations_projection",
                M8AgentToolKind.QUERY_KNOWLEDGE: "query_knowledge",
            }[required_tool]
        )
        if required_tool_name is not None and required_tool_name not in self._schema_tool_names(
            schemas
        ):
            failure_code = M8AgentFailureCode.TOOL_FORBIDDEN
            self._repository.fail_turn(
                actor,
                conversation_id,
                turn.turn_id,
                failure_code,
            )
            event_index[0] += 1
            yield M8AgentStreamEventV1(
                event_kind=M8AgentStreamEventKind.TURN_FAILED,
                conversation_id=conversation_id,
                turn_id=turn.turn_id,
                event_index=event_index[0],
                failure_code=failure_code,
            )
            return
        cache_key = sha256_hex(
            [
                "m8-agent-live-only-response-cache",
                1,
                actor.commit_receipt_id,
                turn.turn_id,
                self._runtime.profile.model_manifest_id,
                self._runtime.profile.prompt_manifest_id,
                self._runtime.profile.tool_schema_manifest_id,
                messages,
                schemas,
            ]
        )
        raw_responses: list[tuple[M8AgentModelCallReceiptV1, bytes]] = []
        try:
            yield from self._live_completion_events(
                principal,
                actor,
                conversation_id,
                turn.turn_id,
                intent,
                messages,
                schemas,
                cache_key,
                event_index,
                raw_responses,
            )
        except M8AgentProviderError as error:
            self._repository.fail_turn(
                actor,
                conversation_id,
                turn.turn_id,
                error.failure_code,
                tuple(raw_responses),
            )
            event_index[0] += 1
            yield M8AgentStreamEventV1(
                event_kind=M8AgentStreamEventKind.TURN_FAILED,
                conversation_id=conversation_id,
                turn_id=turn.turn_id,
                event_index=event_index[0],
                failure_code=error.failure_code,
            )

    def _live_completion_events(
        self,
        principal: M8ApiPrincipalV1,
        actor: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
        turn_id: str,
        intent: M8PlatformAgentIntentV2,
        messages: list[dict[str, object]],
        schemas: tuple[Mapping[str, object], ...],
        cache_key: str,
        event_index: list[int],
        raw_responses: list[tuple[M8AgentModelCallReceiptV1, bytes]],
    ) -> Iterator[M8AgentStreamEventV1]:
        tool_receipts: list[M8AgentToolReceiptV1] = []
        model_receipts: list[M8AgentModelCallReceiptV1] = []
        forced_tool_retry = False
        for round_index in range(1, self._runtime.profile.max_tool_rounds + 1):
            tool_choice = "required" if forced_tool_retry else "auto"
            body = self._request_body(messages, schemas, tool_choice)
            request = M8AgentProviderRequest(
                body=body,
                timeout_seconds=self._runtime.profile.timeout_seconds,
                max_response_bytes=self._runtime.profile.max_response_bytes,
            )
            model_call_id = sha256_hex(
                ["m8-agent-model-call", 1, turn_id, round_index, hashlib.sha256(body).hexdigest()]
            )
            raw_parts: list[bytes] = []
            text_parts: list[str] = []
            calls: dict[int, _ToolCallBuffer] = {}
            input_tokens = 0
            output_tokens = 0
            saw_usage = False
            client = self._runtime.client
            if client is None:
                raise M8AgentProviderError(M8AgentFailureCode.NOT_CONFIGURED)
            try:
                for delta in client.stream(request):
                    raw_parts.append(delta.raw_event)
                    if delta.kind == M8AgentProviderDeltaKind.TEXT:
                        text_parts.append(delta.text)
                    elif delta.kind == M8AgentProviderDeltaKind.TOOL:
                        if delta.tool_index is None:
                            raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
                        calls.setdefault(delta.tool_index, _ToolCallBuffer()).append(
                            delta.tool_call_id,
                            delta.tool_name,
                            delta.tool_arguments_delta,
                        )
                    elif delta.kind == M8AgentProviderDeltaKind.USAGE:
                        input_tokens = delta.input_tokens
                        output_tokens = delta.output_tokens
                        saw_usage = True
                if not saw_usage:
                    raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            except M8AgentProviderError as error:
                raw = b"".join(raw_parts)
                failure_receipt = M8AgentModelCallReceiptV1(
                    model_call_id=model_call_id,
                    round_index=round_index,
                    cache_key=cache_key,
                    provider_profile_id=self._runtime.profile.profile_id,
                    model_manifest_id=self._runtime.profile.model_manifest_id,
                    prompt_manifest_id=self._runtime.profile.prompt_manifest_id,
                    tool_schema_manifest_id=self._runtime.profile.tool_schema_manifest_id,
                    raw_response_ref=model_call_id,
                    raw_response_sha256=hashlib.sha256(raw).hexdigest(),
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cache_hit=False,
                    completed=False,
                    failure_code=error.failure_code,
                )
                raw_responses.append((failure_receipt, raw))
                raise
            raw = b"".join(raw_parts)
            receipt = M8AgentModelCallReceiptV1(
                model_call_id=model_call_id,
                round_index=round_index,
                cache_key=cache_key,
                provider_profile_id=self._runtime.profile.profile_id,
                model_manifest_id=self._runtime.profile.model_manifest_id,
                prompt_manifest_id=self._runtime.profile.prompt_manifest_id,
                tool_schema_manifest_id=self._runtime.profile.tool_schema_manifest_id,
                raw_response_ref=model_call_id,
                raw_response_sha256=hashlib.sha256(raw).hexdigest(),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_hit=False,
                completed=True,
            )
            model_receipts.append(receipt)
            raw_responses.append((receipt, raw))
            if calls:
                if len(calls) != 1:
                    raise M8AgentProviderError(M8AgentFailureCode.TOOL_FORBIDDEN)
                tool_preamble = "".join(text_parts).strip()
                tool_calls: list[_ToolCall] = []
                for call_index in sorted(calls):
                    call_id, name, arguments = calls[call_index].complete()
                    tool_calls.append(
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    )
                messages.append(
                    {
                        "role": "assistant",
                        "content": tool_preamble,
                        "tool_calls": tool_calls,
                    }
                )
                for call in tool_calls:
                    function = call["function"]
                    name = function["name"]
                    arguments = function["arguments"]
                    kind = self._tool_kind_for_name(str(name))
                    event_index[0] += 1
                    yield M8AgentStreamEventV1(
                        event_kind=M8AgentStreamEventKind.TOOL_STARTED,
                        conversation_id=conversation_id,
                        turn_id=turn_id,
                        event_index=event_index[0],
                        tool_kind=kind,
                        tool_call_id=sha256_hex(["m8-agent-tool-call", 1, call["id"]]),
                    )
                    execution = self._tools.execute(
                        principal,
                        actor,
                        str(call["id"]),
                        str(name),
                        str(arguments),
                    )
                    tool_receipts.append(execution.receipt)
                    event_index[0] += 1
                    yield M8AgentStreamEventV1(
                        event_kind=M8AgentStreamEventKind.TOOL_COMPLETED,
                        conversation_id=conversation_id,
                        turn_id=turn_id,
                        event_index=event_index[0],
                        tool_kind=execution.receipt.tool_kind,
                        tool_call_id=execution.receipt.tool_call_id,
                        source_refs=execution.receipt.source_refs,
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": execution.model_content,
                        }
                    )
                forced_tool_retry = False
                continue
            answer = "".join(text_parts).strip()
            if not answer:
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_INVALID)
            if len(answer) > 8_192:
                raise M8AgentProviderError(M8AgentFailureCode.RESPONSE_TOO_LARGE)
            required_tool = _REQUIRED_TOOL_BY_INTENT.get(intent)
            grounded = required_tool is None or any(
                item.tool_kind == required_tool for item in tool_receipts
            )
            if intent in _PLATFORM_QUERY_INTENTS and not grounded:
                if forced_tool_retry:
                    raise M8AgentProviderError(M8AgentFailureCode.TOOL_FORBIDDEN)
                forced_tool_retry = True
                continue
            knowledge = next(
                (
                    item.knowledge_projection
                    for item in reversed(tool_receipts)
                    if item.knowledge_projection is not None
                ),
                None,
            )
            outcome = M8AgentTurnOutcome.ANSWERED
            if knowledge is not None and knowledge.outcome == M8KnowledgeAnswerOutcome.NO_MATCH:
                outcome = M8AgentTurnOutcome.NO_MATCH
                answer = knowledge.answer_receipt.answer.answer_text
            refs = tuple(dict.fromkeys(ref for item in tool_receipts for ref in item.source_refs))[
                :32
            ]
            for chunk in self._chunks(answer):
                event_index[0] += 1
                yield M8AgentStreamEventV1(
                    event_kind=M8AgentStreamEventKind.MESSAGE_DELTA,
                    conversation_id=conversation_id,
                    turn_id=turn_id,
                    event_index=event_index[0],
                    text_delta=chunk,
                )
            completion = M8AgentTurnCompletionV1(
                conversation_id=conversation_id,
                turn_id=turn_id,
                outcome=outcome,
                execution_mode=M8AgentExecutionMode.LIVE_QWEN,
                answer=answer,
                source_refs=refs,
                tool_receipts=tuple(tool_receipts),
                model_call_receipts=tuple(model_receipts),
                knowledge_projection=knowledge,
                completed_at=self._clock(),
            )
            self._repository.complete_turn(
                actor,
                completion,
                tuple(raw_responses),
                cache_key,
            )
            event_index[0] += 1
            yield M8AgentStreamEventV1(
                event_kind=M8AgentStreamEventKind.MESSAGE_COMPLETED,
                conversation_id=conversation_id,
                turn_id=turn_id,
                event_index=event_index[0],
                completion=completion,
            )
            return
        raise M8AgentProviderError(M8AgentFailureCode.TOOL_LOOP_LIMIT)

    def _deterministic_action_events(
        self,
        principal: M8ApiPrincipalV1,
        actor: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
        turn_id: str,
        query: str,
        event_index: list[int],
    ) -> Iterator[M8AgentStreamEventV1]:
        response = self._deterministic_action_query(principal, query)
        outcome = (
            M8AgentTurnOutcome.ACTION_PROPOSED
            if response.proposed_action is not None
            else M8AgentTurnOutcome.NO_MATCH
            if response.outcome == "NO_MATCH"
            else M8AgentTurnOutcome.ANSWERED
        )
        completion = M8AgentTurnCompletionV1(
            conversation_id=conversation_id,
            turn_id=turn_id,
            outcome=outcome,
            execution_mode=M8AgentExecutionMode.DETERMINISTIC_ACTION,
            answer=response.answer,
            source_refs=response.source_refs,
            knowledge_projection=response.knowledge_projection,
            proposed_action=response.proposed_action,
            completed_at=self._clock(),
        )
        event_index[0] += 1
        yield M8AgentStreamEventV1(
            event_kind=M8AgentStreamEventKind.MESSAGE_DELTA,
            conversation_id=conversation_id,
            turn_id=turn_id,
            event_index=event_index[0],
            text_delta=response.answer,
        )
        self._repository.complete_turn(actor, completion, (), None)
        event_index[0] += 1
        yield M8AgentStreamEventV1(
            event_kind=M8AgentStreamEventKind.MESSAGE_COMPLETED,
            conversation_id=conversation_id,
            turn_id=turn_id,
            event_index=event_index[0],
            completion=completion,
        )

    def _messages(self, conversation: M8AgentConversationV1, query: str) -> list[dict[str, object]]:
        history: list[dict[str, object]] = []
        for turn in conversation.turns:
            if turn.completion is None:
                continue
            history.extend(
                (
                    {"role": "user", "content": turn.user_text},
                    {"role": "assistant", "content": turn.completion.answer},
                )
            )
        history = history[-self._runtime.profile.history_message_limit :]
        while history and len(canonical_bytes(history)) > self._runtime.profile.history_byte_limit:
            history = history[2:]
        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            *history,
            {"role": "user", "content": query},
        ]

    def _request_body(
        self,
        messages: list[dict[str, object]],
        schemas: tuple[Mapping[str, object], ...],
        tool_choice: str,
    ) -> bytes:
        return canonical_bytes(
            {
                "model": self._runtime.profile.model,
                "messages": messages,
                "tools": schemas,
                "tool_choice": tool_choice,
                "parallel_tool_calls": False,
                "stream": True,
                "stream_options": {"include_usage": True},
                "enable_thinking": False,
                "temperature": 0.2,
                "max_tokens": self._runtime.profile.max_output_tokens,
            }
        )

    @staticmethod
    def _tool_kind_for_name(name: str) -> M8AgentToolKind:
        try:
            return {
                "read_cases": M8AgentToolKind.READ_CASES,
                "read_notifications": M8AgentToolKind.READ_NOTIFICATIONS,
                "read_operations_projection": M8AgentToolKind.READ_OPERATIONS_PROJECTION,
                "query_knowledge": M8AgentToolKind.QUERY_KNOWLEDGE,
            }[name]
        except KeyError:
            raise M8AgentProviderError(M8AgentFailureCode.TOOL_FORBIDDEN) from None

    @staticmethod
    def _schema_tool_names(
        schemas: tuple[Mapping[str, object], ...],
    ) -> frozenset[str]:
        names: set[str] = set()
        for schema in schemas:
            function = schema.get("function")
            if not isinstance(function, Mapping):
                continue
            name = function.get("name")
            if isinstance(name, str):
                names.add(name)
        return frozenset(names)

    @staticmethod
    def _chunks(value: str, size: int = 96) -> Iterator[str]:
        for start in range(0, len(value), size):
            yield value[start : start + size]


__all__ = ["M8AgentChatService"]
