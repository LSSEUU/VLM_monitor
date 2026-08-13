"""Typed V3 contracts for persistent, tool-grounded platform Agent chat."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_knowledge_projection import M8KnowledgeQueryProjectionV1
from labcourt.contracts.m8_platform_agent import M8PlatformProposedActionV2
from labcourt.contracts.references import ReferenceToken


class M8AgentExecutionMode(StrEnum):
    LIVE_QWEN = "LIVE_QWEN"
    CACHE_REPLAY = "CACHE_REPLAY"
    OFFLINE_FALLBACK = "OFFLINE_FALLBACK"
    DETERMINISTIC_ACTION = "DETERMINISTIC_ACTION"


class M8AgentTurnOutcome(StrEnum):
    ANSWERED = "ANSWERED"
    NO_MATCH = "NO_MATCH"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    FAILED = "FAILED"


class M8AgentFailureCode(StrEnum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
    PROVIDER_REJECTED = "PROVIDER_REJECTED"
    RESPONSE_INVALID = "RESPONSE_INVALID"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    TOOL_ARGUMENT_INVALID = "TOOL_ARGUMENT_INVALID"
    TOOL_FORBIDDEN = "TOOL_FORBIDDEN"
    TOOL_LOOP_LIMIT = "TOOL_LOOP_LIMIT"
    STREAM_INTERRUPTED = "STREAM_INTERRUPTED"
    AUTHORITY_CHANGED = "AUTHORITY_CHANGED"
    CONVERSATION_NOT_FOUND = "CONVERSATION_NOT_FOUND"


class M8AgentModelAvailability(StrEnum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED_NOT_PROBED = "CONFIGURED_NOT_PROBED"
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"


class M8AgentToolKind(StrEnum):
    READ_CASES = "READ_CASES"
    READ_NOTIFICATIONS = "READ_NOTIFICATIONS"
    READ_OPERATIONS_PROJECTION = "READ_OPERATIONS_PROJECTION"
    QUERY_KNOWLEDGE = "QUERY_KNOWLEDGE"


class M8AgentStreamEventKind(StrEnum):
    TURN_ACCEPTED = "turn.accepted"
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    MESSAGE_DELTA = "message.delta"
    MESSAGE_COMPLETED = "message.completed"
    TURN_FAILED = "turn.failed"


class M8AgentTurnState(StrEnum):
    ACCEPTED = "ACCEPTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class M8AgentModelProfileV1(FrozenContractModel):
    schema_version: Literal["m8-agent-model-profile-v1"] = "m8-agent-model-profile-v1"
    profile_id: ReferenceToken
    provider: Literal["alibaba-cloud-model-studio"] = "alibaba-cloud-model-studio"
    protocol: Literal["OPENAI_COMPATIBLE_CHAT_COMPLETIONS"] = "OPENAI_COMPATIBLE_CHAT_COMPLETIONS"
    model: Literal["qwen3.7-plus-2026-05-26"] = "qwen3.7-plus-2026-05-26"
    revision: Literal["2026-05-26"] = "2026-05-26"
    endpoint_env: Literal["LABCOURT_QWEN_ENDPOINT"] = "LABCOURT_QWEN_ENDPOINT"
    api_key_env: Literal["LABCOURT_QWEN_API_KEY"] = "LABCOURT_QWEN_API_KEY"
    timeout_seconds: float = Field(default=45.0, ge=1.0, le=120.0)
    max_output_tokens: int = Field(default=2_048, ge=1, le=8_192, strict=True)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1_024, le=8 * 1024 * 1024)
    max_tool_rounds: int = Field(default=4, ge=1, le=4, strict=True)
    history_message_limit: int = Field(default=20, ge=2, le=40, strict=True)
    history_byte_limit: int = Field(default=64 * 1024, ge=1_024, le=256 * 1024)
    cache_enabled: Literal[True] = True
    enable_thinking: Literal[False] = False
    parallel_tool_calls: Literal[False] = False
    prompt_manifest_id: Sha256Hex
    tool_schema_manifest_id: Sha256Hex
    model_manifest_id: Sha256Hex


class M8AgentModelStatusV1(FrozenContractModel):
    schema_version: Literal["m8-agent-model-status-v1"] = "m8-agent-model-status-v1"
    availability: M8AgentModelAvailability
    default_execution_mode: Literal[
        M8AgentExecutionMode.LIVE_QWEN, M8AgentExecutionMode.OFFLINE_FALLBACK
    ]
    provider: str
    model: str
    revision: str
    endpoint_env: str
    api_key_env: str
    endpoint_configured: bool
    api_key_configured: bool
    secret_exposed: Literal[False] = False
    network_call_at_startup: Literal[False] = False
    last_model_call_ref: ReferenceToken | None = None
    last_failure_code: M8AgentFailureCode | None = None


class M8AgentConversationCreateRequestV1(FrozenContractModel):
    schema_version: Literal["m8-agent-conversation-create-request-v1"] = (
        "m8-agent-conversation-create-request-v1"
    )


class M8AgentConversationSummaryV1(FrozenContractModel):
    schema_version: Literal["m8-agent-conversation-summary-v1"] = "m8-agent-conversation-summary-v1"
    conversation_id: ReferenceToken
    actor_id: ReferenceToken
    actor_role: M8ActorRole
    actor_authority_commit_receipt_id: Sha256Hex
    created_at: datetime
    title: str = Field(min_length=1, max_length=80)
    turn_count: int = Field(ge=0, strict=True)
    latest_activity_at: datetime
    sealed: bool


class M8AgentTurnRequestV1(FrozenContractModel):
    schema_version: Literal["m8-agent-turn-request-v1"] = "m8-agent-turn-request-v1"
    query: str = Field(min_length=1, max_length=4_096)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Agent query must contain non-whitespace text")
        return value


class M8AgentToolReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-agent-tool-receipt-v1"] = "m8-agent-tool-receipt-v1"
    tool_call_id: ReferenceToken
    tool_kind: M8AgentToolKind
    arguments_sha256: Sha256Hex
    result_sha256: Sha256Hex
    source_refs: tuple[ReferenceToken, ...] = Field(default=(), max_length=32)
    result_count: int = Field(ge=0, strict=True)
    knowledge_projection: M8KnowledgeQueryProjectionV1 | None = None


class M8AgentModelCallReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-agent-model-call-receipt-v1"] = "m8-agent-model-call-receipt-v1"
    model_call_id: ReferenceToken
    round_index: int = Field(ge=1, le=4, strict=True)
    cache_key: Sha256Hex
    provider_profile_id: ReferenceToken
    model_manifest_id: Sha256Hex
    prompt_manifest_id: Sha256Hex
    tool_schema_manifest_id: Sha256Hex
    raw_response_ref: ReferenceToken
    raw_response_sha256: Sha256Hex
    input_tokens: int = Field(ge=0, strict=True)
    output_tokens: int = Field(ge=0, strict=True)
    cache_hit: bool
    completed: bool
    failure_code: M8AgentFailureCode | None = None

    @model_validator(mode="after")
    def validate_failure(self) -> Self:
        if self.completed == (self.failure_code is not None):
            raise ValueError("completed model call must not have a failure code")
        return self


class M8AgentTurnCompletionV1(FrozenContractModel):
    schema_version: Literal["m8-agent-turn-completion-v1"] = "m8-agent-turn-completion-v1"
    conversation_id: ReferenceToken
    turn_id: ReferenceToken
    outcome: M8AgentTurnOutcome
    execution_mode: M8AgentExecutionMode
    answer: str = Field(min_length=1, max_length=8_192)
    source_refs: tuple[ReferenceToken, ...] = Field(default=(), max_length=32)
    tool_receipts: tuple[M8AgentToolReceiptV1, ...] = Field(default=(), max_length=16)
    model_call_receipts: tuple[M8AgentModelCallReceiptV1, ...] = Field(default=(), max_length=4)
    knowledge_projection: M8KnowledgeQueryProjectionV1 | None = None
    proposed_action: M8PlatformProposedActionV2 | None = None
    completed_at: datetime
    direct_execution_permitted: Literal[False] = False

    @model_validator(mode="after")
    def validate_mode(self) -> Self:
        if self.outcome == M8AgentTurnOutcome.ACTION_PROPOSED:
            if self.proposed_action is None or self.execution_mode != (
                M8AgentExecutionMode.DETERMINISTIC_ACTION
            ):
                raise ValueError("action outcome requires a deterministic proposed action")
        elif self.proposed_action is not None:
            raise ValueError("non-action outcome cannot contain a proposed action")
        if self.execution_mode == M8AgentExecutionMode.LIVE_QWEN and not (self.model_call_receipts):
            raise ValueError("live Qwen completion requires model call receipts")
        return self


class M8AgentConversationTurnV1(FrozenContractModel):
    schema_version: Literal["m8-agent-conversation-turn-v1"] = "m8-agent-conversation-turn-v1"
    turn_id: ReferenceToken
    user_text: str = Field(min_length=1, max_length=4_096)
    submitted_at: datetime
    state: M8AgentTurnState
    completion: M8AgentTurnCompletionV1 | None = None
    failure_code: M8AgentFailureCode | None = None

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        if self.state == M8AgentTurnState.ACCEPTED:
            if self.completion is not None or self.failure_code is not None:
                raise ValueError("accepted turn cannot contain a terminal result")
        elif self.state == M8AgentTurnState.COMPLETED:
            if self.completion is None or self.failure_code is not None:
                raise ValueError("completed turn requires exactly one completion")
        elif self.completion is not None or self.failure_code is None:
            raise ValueError("failed turn requires exactly one failure code")
        return self


class M8AgentConversationV1(FrozenContractModel):
    schema_version: Literal["m8-agent-conversation-v1"] = "m8-agent-conversation-v1"
    summary: M8AgentConversationSummaryV1
    turns: tuple[M8AgentConversationTurnV1, ...] = Field(default=(), max_length=200)


class M8AgentStreamEventV1(FrozenContractModel):
    schema_version: Literal["m8-agent-stream-event-v1"] = "m8-agent-stream-event-v1"
    event_kind: M8AgentStreamEventKind
    conversation_id: ReferenceToken
    turn_id: ReferenceToken
    event_index: int = Field(ge=1, strict=True)
    text_delta: str | None = Field(default=None, min_length=1, max_length=8_192)
    tool_kind: M8AgentToolKind | None = None
    tool_call_id: ReferenceToken | None = None
    source_refs: tuple[ReferenceToken, ...] = Field(default=(), max_length=32)
    completion: M8AgentTurnCompletionV1 | None = None
    failure_code: M8AgentFailureCode | None = None

    @model_validator(mode="after")
    def validate_event_shape(self) -> Self:
        if self.event_kind == M8AgentStreamEventKind.MESSAGE_DELTA:
            if self.text_delta is None:
                raise ValueError("message delta event requires text")
        elif self.text_delta is not None:
            raise ValueError("only message delta events can contain text")
        if self.event_kind in {
            M8AgentStreamEventKind.TOOL_STARTED,
            M8AgentStreamEventKind.TOOL_COMPLETED,
        }:
            if self.tool_kind is None or self.tool_call_id is None:
                raise ValueError("tool events require a closed tool kind and call id")
        elif self.tool_kind is not None or self.tool_call_id is not None:
            raise ValueError("non-tool event cannot contain tool fields")
        if self.event_kind == M8AgentStreamEventKind.MESSAGE_COMPLETED:
            if self.completion is None:
                raise ValueError("message completed event requires completion")
        elif self.completion is not None:
            raise ValueError("only message completed events contain completion")
        if self.event_kind == M8AgentStreamEventKind.TURN_FAILED:
            if self.failure_code is None:
                raise ValueError("turn failed event requires failure code")
        elif self.failure_code is not None:
            raise ValueError("only failed events contain a failure code")
        return self


__all__ = [
    "M8AgentConversationCreateRequestV1",
    "M8AgentConversationSummaryV1",
    "M8AgentConversationTurnV1",
    "M8AgentConversationV1",
    "M8AgentExecutionMode",
    "M8AgentFailureCode",
    "M8AgentModelAvailability",
    "M8AgentModelCallReceiptV1",
    "M8AgentModelProfileV1",
    "M8AgentModelStatusV1",
    "M8AgentStreamEventKind",
    "M8AgentStreamEventV1",
    "M8AgentToolKind",
    "M8AgentToolReceiptV1",
    "M8AgentTurnCompletionV1",
    "M8AgentTurnOutcome",
    "M8AgentTurnRequestV1",
    "M8AgentTurnState",
]
