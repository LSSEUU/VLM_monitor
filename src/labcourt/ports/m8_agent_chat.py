"""Ports for persistent Agent chat and bounded Qwen model streaming."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m8_agent_chat import (
    M8AgentConversationRemovalReceiptV1,
    M8AgentConversationSummaryV1,
    M8AgentConversationTurnV1,
    M8AgentConversationV1,
    M8AgentFailureCode,
    M8AgentModelCallReceiptV1,
    M8AgentToolReceiptV1,
    M8AgentTurnCompletionV1,
)
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1


class M8AgentProviderDeltaKind(StrEnum):
    TEXT = "TEXT"
    TOOL = "TOOL"
    USAGE = "USAGE"
    DONE = "DONE"
    RAW = "RAW"


@dataclass(frozen=True, slots=True)
class M8AgentProviderDelta:
    kind: M8AgentProviderDeltaKind
    raw_event: bytes = field(repr=False)
    text: str = ""
    tool_index: int | None = None
    tool_call_id: str = ""
    tool_name: str = ""
    tool_arguments_delta: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(frozen=True, slots=True, repr=False)
class M8AgentProviderRequest:
    body: bytes = field(repr=False)
    timeout_seconds: float
    max_response_bytes: int


@dataclass(frozen=True, slots=True)
class M8AgentToolExecution:
    receipt: M8AgentToolReceiptV1
    model_content: str


class M8AgentProviderError(Exception):
    def __init__(self, failure_code: M8AgentFailureCode) -> None:
        self.failure_code = failure_code
        super().__init__(f"M8 Agent provider failed: {failure_code.value}")


class M8AgentModelClient(Protocol):
    def stream(self, request: M8AgentProviderRequest) -> Iterator[M8AgentProviderDelta]: ...


class M8AgentConversationRepositoryError(Exception):
    def __init__(self, failure_code: M8AgentFailureCode) -> None:
        self.failure_code = failure_code
        super().__init__(f"M8 Agent conversation repository failed: {failure_code.value}")


class M8AgentConversationRepository(Protocol):
    def create_conversation(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> M8AgentConversationSummaryV1: ...

    def list_conversations(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> tuple[M8AgentConversationSummaryV1, ...]: ...

    def get_conversation(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
    ) -> M8AgentConversationV1: ...

    def remove_conversation(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
    ) -> M8AgentConversationRemovalReceiptV1: ...

    def begin_turn(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
        query: str,
    ) -> M8AgentConversationTurnV1: ...

    def complete_turn(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        completion: M8AgentTurnCompletionV1,
        raw_responses: tuple[tuple[M8AgentModelCallReceiptV1, bytes], ...],
        cache_key: str | None,
    ) -> M8AgentConversationTurnV1: ...

    def fail_turn(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
        turn_id: str,
        failure_code: M8AgentFailureCode,
        raw_responses: tuple[tuple[M8AgentModelCallReceiptV1, bytes], ...] = (),
    ) -> M8AgentConversationTurnV1: ...

    def read_cache(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        cache_key: str,
    ) -> M8AgentTurnCompletionV1 | None: ...

    def last_model_call(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> M8AgentModelCallReceiptV1 | None: ...


class M8AgentToolExecutor(Protocol):
    def tool_schemas(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> tuple[Mapping[str, object], ...]: ...

    def execute(
        self,
        principal: M8ApiPrincipalV1,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        tool_call_id: str,
        tool_name: str,
        arguments_json: str,
    ) -> M8AgentToolExecution: ...


__all__ = [
    "M8AgentConversationRepository",
    "M8AgentConversationRepositoryError",
    "M8AgentModelClient",
    "M8AgentProviderDelta",
    "M8AgentProviderDeltaKind",
    "M8AgentProviderError",
    "M8AgentProviderRequest",
    "M8AgentToolExecution",
    "M8AgentToolExecutor",
]
