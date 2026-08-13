"""Ports for Feishu live ingress, workers, cards, and Agent replies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from labcourt.contracts.m8_feishu_live import (
    M8FeishuAgentReplyCompletionV1,
    M8FeishuAgentReplyEnvelopeV1,
    M8FeishuAlertBridgeReceiptV1,
    M8FeishuCardActionIntentV1,
    M8FeishuCardActionReceiptV1,
    M8FeishuConversationChannelProjectionV1,
    M8FeishuDutyRouteV1,
    M8FeishuInboundEventV1,
    M8FeishuInboundJobV1,
    M8FeishuReminderReceiptV1,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuTurnOrigin,
)


class M8FeishuLiveRepositoryError(RuntimeError):
    """Raised when immutable live authority cannot be committed safely."""


@dataclass(frozen=True, slots=True)
class M8FeishuInboundEnqueueResult:
    job: M8FeishuInboundJobV1
    duplicate: bool


@dataclass(frozen=True, slots=True)
class M8FeishuAgentReplyClaim:
    envelope: M8FeishuAgentReplyEnvelopeV1
    content: bytes
    worker_token_sha256: str
    claim_fence: int


class M8FeishuLiveRepository(Protocol):
    def commit_duty_route(self, route: M8FeishuDutyRouteV1) -> M8FeishuDutyRouteV1: ...

    def current_duty_route(self) -> M8FeishuDutyRouteV1 | None: ...

    def record_heartbeat(
        self, heartbeat: M8FeishuRuntimeHeartbeatV1
    ) -> M8FeishuRuntimeHeartbeatV1: ...

    def latest_heartbeat(self, component: str) -> M8FeishuRuntimeHeartbeatV1 | None: ...

    def enqueue_inbound(
        self,
        event: M8FeishuInboundEventV1,
        sanitized_event: bytes,
        message_content: bytes | None,
    ) -> M8FeishuInboundEnqueueResult: ...

    def claim_inbound(self, inbound_event_id: str | None = None) -> M8FeishuInboundJobV1 | None: ...

    def inbound_job(self, inbound_event_id: str) -> M8FeishuInboundJobV1 | None: ...

    def commit_inbound_job(self, job: M8FeishuInboundJobV1) -> M8FeishuInboundJobV1: ...

    def read_inbound_content(self, event: M8FeishuInboundEventV1) -> bytes | None: ...

    def bind_conversation(
        self, projection: M8FeishuConversationChannelProjectionV1
    ) -> M8FeishuConversationChannelProjectionV1: ...

    def channel_projection(
        self, conversation_id: str
    ) -> M8FeishuConversationChannelProjectionV1 | None: ...

    def actor_channel_projection(
        self, actor_id: str
    ) -> M8FeishuConversationChannelProjectionV1 | None: ...

    def record_turn_origin(
        self,
        conversation_id: str,
        turn_id: str,
        origin: M8FeishuTurnOrigin,
    ) -> None: ...

    def commit_card_intent(
        self, intent: M8FeishuCardActionIntentV1
    ) -> M8FeishuCardActionIntentV1: ...

    def card_intent_for_token(self, token_sha256: str) -> M8FeishuCardActionIntentV1 | None: ...

    def commit_card_receipt(
        self, receipt: M8FeishuCardActionReceiptV1
    ) -> M8FeishuCardActionReceiptV1: ...

    def card_receipt(self, intent_id: str) -> M8FeishuCardActionReceiptV1 | None: ...

    def commit_alert_bridge(
        self, receipt: M8FeishuAlertBridgeReceiptV1
    ) -> M8FeishuAlertBridgeReceiptV1: ...

    def alert_bridge(
        self, case_id: str, case_version: int
    ) -> M8FeishuAlertBridgeReceiptV1 | None: ...

    def commit_reminder(
        self, receipt: M8FeishuReminderReceiptV1
    ) -> M8FeishuReminderReceiptV1: ...

    def reminder(self, dispatch_request_id: str) -> M8FeishuReminderReceiptV1 | None: ...

    def enqueue_agent_reply(
        self, envelope: M8FeishuAgentReplyEnvelopeV1, content: bytes
    ) -> M8FeishuAgentReplyEnvelopeV1: ...

    def claim_agent_reply(self, worker_token_sha256: str) -> M8FeishuAgentReplyClaim | None: ...

    def complete_agent_reply(
        self,
        claim: M8FeishuAgentReplyClaim,
        completion: M8FeishuAgentReplyCompletionV1,
        raw_response: bytes,
    ) -> M8FeishuAgentReplyCompletionV1: ...


__all__ = [
    "M8FeishuAgentReplyClaim",
    "M8FeishuInboundEnqueueResult",
    "M8FeishuLiveRepository",
    "M8FeishuLiveRepositoryError",
]
