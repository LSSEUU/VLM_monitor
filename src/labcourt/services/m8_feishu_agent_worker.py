"""Authority worker that continues the same Qwen Agent conversation from Feishu."""

# ruff: noqa: RUF001 - Chinese user-facing fallback copy uses full-width punctuation.

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_agent_chat import M8AgentTurnRequestV1
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_live import (
    M8FeishuAgentReplyEnvelopeV1,
    M8FeishuConversationChannelProjectionV1,
    M8FeishuInboundEventKind,
    M8FeishuInboundJobState,
    M8FeishuLiveFailureCode,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuTurnOrigin,
    M8FeishuWorkerState,
)
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.ports.m8_agent_chat import M8AgentProviderError
from labcourt.ports.m8_feishu_live import M8FeishuLiveRepository
from labcourt.services.m8_agent_chat import M8AgentChatService


@dataclass(frozen=True, slots=True)
class M8FeishuTrustedActorContext:
    principal: M8ApiPrincipalV1
    actor_authority: M8ActorAuthorityCommitReceiptV1
    recipient_binding: M8FeishuRecipientBindingAuthorityV1


class M8FeishuAgentAuthorityWorker:
    """Claim P2P jobs, invoke LIVE_ONLY Agent, and enqueue one final response."""

    def __init__(
        self,
        live: M8FeishuLiveRepository,
        agent: M8AgentChatService,
        actor_context: Callable[[str], M8FeishuTrustedActorContext],
        clock: Callable[[], datetime],
        repository_manifest_id: Sha256Hex,
        envelope_manifest_id: Sha256Hex,
        runtime_manifest_id: Sha256Hex,
    ) -> None:
        self._live = live
        self._agent = agent
        self._actor_context = actor_context
        self._clock = clock
        self._repository_manifest = repository_manifest_id
        self._envelope_manifest = envelope_manifest_id
        self._runtime_manifest = runtime_manifest_id

    def run_one(self) -> bool:
        job = self._live.claim_inbound()
        if job is None:
            self._heartbeat(M8FeishuWorkerState.READY)
            return False
        self._heartbeat(M8FeishuWorkerState.BUSY)
        event = job.inbound_event
        if event.event_kind != M8FeishuInboundEventKind.DIRECT_MESSAGE:
            self._fail_job(job, M8FeishuLiveFailureCode.INVALID_EVENT)
            self._heartbeat(M8FeishuWorkerState.READY)
            return True
        try:
            context = self._actor_context(event.sender_open_id_sha256)
            current = self._agent.actor_authority(context.principal)
            if current != context.actor_authority:
                raise ValueError("Feishu actor authority changed")
            if (
                context.recipient_binding.receive_id_sha256
                != event.sender_open_id_sha256
                or context.recipient_binding.target.actor_id != current.authority.actor_id
                or not context.recipient_binding.active
            ):
                raise ValueError("Feishu actor binding changed")
            projection = self._live.actor_channel_projection(current.authority.actor_id)
            if projection is None:
                summary = self._agent.create_conversation(context.principal)
                projection = self._live.bind_conversation(
                    M8FeishuConversationChannelProjectionV1(
                        conversation_id=summary.conversation_id,
                        actor_id=current.authority.actor_id,
                        binding_revision=context.recipient_binding.mapping_revision,
                        chat_id_sha256=event.chat_id_sha256,
                        bound_at=self._clock(),
                    )
                )
            elif projection.chat_id_sha256 != event.chat_id_sha256:
                raise ValueError("Feishu actor chat authority changed")
            content = self._live.read_inbound_content(event)
            if content is None:
                raise ValueError("Feishu direct message content is absent")
            query = content.decode("utf-8", errors="strict")
            try:
                completion = self._agent.complete_turn(
                    context.principal,
                    projection.conversation_id,
                    M8AgentTurnRequestV1(query=query),
                )
                turn_id = completion.turn_id
                reply = completion.answer
                failure = None
            except M8AgentProviderError:
                conversation = self._agent.conversation(
                    context.principal, projection.conversation_id
                )
                if not conversation.turns:
                    raise
                turn_id = conversation.turns[-1].turn_id
                reply = "Qwen 当前不可用，请稍后重试。"
                failure = M8FeishuLiveFailureCode.QWEN_UNAVAILABLE
            self._live.record_turn_origin(
                projection.conversation_id, turn_id, M8FeishuTurnOrigin.FEISHU
            )
            self._queue_reply(context, event.provider_message_id, projection, turn_id, reply)
            terminal = job.model_copy(
                update={
                    "state": (
                        M8FeishuInboundJobState.FAILED
                        if failure is not None
                        else M8FeishuInboundJobState.COMPLETED
                    ),
                    "state_revision": 3,
                    "actor_id": current.authority.actor_id,
                    "conversation_id": projection.conversation_id,
                    "turn_id": turn_id,
                    "failure_code": failure,
                    "occurred_at": self._clock(),
                }
            )
            self._live.commit_inbound_job(terminal)
            self._heartbeat(M8FeishuWorkerState.READY)
            return True
        except (UnicodeDecodeError, ValueError):
            self._fail_job(job, M8FeishuLiveFailureCode.ACTOR_NOT_BOUND)
            self._heartbeat(M8FeishuWorkerState.READY)
            return True

    def _queue_reply(
        self,
        context: M8FeishuTrustedActorContext,
        provider_message_id: str,
        projection: M8FeishuConversationChannelProjectionV1,
        turn_id: str,
        answer: str,
    ) -> None:
        raw = answer.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        envelope = M8FeishuAgentReplyEnvelopeV1(
            actor_id=context.actor_authority.authority.actor_id,
            conversation_id=projection.conversation_id,
            turn_id=turn_id,
            recipient_binding_authority_id=(
                context.recipient_binding.binding_authority_id
            ),
            reply_to_provider_message_id=provider_message_id,
            content_ref=f"feishu-agent-answer-{digest[:24]}",
            content_sha256=digest,
            content_size_bytes=len(raw),
            queued_at=self._clock(),
            envelope_manifest_id=self._envelope_manifest,
        )
        self._live.enqueue_agent_reply(envelope, raw)

    def _fail_job(self, job: object, failure: M8FeishuLiveFailureCode) -> None:
        from labcourt.contracts.m8_feishu_live import M8FeishuInboundJobV1

        if not isinstance(job, M8FeishuInboundJobV1):
            raise TypeError("M8 Feishu failure requires a typed inbound job")
        self._live.commit_inbound_job(
            job.model_copy(
                update={
                    "state": M8FeishuInboundJobState.FAILED,
                    "state_revision": 3,
                    "failure_code": failure,
                    "occurred_at": self._clock(),
                    "repository_manifest_id": self._repository_manifest,
                }
            )
        )

    def _heartbeat(self, state: M8FeishuWorkerState) -> None:
        self._live.record_heartbeat(
            M8FeishuRuntimeHeartbeatV1(
                component="AUTHORITY_WORKER",
                worker_state=state,
                observed_at=self._clock(),
                runtime_manifest_id=self._runtime_manifest,
            )
        )


__all__ = ["M8FeishuAgentAuthorityWorker", "M8FeishuTrustedActorContext"]
