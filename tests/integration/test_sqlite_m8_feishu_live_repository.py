from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_feishu_live_repository import (
    SQLiteM8FeishuLiveRepository,
)
from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME
from labcourt.contracts.m8_access_cases import M8ActorRole, M8OperationalCaseAction
from labcourt.contracts.m8_feishu_live import (
    M8FeishuAgentReplyCompletionV1,
    M8FeishuAgentReplyEnvelopeV1,
    M8FeishuCardActionIntentV1,
    M8FeishuCardStage,
    M8FeishuDutyRouteV1,
    M8FeishuInboundEventKind,
    M8FeishuInboundEventV1,
    M8FeishuInboundJobState,
    M8FeishuLiveFailureCode,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuWorkerState,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition

NOW = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _repository(tmp_path: Path) -> SQLiteM8FeishuLiveRepository:
    return SQLiteM8FeishuLiveRepository.initialize(
        tmp_path / PLATFORM_DATABASE_NAME,
        busy_timeout_ms=2_000,
        repository_manifest_id=SHA_E,
        clock=lambda: NOW,
    )


def test_migration_and_repository_preserve_duty_runtime_and_inbound_dedup(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    route = M8FeishuDutyRouteV1(
        actor_id="safety-officer-demo",
        actor_role=M8ActorRole.SAFETY_OFFICER,
        actor_authority_commit_receipt_id=SHA_A,
        recipient_binding_authority_id=SHA_B,
        activation_revision=1,
        activation_status_id=SHA_C,
        route_revision=1,
        committed_at=NOW,
        repository_manifest_id=SHA_E,
    )
    assert repository.commit_duty_route(route) == route
    assert repository.current_duty_route() == route
    heartbeat = M8FeishuRuntimeHeartbeatV1(
        component="AUTHORITY_WORKER",
        worker_state=M8FeishuWorkerState.READY,
        observed_at=NOW,
        runtime_manifest_id=SHA_A,
    )
    repository.record_heartbeat(heartbeat)
    assert repository.latest_heartbeat("AUTHORITY_WORKER") == heartbeat

    raw = b'{"event_id":"event-live-01","sender":"redacted"}'
    content = "化学楼 301 有哪些设备?".encode()
    event = M8FeishuInboundEventV1(
        event_kind=M8FeishuInboundEventKind.DIRECT_MESSAGE,
        provider_event_id="event-live-01",
        provider_message_id="om-live-01",
        sender_open_id_sha256=SHA_A,
        chat_id_sha256=SHA_B,
        received_at=NOW,
        raw_event_ref="feishu-sanitized-event-01",
        raw_event_sha256=hashlib.sha256(raw).hexdigest(),
        content_ref="feishu-message-content-01",
        content_sha256=hashlib.sha256(content).hexdigest(),
        ingress_manifest_id=SHA_C,
    )
    first = repository.enqueue_inbound(event, raw, content)
    replay = repository.enqueue_inbound(event, raw, content)
    assert first.duplicate is False
    assert replay.duplicate is True
    assert repository.read_inbound_content(event) == content
    claimed = repository.claim_inbound()
    assert claimed is not None
    assert claimed.state == M8FeishuInboundJobState.CLAIMED
    completed = claimed.model_copy(
        update={
            "state": M8FeishuInboundJobState.COMPLETED,
            "state_revision": 3,
            "actor_id": "safety-officer-demo",
            "conversation_id": SHA_C,
            "turn_id": SHA_D,
        }
    )
    assert repository.commit_inbound_job(completed) == completed
    assert repository.claim_inbound() is None

    with sqlite3.connect(tmp_path / PLATFORM_DATABASE_NAME) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m8_feishu_live_inbound_events"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m8_feishu_inbound_job_events"
        ).fetchone() == (3,)


def test_confirmation_intent_and_agent_reply_are_single_use(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    intent = M8FeishuCardActionIntentV1(
        notification_id=SHA_A,
        notification_version=1,
        notification_authority_sha256=SHA_E,
        case_id=SHA_B,
        case_version=2,
        case_authority_sha256=SHA_C,
        actor_id="safety-officer-demo",
        action=M8OperationalCaseAction.CONFIRM,
        stage=M8FeishuCardStage.AWAITING_CONFIRMATION,
        confirmation_token_sha256=SHA_D,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        intent_manifest_id=SHA_A,
    )
    repository.commit_card_intent(intent)
    assert repository.card_intent_for_token(SHA_D) == intent

    content = "已根据平台可信工具完成查询。".encode()
    envelope = M8FeishuAgentReplyEnvelopeV1(
        actor_id="safety-officer-demo",
        conversation_id=SHA_A,
        turn_id=SHA_B,
        recipient_binding_authority_id=SHA_C,
        reply_to_provider_message_id="om-live-01",
        content_ref="feishu-agent-reply-content-01",
        content_sha256=hashlib.sha256(content).hexdigest(),
        content_size_bytes=len(content),
        queued_at=NOW,
        envelope_manifest_id=SHA_D,
    )
    repository.enqueue_agent_reply(envelope, content)
    claim = repository.claim_agent_reply(SHA_E)
    assert claim is not None
    assert repository.claim_agent_reply(SHA_E) is None
    raw_response = b'{"code":999,"msg":"timeout"}'
    completion = M8FeishuAgentReplyCompletionV1(
        envelope=envelope,
        disposition=M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
        failure_code=M8FeishuLiveFailureCode.SEND_UNCERTAIN,
        completed_at=NOW,
        raw_response_ref="feishu-agent-reply-response-01",
        raw_response_sha256=hashlib.sha256(raw_response).hexdigest(),
        completion_manifest_id=SHA_A,
    )
    assert repository.complete_agent_reply(claim, completion, raw_response) == completion
    assert repository.claim_agent_reply(SHA_E) is None
