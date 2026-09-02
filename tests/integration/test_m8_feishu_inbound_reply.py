from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_feishu_inbound_reply_repository import (
    SQLiteM8FeishuInboundReplyRepository,
)
from labcourt.adapters.storage.sqlite_m8_feishu_inbound_repository import (
    SQLiteM8FeishuInboundRepository,
)
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.contracts.m8_feishu_inbound import (
    M8FeishuInboundMessageVerificationReceiptV1,
    M8FeishuInboundWebhookProfileV1,
    M8FeishuWebhookIngressRequestV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind, M8NotificationStatus
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.services.m8_feishu_inbound_reply import M8FeishuInboundReplyService
from tests.contract.test_m8_feishu_inbound_reply_contracts import (
    _activation_status,
    _student_actor_receipt,
)
from tests.integration.test_m8_sqlite_notification_repository import (
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _create_command,
    _plan,
    _queue,
    _support,
)

BUSY_TIMEOUT_MS = 5_000
SEND_TIME = datetime(2026, 8, 11, 14, 0, tzinfo=UTC)
RECEIVED_AT = datetime(2026, 8, 11, 15, 0, tzinfo=UTC)
CARD_BYTES = b'{"type":"template","data":{"template_id":"sandbox-card"}}'
SEND_RESPONSE_BYTES = b'{"code":0,"data":{"message_id":"om_outbound_case_card_01"}}'
ENCRYPTED_BYTES = b'{"encrypt":"offline-fixture"}'
DECRYPTED_BYTES = b'{"schema":"2.0","event":"hash-only-fixture"}'
CONTENT_BYTES = '{"text":"我已补充实验室安全情况,请老师复核。"}'.encode()


class _ActivationRepository:
    def get_current_status(self, candidate_authority_id: str, assessed_at: datetime):
        status = _activation_status()
        assert (
            candidate_authority_id
            == status.activation_receipt.runtime_config.profile.candidate.candidate_authority_id
        )
        assert assessed_at == RECEIVED_AT + timedelta(seconds=2)
        return status


def _repositories(tmp_path: Path):
    database = tmp_path / "labcourt.sqlite3"
    operations = SQLiteM8OperationsRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_C)
    notifications = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    inbound = SQLiteM8FeishuInboundRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    replies = SQLiteM8FeishuInboundReplyRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    return database, operations, notifications, inbound, replies


def _sent_fixture(operations, notifications):
    status = _activation_status()
    binding = status.activation_receipt.runtime_config.recipient_allowlist[0]
    student = _student_actor_receipt().authority
    operations.publish_actor_authority(student, None)
    case = operations.create_operational_case(
        _create_command(),
        student.actor_id,
        SHA_D,
        SHA_E,
    )
    notifications.publish_target_authority(binding.target, None)
    planned = notifications.create_notification(_plan(case, binding.target), SHA_E)
    queued = notifications.transition_notification(_queue(planned), (), SHA_D, SHA_E)
    candidate = status.activation_receipt.runtime_config.profile.candidate
    capability = M8NotificationChannelCapabilityAuthorityV1(
        adapter_id=candidate.adapter_id,
        adapter_revision=candidate.adapter_revision,
        channel=M8NotificationChannelKind.FEISHU,
        request_timeout_ms=candidate.request_timeout_ms,
        network_required=True,
        offline_capable=False,
        simulated=False,
        inbound_response_supported=True,
        adapter_manifest_id=candidate.adapter_manifest_id,
    )
    request = M8NotificationDispatchRequestV1(
        plan=queued.audit_event.notification_authority.plan,
        source_notification_version=queued.notification_version,
        source_notification_authority_sha256=queued.notification_document_sha256,
        attempt_number=1,
        channel_capability=capability,
        rendered_card_ref="feishu-card-sandbox-reply-01",
        rendered_card_sha256=hashlib.sha256(CARD_BYTES).hexdigest(),
        dispatched_at=SEND_TIME,
        timeout_ms=candidate.request_timeout_ms,
        idempotency_key=queued.notification_id,
        request_manifest_id=SHA_D,
    )
    result = M8NotificationDispatchResultV1(
        request=request,
        disposition=M8NotificationDispatchDisposition.ACCEPTED,
        provider_receipt_id="om_outbound_case_card_01",
        raw_response_ref="feishu-send-response-reply-01",
        raw_response_sha256=hashlib.sha256(SEND_RESPONSE_BYTES).hexdigest(),
        completed_at=SEND_TIME + timedelta(seconds=1),
        result_manifest_id=SHA_E,
    )
    command = M8NotificationTransitionCommandV1(
        notification_id=queued.notification_id,
        source_notification_version=queued.notification_version,
        source_notification_authority_sha256=queued.notification_document_sha256,
        source_status=queued.status,
        action=M8NotificationAction.RECORD_SENT,
        initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
        dispatch_result=result,
        supporting_authorities=_support("feishu-sandbox-send-01"),
        explicit_human_confirmation=False,
        occurred_at=result.completed_at,
        command_manifest_id=SHA_E,
    )
    sent = notifications.transition_notification(
        command,
        (CARD_BYTES, SEND_RESPONSE_BYTES),
        SHA_D,
        SHA_E,
    )
    return case, binding, sent


def _inbound_fixture(inbound, binding):
    outbound_profile = _activation_status().activation_receipt.runtime_config.profile
    profile = M8FeishuInboundWebhookProfileV1(
        outbound_profile=outbound_profile,
        request_url_reference_id="feishu-inbound-url-sandbox-reply-01",
        encrypt_key_reference_id="secret-feishu-encrypt-key-reply-01",
        encrypt_key_sha256=SHA_A,
        verification_token_reference_id="secret-feishu-verification-token-reply-01",
        verification_token_sha256=SHA_B,
        profile_manifest_id=SHA_C,
    )
    ingress = M8FeishuWebhookIngressRequestV1(
        inbound_profile_id=profile.inbound_profile_id,
        request_timestamp_seconds=int(RECEIVED_AT.timestamp()),
        request_nonce="nonce-sandbox-reply-01",
        request_signature=SHA_C,
        encrypted_body_ref="feishu-encrypted-reply-01",
        encrypted_body_sha256=hashlib.sha256(ENCRYPTED_BYTES).hexdigest(),
        encrypted_body_size_bytes=len(ENCRYPTED_BYTES),
        received_at=RECEIVED_AT,
        ingress_manifest_id=SHA_D,
    )
    verification = M8FeishuInboundMessageVerificationReceiptV1(
        profile=profile,
        ingress_request=ingress,
        decrypted_event_ref="feishu-decrypted-reply-01",
        decrypted_event_sha256=hashlib.sha256(DECRYPTED_BYTES).hexdigest(),
        decrypted_event_size_bytes=len(DECRYPTED_BYTES),
        provider_event_id="event-sandbox-reply-01",
        provider_message_id="om_student_reply_01",
        provider_parent_message_id="om_outbound_case_card_01",
        provider_root_message_id="om_outbound_case_card_01",
        app_id_sha256=profile.outbound_profile.app_id_sha256,
        tenant_key_sha256=SHA_B,
        verification_token_sha256=profile.verification_token_sha256,
        sender_open_id_sha256=binding.receive_id_sha256,
        event_created_at=RECEIVED_AT - timedelta(seconds=1),
        message_created_at=RECEIVED_AT - timedelta(seconds=2),
        content_document_ref="feishu-text-content-reply-01",
        content_document_sha256=hashlib.sha256(CONTENT_BYTES).hexdigest(),
        content_size_bytes=len(CONTENT_BYTES),
        verification_manifest_id=SHA_E,
    )
    return inbound.commit_verification(
        verification,
        (ENCRYPTED_BYTES, DECRYPTED_BYTES, CONTENT_BYTES),
        SHA_A,
        RECEIVED_AT + timedelta(seconds=1),
        SHA_B,
    )


def _service(inbound, replies, operations):
    return M8FeishuInboundReplyService(
        inbound,
        replies,
        _ActivationRepository(),
        operations,
        lambda: RECEIVED_AT + timedelta(seconds=2),
        SHA_A,
        SHA_B,
        SHA_C,
        SHA_D,
        SHA_E,
    )


def test_verified_reply_atomically_transitions_notification_and_restarts(tmp_path: Path) -> None:
    database, operations, notifications, inbound, replies = _repositories(tmp_path)
    case, binding, sent = _sent_fixture(operations, notifications)
    inbound_commit = _inbound_fixture(inbound, binding)
    service = _service(inbound, replies, operations)

    committed = service.correlate_and_commit(inbound_commit.provider_message_id)

    assert committed.notification_commit.status == M8NotificationStatus.RESPONDED
    assert committed.correlation_authority.notification_commit_chain == (sent,)
    assert committed.correlation_authority.reply.reply_kind.value == "EXPLANATION"
    assert committed.correlation_authority.reply_kind_inferred is False
    assert committed.case_transition_permitted is False
    assert committed.direct_disciplinary_action_permitted is False
    assert notifications.get_current_notification(sent.notification_id) == (
        committed.notification_commit
    )
    assert (
        notifications.read_raw_artifact(committed.correlation_authority.reply.raw_reply_ref)
        == CONTENT_BYTES
    )
    assert operations.get_current_operational_case(case.case_id) == case
    assert service.correlate_and_commit(inbound_commit.provider_message_id) == committed

    reopened = SQLiteM8FeishuInboundReplyRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    assert (
        reopened.get_reply_by_provider_message_id(inbound_commit.provider_message_id) == committed
    )


class _TargetRaceRepository:
    def __init__(self, delegate, notifications):
        self.delegate = delegate
        self.notifications = notifications

    def get_notification_chain_by_provider_message_id(
        self,
        provider_message_id: str,
        adapter_id: str,
    ):
        return self.delegate.get_notification_chain_by_provider_message_id(
            provider_message_id,
            adapter_id,
        )

    def get_reply_by_provider_message_id(self, provider_message_id: str):
        return self.delegate.get_reply_by_provider_message_id(provider_message_id)

    def commit_reply(self, correlation_authority, *manifests):
        target = correlation_authority.current_target_receipt.target
        self.notifications.publish_target_authority(
            target.model_copy(update={"authority_revision": 2, "active": False}),
            1,
        )
        return self.delegate.commit_reply(correlation_authority, *manifests)


def test_current_target_change_fails_before_reply_append(tmp_path: Path) -> None:
    _database, operations, notifications, inbound, replies = _repositories(tmp_path)
    _case, binding, sent = _sent_fixture(operations, notifications)
    inbound_commit = _inbound_fixture(inbound, binding)
    racing = _TargetRaceRepository(replies, notifications)

    with pytest.raises(ConcurrentModification, match="target authority is stale"):
        _service(inbound, racing, operations).correlate_and_commit(
            inbound_commit.provider_message_id
        )

    assert notifications.get_current_notification(sent.notification_id) == sent
    with pytest.raises(EvidenceMissing):
        replies.get_reply_by_provider_message_id(inbound_commit.provider_message_id)


def test_reply_ledger_is_append_only(tmp_path: Path) -> None:
    database, operations, notifications, inbound, replies = _repositories(tmp_path)
    _case, binding, _sent = _sent_fixture(operations, notifications)
    inbound_commit = _inbound_fixture(inbound, binding)
    committed = _service(inbound, replies, operations).correlate_and_commit(
        inbound_commit.provider_message_id
    )

    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        connection.execute(
            "UPDATE m8_feishu_inbound_reply_commits SET reply_commit_manifest_id = ? "
            "WHERE commit_receipt_id = ?",
            (SHA_A, committed.commit_receipt_id),
        )
