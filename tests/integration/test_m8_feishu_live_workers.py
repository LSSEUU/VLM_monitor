from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_feishu_live_repository import (
    SQLiteM8FeishuLiveRepository,
)
from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_live import (
    M8FeishuAgentReplyEnvelopeV1,
    M8FeishuLiveFailureCode,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.ports.m8_feishu_http import (
    M8FeishuHttpCallStage,
    M8FeishuHttpDeliveryCertainty,
    M8FeishuHttpError,
    M8FeishuHttpFailureCode,
    M8FeishuHttpResponse,
)
from labcourt.services.m8_feishu_agent_reply_delivery import (
    M8FeishuAgentReplyDeliveryWorker,
)
from labcourt.services.m8_feishu_live_ingress import (
    M8FeishuLiveIngressService,
    M8FeishuP2PTextIngress,
)
from tests.contract.test_m8_feishu_notification_contracts import _preflight
from tests.contract.test_m8_feishu_transport_contracts import _activation_status
from tests.unit.test_m8_feishu_sandbox_transport import (
    _ActivationRepository,
    _SecretResolver,
)

NOW = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


def _repository(tmp_path: Path) -> SQLiteM8FeishuLiveRepository:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return SQLiteM8FeishuLiveRepository.initialize(
        tmp_path / PLATFORM_DATABASE_NAME,
        2_000,
        SHA_E,
        lambda: NOW,
    )


class _ReplyHttp:
    def __init__(self, *, timeout: bool = False) -> None:
        self.timeout = timeout
        self.message_calls = 0

    def acquire_tenant_access_token(self, _profile, _secrets) -> M8FeishuHttpResponse:
        return M8FeishuHttpResponse(
            200,
            (
                canonical_json(
                    {
                        "code": 0,
                        "expire": 7_200,
                        "msg": "success",
                        "tenant_access_token": "fake-tenant-token",
                    }
                )
                + "\n"
            ).encode(),
            "token-log-01",
        )

    def send_text_reply(
        self,
        _profile,
        _tenant_access_token: bytes,
        _reply_to_provider_message_id: str,
        _provider_uuid: str,
        _text: str,
        _timeout_ms: int,
    ) -> M8FeishuHttpResponse:
        self.message_calls += 1
        if self.timeout:
            raise M8FeishuHttpError(
                M8FeishuHttpCallStage.MESSAGE,
                M8FeishuHttpFailureCode.TIMEOUT,
                M8FeishuHttpDeliveryCertainty.UNKNOWN,
            )
        return M8FeishuHttpResponse(
            200,
            b'{"code":0,"data":{"message_id":"om-reply-01"},"msg":"success"}',
            "message-log-01",
        )


def _enqueue_reply(repository: SQLiteM8FeishuLiveRepository) -> None:
    content = "已根据平台可信工具完成查询。".encode()
    binding = _preflight().recipient_binding
    envelope = M8FeishuAgentReplyEnvelopeV1(
        actor_id="safety-officer-demo",
        conversation_id=SHA_A,
        turn_id=SHA_B,
        recipient_binding_authority_id=binding.binding_authority_id,
        reply_to_provider_message_id="om-inbound-01",
        content_ref="feishu-agent-reply-content-01",
        content_sha256=hashlib.sha256(content).hexdigest(),
        content_size_bytes=len(content),
        queued_at=NOW,
        envelope_manifest_id=SHA_D,
    )
    repository.enqueue_agent_reply(envelope, content)


def test_ingress_accepts_only_p2p_text_and_deduplicates_provider_event(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    service = M8FeishuLiveIngressService(repository, SHA_A)
    request = M8FeishuP2PTextIngress(
        provider_event_id="event-p2p-01",
        provider_message_id="om-p2p-01",
        sender_open_id="ou-clear-never-persisted",
        chat_id="oc-clear-never-persisted",
        chat_type="p2p",
        sender_type="user",
        message_type="text",
        text="查看当前待核实案件",
        received_at=NOW,
    )
    first = service.accept_text(request)
    replay = service.accept_text(request)
    assert first.duplicate is False
    assert replay.duplicate is True
    assert repository.read_inbound_content(first.job.inbound_event) == request.text.encode()
    assert first.job.inbound_event.clear_sender_identifier_persisted is False


def test_agent_reply_is_accepted_once_or_unknown_without_retry(tmp_path: Path) -> None:
    preflight = _preflight()
    binding = preflight.recipient_binding

    accepted_repository = _repository(tmp_path / "accepted")
    _enqueue_reply(accepted_repository)
    accepted_http = _ReplyHttp()
    accepted_worker = M8FeishuAgentReplyDeliveryWorker(
        accepted_repository,
        _ActivationRepository(_activation_status()),
        _SecretResolver(),
        accepted_http,
        preflight.profile,
        lambda _binding_id: binding,
        lambda: NOW,
        SHA_A,
    )
    accepted = accepted_worker.run_one(b"w" * 32)
    assert accepted is not None
    assert accepted.disposition == M8NotificationDispatchDisposition.ACCEPTED
    assert accepted.provider_message_id == "om-reply-01"
    assert accepted_worker.run_one(b"w" * 32) is None

    unknown_repository = _repository(tmp_path / "unknown")
    _enqueue_reply(unknown_repository)
    unknown_http = _ReplyHttp(timeout=True)
    unknown_worker = M8FeishuAgentReplyDeliveryWorker(
        unknown_repository,
        _ActivationRepository(_activation_status()),
        _SecretResolver(),
        unknown_http,
        preflight.profile,
        lambda _binding_id: binding,
        lambda: NOW,
        SHA_A,
    )
    unknown = unknown_worker.run_one(b"x" * 32)
    assert unknown is not None
    assert unknown.disposition == M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
    assert unknown.failure_code == M8FeishuLiveFailureCode.SEND_UNCERTAIN
    assert unknown_worker.run_one(b"x" * 32) is None
    assert unknown_http.message_calls == 1
