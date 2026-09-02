from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_feishu_live_repository import (
    SQLiteM8FeishuLiveRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_platform_bootstrap import (
    PLATFORM_DATABASE_NAME,
    platform_manifest,
)
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_feishu_live import (
    M8FeishuAgentReplyEnvelopeV1,
    M8FeishuInboundJobState,
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
from labcourt.services.m8_feishu_agent_worker import (
    M8FeishuAgentAuthorityWorker,
    M8FeishuTrustedActorContext,
)
from labcourt.services.m8_feishu_live_ingress import (
    M8FeishuLiveIngressService,
    M8FeishuP2PTextIngress,
)
from tests.contract.test_m8_feishu_notification_contracts import (
    FAKE_FEISHU_OPEN_ID,
    _preflight,
)
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


def test_authority_worker_keeps_unexpected_cycle_failure_typed_and_terminal(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    accepted = M8FeishuLiveIngressService(repository, SHA_A).accept_text(
        M8FeishuP2PTextIngress(
            provider_event_id="event-p2p-worker-failure-01",
            provider_message_id="om-p2p-worker-failure-01",
            sender_open_id="ou-worker-failure",
            chat_id="oc-worker-failure",
            chat_type="p2p",
            sender_type="user",
            message_type="text",
            text="你好",
            received_at=NOW,
        )
    )
    moments = iter(NOW + timedelta(microseconds=index) for index in range(10))
    worker = M8FeishuAgentAuthorityWorker(
        repository,
        object(),  # type: ignore[arg-type] - actor resolution fails before Agent access
        lambda _sender: (_ for _ in ()).throw(RuntimeError("unexpected cycle failure")),
        lambda: next(moments),
        SHA_A,
        SHA_B,
        SHA_C,
    )

    assert worker.run_one() is True
    terminal = repository.inbound_job(accepted.job.inbound_event.inbound_event_id)
    assert terminal is not None
    assert terminal.state == M8FeishuInboundJobState.FAILED
    assert terminal.failure_code == M8FeishuLiveFailureCode.WORKER_UNAVAILABLE
    heartbeat = repository.latest_heartbeat("AUTHORITY_WORKER")
    assert heartbeat is not None
    assert heartbeat.worker_state is not None
    assert heartbeat.worker_state.value == "FAILED"
    assert heartbeat.failure_code == M8FeishuLiveFailureCode.WORKER_UNAVAILABLE


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


def test_feishu_agent_uses_shared_conversation_and_has_no_offline_reply(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    media = tmp_path / "fixture.mp4"
    media.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + b"\x00" * 40)
    assembly = assemble_m8_platform_demo_api(
        project_root=Path(__file__).parents[2],
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=media,
        port=0,
    )
    server = assembly.server
    safety_token = server.platform_role_tokens[M8ActorRole.SAFETY_OFFICER]
    principal = server.api_authenticator.authenticate(f"Bearer {safety_token}")
    operations = SQLiteM8OperationsRepository(
        assembly.database_path,
        5_000,
        platform_manifest("labcourt-platform-sqlite-repository-v1"),
    )
    actor = operations.get_current_actor_authority(principal.actor_id)
    original = _preflight().recipient_binding
    target = original.target.model_copy(update={"actor_id": principal.actor_id})
    binding = original.model_copy(update={"target": target})
    sender_open_id = FAKE_FEISHU_OPEN_ID.decode("ascii")
    assert hashlib.sha256(sender_open_id.encode()).hexdigest() == binding.receive_id_sha256
    ingress = M8FeishuLiveIngressService(
        assembly.feishu_live.repository,
        platform_manifest("platform-feishu-live-agent-test-v1"),
    )
    accepted = ingress.accept_text(
        M8FeishuP2PTextIngress(
            provider_event_id="event-feishu-agent-unconfigured-01",
            provider_message_id="om-feishu-agent-unconfigured-01",
            sender_open_id=sender_open_id,
            chat_id="oc-feishu-agent-private-01",
            chat_type="p2p",
            sender_type="user",
            message_type="text",
            text="请查看当前待核实案件",
            received_at=datetime.now(UTC),
        )
    )
    worker = M8FeishuAgentAuthorityWorker(
        assembly.feishu_live.repository,
        server.agent_chat_service,
        lambda sender: (
            M8FeishuTrustedActorContext(principal, actor, binding)
            if sender == binding.receive_id_sha256
            else (_ for _ in ()).throw(ValueError("actor not bound"))
        ),
        lambda: datetime.now(UTC),
        platform_manifest("platform-feishu-live-repository-v1"),
        platform_manifest("platform-feishu-agent-envelope-test-v1"),
        platform_manifest("platform-feishu-agent-worker-test-v1"),
    )

    assert worker.run_one() is True
    terminal = assembly.feishu_live.repository.inbound_job(
        accepted.job.inbound_event.inbound_event_id
    )
    assert terminal is not None
    assert terminal.state == M8FeishuInboundJobState.FAILED
    assert terminal.failure_code == M8FeishuLiveFailureCode.QWEN_UNAVAILABLE
    assert terminal.conversation_id is not None
    projection = assembly.feishu_live.repository.channel_projection(terminal.conversation_id)
    assert projection is not None
    assert projection.actor_id == principal.actor_id
    assert projection.turn_origins[terminal.turn_id] == "FEISHU"
    conversation = server.agent_chat_service.conversation(principal, terminal.conversation_id)
    assert conversation.turns[-1].failure_code.value == "NOT_CONFIGURED"
    reply = assembly.feishu_live.repository.claim_agent_reply("f" * 64)
    assert reply is not None
    assert "Qwen" in reply.content.decode("utf-8")
    assert "离线" not in reply.content.decode("utf-8")
