from __future__ import annotations

import hashlib
import http.client
import json
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_feishu_inbound_activation_repository import (
    SQLiteM8FeishuInboundActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_feishu_inbound_repository import (
    SQLiteM8FeishuInboundRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_adapter_commissioning import (
    M8AdapterActivationIntentV1,
    M8CommissioningEvidenceKind,
)
from labcourt.contracts.m8_feishu_challenge import (
    M8FeishuUrlChallengeCommitReceiptV1,
    M8FeishuUrlChallengeVerificationReceiptV1,
)
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundRevocationReason,
    M8FeishuInboundSandboxActivationCommitReceiptV1,
    M8FeishuInboundSandboxRuntimeConfigV1,
    m8_feishu_inbound_runtime_config_bytes,
)
from labcourt.contracts.m8_feishu_notification import M8FeishuAdapterProfileV1
from labcourt.exceptions import EvidenceMissing
from labcourt.m8_feishu_activated_webhook_server import (
    M8FeishuActivatedWebhookHttpServer,
    build_m8_feishu_activated_webhook_server,
)
from labcourt.services.m8_adapter_commissioning import M8AdapterReadinessService
from labcourt.services.m8_feishu_challenge import M8FeishuUrlChallengeService
from labcourt.services.m8_feishu_inbound import M8FeishuInboundVerificationService
from tests.integration.test_m8_feishu_challenge import (
    _challenge_bytes,
    _encrypted_body,
)
from tests.integration.test_m8_feishu_inbound_verification import (
    ENCRYPT_KEY,
    RECEIVED_AT,
    VERIFICATION_TOKEN,
    _Crypto,
    _event_bytes,
    _SecretResolver,
)
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    BASE_TIME,
    BUSY_TIMEOUT_MS,
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _actor,
    _candidate,
    _evidence,
)


class _ReceiptSink:
    def __init__(self) -> None:
        self.receipts: list[M8FeishuUrlChallengeVerificationReceiptV1] = []

    def record_verification(
        self,
        receipt: M8FeishuUrlChallengeVerificationReceiptV1,
    ) -> M8FeishuUrlChallengeCommitReceiptV1:
        self.receipts.append(receipt)
        return M8FeishuUrlChallengeCommitReceiptV1(
            verification_receipt=receipt,
            committed_at=receipt.verified_at,
            commit_manifest_id=SHA_A,
            repository_manifest_id=SHA_B,
        )


@dataclass
class _Clock:
    now: datetime

    def __call__(self) -> datetime:
        return self.now


@dataclass(frozen=True)
class _Running:
    server: M8FeishuActivatedWebhookHttpServer
    sink: _ReceiptSink
    clock: _Clock
    activation_repository: SQLiteM8FeishuInboundActivationRepository
    inbound_repository: SQLiteM8FeishuInboundRepository
    activation: M8FeishuInboundSandboxActivationCommitReceiptV1
    safety_actor_id: str


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _inbound_profile() -> M8FeishuInboundWebhookProfileV1:
    outbound = M8FeishuAdapterProfileV1(
        candidate=_candidate(),
        credential_bundle_reference_id="secret-feishu-sandbox-campus-main",
        app_id_sha256=hashlib.sha256(b"cli_fake_labcourt_app").hexdigest(),
        profile_manifest_id=SHA_C,
    )
    return M8FeishuInboundWebhookProfileV1(
        outbound_profile=outbound,
        request_url_reference_id="feishu-public-callback-sandbox-01",
        encrypt_key_reference_id="secret-feishu-encrypt-key-01",
        encrypt_key_sha256=hashlib.sha256(ENCRYPT_KEY).hexdigest(),
        verification_token_reference_id="secret-feishu-verification-token-01",
        verification_token_sha256=hashlib.sha256(VERIFICATION_TOKEN).hexdigest(),
        profile_manifest_id=SHA_C,
    )


@contextmanager
def _running_server(tmp_path: Path) -> Iterator[_Running]:
    database = tmp_path / "labcourt.sqlite3"
    operations = SQLiteM8OperationsRepository.initialize(database, BUSY_TIMEOUT_MS, SHA_A)
    operations_receipt = operations.publish_actor_authority(
        _actor(M8ActorRole.OPERATIONS),
        None,
    )
    safety_receipt = operations.publish_actor_authority(
        _actor(M8ActorRole.SAFETY_OFFICER),
        None,
    )
    activation_repository = SQLiteM8FeishuInboundActivationRepository(
        database,
        BUSY_TIMEOUT_MS,
        SHA_A,
        SHA_E,
    )
    activation_repository.register_candidate(
        _candidate(),
        operations_receipt.authority.actor_id,
    )
    operations_review = {
        M8CommissioningEvidenceKind.LICENSE_REVIEW,
        M8CommissioningEvidenceKind.OFFLINE_FALLBACK_DRILL,
        M8CommissioningEvidenceKind.SECURITY_REVIEW,
    }
    for kind in M8CommissioningEvidenceKind:
        reviewer = operations_receipt if kind in operations_review else safety_receipt
        evidence, evidence_raw = _evidence(kind, reviewer)
        activation_repository.commit_evidence(evidence, evidence_raw, SHA_B)

    config = M8FeishuInboundSandboxRuntimeConfigV1(
        profile=_inbound_profile(),
        runtime_config_ref="m8-feishu-inbound-runtime-config-http-01",
        public_callback_url_reference_id="feishu-public-callback-sandbox-01",
        public_callback_url_sha256=SHA_D,
        tls_configuration_reference_id="feishu-public-tls-sandbox-01",
        tls_configuration_sha256=SHA_E,
        application_bind_port=_free_port(),
        runtime_config_manifest_id=SHA_A,
    )
    readiness_service = M8AdapterReadinessService(
        activation_repository,
        operations,
        SHA_E,
    )
    readiness = readiness_service.assess(
        _candidate().candidate_authority_id,
        operations_receipt.authority.actor_id,
        BASE_TIME + timedelta(hours=1),
    )
    config_raw = m8_feishu_inbound_runtime_config_bytes(config)
    intent = M8AdapterActivationIntentV1(
        readiness_assessment=readiness,
        operations_actor_receipt=operations_receipt,
        safety_actor_receipt=safety_receipt,
        runtime_config_ref=config.runtime_config_ref,
        runtime_config_sha256=hashlib.sha256(config_raw).hexdigest(),
        runtime_config_size_bytes=len(config_raw),
        credential_reference_id=(config.profile.outbound_profile.credential_bundle_reference_id),
        requested_at=BASE_TIME + timedelta(hours=2),
        activation_manifest_id=SHA_D,
    )
    activation = activation_repository.commit_inbound_activation(
        intent,
        config,
        config_raw,
        SHA_B,
        BASE_TIME + timedelta(hours=3),
        BASE_TIME + timedelta(hours=4),
    )

    inbound_repository = SQLiteM8FeishuInboundRepository(
        database,
        BUSY_TIMEOUT_MS,
        SHA_C,
    )
    clock = _Clock(RECEIVED_AT)
    challenge_service = M8FeishuUrlChallengeService(
        _SecretResolver(),
        _Crypto(_challenge_bytes()),
        lambda: clock.now + timedelta(milliseconds=10),
        SHA_D,
    )
    inbound_service = M8FeishuInboundVerificationService(
        inbound_repository,
        _SecretResolver(),
        _Crypto(_event_bytes()),
        lambda: clock.now + timedelta(milliseconds=20),
        SHA_D,
        SHA_E,
        SHA_A,
    )
    sink = _ReceiptSink()
    server = build_m8_feishu_activated_webhook_server(
        candidate_authority_id=_candidate().candidate_authority_id,
        activation_repository=activation_repository,
        challenge_service=challenge_service,
        inbound_service=inbound_service,
        challenge_receipt_sink=sink,
        clock=clock,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield _Running(
            server,
            sink,
            clock,
            activation_repository,
            inbound_repository,
            activation,
            safety_receipt.authority.actor_id,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(
    running: _Running,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    body = _encrypted_body()
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        running.server.server_port,
        timeout=3,
    )
    connection.request(
        "POST",
        "/callbacks/feishu/v1",
        body=body,
        headers=request_headers,
    )
    response = connection.getresponse()
    payload = json.loads(response.read())
    status = response.status
    connection.close()
    return status, payload


def _event_headers(clock: _Clock, *, signature: str | None = None) -> dict[str, str]:
    body = _encrypted_body()
    timestamp = int(clock.now.timestamp())
    nonce = "nonce-activated-webhook-01"
    calculated = hashlib.sha256(
        str(timestamp).encode() + nonce.encode() + ENCRYPT_KEY + body
    ).hexdigest()
    return {
        "X-Lark-Request-Timestamp": str(timestamp),
        "X-Lark-Request-Nonce": nonce,
        "X-Lark-Signature": signature or calculated,
    }


def test_activated_server_routes_challenge_and_commits_business_event(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    del socket_enabled
    with _running_server(tmp_path) as running:
        challenge_status, challenge_body = _request(running)
        event_status, event_body = _request(
            running,
            headers=_event_headers(running.clock),
        )

        assert challenge_status == 200
        assert challenge_body == {"challenge": "challenge-clear-fixture"}
        assert len(running.sink.receipts) == 1
        assert event_status == 200
        assert event_body == {}
        committed = running.inbound_repository.get_by_provider_message_id("om_student_reply_01")
        assert committed.case_transition_permitted is False
        assert committed.notification_reply_commit_permitted is False


def test_event_headers_and_signature_fail_closed_without_evidence_commit(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    del socket_enabled
    with _running_server(tmp_path) as running:
        partial = _event_headers(running.clock)
        partial.pop("X-Lark-Signature")
        partial_status, partial_body = _request(running, headers=partial)
        bad_status, bad_body = _request(
            running,
            headers=_event_headers(running.clock, signature="f" * 64),
        )

        assert partial_status == 400
        assert partial_body == {"error": {"code": "invalid_request"}}
        assert bad_status == 400
        assert bad_body == {"error": {"code": "invalid_request"}}
        with pytest.raises(EvidenceMissing):
            running.inbound_repository.get_by_provider_message_id("om_student_reply_01")


def test_revocation_blocks_running_server_before_decrypt_or_commit(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    del socket_enabled
    with _running_server(tmp_path) as running:
        revoked_at = RECEIVED_AT + timedelta(minutes=1)
        running.activation_repository.revoke_inbound_activation(
            running.activation.activation_commit_id,
            running.safety_actor_id,
            M8FeishuInboundRevocationReason.MANUAL_SAFETY_STOP,
            "activated-webhook-stop-01",
            revoked_at,
            SHA_D,
        )
        running.clock.now = revoked_at + timedelta(seconds=1)

        status, body = _request(
            running,
            headers=_event_headers(running.clock),
        )

        assert status == 503
        assert body == {"error": {"code": "ingress_inactive"}}
        with pytest.raises(EvidenceMissing):
            running.inbound_repository.get_by_provider_message_id("om_student_reply_01")
