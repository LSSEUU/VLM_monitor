from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from labcourt.contracts.m8_feishu_challenge import (
    M8FeishuLoopbackChallengeListenerProfileV1,
    M8FeishuUrlChallengeCommitReceiptV1,
    M8FeishuUrlChallengeVerificationReceiptV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.m8_feishu_webhook_server import (
    M8FeishuLoopbackChallengeHttpServer,
    build_m8_feishu_loopback_challenge_server,
)
from labcourt.services.m8_feishu_challenge import M8FeishuUrlChallengeService
from tests.integration.test_m8_feishu_challenge import (
    SHA_A,
    SHA_B,
    _challenge_bytes,
    _encrypted_body,
)
from tests.integration.test_m8_feishu_inbound_verification import (
    RECEIVED_AT,
    _Crypto,
    _SecretResolver,
    _webhook_profile,
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


def _listener() -> M8FeishuLoopbackChallengeListenerProfileV1:
    return M8FeishuLoopbackChallengeListenerProfileV1(
        inbound_profile_id=_webhook_profile().inbound_profile_id,
        requested_port=0,
        listener_manifest_id=SHA_A,
    )


@contextmanager
def _running_server(
    *,
    decrypted: bytes | None = None,
) -> Iterator[tuple[M8FeishuLoopbackChallengeHttpServer, _ReceiptSink]]:
    sink = _ReceiptSink()
    service = M8FeishuUrlChallengeService(
        _SecretResolver(),
        _Crypto(decrypted or _challenge_bytes()),
        lambda: RECEIVED_AT.replace(microsecond=10_000),
        SHA_B,
    )
    server = build_m8_feishu_loopback_challenge_server(
        listener_profile=_listener(),
        inbound_profile=_webhook_profile(),
        challenge_service=service,
        receipt_sink=sink,
        clock=lambda: RECEIVED_AT,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, sink
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(
    server: M8FeishuLoopbackChallengeHttpServer,
    *,
    method: str = "POST",
    path: str = "/callbacks/feishu/v1",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object], dict[str, str]]:
    request_body = _encrypted_body() if body is None else body
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_port,
        timeout=3,
    )
    connection.request(method, path, body=request_body, headers=request_headers)
    response = connection.getresponse()
    response_body = json.loads(response.read())
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, response_body, response_headers


def test_loopback_server_returns_exact_challenge_and_records_hash_only_receipt(
    socket_enabled: None,
) -> None:
    del socket_enabled
    with _running_server() as (server, sink):
        status, body, headers = _request(server)

        assert server.server_address[0] == "127.0.0.1"
        assert status == 200
        assert body == {"challenge": "challenge-clear-fixture"}
        assert headers["cache-control"] == "no-store"
        assert headers["content-type"] == "application/json; charset=utf-8"
        assert len(sink.receipts) == 1
        assert sink.receipts[0].challenge_response_permitted is True
        assert "challenge-clear-fixture" not in sink.receipts[0].model_dump_json()


def test_business_event_headers_are_rejected_until_separate_ingress_activation(
    socket_enabled: None,
) -> None:
    del socket_enabled
    with _running_server() as (server, sink):
        status, body, _headers = _request(
            server,
            headers={
                "X-Lark-Request-Timestamp": str(int(RECEIVED_AT.timestamp())),
                "X-Lark-Request-Nonce": "nonce-fixture-01",
                "X-Lark-Signature": "a" * 64,
            },
        )

        assert status == 503
        assert body == {"error": {"code": "business_event_ingress_inactive"}}
        assert sink.receipts == []


def test_invalid_token_path_method_content_type_and_host_fail_closed(
    socket_enabled: None,
) -> None:
    del socket_enabled
    with _running_server(decrypted=_challenge_bytes(token=b"wrong-verification-token")) as (
        server,
        sink,
    ):
        status, body, _headers = _request(server)
        assert status == 400
        assert body == {"error": {"code": "invalid_request"}}
        assert sink.receipts == []

        status, _body, _headers = _request(server, path="/callbacks/feishu/other")
        assert status == 404
        status, _body, _headers = _request(server, method="GET")
        assert status == 405
        status, _body, _headers = _request(server, method="PUT")
        assert status == 405
        status, _body, _headers = _request(
            server,
            headers={"Content-Type": "text/plain"},
        )
        assert status == 400
        status, _body, _headers = _request(server, headers={"Host": "attacker.invalid"})
        assert status == 403
        assert sink.receipts == []


def test_builder_rejects_profile_graft() -> None:
    inbound = _webhook_profile()
    listener = _listener()
    service = M8FeishuUrlChallengeService(
        _SecretResolver(),
        _Crypto(_challenge_bytes()),
        lambda: RECEIVED_AT.replace(microsecond=10_000),
        SHA_B,
    )
    sink = _ReceiptSink()

    with pytest.raises(ContractViolation, match="profile binding changed"):
        build_m8_feishu_loopback_challenge_server(
            listener_profile=listener.model_copy(update={"inbound_profile_id": "f" * 64}),
            inbound_profile=inbound,
            challenge_service=service,
            receipt_sink=sink,
            clock=lambda: RECEIVED_AT,
        )
