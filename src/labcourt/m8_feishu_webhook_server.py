"""Manual-start loopback HTTP adapter for encrypted Feishu URL challenges."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_challenge import (
    M8FeishuLoopbackChallengeListenerProfileV1,
    M8FeishuUrlChallengeIngressRequestV1,
)
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_feishu_challenge_receipts import (
    M8FeishuUrlChallengeReceiptSink,
)
from labcourt.services.m8_feishu_challenge import M8FeishuUrlChallengeService

_BUSINESS_EVENT_HEADERS = (
    "X-Lark-Request-Timestamp",
    "X-Lark-Request-Nonce",
    "X-Lark-Signature",
)


def _body_ref(body_sha256: str) -> str:
    prefix = "m8-feishu-url-envelope-"
    return f"{prefix}{body_sha256[: 64 - len(prefix)]}"


class M8FeishuLoopbackChallengeHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        listener_profile: M8FeishuLoopbackChallengeListenerProfileV1,
        *,
        inbound_profile: M8FeishuInboundWebhookProfileV1,
        challenge_service: M8FeishuUrlChallengeService,
        receipt_sink: M8FeishuUrlChallengeReceiptSink,
        clock: Callable[[], datetime],
    ) -> None:
        super().__init__(
            (listener_profile.bind_host, listener_profile.requested_port),
            M8FeishuLoopbackChallengeRequestHandler,
        )
        self.listener_profile = listener_profile
        self.inbound_profile = inbound_profile
        self.challenge_service = challenge_service
        self.receipt_sink = receipt_sink
        self.ingress_clock = clock


class M8FeishuLoopbackChallengeRequestHandler(BaseHTTPRequestHandler):
    server: M8FeishuLoopbackChallengeHttpServer
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def do_POST(self) -> None:
        try:
            received_at = self.server.ingress_clock()
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, "local_host_required")
                return
            target = urlsplit(self.path)
            if (
                target.path != self.server.listener_profile.callback_path
                or target.query
                or target.fragment
            ):
                self._error(HTTPStatus.NOT_FOUND, "resource_not_found")
                return
            if any(self.headers.get(name) is not None for name in _BUSINESS_EVENT_HEADERS):
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "business_event_ingress_inactive",
                )
                return
            body = self._request_body()
            body_sha256 = hashlib.sha256(body).hexdigest()
            ingress = M8FeishuUrlChallengeIngressRequestV1(
                inbound_profile_id=self.server.inbound_profile.inbound_profile_id,
                encrypted_body_ref=_body_ref(body_sha256),
                encrypted_body_sha256=body_sha256,
                encrypted_body_size_bytes=len(body),
                received_at=received_at,
                ingress_manifest_id=self.server.listener_profile.listener_manifest_id,
            )
            result = self.server.challenge_service.verify(
                self.server.inbound_profile,
                ingress,
                body,
            )
            self.server.receipt_sink.record_verification(result.receipt)
            self._response(
                HTTPStatus.OK,
                result.response_body(),
                result.receipt.response_content_type,
            )
        except (ContractViolation, ValidationError, ValueError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request")
        except (OSError, RuntimeError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_failure")

    def do_GET(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def do_OPTIONS(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def do_HEAD(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def do_PUT(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def do_PATCH(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def do_DELETE(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _request_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ValueError("M8 Feishu loopback challenge forbids transfer encoding")
        if self.headers.get("Content-Encoding") is not None:
            raise ValueError("M8 Feishu loopback challenge forbids content encoding")
        content_type = self.headers.get("Content-Type", "").split(";", maxsplit=1)[0]
        if content_type.strip().lower() != self.server.listener_profile.request_content_type:
            raise ValueError("M8 Feishu loopback challenge requires application/json")
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            raise ValueError("M8 Feishu loopback challenge requires one Content-Length")
        length_text = lengths[0]
        if (
            not length_text.isascii()
            or not length_text.isdigit()
            or (len(length_text) > 1 and length_text.startswith("0"))
        ):
            raise ValueError("M8 Feishu loopback challenge Content-Length is not canonical")
        length = int(length_text)
        if not 0 < length <= self.server.listener_profile.raw_body_max_bytes:
            raise ValueError("M8 Feishu loopback challenge body is outside its bound")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("M8 Feishu loopback challenge body is incomplete")
        return body

    def _local_host_allowed(self) -> bool:
        host = self.headers.get("Host", "").lower()
        hostname = host.split(":", maxsplit=1)[0]
        return hostname in {"127.0.0.1", "localhost"}

    def _error(self, status: HTTPStatus, code: str) -> None:
        body = canonical_json({"error": {"code": code}}).encode("utf-8")
        self._response(status, body, "application/json")

    def _response(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return


def build_m8_feishu_loopback_challenge_server(
    *,
    listener_profile: M8FeishuLoopbackChallengeListenerProfileV1,
    inbound_profile: M8FeishuInboundWebhookProfileV1,
    challenge_service: M8FeishuUrlChallengeService,
    receipt_sink: M8FeishuUrlChallengeReceiptSink,
    clock: Callable[[], datetime],
) -> M8FeishuLoopbackChallengeHttpServer:
    if not isinstance(listener_profile, M8FeishuLoopbackChallengeListenerProfileV1):
        raise TypeError("M8 Feishu loopback challenge requires a typed listener profile")
    if not isinstance(inbound_profile, M8FeishuInboundWebhookProfileV1):
        raise TypeError("M8 Feishu loopback challenge requires a typed inbound profile")
    if listener_profile.inbound_profile_id != inbound_profile.inbound_profile_id:
        raise ContractViolation("M8 Feishu loopback challenge profile binding changed")
    if not isinstance(challenge_service, M8FeishuUrlChallengeService):
        raise TypeError("M8 Feishu loopback challenge requires a challenge service")
    if receipt_sink is None or not callable(clock):
        raise TypeError("M8 Feishu loopback challenge requires explicit runtime ports")
    return M8FeishuLoopbackChallengeHttpServer(
        listener_profile,
        inbound_profile=inbound_profile,
        challenge_service=challenge_service,
        receipt_sink=receipt_sink,
        clock=clock,
    )


__all__ = [
    "M8FeishuLoopbackChallengeHttpServer",
    "build_m8_feishu_loopback_challenge_server",
]
