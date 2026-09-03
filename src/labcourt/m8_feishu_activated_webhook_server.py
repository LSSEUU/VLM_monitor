"""Activation-gated loopback backend for a Feishu sandbox HTTPS reverse proxy."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_challenge import M8FeishuUrlChallengeIngressRequestV1
from labcourt.contracts.m8_feishu_inbound import M8FeishuWebhookIngressRequestV1
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundSandboxActivationStatusV1,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, ContractViolation, EvidenceMissing
from labcourt.ports.m8_feishu_challenge_receipts import (
    M8FeishuUrlChallengeReceiptSink,
)
from labcourt.ports.m8_feishu_inbound_activation_repository import (
    M8FeishuInboundActivationRepository,
)
from labcourt.services.m8_feishu_challenge import M8FeishuUrlChallengeService
from labcourt.services.m8_feishu_inbound import M8FeishuInboundVerificationService

_TIMESTAMP_HEADER = "X-Lark-Request-Timestamp"
_NONCE_HEADER = "X-Lark-Request-Nonce"
_SIGNATURE_HEADER = "X-Lark-Signature"
_EVENT_HEADERS = (_TIMESTAMP_HEADER, _NONCE_HEADER, _SIGNATURE_HEADER)


def _body_ref(prefix: str, body_sha256: str) -> str:
    return f"{prefix}{body_sha256[: 64 - len(prefix)]}"


def _canonical_positive_integer(value: str, name: str) -> int:
    if not value.isascii() or not value.isdigit() or value.startswith("0") or len(value) > 16:
        raise ValueError(f"M8 Feishu activated webhook {name} is not canonical")
    return int(value)


class M8FeishuActivatedWebhookHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        startup_status: M8FeishuInboundSandboxActivationStatusV1,
        *,
        activation_repository: M8FeishuInboundActivationRepository,
        challenge_service: M8FeishuUrlChallengeService,
        inbound_service: M8FeishuInboundVerificationService,
        challenge_receipt_sink: M8FeishuUrlChallengeReceiptSink,
        clock: Callable[[], datetime],
    ) -> None:
        config = startup_status.activation_receipt.runtime_config
        super().__init__(
            (config.application_bind_host, config.application_bind_port),
            M8FeishuActivatedWebhookRequestHandler,
        )
        self.startup_status = startup_status
        self.activation_repository = activation_repository
        self.challenge_service = challenge_service
        self.inbound_service = inbound_service
        self.challenge_receipt_sink = challenge_receipt_sink
        self.ingress_clock = clock

    def current_status(self, assessed_at: datetime) -> M8FeishuInboundSandboxActivationStatusV1:
        profile = self.startup_status.activation_receipt.runtime_config.profile
        candidate_id = profile.outbound_profile.candidate.candidate_authority_id
        status = self.activation_repository.get_current_inbound_status(
            candidate_id,
            assessed_at,
        )
        if (
            not status.sandbox_external_ingress_permitted
            or status.activation_receipt.activation_commit_id
            != self.startup_status.activation_receipt.activation_commit_id
        ):
            raise ConcurrentModification(
                "M8 Feishu activated webhook authority is inactive or changed"
            )
        return status


class M8FeishuActivatedWebhookRequestHandler(BaseHTTPRequestHandler):
    server: M8FeishuActivatedWebhookHttpServer
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def do_POST(self) -> None:
        try:
            received_at = self.server.ingress_clock()
            status = self.server.current_status(received_at)
            config = status.activation_receipt.runtime_config
            if not self._local_host_allowed(config.application_bind_host):
                self._error(HTTPStatus.FORBIDDEN, "local_proxy_host_required")
                return
            target = urlsplit(self.path)
            if target.path != config.callback_path or target.query or target.fragment:
                self._error(HTTPStatus.NOT_FOUND, "resource_not_found")
                return
            body = self._request_body(config.raw_body_max_bytes)
            present = tuple(self.headers.get(name) is not None for name in _EVENT_HEADERS)
            if present == (False, False, False):
                self._challenge(status, received_at, body)
                return
            if present != (True, True, True):
                raise ValueError("M8 Feishu activated webhook event headers are incomplete")
            self._business_event(status, received_at, body)
        except (ConcurrentModification, EvidenceMissing):
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ingress_inactive")
        except (ContractViolation, ValidationError, ValueError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request")
        except (RepositoryIntegrityError, OSError, RuntimeError, sqlite3.DatabaseError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_failure")

    def _challenge(
        self,
        status: M8FeishuInboundSandboxActivationStatusV1,
        received_at: datetime,
        body: bytes,
    ) -> None:
        if not status.url_challenge_permitted:
            raise ConcurrentModification("M8 Feishu URL challenge ingress is inactive")
        profile = status.activation_receipt.runtime_config.profile
        body_sha256 = hashlib.sha256(body).hexdigest()
        ingress = M8FeishuUrlChallengeIngressRequestV1(
            inbound_profile_id=profile.inbound_profile_id,
            encrypted_body_ref=_body_ref("m8-feishu-url-envelope-", body_sha256),
            encrypted_body_sha256=body_sha256,
            encrypted_body_size_bytes=len(body),
            received_at=received_at,
            ingress_manifest_id=(
                status.activation_receipt.runtime_config.runtime_config_manifest_id
            ),
        )
        result = self.server.challenge_service.verify(profile, ingress, body)
        self.server.challenge_receipt_sink.record_verification(result.receipt)
        self._response(
            HTTPStatus.OK,
            result.response_body(),
            result.receipt.response_content_type,
        )

    def _business_event(
        self,
        status: M8FeishuInboundSandboxActivationStatusV1,
        received_at: datetime,
        body: bytes,
    ) -> None:
        if not status.business_event_ingress_permitted:
            raise ConcurrentModification("M8 Feishu business event ingress is inactive")
        timestamp_text = self.headers[_TIMESTAMP_HEADER]
        nonce = require_reference_token(
            self.headers[_NONCE_HEADER],
            "M8 Feishu request nonce",
        )
        signature = self.headers[_SIGNATURE_HEADER]
        profile = status.activation_receipt.runtime_config.profile
        body_sha256 = hashlib.sha256(body).hexdigest()
        ingress = M8FeishuWebhookIngressRequestV1(
            inbound_profile_id=profile.inbound_profile_id,
            request_timestamp_seconds=_canonical_positive_integer(
                timestamp_text,
                "request timestamp",
            ),
            request_nonce=nonce,
            request_signature=signature,
            encrypted_body_ref=_body_ref("m8-feishu-event-envelope-", body_sha256),
            encrypted_body_sha256=body_sha256,
            encrypted_body_size_bytes=len(body),
            received_at=received_at,
            ingress_manifest_id=(
                status.activation_receipt.runtime_config.runtime_config_manifest_id
            ),
        )
        self.server.inbound_service.verify_and_commit(profile, ingress, body)
        self._response(HTTPStatus.OK, b"{}", "application/json")

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

    def _request_body(self, max_bytes: int) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ValueError("M8 Feishu activated webhook forbids transfer encoding")
        if self.headers.get("Content-Encoding") is not None:
            raise ValueError("M8 Feishu activated webhook forbids content encoding")
        content_type = self.headers.get("Content-Type", "").split(";", maxsplit=1)[0]
        if content_type.strip().lower() != "application/json":
            raise ValueError("M8 Feishu activated webhook requires application/json")
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            raise ValueError("M8 Feishu activated webhook requires one Content-Length")
        length_text = lengths[0]
        if (
            not length_text.isascii()
            or not length_text.isdigit()
            or (len(length_text) > 1 and length_text.startswith("0"))
        ):
            raise ValueError("M8 Feishu activated webhook Content-Length is not canonical")
        length = int(length_text)
        if not 0 < length <= max_bytes:
            raise ValueError("M8 Feishu activated webhook body is outside its bound")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("M8 Feishu activated webhook body is incomplete")
        return body

    def _local_host_allowed(self, bind_host: str) -> bool:
        host = self.headers.get("Host", "").lower()
        hostname = host.split(":", maxsplit=1)[0]
        return hostname in {bind_host, "localhost"}

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


def build_m8_feishu_activated_webhook_server(
    *,
    candidate_authority_id: str,
    activation_repository: M8FeishuInboundActivationRepository,
    challenge_service: M8FeishuUrlChallengeService,
    inbound_service: M8FeishuInboundVerificationService,
    challenge_receipt_sink: M8FeishuUrlChallengeReceiptSink,
    clock: Callable[[], datetime],
) -> M8FeishuActivatedWebhookHttpServer:
    candidate_id = require_reference_token(
        candidate_authority_id,
        "M8 Feishu activated webhook candidate",
    )
    if any(
        port is None
        for port in (
            activation_repository,
            challenge_receipt_sink,
        )
    ) or not callable(clock):
        raise TypeError("M8 Feishu activated webhook requires explicit runtime ports")
    if not isinstance(challenge_service, M8FeishuUrlChallengeService):
        raise TypeError("M8 Feishu activated webhook requires a challenge service")
    if not isinstance(inbound_service, M8FeishuInboundVerificationService):
        raise TypeError("M8 Feishu activated webhook requires an inbound service")
    startup_status = activation_repository.get_current_inbound_status(
        candidate_id,
        clock(),
    )
    if not startup_status.sandbox_external_ingress_permitted:
        raise ConcurrentModification("M8 Feishu activated webhook ingress is inactive")
    return M8FeishuActivatedWebhookHttpServer(
        startup_status,
        activation_repository=activation_repository,
        challenge_service=challenge_service,
        inbound_service=inbound_service,
        challenge_receipt_sink=challenge_receipt_sink,
        clock=clock,
    )


__all__ = [
    "M8FeishuActivatedWebhookHttpServer",
    "build_m8_feishu_activated_webhook_server",
]
