"""Same-origin HTML and typed API adapter for the campus platform Demo."""

from __future__ import annotations

import sqlite3
from http import HTTPStatus
from importlib.resources import files
from typing import Any

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import M8ApiErrorReason, M8ApiKnowledgeQueryRequestV1
from labcourt.contracts.m8_feishu_platform import M8FeishuTestCardCheckRequestV1
from labcourt.contracts.m8_platform_agent import M8PlatformNotificationDispatchRequestV2
from labcourt.contracts.m8_platform_demo import (
    M8PlatformAcknowledgementRequestV1,
    M8PlatformAgentQueryRequestV1,
    M8PlatformLoginRequestV1,
    M8PlatformLoginResponseV1,
    M8PlatformNotificationDispatchRequestV1,
    M8PlatformNotificationReplyRequestV1,
    M8PlatformResetRequestV1,
    M8PlatformScenarioStartRequestV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.m8_api_server import M8ApiHttpServer, M8ApiRequestHandler
from labcourt.ports.m8_api_authentication import M8AuthenticationError
from labcourt.services.m8_operations_api import M8ApiServiceError
from labcourt.services.m8_platform_demo import M8PlatformDemoService
from labcourt.services.pilot_ui import PilotUiVideoSource

_PAGE_PATHS = frozenset(
    {
        "/",
        "/login",
        "/app/monitor",
        "/app/cases",
        "/app/map",
        "/app/notifications",
        "/app/knowledge",
        "/app/agent",
        "/app/profile",
        "/app/settings",
    }
)
_ASSETS = {
    "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/assets/source-serif-4.woff2": ("fonts/source-serif-4.woff2", "font/woff2"),
    "/assets/noto-serif-sc.woff2": ("fonts/noto-serif-sc.woff2", "font/woff2"),
    "/assets/ibm-plex-mono.woff2": ("fonts/ibm-plex-mono.woff2", "font/woff2"),
    "/assets/licenses/source-serif-OFL.md": (
        "licenses/source-serif-OFL.md",
        "text/markdown; charset=utf-8",
    ),
    "/assets/licenses/ibm-plex-OFL.txt": (
        "licenses/ibm-plex-OFL.txt",
        "text/plain; charset=utf-8",
    ),
    "/assets/licenses/noto-serif-sc-OFL.txt": (
        "licenses/noto-serif-sc-OFL.txt",
        "text/plain; charset=utf-8",
    ),
}
_STREAM_CHUNK_BYTES = 1024 * 1024


class M8PlatformHttpServer(M8ApiHttpServer):
    platform_service: M8PlatformDemoService
    platform_role_tokens: dict[M8ActorRole, str]


class M8PlatformRequestHandler(M8ApiRequestHandler):
    server: M8PlatformHttpServer

    def do_HEAD(self) -> None:
        try:
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.LOCAL_HOST_REQUIRED)
                return
            if self.path.split("?", maxsplit=1)[0] == ("/api/m8/demo/public-media/recorded-video"):
                self._public_recorded_video(head_only=True)
                return
        except (OSError, ValueError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_GET(self) -> None:
        try:
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.LOCAL_HOST_REQUIRED)
                return
            if self._serve_static():
                return
            if self.path.split("?", maxsplit=1)[0] == ("/api/m8/demo/public-media/recorded-video"):
                self._public_recorded_video()
                return
            principal = self.server.api_authenticator.authenticate(
                self.headers.get("Authorization")
            )
            segments = self._segments()
            if segments == ("api", "m8", "reservations"):
                self._json(
                    HTTPStatus.OK,
                    self.server.platform_service.reservations(principal),
                )
                return
            if segments == ("api", "m8", "integrations", "feishu", "status"):
                status = self.server.platform_service.feishu_status(principal)
                self._json(HTTPStatus.OK, status.model_dump(mode="json"))
                return
            if (
                len(segments) == 7
                and segments[:4] == ("api", "m8", "knowledge", "catalogs")
                and segments[5] == "documents"
            ):
                document = self.server.platform_service.knowledge_document(
                    principal,
                    segments[4],
                    segments[6],
                )
                self._json(HTTPStatus.OK, document.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "demo", "model-readiness"):
                readiness = self.server.platform_service.model_readiness(principal)
                self._json(HTTPStatus.OK, readiness.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "demo", "scenario-runs", "current"):
                run = self.server.platform_service.current_run(principal)
                self._json(
                    HTTPStatus.OK,
                    run.model_dump(mode="json") if run is not None else None,
                )
                return
            if segments == ("api", "m8", "notification-conversations"):
                conversations = self.server.platform_service.notification_conversations(principal)
                self._json(
                    HTTPStatus.OK,
                    tuple(item.model_dump(mode="json") for item in conversations),
                )
                return
            if len(segments) == 4 and segments[:3] == (
                "api",
                "m8",
                "notification-conversations",
            ):
                conversation = self.server.platform_service.notification_conversation(
                    principal, segments[3]
                )
                self._json(HTTPStatus.OK, conversation.model_dump(mode="json"))
                return
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "demo", "scenario-runs")
                and segments[5] == "evidence-workspace"
            ):
                workspace = self.server.platform_service.evidence_workspace(principal, segments[4])
                self._json(HTTPStatus.OK, workspace.model_dump(mode="json"))
                return
            if len(segments) == 5 and segments[:4] == (
                "api",
                "m8",
                "demo",
                "scenario-runs",
            ):
                run = self.server.platform_service.scenario_run(principal, segments[4])
                self._json(HTTPStatus.OK, run.model_dump(mode="json"))
                return
            if (
                len(segments) == 7
                and segments[:4] == ("api", "m8", "demo", "scenario-runs")
                and segments[5] == "evidence"
            ):
                asset = self.server.platform_service.read_evidence(
                    principal, segments[4], segments[6]
                )
                self._binary(HTTPStatus.OK, asset.bytes, asset.media_type)
                return
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "demo", "scenario-runs")
                and segments[5] == "perception-preview"
            ):
                source = self.server.platform_service.perception_preview(principal, segments[4])
                self._pilot_video(source)
                return
        except M8AuthenticationError as error:
            self._authentication_error(error)
            return
        except M8ApiServiceError as error:
            self._service_error(error)
            return
        except (TypeError, ValueError, ContractViolation, ValidationError):
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
            return
        except (OSError, sqlite3.DatabaseError, RepositoryIntegrityError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)
            return
        super().do_GET()

    def do_POST(self) -> None:
        segments = self._segments()
        try:
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.LOCAL_HOST_REQUIRED)
                return
            if not self._same_origin_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.FORBIDDEN)
                return
            if segments == ("api", "m8", "demo", "login"):
                login_request = M8PlatformLoginRequestV1.model_validate_json(self._json_body())
                token = self.server.platform_role_tokens[login_request.role]
                principal = self.server.api_authenticator.authenticate(f"Bearer {token}")
                session = self.server.api_service.session(principal)
                login_response = M8PlatformLoginResponseV1(
                    bearer_token=token,
                    session=session,
                )
                self._json(HTTPStatus.OK, login_response.model_dump(mode="json"))
                return
            principal = self.server.api_authenticator.authenticate(
                self.headers.get("Authorization")
            )
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "knowledge", "catalogs")
                and segments[5] == "query-projections"
            ):
                knowledge_request = M8ApiKnowledgeQueryRequestV1.model_validate_json(
                    self._json_body()
                )
                projection = self.server.platform_service.knowledge_query_projection(
                    principal,
                    segments[4],
                    knowledge_request,
                )
                self._json(HTTPStatus.OK, projection.model_dump(mode="json"))
                return
            if segments == (
                "api",
                "m8",
                "integrations",
                "feishu",
                "test-card-checks",
            ):
                feishu_request = M8FeishuTestCardCheckRequestV1.model_validate_json(
                    self._json_body()
                )
                receipt = self.server.platform_service.check_feishu_test_card(
                    principal,
                    feishu_request,
                )
                self._json(HTTPStatus.OK, receipt.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "demo", "scenario-runs"):
                scenario_request = M8PlatformScenarioStartRequestV1.model_validate_json(
                    self._json_body()
                )
                run = self.server.platform_service.start_scenario(
                    principal,
                    scenario_request.scenario_kind,
                    scenario_request.recognition_mode,
                    scenario_request.retry_of_run_id,
                )
                self._json(HTTPStatus.ACCEPTED, run.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "demo", "reset"):
                M8PlatformResetRequestV1.model_validate_json(self._json_body())
                result = self.server.platform_service.reset(principal)
                self._json(HTTPStatus.OK, result.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "agent", "queries"):
                agent_request = M8PlatformAgentQueryRequestV1.model_validate_json(
                    self._json_body()
                )
                agent_response = self.server.platform_service.agent_query(
                    principal, agent_request.query
                )
                self._json(HTTPStatus.OK, agent_response.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "cases")
                and segments[4] == "notification-dispatches"
            ):
                raw_request = self._json_body()
                request_v2 = None
                request_v1 = None
                try:
                    request_v2 = M8PlatformNotificationDispatchRequestV2.model_validate_json(
                        raw_request
                    )
                except ValidationError:
                    request_v1 = M8PlatformNotificationDispatchRequestV1.model_validate_json(
                        raw_request
                    )
                dispatch_kind: str
                if request_v2 is not None:
                    dispatch_kind = request_v2.kind
                else:
                    assert request_v1 is not None
                    dispatch_kind = request_v1.kind
                dispatch_result = self.server.platform_service.dispatch_case_notification(
                    principal,
                    segments[3],
                    dispatch_kind,
                    request_v2.source_case_version if request_v2 is not None else None,
                    (
                        request_v2.source_case_authority_sha256
                        if request_v2 is not None
                        else None
                    ),
                )
                self._json(HTTPStatus.OK, dispatch_result.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "notifications")
                and segments[4] == "replies"
            ):
                reply_request = M8PlatformNotificationReplyRequestV1.model_validate_json(
                    self._json_body()
                )
                reply_result = self.server.platform_service.reply_notification(
                    principal, segments[3], reply_request.reply_kind, reply_request.body
                )
                self._json(HTTPStatus.OK, reply_result.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "notifications")
                and segments[4] == "acknowledgements"
            ):
                M8PlatformAcknowledgementRequestV1.model_validate_json(self._json_body())
                acknowledgement_result = self.server.platform_service.acknowledge_notification(
                    principal, segments[3]
                )
                self._json(HTTPStatus.OK, acknowledgement_result.model_dump(mode="json"))
                return
        except M8AuthenticationError as error:
            self._authentication_error(error)
            return
        except M8ApiServiceError as error:
            self._service_error(error)
            return
        except (TypeError, ValueError, ContractViolation, ValidationError):
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
            return
        except (OSError, sqlite3.DatabaseError, RepositoryIntegrityError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)
            return
        super().do_POST()

    def _pilot_video(self, source: PilotUiVideoSource) -> None:
        with (
            SecureWorkspace(
                source.workspace_root,
                max_file_bytes=self.server.platform_service.pilot_service.config.storage.max_media_bytes,
            ) as workspace,
            workspace.open_verified_video(
                source.relative_path,
                self.server.platform_service.pilot_service.config.storage.max_media_bytes,
            ) as opened,
        ):
            if (
                opened.input_file_sha256 != source.expected_sha256
                or opened.size_bytes != source.size_bytes
            ):
                raise ValueError("verified Pilot preview changed after inspection")
            requested = self._requested_range(opened.size_bytes)
            if requested is None:
                return
            start, end, partial = requested
            length = end - start + 1
            self.send_response(HTTPStatus.PARTIAL_CONTENT if partial else HTTPStatus.OK)
            self.send_header("Cache-Control", "private, max-age=3600")
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(length))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if partial:
                self.send_header("Content-Range", f"bytes {start}-{end}/{opened.size_bytes}")
            self.end_headers()
            try:
                with open(opened.decoder_path, "rb") as handle:
                    handle.seek(start)
                    remaining = length
                    while remaining:
                        chunk = handle.read(min(_STREAM_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise OSError("Pilot preview ended before its inspected size")
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                return

    def _public_recorded_video(self, *, head_only: bool = False) -> None:
        path = self.server.platform_service.input_media_path
        size = path.stat().st_size
        requested = self._requested_range(size)
        if requested is None:
            return
        start, end, partial = requested
        length = end - start + 1
        self.send_response(HTTPStatus.PARTIAL_CONTENT if partial else HTTPStatus.OK)
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if head_only:
            return
        try:
            with path.open("rb") as handle:
                handle.seek(start)
                remaining = length
                while remaining:
                    chunk = handle.read(min(_STREAM_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise OSError("recorded demo media ended before inspected size")
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _serve_static(self) -> bool:
        path = self.path.split("?", maxsplit=1)[0]
        if path.startswith("/app/cases/") and len(path.split("/")) == 4:
            path = "/app/cases/{case_id}"
        if path.startswith("/app/notifications/") and len(path.split("/")) == 4:
            path = "/app/notifications/{case_id}"
        if path in _PAGE_PATHS or path in {
            "/app/cases/{case_id}",
            "/app/notifications/{case_id}",
        }:
            body = files("labcourt.m8_ui_web").joinpath("app.html").read_bytes()
            self._binary(HTTPStatus.OK, body, "text/html; charset=utf-8")
            return True
        asset = _ASSETS.get(path)
        if asset is None:
            return False
        relative, media_type = asset
        body = files("labcourt.m8_ui_web").joinpath(relative).read_bytes()
        self._binary(HTTPStatus.OK, body, media_type, cache=True)
        return True

    def _binary(
        self,
        status: HTTPStatus,
        body: bytes,
        media_type: str,
        *,
        cache: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=86400" if cache else "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "font-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "
            "connect-src 'self'; frame-ancestors 'none'",
        )
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return


def build_m8_platform_server(
    *,
    platform_service: M8PlatformDemoService,
    role_tokens: dict[M8ActorRole, str],
    **kwargs: Any,
) -> M8PlatformHttpServer:
    port = kwargs.pop("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65_535:
        raise ValueError("M8 platform port must be an integer from 0 through 65535")
    server = M8PlatformHttpServer(("127.0.0.1", port), **kwargs)
    server.RequestHandlerClass = M8PlatformRequestHandler
    server.platform_service = platform_service
    server.platform_role_tokens = dict(role_tokens)
    return server


__all__ = ["M8PlatformHttpServer", "build_m8_platform_server"]
