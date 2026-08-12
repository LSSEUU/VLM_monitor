"""Same-origin HTML and typed API adapter for the campus platform Demo."""

from __future__ import annotations

import sqlite3
from http import HTTPStatus
from importlib.resources import files

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import M8ApiErrorReason
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

    def do_GET(self) -> None:
        try:
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.LOCAL_HOST_REQUIRED)
                return
            if self._serve_static():
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
            if segments == ("api", "m8", "demo", "scenario-runs", "current"):
                run = self.server.platform_service.current_run(principal)
                self._json(
                    HTTPStatus.OK,
                    run.model_dump(mode="json") if run is not None else None,
                )
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
                source = self.server.platform_service.perception_preview(
                    principal, segments[4]
                )
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
                request = M8PlatformLoginRequestV1.model_validate_json(self._json_body())
                token = self.server.platform_role_tokens[request.role]
                principal = self.server.api_authenticator.authenticate(f"Bearer {token}")
                session = self.server.api_service.session(principal)
                response = M8PlatformLoginResponseV1(
                    bearer_token=token,
                    session=session,
                )
                self._json(HTTPStatus.OK, response.model_dump(mode="json"))
                return
            principal = self.server.api_authenticator.authenticate(
                self.headers.get("Authorization")
            )
            if segments == ("api", "m8", "demo", "scenario-runs"):
                request = M8PlatformScenarioStartRequestV1.model_validate_json(
                    self._json_body()
                )
                run = self.server.platform_service.start_scenario(
                    principal, request.scenario_kind
                )
                self._json(HTTPStatus.ACCEPTED, run.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "demo", "reset"):
                M8PlatformResetRequestV1.model_validate_json(self._json_body())
                result = self.server.platform_service.reset(principal)
                self._json(HTTPStatus.OK, result.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "agent", "queries"):
                request = M8PlatformAgentQueryRequestV1.model_validate_json(
                    self._json_body()
                )
                response = self.server.platform_service.agent_query(principal, request.query)
                self._json(HTTPStatus.OK, response.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "cases")
                and segments[4] == "notification-dispatches"
            ):
                request = M8PlatformNotificationDispatchRequestV1.model_validate_json(
                    self._json_body()
                )
                result = self.server.platform_service.dispatch_case_notification(
                    principal, segments[3], request.kind
                )
                self._json(HTTPStatus.OK, result.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "notifications")
                and segments[4] == "replies"
            ):
                request = M8PlatformNotificationReplyRequestV1.model_validate_json(
                    self._json_body()
                )
                result = self.server.platform_service.reply_notification(
                    principal, segments[3], request.reply_kind, request.body
                )
                self._json(HTTPStatus.OK, result.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "notifications")
                and segments[4] == "acknowledgements"
            ):
                M8PlatformAcknowledgementRequestV1.model_validate_json(self._json_body())
                result = self.server.platform_service.acknowledge_notification(
                    principal, segments[3]
                )
                self._json(HTTPStatus.OK, result.model_dump(mode="json"))
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

    def _serve_static(self) -> bool:
        path = self.path.split("?", maxsplit=1)[0]
        if path.startswith("/app/cases/") and len(path.split("/")) == 4:
            path = "/app/cases/{case_id}"
        if path in _PAGE_PATHS or path == "/app/cases/{case_id}":
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
    **kwargs,
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
