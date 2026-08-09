"""Loopback-only dependency-free HTTP boundary for the pilot operator UI."""

from __future__ import annotations

import re
import webbrowser
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.pilot_a5 import PilotA5RunReport
from labcourt.contracts.pilot_ui import PilotUiErrorResponse, PilotUiJobStartRequest
from labcourt.exceptions import ArtifactIntegrityViolation, PathBoundaryViolation
from labcourt.services.pilot_ui import (
    PilotUiBoundaryError,
    PilotUiJobManager,
    PilotUiService,
    PilotUiVideoSource,
)

_ASSET_NAMES = frozenset({"app.css", "app.js"})
_RANGE = re.compile(r"^bytes=(?P<start>\d*)-(?P<end>\d*)$")
_MAX_REQUEST_BYTES = 4096
_STREAM_CHUNK_BYTES = 64 * 1024
_Runner = Callable[..., PilotA5RunReport]


class PilotUiHttpServer(ThreadingHTTPServer):
    """Threaded local server carrying its typed service and job manager."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        service: PilotUiService,
        jobs: PilotUiJobManager,
    ) -> None:
        super().__init__(server_address, PilotUiRequestHandler)
        self.ui_service = service
        self.ui_jobs = jobs


class PilotUiRequestHandler(BaseHTTPRequestHandler):
    """Small same-origin JSON and media API; host paths never enter responses."""

    server: PilotUiHttpServer
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def do_GET(self) -> None:
        try:
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, "LOCAL_HOST_REQUIRED")
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                self._asset("index.html", "text/html; charset=utf-8")
                return
            if parsed.path.startswith("/assets/"):
                name = parsed.path.removeprefix("/assets/")
                if name not in _ASSET_NAMES:
                    self._error(HTTPStatus.NOT_FOUND, "RESOURCE_NOT_FOUND")
                    return
                media_type = (
                    "text/css; charset=utf-8"
                    if name.endswith(".css")
                    else "text/javascript; charset=utf-8"
                )
                self._asset(name, media_type)
                return
            if parsed.path == "/api/dashboard":
                query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=4)
                run_id = query.get("run_id", [None])[0]
                video_id = query.get("video_id", [None])[0]
                dashboard = self.server.ui_service.dashboard(
                    run_id=run_id,
                    video_id=video_id,
                    job=self.server.ui_jobs.snapshot(),
                )
                self._json(HTTPStatus.OK, dashboard.model_dump(mode="json"))
                return
            if parsed.path == "/api/jobs/current":
                self._json(
                    HTTPStatus.OK,
                    self.server.ui_jobs.snapshot().model_dump(mode="json"),
                )
                return
            segments = tuple(unquote(item) for item in parsed.path.split("/") if item)
            if len(segments) == 3 and segments[:2] == ("api", "videos"):
                source = self.server.ui_service.video_source(segments[2])
                self._video(source)
                return
            if (
                len(segments) == 4
                and segments[0] == "api"
                and segments[1] == "runs"
                and segments[3] == "preview"
            ):
                source = self.server.ui_service.preview_source(segments[2])
                self._video(source)
                return
            if (
                len(segments) == 5
                and segments[0] == "api"
                and segments[1] == "runs"
                and segments[3] == "evidence"
            ):
                asset = self.server.ui_service.read_evidence(segments[2], segments[4])
                self._bytes(
                    HTTPStatus.OK,
                    asset.bytes,
                    asset.media_type,
                    cache_control="private, max-age=31536000, immutable",
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "RESOURCE_NOT_FOUND")
        except PilotUiBoundaryError as error:
            self._boundary_error(error)
        except _ResponseComplete:
            return
        except (ArtifactIntegrityViolation, PathBoundaryViolation):
            self._error(HTTPStatus.CONFLICT, "MEDIA_NOT_VERIFIED")
        except (OSError, TypeError, ValueError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "UI_BOUNDARY_FAILURE")

    def do_POST(self) -> None:
        try:
            if not self._local_host_allowed() or not self._same_origin_allowed():
                self._error(HTTPStatus.FORBIDDEN, "SAME_ORIGIN_REQUIRED")
                return
            parsed = urlsplit(self.path)
            if parsed.path != "/api/jobs":
                self._error(HTTPStatus.NOT_FOUND, "RESOURCE_NOT_FOUND")
                return
            content_type = self.headers.get("Content-Type", "").split(";", maxsplit=1)[0].strip()
            if content_type != "application/json":
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "JSON_REQUIRED")
                return
            length_text = self.headers.get("Content-Length")
            if length_text is None:
                self._error(HTTPStatus.LENGTH_REQUIRED, "CONTENT_LENGTH_REQUIRED")
                return
            length = int(length_text)
            if length <= 0 or length > _MAX_REQUEST_BYTES:
                self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "REQUEST_TOO_LARGE")
                return
            request = PilotUiJobStartRequest.model_validate_json(self.rfile.read(length))
            status = self.server.ui_jobs.start(request)
            self._json(HTTPStatus.ACCEPTED, status.model_dump(mode="json"))
        except ValidationError:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST")
        except PilotUiBoundaryError as error:
            self._boundary_error(error)
        except (OSError, TypeError, ValueError):
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST")

    def do_OPTIONS(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED")

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _asset(self, name: str, media_type: str) -> None:
        data = files("labcourt.pilot_ui_web").joinpath(name).read_bytes()
        self._bytes(
            HTTPStatus.OK,
            data,
            media_type,
            cache_control="no-store",
        )

    def _video(self, source: PilotUiVideoSource) -> None:
        with (
            SecureWorkspace(
                source.workspace_root,
                max_file_bytes=self.server.ui_service.config.storage.max_media_bytes,
            ) as workspace,
            workspace.open_verified_video(
                source.relative_path,
                self.server.ui_service.config.storage.max_media_bytes,
            ) as opened,
        ):
            if (
                opened.input_file_sha256 != source.expected_sha256
                or opened.size_bytes != source.size_bytes
            ):
                raise PilotUiBoundaryError("MEDIA_NOT_VERIFIED")
            start, end, partial = self._requested_range(opened.size_bytes)
            length = end - start + 1
            status = HTTPStatus.PARTIAL_CONTENT if partial else HTTPStatus.OK
            self.send_response(status)
            self._security_headers(cache_control="private, max-age=3600")
            self.send_header("Content-Type", source.media_type)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(length))
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
                            raise OSError("verified video ended before its inspected size")
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                return

    def _requested_range(self, size_bytes: int) -> tuple[int, int, bool]:
        value = self.headers.get("Range")
        if value is None:
            return 0, size_bytes - 1, False
        matched = _RANGE.fullmatch(value.strip())
        if matched is None:
            self._range_error(size_bytes)
        start_text = matched.group("start")
        end_text = matched.group("end")
        if not start_text and not end_text:
            self._range_error(size_bytes)
        if start_text:
            start = int(start_text)
            end = int(end_text) if end_text else size_bytes - 1
        else:
            suffix = int(end_text)
            if suffix <= 0:
                self._range_error(size_bytes)
            start = max(0, size_bytes - suffix)
            end = size_bytes - 1
        if start >= size_bytes or end < start:
            self._range_error(size_bytes)
        return start, min(end, size_bytes - 1), True

    def _range_error(self, size_bytes: int) -> NoReturn:
        payload = PilotUiErrorResponse(reason_code="RANGE_NOT_SATISFIABLE")
        data = canonical_json(payload.model_dump(mode="json")).encode("utf-8")
        self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
        self._security_headers(cache_control="no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Range", f"bytes */{size_bytes}")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        raise _ResponseComplete

    def _boundary_error(self, error: PilotUiBoundaryError) -> None:
        if error.reason_code in {"RUN_NOT_FOUND", "VIDEO_NOT_FOUND", "RESOURCE_NOT_FOUND"}:
            status = HTTPStatus.NOT_FOUND
        elif error.reason_code == "JOB_ALREADY_RUNNING":
            status = HTTPStatus.CONFLICT
        else:
            status = HTTPStatus.CONFLICT
        self._error(status, error.reason_code)

    def _error(self, status: HTTPStatus, reason_code: str) -> None:
        payload = PilotUiErrorResponse(reason_code=reason_code)
        self._json(status, payload.model_dump(mode="json"))

    def _json(self, status: HTTPStatus, payload: object) -> None:
        data = canonical_json(payload).encode("utf-8")
        self._bytes(status, data, "application/json; charset=utf-8", cache_control="no-store")

    def _bytes(
        self,
        status: HTTPStatus,
        data: bytes,
        media_type: str,
        *,
        cache_control: str,
    ) -> None:
        self.send_response(status)
        self._security_headers(cache_control=cache_control)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _security_headers(self, *, cache_control: str) -> None:
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; img-src 'self' data:; media-src 'self'; "
            "style-src 'self'; script-src 'self'; connect-src 'self'",
        )

    def _local_host_allowed(self) -> bool:
        host = self.headers.get("Host", "").lower()
        hostname = host.split(":", maxsplit=1)[0]
        return hostname in {"127.0.0.1", "localhost"}

    def _same_origin_allowed(self) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        return origin in {
            f"http://{self.headers.get('Host', '')}",
            f"http://127.0.0.1:{self.server.server_port}",
            f"http://localhost:{self.server.server_port}",
        }


class _ResponseComplete(Exception):
    pass


def build_pilot_ui_server(
    *,
    project_root: Path,
    config_path: Path,
    port: int,
    runner: _Runner | None = None,
) -> PilotUiHttpServer:
    """Build a loopback server; port zero is accepted for isolated tests."""

    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("pilot UI port must be from zero through 65535")
    service = PilotUiService(project_root=project_root, config_path=config_path)
    jobs = (
        PilotUiJobManager(service=service)
        if runner is None
        else PilotUiJobManager(service=service, runner=runner)
    )
    return PilotUiHttpServer(("127.0.0.1", port), service=service, jobs=jobs)


def run_pilot_ui_server(
    *,
    project_root: Path,
    config_path: Path,
    port: int,
    open_browser: bool,
) -> None:
    """Serve until interrupted, optionally opening the system browser once bound."""

    server = build_pilot_ui_server(
        project_root=project_root,
        config_path=config_path,
        port=port,
    )
    url = f"http://127.0.0.1:{server.server_port}/"
    if open_browser:
        webbrowser.open(url, new=2)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


__all__ = ["PilotUiHttpServer", "build_pilot_ui_server", "run_pilot_ui_server"]
