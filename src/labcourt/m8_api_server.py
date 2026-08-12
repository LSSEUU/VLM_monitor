"""Authenticated loopback-only HTTP adapter for M8 campus operations."""

from __future__ import annotations

import re
import sqlite3
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import ValidationError

from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_api import (
    M8ApiCaseTransitionRequestV1,
    M8ApiErrorReason,
    M8ApiErrorResponseV1,
    M8ApiKnowledgeQueryRequestV1,
    M8ApiPrincipalV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_api_authentication import (
    M8AuthenticationError,
    M8AuthenticationFailureCode,
    M8RequestAuthenticator,
)
from labcourt.services.m8_commissioning_api import M8CommissioningApiService
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
    M8OperationsApiService,
)
from labcourt.services.m8_projection_api import M8ProjectionApiService
from labcourt.services.m8_recorded_media_api import M8RecordedMediaApiService
from labcourt.services.m8_rule_config_api import M8RuleConfigApiService
from labcourt.services.m8_user_permission_api import M8UserPermissionApiService

_MAX_REQUEST_BYTES = 64 * 1024
_STREAM_CHUNK_BYTES = 1024 * 1024
_RANGE = re.compile(r"bytes=(?P<start>\d*)-(?P<end>\d*)")


class M8ApiHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        service: M8OperationsApiService,
        knowledge_service: M8KnowledgeApiService,
        notification_service: M8NotificationApiService,
        projection_service: M8ProjectionApiService,
        commissioning_service: M8CommissioningApiService,
        authenticator: M8RequestAuthenticator,
        recorded_media_service: M8RecordedMediaApiService | None = None,
        user_permission_service: M8UserPermissionApiService | None = None,
        rule_config_service: M8RuleConfigApiService | None = None,
    ) -> None:
        super().__init__(server_address, M8ApiRequestHandler)
        self.api_service = service
        self.knowledge_service = knowledge_service
        self.notification_service = notification_service
        self.projection_service = projection_service
        self.commissioning_service = commissioning_service
        self.api_authenticator = authenticator
        self.recorded_media_service = recorded_media_service
        self.user_permission_service = user_permission_service
        self.rule_config_service = rule_config_service


class M8ApiRequestHandler(BaseHTTPRequestHandler):
    server: M8ApiHttpServer
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def do_GET(self) -> None:
        try:
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.LOCAL_HOST_REQUIRED)
                return
            principal = self.server.api_authenticator.authenticate(
                self.headers.get("Authorization")
            )
            segments = self._segments()
            if segments == ("api", "m8", "session"):
                session = self.server.api_service.session(principal)
                self._json(HTTPStatus.OK, session.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "cases"):
                if urlsplit(self.path).query:
                    self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
                    return
                cases = self.server.api_service.cases(principal)
                self._json(
                    HTTPStatus.OK,
                    [case.model_dump(mode="json") for case in cases],
                )
                return
            if segments == ("api", "m8", "users"):
                if urlsplit(self.path).query:
                    self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
                    return
                user_service = self.server.user_permission_service
                if user_service is None:
                    self._error(HTTPStatus.NOT_FOUND, M8ApiErrorReason.RESOURCE_NOT_FOUND)
                    return
                users = user_service.users(principal)
                self._json(
                    HTTPStatus.OK,
                    [user.model_dump(mode="json") for user in users],
                )
                return
            if segments == ("api", "m8", "rules"):
                if urlsplit(self.path).query:
                    self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
                    return
                rule_service = self.server.rule_config_service
                if rule_service is None:
                    self._error(HTTPStatus.NOT_FOUND, M8ApiErrorReason.RESOURCE_NOT_FOUND)
                    return
                policy = rule_service.current_policy(principal)
                self._json(HTTPStatus.OK, policy.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "notifications"):
                if urlsplit(self.path).query:
                    self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
                    return
                notifications = self.server.notification_service.notifications(principal)
                self._json(
                    HTTPStatus.OK,
                    [item.model_dump(mode="json") for item in notifications],
                )
                return
            if segments == ("api", "m8", "cameras"):
                if urlsplit(self.path).query:
                    self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
                    return
                media_service = self.server.recorded_media_service
                if media_service is None:
                    self._json(HTTPStatus.OK, [])
                    return
                cameras = media_service.cameras(principal)
                self._json(
                    HTTPStatus.OK,
                    [camera.model_dump(mode="json") for camera in cameras],
                )
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "cameras")
                and segments[4] in {"media", "media-metadata"}
            ):
                media_service = self.server.recorded_media_service
                if media_service is None:
                    self._error(HTTPStatus.NOT_FOUND, M8ApiErrorReason.RESOURCE_NOT_FOUND)
                    return
                if segments[4] == "media-metadata":
                    metadata = media_service.metadata(principal, segments[3])
                    self._json(HTTPStatus.OK, metadata.model_dump(mode="json"))
                    return
                self._recorded_media(media_service, principal, segments[3])
                return
            if len(segments) == 4 and segments[:3] == ("api", "m8", "notifications"):
                notification = self.server.notification_service.notification(
                    principal,
                    segments[3],
                )
                self._json(HTTPStatus.OK, notification.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "notifications")
                and segments[4] == "audit"
            ):
                audit = self.server.notification_service.audit(principal, segments[3])
                self._json(
                    HTTPStatus.OK,
                    [item.model_dump(mode="json") for item in audit],
                )
                return
            if len(segments) == 5 and segments[:3] == ("api", "m8", "campuses"):
                if segments[4] == "topology":
                    topology = self.server.api_service.topology(principal, segments[3])
                    self._json(HTTPStatus.OK, topology.model_dump(mode="json"))
                    return
                if segments[4] == "sources":
                    source_catalog = self.server.api_service.source_catalog(principal, segments[3])
                    self._json(HTTPStatus.OK, source_catalog.model_dump(mode="json"))
                    return
                if segments[4] == "operations-projection":
                    projection = self.server.projection_service.projection(
                        principal,
                        segments[3],
                    )
                    self._json(HTTPStatus.OK, projection.model_dump(mode="json"))
                    return
                if segments[4] in {"device-health", "sensors"}:
                    projection = self.server.projection_service.projection(
                        principal,
                        segments[3],
                    )
                    sources = projection.visible_projection.sources
                    if segments[4] == "sensors":
                        sources = tuple(
                            item
                            for item in sources
                            if item.source.source_kind.value == "SENSOR"
                        )
                    self._json(
                        HTTPStatus.OK,
                        [item.model_dump(mode="json") for item in sources],
                    )
                    return
            if len(segments) == 4 and segments[:3] == ("api", "m8", "cases"):
                case = self.server.api_service.case(principal, segments[3])
                self._json(HTTPStatus.OK, case.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "cases")
                and segments[4] == "audit"
            ):
                values = self.server.api_service.case_audit(principal, segments[3])
                self._json(
                    HTTPStatus.OK,
                    [value.model_dump(mode="json") for value in values],
                )
                return
            if len(segments) == 4 and segments[:3] == ("api", "m8", "sensor-polls"):
                poll = self.server.api_service.sensor_poll(principal, segments[3])
                self._json(HTTPStatus.OK, poll.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "adapter-candidates")
                and segments[4] == "readiness"
            ):
                if urlsplit(self.path).query:
                    self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
                    return
                readiness = self.server.commissioning_service.readiness(
                    principal,
                    segments[3],
                )
                self._json(HTTPStatus.OK, readiness.model_dump(mode="json"))
                return
            if len(segments) == 5 and segments[:4] == (
                "api",
                "m8",
                "knowledge",
                "catalogs",
            ):
                catalog = self.server.knowledge_service.current_catalog(principal, segments[4])
                self._json(HTTPStatus.OK, catalog.model_dump(mode="json"))
                return
            if len(segments) == 5 and segments[:4] == (
                "api",
                "m8",
                "knowledge",
                "answers",
            ):
                answer = self.server.knowledge_service.answer(principal, segments[4])
                self._json(HTTPStatus.OK, answer.model_dump(mode="json"))
                return
            self._error(HTTPStatus.NOT_FOUND, M8ApiErrorReason.RESOURCE_NOT_FOUND)
        except M8AuthenticationError as error:
            self._authentication_error(error)
        except M8ApiServiceError as error:
            self._service_error(error)
        except (TypeError, ValueError):
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
        except RepositoryIntegrityError:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)
        except ContractViolation:
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
        except (OSError, sqlite3.DatabaseError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)

    def do_POST(self) -> None:
        try:
            if not self._local_host_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.LOCAL_HOST_REQUIRED)
                return
            if not self._same_origin_allowed():
                self._error(HTTPStatus.FORBIDDEN, M8ApiErrorReason.FORBIDDEN)
                return
            principal = self.server.api_authenticator.authenticate(
                self.headers.get("Authorization")
            )
            segments = self._segments()
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "knowledge", "catalogs")
                and segments[5] == "queries"
            ):
                knowledge_request = M8ApiKnowledgeQueryRequestV1.model_validate_json(
                    self._json_body()
                )
                answer_value = self.server.knowledge_service.query(
                    principal,
                    segments[4],
                    knowledge_request,
                )
                self._json(HTTPStatus.OK, answer_value.model_dump(mode="json"))
                return
            if not (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "cases")
                and segments[4] == "transitions"
            ):
                self._error(HTTPStatus.NOT_FOUND, M8ApiErrorReason.RESOURCE_NOT_FOUND)
                return
            transition_request = M8ApiCaseTransitionRequestV1.model_validate_json(self._json_body())
            case_value = self.server.api_service.transition_case(
                principal,
                segments[3],
                transition_request,
            )
            self._json(HTTPStatus.OK, case_value.model_dump(mode="json"))
        except M8AuthenticationError as error:
            self._authentication_error(error)
        except M8ApiServiceError as error:
            self._service_error(error)
        except ValidationError:
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
        except RepositoryIntegrityError:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)
        except (ContractViolation, TypeError, ValueError):
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
        except (OSError, sqlite3.DatabaseError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)

    def do_OPTIONS(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, M8ApiErrorReason.METHOD_NOT_ALLOWED)

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _segments(self) -> tuple[str, ...]:
        path = urlsplit(self.path).path
        return tuple(unquote(item) for item in path.split("/") if item)

    def _json_body(self) -> bytes:
        content_type = self.headers.get("Content-Type", "").split(";", maxsplit=1)[0].strip()
        if content_type != "application/json":
            raise ValueError("M8 API requires application/json")
        length_text = self.headers.get("Content-Length")
        if length_text is None:
            raise ValueError("M8 API requires Content-Length")
        length = int(length_text)
        if length <= 0 or length > _MAX_REQUEST_BYTES:
            raise ValueError("M8 API request body is outside the bounded size")
        return self.rfile.read(length)

    def _recorded_media(
        self,
        service: M8RecordedMediaApiService,
        principal: M8ApiPrincipalV1,
        source_id: str,
    ) -> None:
        with service.open_verified(principal, source_id) as opened:
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
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if partial:
                self.send_header("Content-Range", f"bytes {start}-{end}/{opened.size_bytes}")
            self.end_headers()
            try:
                opened.handle.seek(start)
                remaining = length
                while remaining:
                    chunk = opened.handle.read(min(_STREAM_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise OSError("verified M8 media ended before its inspected size")
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                return

    def _requested_range(self, size_bytes: int) -> tuple[int, int, bool] | None:
        value = self.headers.get("Range")
        if value is None:
            return 0, size_bytes - 1, False
        matched = _RANGE.fullmatch(value.strip())
        if matched is None:
            self._range_error(size_bytes)
            return None
        start_text = matched.group("start")
        end_text = matched.group("end")
        if not start_text and not end_text:
            self._range_error(size_bytes)
            return None
        if start_text:
            start = int(start_text)
            end = int(end_text) if end_text else size_bytes - 1
        else:
            suffix = int(end_text)
            if suffix <= 0:
                self._range_error(size_bytes)
                return None
            start = max(0, size_bytes - suffix)
            end = size_bytes - 1
        if start >= size_bytes or end < start:
            self._range_error(size_bytes)
            return None
        return start, min(end, size_bytes - 1), True

    def _range_error(self, size_bytes: int) -> None:
        payload = M8ApiErrorResponseV1(reason_code=M8ApiErrorReason.INVALID_REQUEST)
        data = canonical_json(payload.model_dump(mode="json")).encode("utf-8")
        self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Range", f"bytes */{size_bytes}")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _authentication_error(self, error: M8AuthenticationError) -> None:
        reason = (
            M8ApiErrorReason.AUTHENTICATION_REQUIRED
            if error.reason_code == M8AuthenticationFailureCode.AUTHENTICATION_REQUIRED
            else M8ApiErrorReason.INVALID_CREDENTIAL
        )
        self._error(HTTPStatus.UNAUTHORIZED, reason, bearer=True)

    def _service_error(self, error: M8ApiServiceError) -> None:
        mapping = {
            M8ApiServiceFailureCode.FORBIDDEN: (
                HTTPStatus.FORBIDDEN,
                M8ApiErrorReason.FORBIDDEN,
            ),
            M8ApiServiceFailureCode.RESOURCE_NOT_FOUND: (
                HTTPStatus.NOT_FOUND,
                M8ApiErrorReason.RESOURCE_NOT_FOUND,
            ),
            M8ApiServiceFailureCode.CONCURRENT_MODIFICATION: (
                HTTPStatus.CONFLICT,
                M8ApiErrorReason.CONCURRENT_MODIFICATION,
            ),
            M8ApiServiceFailureCode.INVALID_REQUEST: (
                HTTPStatus.BAD_REQUEST,
                M8ApiErrorReason.INVALID_REQUEST,
            ),
            M8ApiServiceFailureCode.INTERNAL_FAILURE: (
                HTTPStatus.INTERNAL_SERVER_ERROR,
                M8ApiErrorReason.INTERNAL_FAILURE,
            ),
        }
        status, reason = mapping[error.reason_code]
        self._error(status, reason)

    def _error(
        self,
        status: HTTPStatus,
        reason: M8ApiErrorReason,
        *,
        bearer: bool = False,
    ) -> None:
        payload = M8ApiErrorResponseV1(reason_code=reason)
        self._json(status, payload.model_dump(mode="json"), bearer=bearer)

    def _json(
        self,
        status: HTTPStatus,
        payload: object,
        *,
        bearer: bool = False,
    ) -> None:
        data = canonical_json(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        if bearer:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            return

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


def build_m8_api_server(
    *,
    port: int,
    service: M8OperationsApiService,
    knowledge_service: M8KnowledgeApiService,
    notification_service: M8NotificationApiService,
    projection_service: M8ProjectionApiService,
    commissioning_service: M8CommissioningApiService,
    authenticator: M8RequestAuthenticator,
    recorded_media_service: M8RecordedMediaApiService | None = None,
    user_permission_service: M8UserPermissionApiService | None = None,
    rule_config_service: M8RuleConfigApiService | None = None,
) -> M8ApiHttpServer:
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("M8 API port must be from zero through 65535")
    if not isinstance(service, M8OperationsApiService):
        raise TypeError("M8 API requires an operations service")
    if not isinstance(knowledge_service, M8KnowledgeApiService):
        raise TypeError("M8 API requires a knowledge service")
    if not isinstance(notification_service, M8NotificationApiService):
        raise TypeError("M8 API requires a notification service")
    if not isinstance(projection_service, M8ProjectionApiService):
        raise TypeError("M8 API requires a projection service")
    if not isinstance(commissioning_service, M8CommissioningApiService):
        raise TypeError("M8 API requires a commissioning service")
    if authenticator is None:
        raise TypeError("M8 API requires an explicit authenticator")
    if recorded_media_service is not None and not isinstance(
        recorded_media_service, M8RecordedMediaApiService
    ):
        raise TypeError("M8 API requires a recorded media service or None")
    if user_permission_service is not None and not isinstance(
        user_permission_service, M8UserPermissionApiService
    ):
        raise TypeError("M8 API requires a user permission service or None")
    if rule_config_service is not None and not isinstance(
        rule_config_service, M8RuleConfigApiService
    ):
        raise TypeError("M8 API requires a rule config service or None")
    return M8ApiHttpServer(
        ("127.0.0.1", port),
        service=service,
        knowledge_service=knowledge_service,
        notification_service=notification_service,
        projection_service=projection_service,
        commissioning_service=commissioning_service,
        authenticator=authenticator,
        recorded_media_service=recorded_media_service,
        user_permission_service=user_permission_service,
        rule_config_service=rule_config_service,
    )


__all__ = ["M8ApiHttpServer", "build_m8_api_server"]
