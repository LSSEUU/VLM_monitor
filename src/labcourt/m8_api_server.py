"""Authenticated loopback-only HTTP adapter for M8 campus operations."""

from __future__ import annotations

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
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_api_authentication import (
    M8AuthenticationError,
    M8AuthenticationFailureCode,
    M8RequestAuthenticator,
)
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
    M8OperationsApiService,
)
from labcourt.services.m8_projection_api import M8ProjectionApiService

_MAX_REQUEST_BYTES = 64 * 1024


class M8ApiHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        service: M8OperationsApiService,
        knowledge_service: M8KnowledgeApiService,
        projection_service: M8ProjectionApiService,
        authenticator: M8RequestAuthenticator,
    ) -> None:
        super().__init__(server_address, M8ApiRequestHandler)
        self.api_service = service
        self.knowledge_service = knowledge_service
        self.projection_service = projection_service
        self.api_authenticator = authenticator


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
    projection_service: M8ProjectionApiService,
    authenticator: M8RequestAuthenticator,
) -> M8ApiHttpServer:
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("M8 API port must be from zero through 65535")
    if not isinstance(service, M8OperationsApiService):
        raise TypeError("M8 API requires an operations service")
    if not isinstance(knowledge_service, M8KnowledgeApiService):
        raise TypeError("M8 API requires a knowledge service")
    if not isinstance(projection_service, M8ProjectionApiService):
        raise TypeError("M8 API requires a projection service")
    if authenticator is None:
        raise TypeError("M8 API requires an explicit authenticator")
    return M8ApiHttpServer(
        ("127.0.0.1", port),
        service=service,
        knowledge_service=knowledge_service,
        projection_service=projection_service,
        authenticator=authenticator,
    )


__all__ = ["M8ApiHttpServer", "build_m8_api_server"]
