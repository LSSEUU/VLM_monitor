"""Same-origin HTML and typed API adapter for the campus platform Demo."""

from __future__ import annotations

import sqlite3
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from importlib.resources import files
from typing import Any

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_agent_chat import (
    M8AgentConversationCreateRequestV1,
    M8AgentFailureCode,
    M8AgentTurnRequestV1,
)
from labcourt.contracts.m8_api import (
    M8ApiErrorReason,
    M8ApiKnowledgeQueryRequestV1,
    M8ApiPrincipalV1,
)
from labcourt.contracts.m8_calibration_api import (
    M8CalibrationDatasetCreateRequestV1,
    M8CalibrationFitRequestV1,
)
from labcourt.contracts.m8_evaluation import (
    MAX_M8_EVALUATION_MEDIA_BYTES,
    M8EvaluationCampaignCreateRequestV1,
    M8EvaluationCampaignStartRequestV1,
    M8EvaluationGroundTruthImportRequestV1,
    M8EvaluationGroundTruthV1,
    M8EvaluationMediaImportRequestV1,
)
from labcourt.contracts.m8_feishu_live import (
    M8FeishuDutyRouteRevisionRequestV1,
    M8FeishuNotificationDispatchRequestV1,
    M8FeishuTestCardDispatchRequestV1,
)
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
from labcourt.ports.m8_agent_chat import (
    M8AgentConversationRepositoryError,
    M8AgentProviderError,
)
from labcourt.ports.m8_api_authentication import M8AuthenticationError
from labcourt.services.m8_agent_chat import M8AgentChatService
from labcourt.services.m8_calibration_api import M8CalibrationApiService
from labcourt.services.m8_evaluation import M8EvaluationService
from labcourt.services.m8_feishu_live_api import M8FeishuLiveApiService
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
        "/app/evaluation",
    }
)
_ASSETS = {
    "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/assets/agent-chat.css": ("agent-chat.css", "text/css; charset=utf-8"),
    "/assets/agent-chat.js": ("agent-chat.js", "text/javascript; charset=utf-8"),
    "/assets/feishu-live.css": ("feishu-live.css", "text/css; charset=utf-8"),
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
_MAX_EVALUATION_JSON_BYTES = 8 * 1024 * 1024
_MAX_MULTIPART_OVERHEAD_BYTES = 1024 * 1024


class M8PlatformHttpServer(M8ApiHttpServer):
    platform_service: M8PlatformDemoService
    agent_chat_service: M8AgentChatService
    feishu_live_service: M8FeishuLiveApiService
    evaluation_service: M8EvaluationService
    calibration_service: M8CalibrationApiService
    platform_role_tokens: dict[M8ActorRole, str]

    def server_close(self) -> None:
        self.evaluation_service.close()
        super().server_close()


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
            if segments == ("api", "m8", "agent", "status"):
                agent_status = self.server.agent_chat_service.status(principal)
                self._json(HTTPStatus.OK, agent_status.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "agent", "conversations"):
                agent_conversations = self.server.agent_chat_service.conversations(principal)
                self._json(
                    HTTPStatus.OK,
                    tuple(item.model_dump(mode="json") for item in agent_conversations),
                )
                return
            if len(segments) == 5 and segments[:4] == ("api", "m8", "agent", "conversations"):
                agent_conversation = self.server.agent_chat_service.conversation(
                    principal, segments[4]
                )
                self._json(HTTPStatus.OK, agent_conversation.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "reservations"):
                self._json(
                    HTTPStatus.OK,
                    self.server.platform_service.reservations(principal),
                )
                return
            if segments == ("api", "m8", "integrations", "feishu", "status"):
                feishu_status = self.server.platform_service.feishu_status(principal)
                self._json(HTTPStatus.OK, feishu_status.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "integrations", "feishu", "runtime-status"):
                runtime = self.server.feishu_live_service.runtime_status(principal)
                self._json(HTTPStatus.OK, runtime.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "integrations", "feishu", "duty-route"):
                route = self.server.feishu_live_service.duty_route(principal)
                self._json(
                    HTTPStatus.OK,
                    None if route is None else route.model_dump(mode="json"),
                )
                return
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "agent", "conversations")
                and segments[5] == "channel-projection"
            ):
                projection = self.server.feishu_live_service.channel_projection(
                    principal, segments[4]
                )
                self._json(
                    HTTPStatus.OK,
                    None if projection is None else projection.model_dump(mode="json"),
                )
                return
            if segments == ("api", "m8", "evaluation", "dashboard"):
                dashboard = self.server.evaluation_service.dashboard(principal)
                self._json(HTTPStatus.OK, dashboard.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "evaluation", "calibration"):
                calibration_dashboard = self.server.calibration_service.dashboard(principal)
                self._json(HTTPStatus.OK, calibration_dashboard.model_dump(mode="json"))
                return
            if len(segments) == 6 and segments[:5] == (
                "api",
                "m8",
                "evaluation",
                "calibration",
                "reports",
            ):
                report = self.server.calibration_service.report(principal, segments[5])
                self._json(HTTPStatus.OK, report.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "evaluation", "media"):
                media = self.server.evaluation_service.media(principal)
                self._json(
                    HTTPStatus.OK,
                    tuple(item.model_dump(mode="json") for item in media),
                )
                return
            if segments == ("api", "m8", "evaluation", "campaigns"):
                campaigns = self.server.evaluation_service.campaigns(principal)
                self._json(
                    HTTPStatus.OK,
                    tuple(item.model_dump(mode="json") for item in campaigns),
                )
                return
            if len(segments) == 5 and segments[:4] == (
                "api",
                "m8",
                "evaluation",
                "campaigns",
            ):
                campaign = self.server.evaluation_service.campaign(principal, segments[4])
                self._json(HTTPStatus.OK, campaign.model_dump(mode="json"))
                return
            if len(segments) == 5 and segments[:4] == (
                "api",
                "m8",
                "evaluation",
                "runs",
            ):
                evaluation_run = self.server.evaluation_service.run(principal, segments[4])
                self._json(HTTPStatus.OK, evaluation_run.model_dump(mode="json"))
                return
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "evaluation", "runs")
                and segments[5] == "risk-assessment"
            ):
                assessment = self.server.calibration_service.risk_assessment(principal, segments[4])
                self._json(HTTPStatus.OK, assessment.model_dump(mode="json"))
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
                current_scenario = self.server.platform_service.current_run(principal)
                self._json(
                    HTTPStatus.OK,
                    current_scenario.model_dump(mode="json")
                    if current_scenario is not None
                    else None,
                )
                return
            if segments == ("api", "m8", "notification-conversations"):
                notification_conversations = (
                    self.server.platform_service.notification_conversations(principal)
                )
                self._json(
                    HTTPStatus.OK,
                    tuple(item.model_dump(mode="json") for item in notification_conversations),
                )
                return
            if len(segments) == 4 and segments[:3] == (
                "api",
                "m8",
                "notification-conversations",
            ):
                notification_conversation = self.server.platform_service.notification_conversation(
                    principal, segments[3]
                )
                self._json(HTTPStatus.OK, notification_conversation.model_dump(mode="json"))
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
                scenario_run = self.server.platform_service.scenario_run(principal, segments[4])
                self._json(HTTPStatus.OK, scenario_run.model_dump(mode="json"))
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
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "demo", "scenario-runs")
                and segments[5] == "source-video"
            ):
                source = self.server.platform_service.scenario_source_video(principal, segments[4])
                self._pilot_video(source)
                return
        except M8AuthenticationError as error:
            self._authentication_error(error)
            return
        except M8ApiServiceError as error:
            self._service_error(error)
            return
        except M8AgentConversationRepositoryError as error:
            self._agent_repository_error(error)
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
            if segments == ("api", "m8", "agent", "conversations"):
                M8AgentConversationCreateRequestV1.model_validate_json(self._json_body())
                conversation = self.server.agent_chat_service.create_conversation(principal)
                self._json(HTTPStatus.CREATED, conversation.model_dump(mode="json"))
                return
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "agent", "conversations")
                and segments[5] == "turns"
            ):
                turn_request = M8AgentTurnRequestV1.model_validate_json(self._json_body())
                if "text/event-stream" in self.headers.get("Accept", ""):
                    self._agent_event_stream(principal, segments[4], turn_request)
                else:
                    completion = self.server.agent_chat_service.complete_turn(
                        principal, segments[4], turn_request
                    )
                    self._json(HTTPStatus.OK, completion.model_dump(mode="json"))
                return
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
            if segments == (
                "api",
                "m8",
                "integrations",
                "feishu",
                "duty-route-revisions",
            ):
                route_request = M8FeishuDutyRouteRevisionRequestV1.model_validate_json(
                    self._json_body()
                )
                route = self.server.feishu_live_service.revise_duty_route(principal, route_request)
                self._json(HTTPStatus.CREATED, route.model_dump(mode="json"))
                return
            if segments == (
                "api",
                "m8",
                "integrations",
                "feishu",
                "test-card-dispatches",
            ):
                test_dispatch_request = M8FeishuTestCardDispatchRequestV1.model_validate_json(
                    self._json_body()
                )
                test_dispatch_receipt = self.server.feishu_live_service.dispatch_test_card(
                    principal, test_dispatch_request
                )
                self._json(HTTPStatus.OK, test_dispatch_receipt.model_dump(mode="json"))
                return
            if (
                len(segments) == 5
                and segments[:3] == ("api", "m8", "notifications")
                and segments[4] == "feishu-dispatches"
            ):
                notification_dispatch_request = (
                    M8FeishuNotificationDispatchRequestV1.model_validate_json(self._json_body())
                )
                notification_dispatch_receipt = (
                    self.server.feishu_live_service.dispatch_notification(
                        principal, segments[3], notification_dispatch_request
                    )
                )
                self._json(
                    HTTPStatus.ACCEPTED,
                    notification_dispatch_receipt.model_dump(mode="json"),
                )
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
            if segments == ("api", "m8", "evaluation", "media", "uploads"):
                display_name, body = self._evaluation_upload()
                asset = self.server.evaluation_service.upload_media(
                    principal,
                    display_name=display_name,
                    body=body,
                )
                self._json(HTTPStatus.CREATED, asset.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "evaluation", "media", "imports"):
                media_import_request = M8EvaluationMediaImportRequestV1.model_validate_json(
                    self._evaluation_json_body()
                )
                media = self.server.evaluation_service.import_media(principal, media_import_request)
                self._json(
                    HTTPStatus.CREATED,
                    tuple(item.model_dump(mode="json") for item in media),
                )
                return
            if segments == ("api", "m8", "evaluation", "ground-truth-imports"):
                truth_import_request = M8EvaluationGroundTruthImportRequestV1.model_validate_json(
                    self._evaluation_json_body()
                )
                labels = self.server.evaluation_service.import_ground_truth(
                    principal, truth_import_request
                )
                self._json(
                    HTTPStatus.CREATED,
                    tuple(item.model_dump(mode="json") for item in labels),
                )
                return
            if segments == ("api", "m8", "evaluation", "campaigns"):
                campaign_request = M8EvaluationCampaignCreateRequestV1.model_validate_json(
                    self._evaluation_json_body()
                )
                campaign = self.server.evaluation_service.create_campaign(
                    principal, campaign_request
                )
                self._json(HTTPStatus.CREATED, campaign.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "evaluation", "calibration", "datasets"):
                calibration_dataset_request = (
                    M8CalibrationDatasetCreateRequestV1.model_validate_json(
                        self._evaluation_json_body()
                    )
                )
                manifest = self.server.calibration_service.create_dataset(
                    principal,
                    calibration_dataset_request,
                )
                self._json(HTTPStatus.CREATED, manifest.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "evaluation", "calibration", "fits"):
                calibration_fit_request = M8CalibrationFitRequestV1.model_validate_json(
                    self._evaluation_json_body()
                )
                calibration_fit_result = self.server.calibration_service.fit(
                    principal,
                    calibration_fit_request,
                )
                self._json(HTTPStatus.OK, calibration_fit_result.model_dump(mode="json"))
                return
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "evaluation", "campaigns")
                and segments[5] == "start"
            ):
                M8EvaluationCampaignStartRequestV1.model_validate_json(self._evaluation_json_body())
                campaign = self.server.evaluation_service.start_campaign(principal, segments[4])
                self._json(HTTPStatus.ACCEPTED, campaign.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "demo", "reset"):
                M8PlatformResetRequestV1.model_validate_json(self._json_body())
                result = self.server.platform_service.reset(principal)
                self._json(HTTPStatus.OK, result.model_dump(mode="json"))
                return
            if segments == ("api", "m8", "agent", "queries"):
                agent_request = M8PlatformAgentQueryRequestV1.model_validate_json(self._json_body())
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
                    (request_v2.source_case_authority_sha256 if request_v2 is not None else None),
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
        except M8AgentConversationRepositoryError as error:
            self._agent_repository_error(error)
            return
        except M8AgentProviderError as error:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"failure_code": error.failure_code.value},
            )
            return
        except (TypeError, ValueError, ContractViolation, ValidationError):
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
            return
        except (OSError, sqlite3.DatabaseError, RepositoryIntegrityError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        segments = self._segments()
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
            if len(segments) == 5 and segments[:4] == (
                "api",
                "m8",
                "agent",
                "conversations",
            ):
                receipt = self.server.agent_chat_service.remove_conversation(principal, segments[4])
                self._json(HTTPStatus.OK, receipt.model_dump(mode="json"))
                return
        except M8AuthenticationError as error:
            self._authentication_error(error)
            return
        except M8ApiServiceError as error:
            self._service_error(error)
            return
        except M8AgentConversationRepositoryError as error:
            self._agent_repository_error(error)
            return
        except (TypeError, ValueError, ContractViolation, ValidationError):
            self._error(HTTPStatus.BAD_REQUEST, M8ApiErrorReason.INVALID_REQUEST)
            return
        except (OSError, sqlite3.DatabaseError, RepositoryIntegrityError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_PUT(self) -> None:
        segments = self._segments()
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
            if (
                len(segments) == 6
                and segments[:4] == ("api", "m8", "evaluation", "media")
                and segments[5:] == ("ground-truth",)
            ):
                truth = M8EvaluationGroundTruthV1.model_validate_json(self._evaluation_json_body())
                published = self.server.evaluation_service.put_ground_truth(
                    principal, segments[4], truth
                )
                self._json(HTTPStatus.OK, published.model_dump(mode="json"))
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
        self._error(HTTPStatus.NOT_FOUND, M8ApiErrorReason.RESOURCE_NOT_FOUND)

    def _agent_event_stream(
        self,
        principal: M8ApiPrincipalV1,
        conversation_id: str,
        request: M8AgentTurnRequestV1,
    ) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        disconnected = False
        for event in self.server.agent_chat_service.stream_turn(
            principal,
            conversation_id,
            request,
        ):
            if disconnected:
                continue
            payload = canonical_json(event.model_dump(mode="json"))
            body = f"event: {event.event_kind.value}\ndata: {payload}\n\n".encode()
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                disconnected = True
        self.close_connection = True

    def _agent_repository_error(self, error: M8AgentConversationRepositoryError) -> None:
        if error.failure_code == M8AgentFailureCode.CONVERSATION_NOT_FOUND:
            self._error(HTTPStatus.NOT_FOUND, M8ApiErrorReason.RESOURCE_NOT_FOUND)
        elif error.failure_code == M8AgentFailureCode.AUTHORITY_CHANGED:
            self._error(HTTPStatus.CONFLICT, M8ApiErrorReason.CONCURRENT_MODIFICATION)
        else:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, M8ApiErrorReason.INTERNAL_FAILURE)

    def _evaluation_json_body(self) -> bytes:
        content_type = self.headers.get("Content-Type", "").split(";", maxsplit=1)[0].strip()
        if content_type != "application/json":
            raise ValueError("M8 evaluation API requires application/json")
        length_text = self.headers.get("Content-Length")
        if length_text is None:
            raise ValueError("M8 evaluation API requires Content-Length")
        length = int(length_text)
        if length <= 0 or length > _MAX_EVALUATION_JSON_BYTES:
            raise ValueError("M8 evaluation JSON body is outside its bound")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("M8 evaluation JSON body ended early")
        return body

    def _evaluation_upload(self) -> tuple[str, bytes]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.casefold().startswith("multipart/form-data;"):
            raise ValueError("M8 evaluation upload requires multipart/form-data")
        length_text = self.headers.get("Content-Length")
        if length_text is None:
            raise ValueError("M8 evaluation upload requires Content-Length")
        length = int(length_text)
        maximum = MAX_M8_EVALUATION_MEDIA_BYTES + _MAX_MULTIPART_OVERHEAD_BYTES
        if length <= 0 or length > maximum:
            raise ValueError("M8 evaluation upload body is outside its bound")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("M8 evaluation upload ended early")
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + content_type.encode("ascii") + b"\r\n\r\n" + body
        )
        parts = tuple(message.iter_parts()) if message.is_multipart() else ()
        files = tuple(
            part
            for part in parts
            if part.get_content_disposition() == "form-data"
            and part.get_param("name", header="content-disposition") == "file"
        )
        if len(files) != 1 or len(parts) != 1:
            raise ValueError("M8 evaluation upload requires exactly one file part")
        filename = files[0].get_filename()
        payload = files[0].get_payload(decode=True)
        if not isinstance(filename, str) or not isinstance(payload, bytes):
            raise ValueError("M8 evaluation upload file is invalid")
        return filename, payload

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
    agent_chat_service: M8AgentChatService,
    feishu_live_service: M8FeishuLiveApiService,
    evaluation_service: M8EvaluationService,
    calibration_service: M8CalibrationApiService,
    role_tokens: dict[M8ActorRole, str],
    **kwargs: Any,
) -> M8PlatformHttpServer:
    port = kwargs.pop("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65_535:
        raise ValueError("M8 platform port must be an integer from 0 through 65535")
    server = M8PlatformHttpServer(("127.0.0.1", port), **kwargs)
    server.RequestHandlerClass = M8PlatformRequestHandler
    server.platform_service = platform_service
    server.agent_chat_service = agent_chat_service
    server.feishu_live_service = feishu_live_service
    server.evaluation_service = evaluation_service
    server.calibration_service = calibration_service
    server.platform_role_tokens = dict(role_tokens)
    return server


__all__ = ["M8PlatformHttpServer", "build_m8_platform_server"]
