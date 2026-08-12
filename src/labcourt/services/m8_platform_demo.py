"""Application service for the complete offline campus-operations Demo."""

from __future__ import annotations

import hashlib
import shutil
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.m8_offline_notification_channel import (
    DeterministicOfflineNotificationChannel,
)
from labcourt.adapters.m8_platform_pilot_fixture import (
    DeterministicRecordedPpePerceptionTransport,
    DeterministicRecordedPpeScreeningTransport,
)
from labcourt.adapters.simulated_sensors import DeterministicSimulatedSensorAdapter
from labcourt.adapters.storage.sqlite_m8_inventory_repository import SQLiteM8InventoryRepository
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.adapters.storage.sqlite_m8_sensor_persistence_repository import (
    SQLiteM8SensorPersistenceRepository,
)
from labcourt.application.m8_platform_bootstrap import (
    PLATFORM_BOOTSTRAP_RECEIPT_NAME,
    PLATFORM_CAMERA_ID,
    PLATFORM_CAMPUS_ID,
    PLATFORM_LOCATION_ID,
    PLATFORM_MEDIA_RECEIPT_NAME,
    PLATFORM_SCENARIO_STATE_NAME,
    PLATFORM_SMOKE_ID,
    PLATFORM_TEMPERATURE_ID,
    bootstrap_m8_platform_demo,
    load_m8_platform_bootstrap,
    platform_manifest,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_api import (
    M8ApiKnowledgeQueryRequestV1,
    M8ApiPrincipalV1,
)
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_notification_cards import (
    M8NotificationWorkflowManifestAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationReplyKind,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationAudienceKind,
    M8NotificationChannelKind,
    M8NotificationEscalationPolicyAuthorityV1,
    M8NotificationPlanAuthorityV1,
    M8NotificationPurpose,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
    M8NotificationTemplateAuthorityV1,
)
from labcourt.contracts.m8_platform_demo import (
    M8PlatformAgentActionKind,
    M8PlatformAgentQueryResponseV1,
    M8PlatformEvidenceViewV1,
    M8PlatformProposedActionV1,
    M8PlatformResetResponseV1,
    M8PlatformScenarioKind,
    M8PlatformScenarioRunV1,
    M8PlatformScenarioStage,
    M8PlatformScenarioStageV1,
    M8PlatformStageState,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorQuality,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)
from labcourt.contracts.pilot_ui import PilotUiJobStartRequest
from labcourt.exceptions import EvidenceMissing
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_notifications import M8NotificationService
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
    M8OperationsApiService,
)
from labcourt.services.pilot_a5 import run_pilot_a5
from labcourt.services.pilot_operations import build_expected_perception_manifest
from labcourt.services.pilot_ui import PilotUiBoundaryError, PilotUiJobManager, PilotUiService

_BUSY_TIMEOUT_MS = 5_000


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _workflow() -> M8NotificationWorkflowManifestAuthorityV1:
    return M8NotificationWorkflowManifestAuthorityV1(
        card_renderer_manifest_id=platform_manifest("platform-card-renderer-v1"),
        dispatch_request_manifest_id=platform_manifest("platform-dispatch-request-v1"),
        transition_command_manifest_id=platform_manifest("platform-notification-transition-v1"),
        raw_storage_manifest_id=platform_manifest("platform-notification-raw-store-v1"),
        audit_manifest_id=platform_manifest("platform-notification-audit-v1"),
        workflow_manifest_id=platform_manifest("platform-notification-workflow-v1"),
    )


def _notification_channel() -> DeterministicOfflineNotificationChannel:
    return DeterministicOfflineNotificationChannel(
        M8NotificationChannelCapabilityAuthorityV1(
            adapter_id="m8-platform-local-message-fake",
            adapter_revision="platform-demo-v1",
            channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
            request_timeout_ms=1_000,
            network_required=False,
            offline_capable=True,
            simulated=True,
            inbound_response_supported=True,
            adapter_manifest_id=platform_manifest("platform-local-message-adapter-v1"),
        )
    )


def _pending_stages() -> tuple[M8PlatformScenarioStageV1, ...]:
    return tuple(
        M8PlatformScenarioStageV1(
            stage=stage,
            state=(
                M8PlatformStageState.RUNNING
                if stage == M8PlatformScenarioStage.VIDEO
                else M8PlatformStageState.PENDING
            ),
            summary="正在准备录像" if stage == M8PlatformScenarioStage.VIDEO else "尚未生成",
        )
        for stage in M8PlatformScenarioStage
    )


class M8PlatformDemoService:
    """Compose existing Pilot, sensor, Case, notification and knowledge services."""

    def __init__(
        self,
        *,
        project_root: Path,
        database_path: Path,
        input_media_path: Path,
        api_service: M8OperationsApiService,
        knowledge_service: M8KnowledgeApiService,
        pilot_service: PilotUiService,
    ) -> None:
        self.project_root = project_root.absolute()
        self.database_path = database_path.absolute()
        self.artifact_root = self.database_path.parent
        self.input_media_path = input_media_path.absolute()
        self.api_service = api_service
        self.knowledge_service = knowledge_service
        self.pilot_service = pilot_service
        self._operation_lock = threading.Lock()
        self._screening_transport = DeterministicRecordedPpeScreeningTransport()
        perception = DeterministicRecordedPpePerceptionTransport(
            build_expected_perception_manifest(pilot_service.config)
        )

        def runner(**kwargs):
            return run_pilot_a5(
                **kwargs,
                perception_transport=perception,
                screening_transport=self._screening_transport,
            )

        self.pilot_jobs = PilotUiJobManager(service=pilot_service, runner=runner)

    def reservations(self, principal: M8ApiPrincipalV1) -> tuple[dict[str, object], ...]:
        actor = self._actor(principal)
        reservation = load_m8_platform_bootstrap(self.artifact_root).reservation
        if actor.role == M8ActorRole.STUDENT and reservation.actor_id != actor.actor_id:
            return ()
        return (reservation.model_dump(mode="json"),)

    def start_scenario(
        self,
        principal: M8ApiPrincipalV1,
        kind: M8PlatformScenarioKind,
    ) -> M8PlatformScenarioRunV1:
        self._require_role(principal, M8ActorRole.OPERATIONS)
        if not self._operation_lock.acquire(blocking=False):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        try:
            if self.pilot_jobs.snapshot().state == "RUNNING":
                raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
            if kind == M8PlatformScenarioKind.PPE_GOGGLES_MISSING:
                return self._start_ppe()
            return self._run_smoke_temperature()
        finally:
            self._operation_lock.release()

    def current_run(self, principal: M8ApiPrincipalV1) -> M8PlatformScenarioRunV1 | None:
        self._actor(principal)
        path = self.artifact_root / PLATFORM_SCENARIO_STATE_NAME
        if not path.is_file():
            return None
        run = M8PlatformScenarioRunV1.model_validate_json(path.read_bytes())
        return self._refresh_ppe(run) if run.state == "RUNNING" else run

    def scenario_run(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
    ) -> M8PlatformScenarioRunV1:
        run = self.current_run(principal)
        if run is None or run.run_id != run_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        return run

    def read_evidence(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        evidence_id: str,
    ):
        run = self.scenario_run(principal, run_id)
        if not any(item.evidence_id == evidence_id for item in run.evidence):
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        try:
            return self.pilot_service.read_evidence(run_id, evidence_id)
        except PilotUiBoundaryError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error

    def dispatch_case_notification(
        self,
        principal: M8ApiPrincipalV1,
        case_id: str,
        kind: str,
    ):
        self._require_role(principal, M8ActorRole.SAFETY_OFFICER)
        operations = self._operations()
        case = operations.get_current_operational_case(case_id)
        subject = case.audit_event.case_authority.subject_actor_id
        if subject is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        if kind == "APPEAL_OUTCOME" and case.status != M8OperationalCaseStatus.APPEAL_RESOLVED:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        purpose = (
            M8NotificationPurpose.APPEAL_OUTCOME
            if kind == "APPEAL_OUTCOME"
            else M8NotificationPurpose.CASE_UPDATED
        )
        return self._notify_case(
            case_id=case_id,
            target_actor_id=subject,
            purpose=purpose,
            audience=M8NotificationAudienceKind.CASE_SUBJECT,
            inbound_response_supported=kind == "CASE_UPDATED",
        )

    def reply_notification(
        self,
        principal: M8ApiPrincipalV1,
        notification_id: str,
        reply_kind: M8NotificationReplyKind,
        body: str,
    ):
        actor = self._require_role(principal, M8ActorRole.STUDENT)
        notifications = self._notifications()
        current = notifications.get_current_notification(notification_id)
        plan = current.audit_event.notification_authority.plan
        if plan.target.actor_id != actor.actor_id or not plan.target.inbound_response_supported:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        raw = body.encode("utf-8")
        service = M8NotificationService(
            notifications, self._operations(), _notification_channel(), _workflow()
        )
        supporting = (
            self._operations()
            .get_current_operational_case(plan.case_id)
            .audit_event.case_authority.create_command.trigger_authorities
        )
        return service.respond(
            notification_id,
            actor.actor_id,
            reply_kind,
            hashlib.sha256(raw).hexdigest(),
            raw,
            _utc_now(),
            supporting,
        )

    def acknowledge_notification(
        self,
        principal: M8ApiPrincipalV1,
        notification_id: str,
    ):
        actor = self._require_role(principal, M8ActorRole.STUDENT)
        notifications = self._notifications()
        current = notifications.get_current_notification(notification_id)
        plan = current.audit_event.notification_authority.plan
        if plan.target.actor_id != actor.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        service = M8NotificationService(
            notifications, self._operations(), _notification_channel(), _workflow()
        )
        supporting = (
            self._operations()
            .get_current_operational_case(plan.case_id)
            .audit_event.case_authority.create_command.trigger_authorities
        )
        return service.acknowledge(
            notification_id,
            actor.actor_id,
            _utc_now(),
            supporting,
        )

    def agent_query(
        self,
        principal: M8ApiPrincipalV1,
        query: str,
    ) -> M8PlatformAgentQueryResponseV1:
        actor = self._actor(principal)
        normalized = query.casefold()
        cases = self.api_service.cases(principal)
        if actor.role == M8ActorRole.OPERATIONS and any(
            word in normalized for word in ("触发", "烟雾", "温度", "复位", "reset")
        ):
            reset = "复位" in normalized or "reset" in normalized
            return M8PlatformAgentQueryResponseV1(
                outcome="ANSWERED",
                answer=("可生成复位操作卡。" if reset else "可生成烟雾与温度联动场景卡。"),
                proposed_action=M8PlatformProposedActionV1(
                    action_kind=(
                        M8PlatformAgentActionKind.RESET_DEMO
                        if reset
                        else M8PlatformAgentActionKind.RUN_SCENARIO
                    ),
                    target_ref=("platform-demo" if reset else "smoke-temperature-emergency"),
                    current_version=0,
                    impact_summary=(
                        "归档当前 Demo 并恢复无案件基线"
                        if reset
                        else "写入两路模拟信号并自动建立紧急案件"
                    ),
                    request_payload=(
                        {"explicit_human_confirmation": True}
                        if reset
                        else {
                            "scenario_kind": "SMOKE_TEMPERATURE_EMERGENCY",
                            "explicit_human_confirmation": True,
                        }
                    ),
                ),
            )
        if (
            actor.role == M8ActorRole.SAFETY_OFFICER
            and cases
            and any(word in normalized for word in ("处置", "确认", "案件"))
        ):
            pending = next(
                (
                    item
                    for item in cases
                    if item.status == M8OperationalCaseStatus.PENDING_VERIFICATION
                ),
                None,
            )
            if pending is None:
                return M8PlatformAgentQueryResponseV1(
                    outcome="ANSWERED",
                    answer="当前没有处于待核实状态的案件；请在案件中心查看其他可用动作。",
                    source_refs=tuple(item.case_id for item in cases),
                )
            case = pending
            return M8PlatformAgentQueryResponseV1(
                outcome="ANSWERED",
                answer="已按当前案件版本生成处置操作卡，确认后仍由案件接口复核权限和版本。",  # noqa: RUF001
                source_refs=(case.case_id,),
                proposed_action=M8PlatformProposedActionV1(
                    action_kind=M8PlatformAgentActionKind.CASE_TRANSITION,
                    target_ref=case.case_id,
                    current_version=case.case_version,
                    impact_summary="将待核实案件转为已确认，后续可通知关联学生",
                    request_payload={
                        "action": "CONFIRM",
                        "source_case_version": case.case_version,
                        "source_case_authority_sha256": case.case_document_sha256,
                        "source_status": case.status.value,
                        "explicit_human_confirmation": True,
                    },
                ),
            )
        if "案件" in normalized:
            return M8PlatformAgentQueryResponseV1(
                outcome="ANSWERED",
                answer=f"当前权限范围内共有 {len(cases)} 个案件。",
                source_refs=tuple(item.case_id for item in cases),
            )
        if any(word in normalized for word in ("设备", "传感器", "地图")):
            projection = self.api_service.source_catalog(principal, PLATFORM_CAMPUS_ID)
            return M8PlatformAgentQueryResponseV1(
                outcome="ANSWERED",
                answer=(
                    f"当前校区登记 {len(projection.catalog.sources)} 个数据源，"  # noqa: RUF001
                    "状态来自运营投影。"
                ),
                source_refs=tuple(item.source_id for item in projection.catalog.sources),
            )
        try:
            catalog = self.knowledge_service.current_catalog(principal, "campus-safety-knowledge")
            request = M8ApiKnowledgeQueryRequestV1(
                query_text=query,
                locale="zh-CN",
                as_of=_utc_now(),
                allowed_document_types=tuple(
                    sorted(M8KnowledgeDocumentType, key=lambda item: item.value)
                ),
                max_citations=3,
            )
            answer = self.knowledge_service.query(principal, catalog.catalog.catalog_id, request)
        except (EvidenceMissing, M8ApiServiceError, TypeError, ValueError):
            return M8PlatformAgentQueryResponseV1(
                outcome="NO_MATCH",
                answer="离线知识库中没有匹配答案；Agent 未执行任何操作。",  # noqa: RUF001
            )
        return M8PlatformAgentQueryResponseV1(
            outcome=answer.answer.outcome.value,
            answer=answer.answer.answer_text,
            source_refs=tuple(
                item.document.logical_document_id for item in answer.answer.citations
            ),
        )

    def reset(self, principal: M8ApiPrincipalV1) -> M8PlatformResetResponseV1:
        self._require_role(principal, M8ActorRole.OPERATIONS)
        if not self._operation_lock.acquire(blocking=False):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        try:
            if self.pilot_jobs.snapshot().state == "RUNNING":
                raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
            old = load_m8_platform_bootstrap(self.artifact_root)
            new_session = f"session-{uuid.uuid4().hex[:16]}"
            staging = self.artifact_root / f".reset-{new_session}"
            staging.mkdir(parents=False, exist_ok=False)
            staged_database = staging / self.database_path.name
            fresh = bootstrap_m8_platform_demo(
                staged_database, self.input_media_path, session_id=new_session
            )
            archive = self.artifact_root / "archive" / old.session_id
            archive.mkdir(parents=True, exist_ok=False)
            for path in self._archive_paths():
                if path.exists():
                    destination = archive / path.relative_to(self.artifact_root)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    path.replace(destination)
            staged_database.replace(self.database_path)
            for relative in (
                Path(PLATFORM_BOOTSTRAP_RECEIPT_NAME),
                Path(PLATFORM_MEDIA_RECEIPT_NAME),
                Path("media/camera-recorded-demo-01.mp4"),
            ):
                source = staging / relative
                destination = self.artifact_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source.replace(destination)
            shutil.rmtree(staging)
            return M8PlatformResetResponseV1(
                session_id=fresh.receipt.session_id,
                archived_session_id=old.session_id,
                archive_ref=f"archive/{old.session_id}",
                baseline_summary={
                    "locations": fresh.receipt.location_count,
                    "sources": fresh.receipt.source_count,
                    "cases": fresh.receipt.current_case_count,
                    "notifications": fresh.receipt.current_notification_count,
                },
            )
        finally:
            self._operation_lock.release()

    def _start_ppe(self) -> M8PlatformScenarioRunV1:
        dashboard = self.pilot_service.dashboard()
        video = next(
            (item for item in dashboard.videos if item.display_name == "goggles-missing.mp4"),
            None,
        )
        if video is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        run_id = f"platform-ppe-{uuid.uuid4().hex[:12]}"
        self.pilot_jobs.start(
            PilotUiJobStartRequest(video_id=video.video_id, run_id=run_id, resume=True)
        )
        run = M8PlatformScenarioRunV1(
            run_id=run_id,
            scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
            state="RUNNING",
            stages=_pending_stages(),
            model_or_fixture_id="fixture-ppe-screening-v1",
        )
        self._write_run(run)
        return run

    def _refresh_ppe(self, run: M8PlatformScenarioRunV1) -> M8PlatformScenarioRunV1:
        if run.scenario_kind != M8PlatformScenarioKind.PPE_GOGGLES_MISSING:
            return run
        job = self.pilot_jobs.snapshot()
        if job.run_id != run.run_id:
            failed = run.model_copy(
                update={
                    "state": "FAILED",
                    "failure_code": "PILOT_JOB_STATE_UNAVAILABLE",
                    "stages": tuple(
                        item.model_copy(
                            update={
                                "state": M8PlatformStageState.FAILED,
                                "summary": "服务重启后没有可恢复的进程内 Pilot 作业",
                            }
                        )
                        if item.stage == M8PlatformScenarioStage.PERCEPTION
                        else item
                        for item in run.stages
                    ),
                }
            )
            self._write_run(failed)
            return failed
        if job.state == "RUNNING":
            return run
        if job.state not in {"SUCCEEDED", "ATTENTION_REQUIRED"}:
            failed = run.model_copy(
                update={
                    "state": "FAILED",
                    "failure_code": job.reason_code or "PILOT_RUN_FAILED",
                    "stages": tuple(
                        item.model_copy(
                            update={
                                "state": (
                                    M8PlatformStageState.FAILED
                                    if item.stage == M8PlatformScenarioStage.PERCEPTION
                                    else item.state
                                ),
                                "summary": job.reason_code or "typed Pilot failure",
                            }
                        )
                        for item in run.stages
                    ),
                }
            )
            self._write_run(failed)
            return failed
        try:
            return self._finalize_ppe(run)
        except (EvidenceMissing, PilotUiBoundaryError, TypeError, ValueError, OSError) as error:
            failed = run.model_copy(
                update={"state": "FAILED", "failure_code": type(error).__name__}
            )
            self._write_run(failed)
            return failed

    def _finalize_ppe(self, run: M8PlatformScenarioRunV1) -> M8PlatformScenarioRunV1:
        dashboard = self.pilot_service.dashboard(run_id=run.run_id)
        if not dashboard.cases or dashboard.metrics_id is None or dashboard.manifest_id is None:
            raise ValueError("Pilot produced no PPE case artifacts")
        pilot_case = dashboard.cases[0]
        bootstrap = load_m8_platform_bootstrap(self.artifact_root)
        reservations = tuple(
            item
            for item in (bootstrap.reservation,)
            if item.active and item.location_id == PLATFORM_LOCATION_ID
        )
        subject = reservations[0].actor_id if len(reservations) == 1 else None
        triggers = [
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.VIDEO_EVENT,
                authority_id=pilot_case.case_id,
                document_sha256=sha256_hex(pilot_case.model_dump(mode="json")),
            ),
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.EVIDENCE_PACK,
                authority_id=dashboard.metrics_id,
                document_sha256=dashboard.metrics_id,
            ),
        ]
        if subject is not None:
            triggers.append(
                M8AuthorityReference(
                    kind=M8AuthorityReferenceKind.RESERVATION,
                    authority_id=bootstrap.reservation.reservation_id,
                    document_sha256=sha256_hex(bootstrap.reservation.model_dump(mode="json")),
                )
            )
        catalog = self._inventory().get_current_source_catalog(PLATFORM_CAMPUS_ID)
        case = self._operations().create_operational_case(
            M8OperationalCaseCreateCommandV1(
                source_catalog_id=catalog.catalog.catalog_id,
                location_id=PLATFORM_LOCATION_ID,
                risk_level=M8OperationalRiskLevel.GENERAL,
                policy_rule_id="ppe-goggles-missing-general-risk-v1",
                policy_manifest_id=platform_manifest("platform-ppe-policy-v1"),
                source_ids=(PLATFORM_CAMERA_ID,),
                simulated_source_ids=(PLATFORM_CAMERA_ID,),
                trigger_authorities=tuple(
                    sorted(
                        triggers,
                        key=lambda item: (
                            item.kind.value,
                            item.authority_id,
                            item.document_sha256,
                        ),
                    )
                ),
                automation_component_id="m8-platform-pilot-case-projector",
                automation_manifest_id=platform_manifest("platform-pilot-projector-v1"),
            ),
            subject,
            platform_manifest("platform-case-authority-v1"),
            platform_manifest("platform-case-audit-v1"),
        )
        notification = self._notify_case(
            case_id=case.case_id,
            target_actor_id="safety-officer-demo",
            purpose=M8NotificationPurpose.CASE_ACTION_REQUIRED,
            audience=M8NotificationAudienceKind.SAFETY_RESPONDER,
            inbound_response_supported=False,
        )
        evidence = tuple(
            M8PlatformEvidenceViewV1(
                evidence_id=item.crop_id,
                role=item.role,
                frame_index=item.frame_index,
                media_url=(f"/api/m8/demo/scenario-runs/{run.run_id}/evidence/{item.crop_id}"),
                integrity=item.integrity,
            )
            for item in pilot_case.evidence
            if item.integrity == "VERIFIED"
        )
        raw_ref = self._pilot_raw_response_ref(run.run_id)
        stages = (
            self._stage(
                M8PlatformScenarioStage.VIDEO,
                "真实录像已校验",
                (PLATFORM_CAMERA_ID,),
            ),
            self._stage(
                M8PlatformScenarioStage.PERCEPTION,
                "视觉感知和目标定位已生成",
                (dashboard.manifest_id,),
            ),
            self._stage(
                M8PlatformScenarioStage.EVIDENCE,
                "全景、主体与护目镜焦点裁剪已校验",
                tuple(item.evidence_id for item in evidence),
            ),
            self._stage(
                M8PlatformScenarioStage.SCREENING,
                "结构化 Fixture 初审已保存为弱标签",
                (dashboard.metrics_id,),
            ),
            self._stage(
                M8PlatformScenarioStage.CASE,
                "一般风险案件已由规则投影建立",
                (case.case_id,),
            ),
            self._stage(
                M8PlatformScenarioStage.NOTIFICATION,
                "安全负责人本地模拟通知已送达",
                (notification.notification_id,),
            ),
        )
        completed = M8PlatformScenarioRunV1(
            run_id=run.run_id,
            scenario_kind=run.scenario_kind,
            state="SUCCEEDED",
            stages=stages,
            case_id=case.case_id,
            case_status=case.status,
            notification_id=notification.notification_id,
            evidence=evidence,
            model_or_fixture_id="fixture-ppe-screening-v1",
            raw_response_ref=raw_ref,
        )
        self._write_run(completed)
        return completed

    def _run_smoke_temperature(self) -> M8PlatformScenarioRunV1:
        run_id = f"platform-sensor-{uuid.uuid4().hex[:12]}"
        catalog = self._inventory().get_current_source_catalog(PLATFORM_CAMPUS_ID)
        source_by_id = {item.source_id: item for item in catalog.catalog.sources}
        samples = []
        sensors = self._sensors()
        for source_id, value in ((PLATFORM_SMOKE_ID, True), (PLATFORM_TEMPERATURE_ID, 82_000)):
            source = source_by_id[source_id]
            if source.sensor_type is None:
                raise ValueError("platform sensor source is missing its closed sensor type")
            capability = M8SensorAdapterCapabilityAuthorityV1(
                adapter_id=source.adapter_id,
                adapter_manifest_id=source.manifest_id,
                supported_source_modes=(source.mode,),
                supported_sensor_types=(source.sensor_type,),
                offline_capable=True,
                network_required=False,
                deterministic_replay=True,
                raw_reference_required=True,
                max_batch_size=1,
                poll_timeout_ms=1_000,
            )
            scenario = M8SimulatedSensorScenarioAuthorityV1(
                scenario_id=f"{run_id}-{source_id}",
                source_catalog_id=catalog.catalog.catalog_id,
                source=source,
                readings=(
                    M8SimulatedSensorReading(
                        source_sequence=0,
                        simulation_tick=0,
                        value=value,
                        quality=M8SensorQuality.GOOD,
                    ),
                ),
                fixture_manifest_id=platform_manifest(f"platform-fixture-{source_id}-v1"),
            )
            adapter = DeterministicSimulatedSensorAdapter(scenario, capability)
            poll = adapter.poll(
                M8SensorPollRequestV1(
                    source_catalog_id=catalog.catalog.catalog_id,
                    source=source,
                    adapter_capability=capability,
                    limit=1,
                    timeout_ms=500,
                )
            )
            committed = sensors.commit_poll_result(
                poll,
                tuple(adapter.read_raw_signal(item.raw_signal_ref) for item in poll.samples),
                platform_manifest("platform-sensor-raw-store-v1"),
                platform_manifest("platform-sensor-cache-v1"),
            )
            samples.append(committed.sample_receipts[0])
        smoke, temperature = (item.sample for item in samples)
        if smoke.value is not True or temperature.value < 60_000:
            raise ValueError("platform sensor conjunction did not reach EMERGENCY")
        case = self._operations().create_operational_case(
            M8OperationalCaseCreateCommandV1(
                source_catalog_id=catalog.catalog.catalog_id,
                location_id=PLATFORM_LOCATION_ID,
                risk_level=M8OperationalRiskLevel.EMERGENCY,
                policy_rule_id="smoke-temperature-conjunction-emergency-v1",
                policy_manifest_id=platform_manifest("platform-sensor-conjunction-policy-v1"),
                source_ids=(PLATFORM_SMOKE_ID, PLATFORM_TEMPERATURE_ID),
                simulated_source_ids=(PLATFORM_SMOKE_ID, PLATFORM_TEMPERATURE_ID),
                trigger_authorities=tuple(
                    sorted(
                        (
                            M8AuthorityReference(
                                kind=M8AuthorityReferenceKind.SENSOR_SIGNAL,
                                authority_id=item.sample.sample_id,
                                document_sha256=item.sample_document_sha256,
                            )
                            for item in samples
                        ),
                        key=lambda item: (
                            item.kind.value,
                            item.authority_id,
                            item.document_sha256,
                        ),
                    )
                ),
                automation_component_id="m8-platform-sensor-conjunction",
                automation_manifest_id=platform_manifest("platform-sensor-conjunction-v1"),
            ),
            None,
            platform_manifest("platform-case-authority-v1"),
            platform_manifest("platform-case-audit-v1"),
        )
        notification = self._notify_case(
            case_id=case.case_id,
            target_actor_id="safety-officer-demo",
            purpose=M8NotificationPurpose.CASE_ACTION_REQUIRED,
            audience=M8NotificationAudienceKind.SAFETY_RESPONDER,
            inbound_response_supported=False,
        )
        run = M8PlatformScenarioRunV1(
            run_id=run_id,
            scenario_kind=M8PlatformScenarioKind.SMOKE_TEMPERATURE_EMERGENCY,
            state="SUCCEEDED",
            stages=tuple(
                self._stage(stage, summary, refs)
                for stage, summary, refs in (
                    (M8PlatformScenarioStage.VIDEO, "传感器场景无需录像", ()),
                    (
                        M8PlatformScenarioStage.PERCEPTION,
                        "两路模拟信号已由适配器读取",
                        tuple(item.sample.source_id for item in samples),
                    ),
                    (
                        M8PlatformScenarioStage.EVIDENCE,
                        "原始信号引用与哈希已持久化",
                        tuple(item.sample.sample_id for item in samples),
                    ),
                    (
                        M8PlatformScenarioStage.SCREENING,
                        "烟雾与高温联动规则判定 EMERGENCY",
                        ("smoke-temperature-conjunction-emergency-v1",),
                    ),
                    (
                        M8PlatformScenarioStage.CASE,
                        "自动建立待核实紧急案件",
                        (case.case_id,),
                    ),
                    (
                        M8PlatformScenarioStage.NOTIFICATION,
                        "安全负责人本地模拟告警已送达",
                        (notification.notification_id,),
                    ),
                )
            ),
            case_id=case.case_id,
            case_status=case.status,
            notification_id=notification.notification_id,
            model_or_fixture_id="fixture-smoke-temperature-v1",
            raw_response_ref=f"sensor-polls/{samples[0].sample.sample_id}",
        )
        self._write_run(run)
        return run

    def _notify_case(
        self,
        *,
        case_id: str,
        target_actor_id: str,
        purpose: M8NotificationPurpose,
        audience: M8NotificationAudienceKind,
        inbound_response_supported: bool,
    ):
        operations = self._operations()
        notifications = self._notifications()
        case = operations.get_current_operational_case(case_id)
        service = M8NotificationService(
            notifications, operations, _notification_channel(), _workflow()
        )
        try:
            current_target = notifications.get_current_target_authority(
                target_actor_id, M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
            )
            revision = current_target.target.authority_revision + 1
            prior_revision: int | None = current_target.target.authority_revision
        except EvidenceMissing:
            revision = 1
            prior_revision = None
        target = M8NotificationTargetAuthorityV1(
            actor_id=target_actor_id,
            identity_provider_id="labcourt-local-fake",
            external_subject_binding_sha256=platform_manifest(
                f"platform-local-message-{target_actor_id}"
            ),
            channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
            authority_revision=revision,
            active=True,
            inbound_response_supported=inbound_response_supported,
            manifest_id=platform_manifest("platform-notification-target-v1"),
        )
        service.publish_target(target, prior_revision)
        now = _utc_now()
        authority = case.audit_event.case_authority
        plan = M8NotificationPlanAuthorityV1(
            case_id=case.case_id,
            case_version=case.case_version,
            case_authority_sha256=case.case_document_sha256,
            case_status=case.status,
            case_subject_actor_id=authority.subject_actor_id,
            risk_level=authority.risk_level,
            location_id=authority.location_id,
            purpose=purpose,
            audience=audience,
            target=target,
            template=M8NotificationTemplateAuthorityV1(
                template_id=f"platform-{purpose.value.casefold()}-card",
                template_version=1,
                locale="zh-CN",
                effective_at=now - timedelta(days=1),
                content_document_sha256=platform_manifest(
                    f"platform-card-content-{purpose.value}-{case.case_id}-{case.case_version}"
                ),
                allowed_purposes=(purpose,),
                allowed_channels=(M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,),
                manifest_id=platform_manifest("platform-notification-template-v1"),
            ),
            escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
                policy_rule_id=f"platform-{purpose.value.casefold()}-response-v1",
                risk_level=authority.risk_level,
                response_timeout_seconds=86_400,
                max_delivery_attempts=1,
                escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
                requires_human_send_confirmation=False,
                policy_manifest_id=platform_manifest("platform-notification-policy-v1"),
            ),
            planned_at=now,
            notification_manifest_id=platform_manifest(
                f"platform-notification-{purpose.value}-{case.case_id}-{case.case_version}"
            ),
        )
        current = service.create_notification(plan)
        supporting = authority.create_command.trigger_authorities
        if current.status == M8NotificationStatus.PLANNED:
            current = service.queue_as_system(current.notification_id, now, supporting)
        if current.status == M8NotificationStatus.QUEUED:
            current = service.dispatch(current.notification_id, supporting)
        if current.status == M8NotificationStatus.SENT:
            current = service.confirm_simulated_delivery(
                current.notification_id, now + timedelta(seconds=1), supporting
            )
        if current.status != M8NotificationStatus.DELIVERED:
            raise ValueError("platform local notification did not reach simulated delivery")
        return current

    def _actor(self, principal: M8ApiPrincipalV1):
        return self._operations().get_current_actor_authority(principal.actor_id).authority

    def _require_role(self, principal: M8ApiPrincipalV1, role: M8ActorRole):
        actor = self._actor(principal)
        if actor.role != role:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return actor

    def _inventory(self) -> SQLiteM8InventoryRepository:
        return SQLiteM8InventoryRepository(
            self.database_path,
            _BUSY_TIMEOUT_MS,
            platform_manifest("labcourt-platform-sqlite-repository-v1"),
        )

    def _operations(self) -> SQLiteM8OperationsRepository:
        return SQLiteM8OperationsRepository(
            self.database_path,
            _BUSY_TIMEOUT_MS,
            platform_manifest("labcourt-platform-sqlite-repository-v1"),
        )

    def _notifications(self) -> SQLiteM8NotificationRepository:
        return SQLiteM8NotificationRepository(
            self.database_path,
            _BUSY_TIMEOUT_MS,
            platform_manifest("labcourt-platform-sqlite-repository-v1"),
        )

    def _sensors(self) -> SQLiteM8SensorPersistenceRepository:
        return SQLiteM8SensorPersistenceRepository(
            self.database_path,
            _BUSY_TIMEOUT_MS,
            platform_manifest("labcourt-platform-sqlite-repository-v1"),
        )

    @staticmethod
    def _stage(
        stage: M8PlatformScenarioStage,
        summary: str,
        refs: tuple[str, ...],
    ) -> M8PlatformScenarioStageV1:
        return M8PlatformScenarioStageV1(
            stage=stage,
            state=M8PlatformStageState.COMPLETE,
            summary=summary,
            authority_refs=refs,
        )

    def _write_run(self, run: M8PlatformScenarioRunV1) -> None:
        path = self.artifact_root / PLATFORM_SCENARIO_STATE_NAME
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(canonical_json(run.model_dump(mode="json")), encoding="utf-8")
        temporary.replace(path)

    def _pilot_raw_response_ref(self, run_id: str) -> str:
        run_root = self.project_root / self.pilot_service.config.run.workspace / run_id
        candidates = sorted(run_root.rglob("*response*"))
        path = next((item for item in candidates if item.is_file()), None)
        if path is None:
            return f"runs/{run_id}/raw-response-not-generated"
        return path.relative_to(self.project_root).as_posix()

    def _archive_paths(self) -> tuple[Path, ...]:
        values = [
            self.database_path,
            self.database_path.with_name(f"{self.database_path.name}-wal"),
            self.database_path.with_name(f"{self.database_path.name}-shm"),
            self.artifact_root / PLATFORM_BOOTSTRAP_RECEIPT_NAME,
            self.artifact_root / PLATFORM_MEDIA_RECEIPT_NAME,
            self.artifact_root / PLATFORM_SCENARIO_STATE_NAME,
            self.artifact_root / "platform-local-access.json",
            self.artifact_root / "media/camera-recorded-demo-01.mp4",
        ]
        return tuple(values)


__all__ = ["M8PlatformDemoService"]
