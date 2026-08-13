"""Application service for the complete offline campus-operations Demo."""

# ruff: noqa: RUF001 - Chinese product copy intentionally uses full-width punctuation.

from __future__ import annotations

import hashlib
import os
import shutil
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.m8_offline_notification_channel import (
    DeterministicOfflineNotificationChannel,
)
from labcourt.adapters.m8_platform_pilot_fixture import (
    DeterministicRecordedPpePerceptionTransport,
    DeterministicRecordedPpeScreeningTransport,
)
from labcourt.adapters.recorded_run_acquisition import (
    RecordedRunFrameAcquisitionExecutor,
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
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.evidence import EvidencePack
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
from labcourt.contracts.m8_evaluation import M8RunSourceRefV1
from labcourt.contracts.m8_hearing_api import M8HearingModelMode
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_notification_cards import (
    M8NotificationWorkflowManifestAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
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
    M8NotificationConversationActionKind,
    M8NotificationConversationActionV1,
    M8NotificationConversationEventKind,
    M8NotificationConversationEventV1,
    M8NotificationConversationSummaryV1,
    M8NotificationConversationTechnicalV1,
    M8NotificationConversationV1,
    M8PlatformAgentActionKind,
    M8PlatformAgentQueryResponseV1,
    M8PlatformEvidenceAccess,
    M8PlatformEvidenceDetectionV1,
    M8PlatformEvidenceFrameAnnotationV1,
    M8PlatformEvidenceItemV1,
    M8PlatformEvidenceKeypointV1,
    M8PlatformEvidenceScreeningV1,
    M8PlatformEvidenceViewScope,
    M8PlatformEvidenceViewV1,
    M8PlatformEvidenceWorkspaceStage,
    M8PlatformEvidenceWorkspaceStageV1,
    M8PlatformEvidenceWorkspaceV1,
    M8PlatformExecutionSource,
    M8PlatformKnowledgeDocumentViewV1,
    M8PlatformModelComponentV1,
    M8PlatformModelReadinessComponentV1,
    M8PlatformModelReadinessV1,
    M8PlatformProposedActionV1,
    M8PlatformRecognitionMode,
    M8PlatformResetResponseV1,
    M8PlatformScenarioKind,
    M8PlatformScenarioRunV1,
    M8PlatformScenarioStage,
    M8PlatformScenarioStageV1,
    M8PlatformStageState,
    M8PlatformVideoProfileV1,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorQuality,
    M8SimulatedSensorReading,
    M8SimulatedSensorScenarioAuthorityV1,
)
from labcourt.contracts.manifests import ModelManifest, RunManifest, StreamManifest
from labcourt.contracts.pilot import PilotA2Report
from labcourt.contracts.pilot_ui import PilotUiJobStartRequest
from labcourt.contracts.projection_generation import ProjectionCurrentPointer
from labcourt.exceptions import EvidenceMissing
from labcourt.services.m8_hearing_api import M4HearingApiRuntime
from labcourt.services.m8_hearing_runtime import open_m8_hearing_runtime
from labcourt.services.m8_knowledge_api import M8KnowledgeApiService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_notifications import M8NotificationService
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
    M8OperationsApiService,
)
from labcourt.services.pilot_a5 import run_pilot_a5
from labcourt.services.pilot_operations import build_expected_perception_manifest
from labcourt.services.pilot_progress import PilotProgressUpdate
from labcourt.services.pilot_ui import (
    PilotUiBoundaryError,
    PilotUiJobManager,
    PilotUiService,
    PilotUiVideoSource,
)

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
        fixture_pilot_service: PilotUiService,
        model_pilot_service: PilotUiService,
    ) -> None:
        self.project_root = project_root.absolute()
        self.database_path = database_path.absolute()
        self.artifact_root = self.database_path.parent
        self.input_media_path = input_media_path.absolute()
        self.api_service = api_service
        self.knowledge_service = knowledge_service
        self.fixture_pilot_service = fixture_pilot_service
        self.model_pilot_service = model_pilot_service
        self.pilot_service = fixture_pilot_service
        self._operation_lock = threading.RLock()
        self._screening_transport = DeterministicRecordedPpeScreeningTransport()
        perception = DeterministicRecordedPpePerceptionTransport(
            build_expected_perception_manifest(fixture_pilot_service.config)
        )

        def runner(**kwargs):
            return run_pilot_a5(
                **kwargs,
                perception_transport=perception,
                screening_transport=self._screening_transport,
            )

        self.fixture_pilot_jobs = PilotUiJobManager(service=fixture_pilot_service, runner=runner)
        self.model_pilot_jobs = PilotUiJobManager(service=model_pilot_service)

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
        recognition_mode: M8PlatformRecognitionMode | None = None,
        retry_of_run_id: str | None = None,
    ) -> M8PlatformScenarioRunV1:
        self._require_role(principal, M8ActorRole.OPERATIONS)
        if not self._operation_lock.acquire(blocking=False):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        try:
            if any(
                jobs.snapshot().state == "RUNNING"
                for jobs in (self.fixture_pilot_jobs, self.model_pilot_jobs)
            ):
                raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
            if kind == M8PlatformScenarioKind.PPE_GOGGLES_MISSING:
                assert recognition_mode is not None
                if (
                    recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
                    and not self.model_readiness(principal).full_model_ready
                ):
                    raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
                if retry_of_run_id is not None:
                    previous = self._read_run_snapshot(retry_of_run_id)
                    if (
                        previous.state != "FAILED"
                        or previous.recognition_mode != M8PlatformRecognitionMode.FULL_MODEL
                    ):
                        raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
                return self._start_ppe(recognition_mode, retry_of_run_id)
            return self._run_smoke_temperature()
        finally:
            self._operation_lock.release()

    def current_run(self, principal: M8ApiPrincipalV1) -> M8PlatformScenarioRunV1 | None:
        self._actor(principal)
        path = self.artifact_root / PLATFORM_SCENARIO_STATE_NAME
        if not path.is_file():
            return None
        run = M8PlatformScenarioRunV1.model_validate_json(path.read_bytes())
        if run.state == "RUNNING":
            with self._operation_lock:
                # Another polling request may have finalized this run while this
                # request waited for the lock. Re-read before creating projections.
                run = M8PlatformScenarioRunV1.model_validate_json(path.read_bytes())
                if run.state == "RUNNING":
                    run = self._refresh_ppe(run)
        elif self._is_legacy_screening_failure(run):
            # Preserve the original snapshot on disk, but project the already
            # persisted Pilot authorities correctly for older runs that were
            # previously misclassified as a CASE/ValueError failure.
            with suppress(
                EvidenceMissing,
                PilotUiBoundaryError,
                TypeError,
                ValueError,
                OSError,
            ):
                run = self._finalize_attention_required_ppe(run, persist=False)
        if run.case_id is not None:
            try:
                current_case = self._operations().get_current_operational_case(run.case_id)
            except EvidenceMissing:
                current_case = None
            if current_case is not None and current_case.status != run.case_status:
                run = run.model_copy(update={"case_status": current_case.status})
                self._write_run(run)
        return run

    def scenario_run(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
    ) -> M8PlatformScenarioRunV1:
        self._actor(principal)
        try:
            run = self._read_run_snapshot(run_id)
        except (OSError, ValueError):
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from None
        current = self.current_run(principal)
        if current is not None and current.run_id == run_id:
            return current
        if self._is_legacy_screening_failure(run):
            try:
                return self._finalize_attention_required_ppe(run, persist=False)
            except (EvidenceMissing, PilotUiBoundaryError, TypeError, ValueError, OSError):
                pass
        return run

    @contextmanager
    def open_hearing_runtime(self, run_id: str) -> Iterator[M4HearingApiRuntime]:
        """Resolve one persisted Pilot run without keeping process-local hearing state."""

        try:
            run = self._read_run_snapshot(run_id)
        except (OSError, ValueError):
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from None
        if (
            run.scenario_kind != M8PlatformScenarioKind.PPE_GOGGLES_MISSING
            or run.hearing_case_id is None
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        service = self._pilot_service_for(run)
        config = service.config
        profiles = tuple(
            config.providers[name]
            for name in (
                config.hearing.prosecutor_profile,
                config.hearing.defender_profile,
                config.hearing.judge_profile,
            )
        )
        qwen_mode = all(
            profile.provider == "openai-compatible" and "qwen" in profile.model.lower()
            for profile in profiles
        )
        model_mode = (
            M8HearingModelMode.OPENAI_COMPATIBLE_QWEN
            if qwen_mode
            else M8HearingModelMode.OFFLINE_FIXTURE
        )
        workspace_root = self.project_root / config.run.workspace
        database = workspace_root / run_id / config.storage.database_filename
        input_relative_path = self._run_input_relative_path(run_id)
        with open_m8_hearing_runtime(
            config=config,
            run_id=run_id,
            workspace_root=workspace_root,
            database_path=database,
            location_by_zone={zone.zone_id: PLATFORM_LOCATION_ID for zone in config.zones},
            model_mode=model_mode,
            synthetic_demo_fixture=(model_mode == M8HearingModelMode.OFFLINE_FIXTURE),
            environment=os.environ if qwen_mode else None,
            acquisition_executor_factory=(
                (
                    lambda _workspace, manifest: RecordedRunFrameAcquisitionExecutor(
                        project_root=self.project_root,
                        input_relative_path=input_relative_path,
                        manifest=manifest,
                        max_input_bytes=config.storage.max_media_bytes,
                        max_frame_pixels=config.storage.max_image_pixels,
                    )
                )
                if qwen_mode
                else None
            ),
        ) as runtime:
            yield runtime

    def model_readiness(self, principal: M8ApiPrincipalV1) -> M8PlatformModelReadinessV1:
        self._actor(principal)
        config = self.model_pilot_service.config
        perception = build_expected_perception_manifest(config)
        worker_env = config.perception.worker.python_executable_env  # type: ignore[union-attr]
        configured = os.environ.get(worker_env)
        candidates = tuple(
            value
            for value in (
                Path(configured).absolute() if configured else None,
                self.project_root / ".venv-perception/Scripts/python.exe",
                self.project_root / ".venv-perception/bin/python",
            )
            if value is not None
        )
        perception_ready = any(path.is_file() for path in candidates)
        profile = config.providers[config.screening.provider_profile]
        endpoint_ready = bool(profile.endpoint_env and os.environ.get(profile.endpoint_env))
        key_ready = bool(profile.api_key_env and os.environ.get(profile.api_key_env))
        screening_ready = endpoint_ready and key_ready
        screening_manifest = self._model_manifest("screening", profile)
        components = (
            M8PlatformModelReadinessComponentV1(
                component="PERCEPTION",
                ready=perception_ready,
                provider="HuggingFace + Roboflow",
                model=(
                    f"{perception.detector.model} + "
                    f"{perception.pose.model if perception.pose is not None else 'pose-disabled'}"
                ),
                revision=(
                    f"{perception.detector.revision} + "
                    f"{perception.pose.revision if perception.pose is not None else 'none'}"
                ),
                manifest_id=perception.manifest_id,
                failure_code=(None if perception_ready else "PERCEPTION_ENVIRONMENT_UNAVAILABLE"),
            ),
            M8PlatformModelReadinessComponentV1(
                component="SCREENING",
                ready=screening_ready,
                provider=profile.provider,
                model=profile.model,
                revision=profile.revision,
                manifest_id=screening_manifest.model_manifest_id,
                failure_code=(None if screening_ready else "SCREENING_CREDENTIALS_UNAVAILABLE"),
            ),
        )
        return M8PlatformModelReadinessV1(
            full_model_ready=perception_ready and screening_ready,
            components=components,
        )

    def read_evidence(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
        evidence_id: str,
    ):
        actor = self._actor(principal)
        run = self.scenario_run(principal, run_id)
        item = next((value for value in run.evidence if value.evidence_id == evidence_id), None)
        if item is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        if actor.role == M8ActorRole.LEADER:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        if actor.role == M8ActorRole.STUDENT:
            if item.role in {"PANORAMA", "SUBJECT"} or run.case_id is None:
                raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
            current_case = self._operations().get_current_operational_case(run.case_id)
            if current_case.audit_event.case_authority.subject_actor_id != actor.actor_id:
                raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        try:
            return self._pilot_service_for(run).read_evidence(run_id, evidence_id)
        except PilotUiBoundaryError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error

    def evidence_workspace(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
    ) -> M8PlatformEvidenceWorkspaceV1:
        actor = self._actor(principal)
        run = self.scenario_run(principal, run_id)
        if (
            run.scenario_kind != M8PlatformScenarioKind.PPE_GOGGLES_MISSING
            or run.video_profile is None
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        if actor.role == M8ActorRole.STUDENT:
            if run.case_id is None:
                raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
            current_case = self._operations().get_current_operational_case(run.case_id)
            if current_case.audit_event.case_authority.subject_actor_id != actor.actor_id:
                raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
            view_scope = M8PlatformEvidenceViewScope.REDACTED_CASE
        elif actor.role == M8ActorRole.LEADER:
            view_scope = M8PlatformEvidenceViewScope.SUMMARY_ONLY
        else:
            view_scope = M8PlatformEvidenceViewScope.FULL_PIPELINE

        service = self._pilot_service_for(run)
        run_root = self.project_root / service.config.run.workspace / run.run_id
        dashboard = service.dashboard(run_id=run.run_id)
        pilot_case = dashboard.cases[0] if dashboard.cases else None
        frame_annotations = (
            self._workspace_annotations(run_root, run.video_profile)
            if view_scope == M8PlatformEvidenceViewScope.FULL_PIPELINE
            else ()
        )
        evidence = tuple(
            self._workspace_evidence_item(run, item, view_scope)
            for item in (pilot_case.evidence if pilot_case is not None else ())
        )
        screening = self._workspace_screening(run, evidence)
        source_available = (run_root / "pilot/run-manifest.json").is_file()
        stages = (
            M8PlatformEvidenceWorkspaceStageV1(
                stage=M8PlatformEvidenceWorkspaceStage.SOURCE_REPLAY,
                state=(
                    "AVAILABLE"
                    if view_scope == M8PlatformEvidenceViewScope.FULL_PIPELINE and source_available
                    else "RESTRICTED"
                ),
                summary=(
                    "H.264 原始录像可回放；来源为录像模拟机位"
                    if view_scope == M8PlatformEvidenceViewScope.FULL_PIPELINE
                    else "原始录像按当前角色隐藏，仅提供案件处理依据"
                ),
            ),
            M8PlatformEvidenceWorkspaceStageV1(
                stage=M8PlatformEvidenceWorkspaceStage.PERSON_LOCALIZATION,
                state=(
                    "AVAILABLE"
                    if frame_annotations
                    else (
                        "RESTRICTED"
                        if view_scope != M8PlatformEvidenceViewScope.FULL_PIPELINE
                        else "NOT_GENERATED"
                    )
                ),
                summary=(
                    f"已读取 {len(frame_annotations)} 帧真实人物框与关键点"
                    if frame_annotations
                    else "人物框、匿名轨迹与关键点按当前角色隐藏"
                ),
            ),
            M8PlatformEvidenceWorkspaceStageV1(
                stage=M8PlatformEvidenceWorkspaceStage.PRIVACY_CROPS,
                state="AVAILABLE" if evidence else "NOT_GENERATED",
                summary=(
                    f"{sum(item.access == M8PlatformEvidenceAccess.CLOUD_ALLOWED for item in evidence)} "  # noqa: E501
                    "份送审裁剪；全量脱敏件仅本地封存"
                    if evidence
                    else "尚未生成隐私裁剪"
                ),
            ),
            M8PlatformEvidenceWorkspaceStageV1(
                stage=M8PlatformEvidenceWorkspaceStage.VLM_SCREENING,
                state="AVAILABLE" if screening is not None else "NOT_GENERATED",
                summary=(
                    "结构化初审及其输入、模型与原始响应引用已绑定"
                    if screening is not None
                    else "尚未生成结构化初审"
                ),
            ),
        )
        manifests = tuple(
            dict.fromkeys(
                (
                    *(item.manifest_id for item in run.model_components),
                    *(
                        item.model_manifest_id
                        for frame in frame_annotations
                        for item in frame.detections
                    ),
                    *((dashboard.manifest_id,) if dashboard.manifest_id is not None else ()),
                    *((dashboard.metrics_id,) if dashboard.metrics_id is not None else ()),
                )
            )
        )
        return M8PlatformEvidenceWorkspaceV1(
            run_id=run.run_id,
            case_id=run.case_id,
            view_scope=view_scope,
            stages=stages,
            video_profile=run.video_profile,
            media_url=(
                (
                    f"/api/m8/demo/scenario-runs/{run.run_id}/source-video"
                    if self._is_evaluation_run(run.run_id)
                    else "/api/m8/demo/public-media/recorded-video"
                )
                if view_scope == M8PlatformEvidenceViewScope.FULL_PIPELINE
                else None
            ),
            frame_annotations=frame_annotations,
            evidence=evidence,
            screening=screening,
            technical_manifest_refs=manifests,
        )

    def notification_conversations(
        self,
        principal: M8ApiPrincipalV1,
    ) -> tuple[M8NotificationConversationSummaryV1, ...]:
        current = M8NotificationApiService(self._notifications(), self._operations()).notifications(
            principal
        )
        case_ids = tuple(
            sorted({item.audit_event.notification_authority.plan.case_id for item in current})
        )
        summaries = tuple(
            self._build_conversation(principal, case_id, current).summary for case_id in case_ids
        )
        return tuple(
            sorted(
                summaries,
                key=lambda item: (
                    item.last_activity_at or datetime.min.replace(tzinfo=UTC),
                    item.case_id,
                ),
                reverse=True,
            )
        )

    def notification_conversation(
        self,
        principal: M8ApiPrincipalV1,
        case_id: str,
    ) -> M8NotificationConversationV1:
        current = M8NotificationApiService(self._notifications(), self._operations()).notifications(
            principal
        )
        if not any(
            item.audit_event.notification_authority.plan.case_id == case_id for item in current
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        return self._build_conversation(principal, case_id, current)

    def perception_preview(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
    ) -> PilotUiVideoSource:
        run = self.scenario_run(principal, run_id)
        if run.perception_preview_url is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        try:
            return self._pilot_service_for(run).preview_source(run_id)
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
                    current_version=1,
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
                    answer="当前没有处于待核实状态的案件; 请在案件中心查看其他可用动作。",
                    source_refs=tuple(item.case_id for item in cases),
                )
            case = pending
            return M8PlatformAgentQueryResponseV1(
                outcome="ANSWERED",
                answer="已按当前案件版本生成处置操作卡，确认后仍由案件接口复核权限和版本。",
                source_refs=(case.case_id,),
                proposed_action=M8PlatformProposedActionV1(
                    action_kind=M8PlatformAgentActionKind.CASE_TRANSITION,
                    target_ref=case.case_id,
                    current_version=case.case_version,
                    impact_summary="将待核实案件转为已确认, 后续可通知关联学生",
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
                    f"当前校区登记 {len(projection.catalog.sources)} 个数据源，状态来自运营投影。"
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
                answer="离线知识库中没有匹配答案；Agent 未执行任何操作。",
            )
        return M8PlatformAgentQueryResponseV1(
            outcome=answer.answer.outcome.value,
            answer=answer.answer.answer_text,
            source_refs=tuple(
                item.document.logical_document_id for item in answer.answer.citations
            ),
        )

    def knowledge_document(
        self,
        principal: M8ApiPrincipalV1,
        catalog_id: str,
        logical_document_id: str,
    ) -> M8PlatformKnowledgeDocumentViewV1:
        catalog, document, raw = self.knowledge_service.current_document_content(
            principal,
            catalog_id,
            logical_document_id,
        )
        if hashlib.sha256(raw).hexdigest() != document.content_sha256:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE)
        try:
            content = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error
        return M8PlatformKnowledgeDocumentViewV1(
            catalog_id=catalog.catalog.catalog_id,
            catalog_revision=catalog.catalog.catalog_revision,
            catalog_authority_id=catalog.catalog.catalog_authority_id,
            document=document,
            content=content,
        )

    def reset(self, principal: M8ApiPrincipalV1) -> M8PlatformResetResponseV1:
        self._require_role(principal, M8ActorRole.OPERATIONS)
        if not self._operation_lock.acquire(blocking=False):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        try:
            if any(
                jobs.snapshot().state == "RUNNING"
                for jobs in (self.fixture_pilot_jobs, self.model_pilot_jobs)
            ):
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

    def _start_ppe(
        self,
        recognition_mode: M8PlatformRecognitionMode,
        retry_of_run_id: str | None,
        *,
        source_relative_path: str | None = None,
        requested_run_id: str | None = None,
        source_ref: M8RunSourceRefV1 | None = None,
    ) -> M8PlatformScenarioRunV1:
        service = (
            self.model_pilot_service
            if recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
            else self.fixture_pilot_service
        )
        jobs = (
            self.model_pilot_jobs
            if recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
            else self.fixture_pilot_jobs
        )
        dashboard = service.dashboard()
        video = next(
            (
                item
                for item in dashboard.videos
                if (
                    item.relative_path == source_relative_path
                    if source_relative_path is not None
                    else item.display_name == "goggles-missing.mp4"
                )
            ),
            None,
        )
        if video is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        run_id = requested_run_id or f"platform-ppe-{uuid.uuid4().hex[:12]}"
        if source_ref is not None:
            if source_ref.run_id != run_id or source_ref.relative_path != video.relative_path:
                raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
            inspected = service.video_source(video.video_id)
            if (
                inspected.expected_sha256 != source_ref.media_sha256
                or inspected.relative_path != source_ref.relative_path
            ):
                raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
            self._write_run_source(source_ref)
        jobs.start(PilotUiJobStartRequest(video_id=video.video_id, run_id=run_id, resume=True))
        run = M8PlatformScenarioRunV1(
            run_id=run_id,
            scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
            state="RUNNING",
            stages=_pending_stages(),
            recognition_mode=recognition_mode,
            retry_of_run_id=retry_of_run_id,
            model_or_fixture_id=(
                "qwen3-vl-plus-2025-12-19"
                if recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
                else "fixture-ppe-screening-v1"
            ),
        )
        self._write_run(run)
        return run

    def start_evaluation_scenario(
        self,
        source: M8RunSourceRefV1,
    ) -> M8PlatformScenarioRunV1:
        """Start one exact, content-bound real-model run for the evaluation queue."""

        if not isinstance(source, M8RunSourceRefV1):
            raise TypeError("evaluation scenario requires a typed run source")
        if not self._operation_lock.acquire(blocking=False):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        try:
            if any(
                jobs.snapshot().state == "RUNNING"
                for jobs in (self.fixture_pilot_jobs, self.model_pilot_jobs)
            ):
                raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
            return self._start_ppe(
                M8PlatformRecognitionMode.FULL_MODEL,
                None,
                source_relative_path=source.relative_path,
                requested_run_id=source.run_id,
                source_ref=source,
            )
        finally:
            self._operation_lock.release()

    def refresh_evaluation_scenario(self, run_id: str) -> M8PlatformScenarioRunV1:
        """Refresh one persisted evaluation run without relying on the current-run pointer."""

        with self._operation_lock:
            try:
                run = self._read_run_snapshot(run_id)
            except (OSError, ValueError):
                raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from None
            if run.state == "RUNNING":
                run = self._refresh_ppe(run)
            if run.case_id is not None:
                try:
                    current_case = self._operations().get_current_operational_case(run.case_id)
                except EvidenceMissing:
                    current_case = None
                if current_case is not None and current_case.status != run.case_status:
                    run = run.model_copy(update={"case_status": current_case.status})
                    self._write_run(run)
            return run

    def _refresh_ppe(self, run: M8PlatformScenarioRunV1) -> M8PlatformScenarioRunV1:
        if run.scenario_kind != M8PlatformScenarioKind.PPE_GOGGLES_MISSING:
            return run
        jobs = self._pilot_jobs_for(run)
        job = jobs.snapshot()
        progress = jobs.progress_snapshot()
        if job.run_id != run.run_id:
            failed = self._failed_ppe_run(
                run,
                failure_code="PILOT_JOB_STATE_UNAVAILABLE",
                failed_stage=self._running_m8_stage(run),
            )
            self._write_run(failed)
            return failed
        if job.state == "RUNNING":
            projected = self._project_ppe_progress(run, progress, job.active_stage)
            if tuple(item.state for item in projected.stages) != tuple(
                item.state for item in run.stages
            ):
                # Persist stage boundaries, not every in-memory frame update.
                self._write_run(projected)
            return projected
        if job.state not in {"SUCCEEDED", "ATTENTION_REQUIRED"}:
            failure_code = job.reason_code or "PILOT_RUN_FAILED"
            projected = self._project_ppe_progress(run, progress, job.active_stage)
            failed = self._failed_ppe_run(
                projected,
                failure_code=failure_code,
                failed_stage=self._pilot_failure_stage(
                    failure_code,
                    progress,
                    projected,
                ),
            )
            self._write_run(failed)
            return failed
        projected = self._project_ppe_progress(run, progress, "REPORT")
        try:
            if job.state == "ATTENTION_REQUIRED":
                return self._finalize_attention_required_ppe(projected)
            return self._finalize_ppe(projected)
        except (EvidenceMissing, PilotUiBoundaryError, TypeError, ValueError, OSError) as error:
            attention_required = job.state == "ATTENTION_REQUIRED"
            failed = self._failed_ppe_run(
                projected,
                failure_code=(
                    "SCREENING_PROJECTION_INVALID" if attention_required else type(error).__name__
                ),
                failed_stage=(
                    M8PlatformScenarioStage.SCREENING
                    if attention_required
                    else M8PlatformScenarioStage.CASE
                ),
            )
            self._write_run(failed)
            return failed

    @staticmethod
    def _is_legacy_screening_failure(run: M8PlatformScenarioRunV1) -> bool:
        return (
            run.scenario_kind == M8PlatformScenarioKind.PPE_GOGGLES_MISSING
            and run.recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
            and run.state == "FAILED"
            and run.failure_code == "ValueError"
            and run.screening_decision is None
            and any(
                item.stage == M8PlatformScenarioStage.PERCEPTION
                and item.state == M8PlatformStageState.COMPLETE
                for item in run.stages
            )
        )

    @staticmethod
    def _pilot_to_m8_stage(stage: str) -> M8PlatformScenarioStage:
        return {
            "VIDEO": M8PlatformScenarioStage.VIDEO,
            "PERCEPTION": M8PlatformScenarioStage.PERCEPTION,
            "EVIDENCE": M8PlatformScenarioStage.EVIDENCE,
            "SCREENING": M8PlatformScenarioStage.SCREENING,
            "REPORT": M8PlatformScenarioStage.CASE,
        }.get(stage, M8PlatformScenarioStage.PERCEPTION)

    @staticmethod
    def _running_m8_stage(run: M8PlatformScenarioRunV1) -> M8PlatformScenarioStage:
        return next(
            (item.stage for item in run.stages if item.state == M8PlatformStageState.RUNNING),
            M8PlatformScenarioStage.PERCEPTION,
        )

    def _project_ppe_progress(
        self,
        run: M8PlatformScenarioRunV1,
        progress: tuple[PilotProgressUpdate, ...],
        fallback_stage: str | None,
    ) -> M8PlatformScenarioRunV1:
        latest = progress[-1] if progress else None
        pilot_stage = latest.stage if latest is not None else (fallback_stage or "VIDEO")
        active_stage = self._pilot_to_m8_stage(pilot_stage)
        active_index = tuple(M8PlatformScenarioStage).index(active_stage)
        perception = next(
            (item for item in reversed(progress) if item.stage == "PERCEPTION"),
            None,
        )
        running_summaries = {
            M8PlatformScenarioStage.VIDEO: "正在校验录像与解码参数",
            M8PlatformScenarioStage.PERCEPTION: "正在运行本地视觉感知与目标定位",
            M8PlatformScenarioStage.EVIDENCE: "正在生成并校验证据裁剪",
            M8PlatformScenarioStage.SCREENING: "正在执行结构化视觉初审",
            M8PlatformScenarioStage.CASE: "Pilot 汇总已就绪 / 正在准备 M8 案件投影",
            M8PlatformScenarioStage.NOTIFICATION: "正在准备本地模拟通知",
        }
        completed_summaries = {
            M8PlatformScenarioStage.VIDEO: "真实录像已校验",
            M8PlatformScenarioStage.PERCEPTION: "本地视觉感知与目标定位已完成",
            M8PlatformScenarioStage.EVIDENCE: "证据裁剪与完整性校验已完成",
            M8PlatformScenarioStage.SCREENING: "结构化视觉初审已完成",
            M8PlatformScenarioStage.CASE: "案件投影阶段已完成",
            M8PlatformScenarioStage.NOTIFICATION: "通知阶段已完成",
        }
        projected: list[M8PlatformScenarioStageV1] = []
        for index, item in enumerate(run.stages):
            if index < active_index:
                state = M8PlatformStageState.COMPLETE
                summary = completed_summaries[item.stage]
            elif index == active_index:
                state = (
                    M8PlatformStageState.COMPLETE
                    if latest is not None
                    and latest.state == "COMPLETE"
                    and latest.stage != "REPORT"
                    else M8PlatformStageState.RUNNING
                )
                summary = (
                    completed_summaries[item.stage]
                    if state == M8PlatformStageState.COMPLETE
                    else running_summaries[item.stage]
                )
            else:
                state = M8PlatformStageState.PENDING
                summary = "尚未生成"
            update: dict[str, object] = {"state": state, "summary": summary}
            if item.stage == M8PlatformScenarioStage.PERCEPTION and perception is not None:
                update.update(
                    {
                        "completed_units": perception.completed_units,
                        "total_units": perception.total_units,
                        "unit": perception.unit,
                    }
                )
                if perception.completed_units is not None and perception.total_units is not None:
                    update["summary"] = (
                        f"真实 Worker 响应 {perception.completed_units}/{perception.total_units} 帧"
                    )
            projected.append(item.model_copy(update=update))
        return run.model_copy(update={"stages": tuple(projected)})

    def _pilot_failure_stage(
        self,
        failure_code: str,
        progress: tuple[PilotProgressUpdate, ...],
        run: M8PlatformScenarioRunV1,
    ) -> M8PlatformScenarioStage:
        if progress:
            return self._pilot_to_m8_stage(progress[-1].stage)
        if failure_code == "SCREENING_FAILED":
            return M8PlatformScenarioStage.SCREENING
        if failure_code == "REPORTING_FAILED":
            return M8PlatformScenarioStage.CASE
        if failure_code == "EVIDENCE_FAILED":
            return M8PlatformScenarioStage.EVIDENCE
        if failure_code.startswith("VIDEO_") or failure_code == "REPLAY_MODE_REQUIRED":
            return M8PlatformScenarioStage.VIDEO
        return self._running_m8_stage(run)

    @staticmethod
    def _failed_ppe_run(
        run: M8PlatformScenarioRunV1,
        *,
        failure_code: str,
        failed_stage: M8PlatformScenarioStage,
    ) -> M8PlatformScenarioRunV1:
        failed_index = tuple(M8PlatformScenarioStage).index(failed_stage)
        stages = tuple(
            item.model_copy(
                update={
                    "state": (
                        M8PlatformStageState.COMPLETE
                        if index < failed_index
                        else M8PlatformStageState.FAILED
                        if index == failed_index
                        else M8PlatformStageState.PENDING
                    ),
                    "summary": (
                        failure_code
                        if index == failed_index
                        else item.summary
                        if index < failed_index
                        else "尚未生成"
                    ),
                }
            )
            for index, item in enumerate(run.stages)
        )
        return run.model_copy(
            update={
                "state": "FAILED",
                "failure_code": failure_code,
                "stages": stages,
            }
        )

    @staticmethod
    def _preserve_perception_progress(
        stages: tuple[M8PlatformScenarioStageV1, ...],
        run: M8PlatformScenarioRunV1,
    ) -> tuple[M8PlatformScenarioStageV1, ...]:
        progress = next(
            (
                item
                for item in run.stages
                if item.stage == M8PlatformScenarioStage.PERCEPTION
                and item.completed_units is not None
            ),
            None,
        )
        if progress is None:
            return stages
        return tuple(
            item.model_copy(
                update={
                    "completed_units": progress.completed_units,
                    "total_units": progress.total_units,
                    "unit": progress.unit,
                }
            )
            if item.stage == M8PlatformScenarioStage.PERCEPTION
            else item
            for item in stages
        )

    def _finalize_ppe(self, run: M8PlatformScenarioRunV1) -> M8PlatformScenarioRunV1:
        service = self._pilot_service_for(run)
        dashboard = service.dashboard(run_id=run.run_id)
        run_root = self.project_root / service.config.run.workspace / run.run_id
        a2 = PilotA2Report.model_validate_json((run_root / "pilot/a2-report.json").read_bytes())
        manifest = RunManifest.model_validate_json(
            (run_root / "pilot/run-manifest.json").read_bytes()
        )
        if a2.state == "NO_CANDIDATE":
            return self._finalize_no_action_ppe(run, a2, manifest)
        if not dashboard.cases or dashboard.metrics_id is None or dashboard.manifest_id is None:
            raise ValueError("Pilot produced incomplete PPE case artifacts")
        pilot_case = dashboard.cases[0]
        source_case, source_pack, stream, raw_ref = self._pilot_ppe_authorities(run)
        if source_case.case_id != pilot_case.case_id:
            raise ValueError("Pilot dashboard Case conflicts with its typed projection")
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
        if source_case.screening_results[-1].decision.value == "NOT_ESTABLISHED":
            return self._finalize_screening_no_action(
                run, source_case, source_pack, stream, raw_ref, evidence, manifest
            )
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
                authority_id=source_case.event.event_id,
                document_sha256=self._document_sha256(source_case.event),
            ),
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.EVIDENCE_PACK,
                authority_id=source_pack.pack_id,
                document_sha256=self._document_sha256(source_pack),
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
        evaluation_run = self._is_evaluation_run(run.run_id)
        notification = (
            None
            if evaluation_run
            else self._notify_case(
                case_id=case.case_id,
                target_actor_id="safety-officer-demo",
                purpose=M8NotificationPurpose.CASE_ACTION_REQUIRED,
                audience=M8NotificationAudienceKind.SAFETY_RESPONDER,
                inbound_response_supported=False,
            )
        )
        stages = (
            self._stage(
                M8PlatformScenarioStage.VIDEO,
                "真实录像已校验",
                (PLATFORM_CAMERA_ID,),
            ),
            self._stage(
                M8PlatformScenarioStage.PERCEPTION,
                "视觉感知和目标定位已生成",
                (source_case.manifest_id,),
            ),
            self._stage(
                M8PlatformScenarioStage.EVIDENCE,
                "全景、主体与时序眼部焦点裁剪已校验",
                (source_pack.pack_id, *(item.evidence_id for item in evidence)),
            ),
            self._stage(
                M8PlatformScenarioStage.SCREENING,
                (
                    "Qwen3-VL 结构化初审已保存为弱标签"
                    if run.recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
                    else "结构化 Fixture 初审已保存为弱标签"
                ),
                (source_case.screening_results[-1].screening_id,),
            ),
            self._stage(
                M8PlatformScenarioStage.CASE,
                "一般风险案件已由规则投影建立",
                (case.case_id,),
            ),
            (
                M8PlatformScenarioStageV1(
                    stage=M8PlatformScenarioStage.NOTIFICATION,
                    state=M8PlatformStageState.PENDING,
                    summary="评估案件等待现有 Feishu activation-gated outbox 显式投递",
                    authority_refs=(),
                )
                if evaluation_run
                else self._stage(
                    M8PlatformScenarioStage.NOTIFICATION,
                    "安全负责人本地模拟通知已送达",
                    (notification.notification_id,),  # type: ignore[union-attr]
                )
            ),
        )
        completed = M8PlatformScenarioRunV1(
            run_id=run.run_id,
            scenario_kind=run.scenario_kind,
            state="SUCCEEDED",
            stages=self._preserve_perception_progress(stages, run),
            case_id=case.case_id,
            hearing_case_id=source_case.case_id,
            case_status=case.status,
            notification_id=(notification.notification_id if notification else None),
            recognition_mode=run.recognition_mode,
            retry_of_run_id=run.retry_of_run_id,
            model_components=self._model_components(run, manifest),
            outcome="ACTIONABLE_RISK",
            evidence=evidence,
            video_profile=M8PlatformVideoProfileV1(
                input_file_sha256=stream.input_file_sha256,
                fps_num=stream.fps_num,
                fps_den=stream.fps_den,
                frame_count=stream.frame_count,
                width=stream.width,
                height=stream.height,
                duration_millis=(stream.frame_count * 1000 * stream.fps_den + stream.fps_num - 1)
                // stream.fps_num,
            ),
            perception_preview_url=(f"/api/m8/demo/scenario-runs/{run.run_id}/perception-preview"),
            model_or_fixture_id=(
                manifest.models["screening"].model
                if run.recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
                else "fixture-ppe-screening-v1"
            ),
            raw_response_ref=raw_ref,
            screening_decision=source_case.screening_results[-1].decision.value,
            screening_summary=(source_case.screening_results[-1].parsed_output.rationale_summary),
            rule_judgment="GENERAL_RISK",
        )
        self._write_run(completed)
        return completed

    def _finalize_attention_required_ppe(
        self,
        run: M8PlatformScenarioRunV1,
        *,
        persist: bool = True,
    ) -> M8PlatformScenarioRunV1:
        """Project a Pilot screening backlog without pretending CASE was reached."""

        service = self._pilot_service_for(run)
        dashboard = service.dashboard(run_id=run.run_id)
        source_case, source_pack, stream, manifest = self._pilot_ppe_base_authorities(run)
        if source_case.screening_results:
            return self._finalize_ppe(run) if persist else run

        reason_code = self._screening_attention_reason(source_case)
        failure_code = self._screening_failure_code(reason_code)
        pilot_case = dashboard.cases[0] if dashboard.cases else None
        evidence = tuple(
            M8PlatformEvidenceViewV1(
                evidence_id=item.crop_id,
                role=item.role,
                frame_index=item.frame_index,
                media_url=(f"/api/m8/demo/scenario-runs/{run.run_id}/evidence/{item.crop_id}"),
                integrity=item.integrity,
            )
            for item in (pilot_case.evidence if pilot_case is not None else ())
            if item.integrity == "VERIFIED"
        )
        stages = self._preserve_perception_progress(
            (
                self._stage(
                    M8PlatformScenarioStage.VIDEO,
                    "真实录像已校验",
                    (PLATFORM_CAMERA_ID,),
                ),
                self._stage(
                    M8PlatformScenarioStage.PERCEPTION,
                    "本地视觉感知和目标定位已完成",
                    (source_case.manifest_id,),
                ),
                self._stage(
                    M8PlatformScenarioStage.EVIDENCE,
                    "证据裁剪与完整性校验已完成",
                    (source_pack.pack_id, *(item.evidence_id for item in evidence)),
                ),
                M8PlatformScenarioStageV1(
                    stage=M8PlatformScenarioStage.SCREENING,
                    state=M8PlatformStageState.FAILED,
                    summary=failure_code,
                    authority_refs=(),
                ),
                M8PlatformScenarioStageV1(
                    stage=M8PlatformScenarioStage.CASE,
                    state=M8PlatformStageState.PENDING,
                    summary="尚未生成",
                    authority_refs=(),
                ),
                M8PlatformScenarioStageV1(
                    stage=M8PlatformScenarioStage.NOTIFICATION,
                    state=M8PlatformStageState.PENDING,
                    summary="尚未生成",
                    authority_refs=(),
                ),
            ),
            run,
        )
        failed = M8PlatformScenarioRunV1(
            run_id=run.run_id,
            scenario_kind=run.scenario_kind,
            state="FAILED",
            failure_code=failure_code,
            stages=stages,
            recognition_mode=run.recognition_mode,
            retry_of_run_id=run.retry_of_run_id,
            model_components=self._model_components(run, manifest),
            evidence=evidence,
            video_profile=self._video_profile(stream),
            perception_preview_url=(f"/api/m8/demo/scenario-runs/{run.run_id}/perception-preview"),
            model_or_fixture_id=manifest.models["screening"].model,
        )
        if persist:
            self._write_run(failed)
        return failed

    @staticmethod
    def _screening_attention_reason(source_case: Case) -> str | None:
        if source_case.screening_results:
            return None
        for entry in reversed(source_case.timeline):
            reason = entry.details.get("reason_code")
            if isinstance(reason, str):
                return reason
        return None

    @staticmethod
    def _screening_failure_code(reason_code: str | None) -> str:
        """Expose the controlled screening outcome without provider secrets."""

        return {
            "PROVIDER_UNAVAILABLE": "SCREENING_PROVIDER_UNAVAILABLE",
            "MODEL_OUTPUT_INVALID": "SCREENING_RESPONSE_INVALID",
            "RESPONSE_INTEGRITY_FAILURE": "SCREENING_RESPONSE_INVALID",
            "BUDGET_EXCEEDED": "SCREENING_RESPONSE_BUDGET_EXCEEDED",
            "CURRENT_PACK_CHANGED": "SCREENING_EVIDENCE_CHANGED",
        }.get(reason_code, "SCREENING_ATTENTION_REQUIRED")

    @staticmethod
    def _video_profile(stream: StreamManifest) -> M8PlatformVideoProfileV1:
        return M8PlatformVideoProfileV1(
            input_file_sha256=stream.input_file_sha256,
            fps_num=stream.fps_num,
            fps_den=stream.fps_den,
            frame_count=stream.frame_count,
            width=stream.width,
            height=stream.height,
            duration_millis=(stream.frame_count * 1000 * stream.fps_den + stream.fps_num - 1)
            // stream.fps_num,
        )

    def _finalize_screening_no_action(
        self,
        run: M8PlatformScenarioRunV1,
        source_case: Case,
        source_pack: EvidencePack,
        stream: StreamManifest,
        raw_ref: str,
        evidence: tuple[M8PlatformEvidenceViewV1, ...],
        manifest: RunManifest,
    ) -> M8PlatformScenarioRunV1:
        screening = source_case.screening_results[-1]
        completed = M8PlatformScenarioRunV1(
            run_id=run.run_id,
            scenario_kind=run.scenario_kind,
            state="SUCCEEDED",
            stages=self._preserve_perception_progress(
                (
                    self._stage(
                        M8PlatformScenarioStage.VIDEO, "真实录像已校验", (PLATFORM_CAMERA_ID,)
                    ),
                    self._stage(
                        M8PlatformScenarioStage.PERCEPTION,
                        "视觉感知和目标定位已生成",
                        (source_case.manifest_id,),
                    ),
                    self._stage(
                        M8PlatformScenarioStage.EVIDENCE,
                        "全景、主体与时序眼部焦点裁剪已校验",
                        (source_pack.pack_id, *(item.evidence_id for item in evidence)),
                    ),
                    self._stage(
                        M8PlatformScenarioStage.SCREENING,
                        "结构化初审未建立可行动风险，已保存为弱标签",
                        (screening.screening_id,),
                    ),
                    self._stage(
                        M8PlatformScenarioStage.CASE,
                        "规则未建立风险，未自动建案",
                        (),
                    ),
                    self._stage(M8PlatformScenarioStage.NOTIFICATION, "无需发送案件通知", ()),
                ),
                run,
            ),
            recognition_mode=run.recognition_mode,
            retry_of_run_id=run.retry_of_run_id,
            model_components=self._model_components(run, manifest),
            outcome="NO_ACTIONABLE_RISK_ESTABLISHED",
            evidence=evidence,
            video_profile=M8PlatformVideoProfileV1(
                input_file_sha256=stream.input_file_sha256,
                fps_num=stream.fps_num,
                fps_den=stream.fps_den,
                frame_count=stream.frame_count,
                width=stream.width,
                height=stream.height,
                duration_millis=(stream.frame_count * 1000 * stream.fps_den + stream.fps_num - 1)
                // stream.fps_num,
            ),
            perception_preview_url=(f"/api/m8/demo/scenario-runs/{run.run_id}/perception-preview"),
            model_or_fixture_id=manifest.models["screening"].model,
            raw_response_ref=raw_ref,
            screening_decision="NOT_ESTABLISHED",
            screening_summary=screening.parsed_output.rationale_summary,
            rule_judgment="NO_ACTIONABLE_RISK_ESTABLISHED",
        )
        self._write_run(completed)
        return completed

    def _finalize_no_action_ppe(
        self,
        run: M8PlatformScenarioRunV1,
        a2: PilotA2Report,
        manifest: RunManifest,
    ) -> M8PlatformScenarioRunV1:
        if len(manifest.streams) != 1:
            raise ValueError("no-action Pilot run requires one video stream")
        stream = manifest.streams[0]
        stages = tuple(
            self._stage(stage, summary, refs)
            for stage, summary, refs in (
                (M8PlatformScenarioStage.VIDEO, "真实录像已校验", (PLATFORM_CAMERA_ID,)),
                (
                    M8PlatformScenarioStage.PERCEPTION,
                    "真实视觉感知已完成，未产生可行动候选事件",
                    (a2.perception_manifest_id, a2.perception_completion_id),
                ),
                (M8PlatformScenarioStage.EVIDENCE, "没有需要裁剪的候选证据", ()),
                (M8PlatformScenarioStage.SCREENING, "没有候选证据需要调用结构化初审", ()),
                (
                    M8PlatformScenarioStage.CASE,
                    "未建立可行动风险，未自动建案",
                    (),
                ),
                (M8PlatformScenarioStage.NOTIFICATION, "无需发送案件通知", ()),
            )
        )
        completed = M8PlatformScenarioRunV1(
            run_id=run.run_id,
            scenario_kind=run.scenario_kind,
            state="SUCCEEDED",
            stages=self._preserve_perception_progress(stages, run),
            recognition_mode=run.recognition_mode,
            retry_of_run_id=run.retry_of_run_id,
            model_components=self._model_components(run, manifest),
            outcome="NO_ACTIONABLE_RISK_ESTABLISHED",
            video_profile=M8PlatformVideoProfileV1(
                input_file_sha256=stream.input_file_sha256,
                fps_num=stream.fps_num,
                fps_den=stream.fps_den,
                frame_count=stream.frame_count,
                width=stream.width,
                height=stream.height,
                duration_millis=(stream.frame_count * 1000 * stream.fps_den + stream.fps_num - 1)
                // stream.fps_num,
            ),
            model_or_fixture_id=(
                manifest.models["screening"].model
                if run.recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
                else "fixture-ppe-screening-v1"
            ),
            rule_judgment="NO_ACTIONABLE_RISK_ESTABLISHED",
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
            rule_judgment="EMERGENCY",
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

    @staticmethod
    def _workspace_annotations(
        run_root: Path,
        profile: M8PlatformVideoProfileV1,
    ) -> tuple[M8PlatformEvidenceFrameAnnotationV1, ...]:
        path = run_root / "perception/frame-bundles.jsonl"
        if not path.is_file():
            return ()
        annotations: list[M8PlatformEvidenceFrameAnnotationV1] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            bundle = FrameBundle.model_validate_json(line)
            if bundle.frame.frame_index >= profile.frame_count:
                raise ValueError("perception frame lies outside the verified stream")
            detections = tuple(
                M8PlatformEvidenceDetectionV1(
                    detection_id=item.detection_id,
                    bbox=item.bbox,
                    anonymous_track_ref=item.track_ref,
                    keypoints=tuple(
                        M8PlatformEvidenceKeypointV1(name=point.name, x=point.x, y=point.y)
                        for point in item.keypoints
                    ),
                    model_manifest_id=item.model_manifest_id,
                )
                for item in bundle.detections
                if item.label.casefold() == "person"
            )
            if detections:
                annotations.append(
                    M8PlatformEvidenceFrameAnnotationV1(
                        frame_index=bundle.frame.frame_index,
                        timestamp_millis=bundle.frame.timestamp_ms,
                        width=bundle.frame.width,
                        height=bundle.frame.height,
                        detections=detections,
                    )
                )
        if tuple(item.frame_index for item in annotations) != tuple(
            sorted({item.frame_index for item in annotations})
        ):
            raise ValueError("perception frame annotations must be unique and ordered")
        return tuple(annotations)

    @staticmethod
    def _workspace_evidence_item(
        run: M8PlatformScenarioRunV1,
        item,
        view_scope: M8PlatformEvidenceViewScope,
    ) -> M8PlatformEvidenceItemV1:
        sealed = item.role in {"PANORAMA", "SUBJECT"}
        if view_scope == M8PlatformEvidenceViewScope.SUMMARY_ONLY:
            access = M8PlatformEvidenceAccess.SUMMARY_ONLY
            media_url = None
            submitted = False
        elif sealed:
            access = M8PlatformEvidenceAccess.SEALED_LOCAL
            media_url = None
            submitted = False
        else:
            access = M8PlatformEvidenceAccess.CLOUD_ALLOWED
            media_url = f"/api/m8/demo/scenario-runs/{run.run_id}/evidence/{item.crop_id}"
            submitted = True
        return M8PlatformEvidenceItemV1(
            evidence_id=item.crop_id,
            role=item.role,
            frame_index=item.frame_index,
            timestamp_millis=item.time_millis,
            width=item.width,
            height=item.height,
            integrity=item.integrity,
            privacy_policy=("FULL_REDACTION" if sealed else "PPE_PRESERVING_REDACTION"),
            access=access,
            submitted_to_screening=submitted,
            media_url=media_url,
        )

    @staticmethod
    def _workspace_screening(
        run: M8PlatformScenarioRunV1,
        evidence: tuple[M8PlatformEvidenceItemV1, ...],
    ) -> M8PlatformEvidenceScreeningV1 | None:
        component = next(
            (item for item in run.model_components if item.component == "SCREENING"), None
        )
        inputs = tuple(
            item.evidence_id
            for item in evidence
            if item.role in {"FOCUS", "TEMPORAL"} and item.integrity == "VERIFIED"
        )
        if (
            component is None
            or run.screening_decision is None
            or run.screening_summary is None
            or run.raw_response_ref is None
            or not inputs
        ):
            return None
        return M8PlatformEvidenceScreeningV1(
            source=component.source,
            provider=component.provider,
            model=component.model,
            revision=component.revision,
            manifest_id=component.manifest_id,
            decision=run.screening_decision,
            summary=run.screening_summary,
            input_evidence_ids=inputs,
            raw_response_ref=run.raw_response_ref,
        )

    @staticmethod
    def _notification_copy(plan) -> tuple[str, str]:
        purpose = plan.purpose
        if purpose == M8NotificationPurpose.APPEAL_OUTCOME:
            return (
                "申诉处理结果已送达",
                "安全负责人已完成申诉复核。处理决定保留在案件会话中，请查看后确认。",
            )
        if purpose == M8NotificationPurpose.CASE_UPDATED:
            return (
                "案件状态已更新",
                f"实验室 {plan.location_id} 的案件现为 {plan.case_status.value}。"
                "你可以提交情况说明或申诉，机器输出不直接作为处分依据。",
            )
        if purpose in {
            M8NotificationPurpose.CASE_CREATED,
            M8NotificationPurpose.CASE_ACTION_REQUIRED,
        }:
            return (
                "安全事件等待人工核实",
                f"{plan.location_id} 已建立 {plan.risk_level.value} 级候选案件，"
                "等待安全负责人处理。",
            )
        return ("案件进展通知", f"案件发生 {purpose.value} 进展，详情以案件 authority 为准。")

    def _build_conversation(
        self,
        principal: M8ApiPrincipalV1,
        case_id: str,
        visible_notifications,
    ) -> M8NotificationConversationV1:
        actor = self._actor(principal)
        operations = self._operations()
        notifications = self._notifications()
        current_case = operations.get_current_operational_case(case_id)
        authority = current_case.audit_event.case_authority
        case_notifications = tuple(
            item
            for item in visible_notifications
            if item.audit_event.notification_authority.plan.case_id == case_id
        )
        event_rows: list[tuple[int, datetime | None, str, dict[str, object]]] = []
        reply_count = 0
        replies = []
        outcome_notifications = []
        for current in case_notifications:
            notification = current.audit_event.notification_authority
            plan = notification.plan
            title, body = self._notification_copy(plan)
            is_outcome = plan.purpose == M8NotificationPurpose.APPEAL_OUTCOME
            if is_outcome:
                outcome_notifications.append(current)
            kind = (
                M8NotificationConversationEventKind.OUTCOME_NOTIFICATION
                if is_outcome
                else M8NotificationConversationEventKind.NOTIFICATION
            )
            event_rows.append(
                (
                    (
                        30
                        if is_outcome
                        else 0
                        if plan.purpose
                        in {
                            M8NotificationPurpose.CASE_CREATED,
                            M8NotificationPurpose.CASE_ACTION_REQUIRED,
                        }
                        else 10
                    ),
                    plan.planned_at,
                    notification.notification_id,
                    {
                        "event_id": sha256_hex(
                            ["m8-conversation-notification", 1, notification.notification_id]
                        ),
                        "kind": kind,
                        "sender": "SAFETY_OFFICER"
                        if plan.audience.value == "CASE_SUBJECT"
                        else "SYSTEM",
                        "title": title,
                        "body": body,
                        "occurred_at": plan.planned_at,
                        "notification_id": notification.notification_id,
                        "authority_id": notification.notification_authority_id,
                        "status": notification.status.value,
                        "technical": M8NotificationConversationTechnicalV1(
                            authority_ref=notification.notification_authority_id,
                            document_sha256=current.notification_document_sha256,
                        ),
                    },
                )
            )
            for audit in notifications.list_notification_audit(notification.notification_id):
                command = audit.transition_command
                if command is None:
                    continue
                if command.reply is not None:
                    reply = command.reply
                    raw = notifications.read_raw_artifact(reply.raw_reply_ref)
                    digest = hashlib.sha256(raw).hexdigest()
                    if digest not in {reply.raw_reply_sha256, reply.reply_document_sha256} or (
                        reply.raw_reply_sha256 != reply.reply_document_sha256
                    ):
                        raise ValueError("notification reply raw hash conflicts with its authority")
                    text = raw.decode("utf-8", errors="strict")
                    kind = (
                        M8NotificationConversationEventKind.STUDENT_APPEAL
                        if reply.reply_kind == M8NotificationReplyKind.APPEAL_REQUEST
                        else M8NotificationConversationEventKind.STUDENT_EXPLANATION
                    )
                    replies.append(reply)
                    reply_count += 1
                    event_rows.append(
                        (
                            10,
                            reply.received_at,
                            reply.reply_authority_id,
                            {
                                "event_id": reply.reply_authority_id,
                                "kind": kind,
                                "sender": "STUDENT",
                                "title": "学生提交申诉"
                                if kind.value == "STUDENT_APPEAL"
                                else "学生补充情况说明",
                                "body": text
                                if actor.role in {M8ActorRole.STUDENT, M8ActorRole.SAFETY_OFFICER}
                                else None,
                                "occurred_at": reply.received_at,
                                "notification_id": notification.notification_id,
                                "authority_id": reply.reply_authority_id,
                                "status": "STORED_AND_HASH_VERIFIED",
                            },
                        )
                    )
                if command.action == M8NotificationAction.ACKNOWLEDGE:
                    event_rows.append(
                        (
                            40,
                            command.occurred_at,
                            command.command_id,
                            {
                                "event_id": command.command_id,
                                "kind": M8NotificationConversationEventKind.STUDENT_ACKNOWLEDGEMENT,
                                "sender": "STUDENT",
                                "title": "学生已确认处理结果",
                                "body": "结果通知已由本人明确确认，完整案件历史仍然保留。",
                                "occurred_at": command.occurred_at,
                                "notification_id": notification.notification_id,
                                "authority_id": command.command_id,
                                "status": "ACKNOWLEDGED",
                            },
                        )
                    )

        for audit in operations.list_operational_case_audit(case_id):
            intent = audit.transition_intent
            if intent is None or intent.command.actor_authority.role != M8ActorRole.SAFETY_OFFICER:
                continue
            command = intent.command
            if command.action.value not in {"CONFIRM", "REJECT", "RESOLVE", "RESOLVE_APPEAL"}:
                continue
            decision = (
                f"申诉结论：{command.appeal_resolution.value}"
                if command.appeal_resolution is not None
                else f"案件操作：{command.action.value}"
            )
            event_rows.append(
                (
                    20 if command.action.value == "RESOLVE_APPEAL" else 5,
                    None,
                    command.command_id,
                    {
                        "event_id": command.command_id,
                        "kind": M8NotificationConversationEventKind.SAFETY_DECISION,
                        "sender": "SAFETY_OFFICER",
                        "title": decision,
                        "body": command.reason_summary,
                        "occurred_at": None,
                        "authority_id": command.command_id,
                        "status": command.target_status.value,
                    },
                )
            )

        event_rows.sort(
            key=lambda item: (item[0], item[1] or datetime.min.replace(tzinfo=UTC), item[2])
        )
        events = tuple(
            M8NotificationConversationEventV1(sequence=index, **row[3])
            for index, row in enumerate(event_rows, start=1)
        )
        actions: list[M8NotificationConversationActionV1] = []
        case_updated = tuple(
            item
            for item in case_notifications
            if item.audit_event.notification_authority.plan.purpose
            == M8NotificationPurpose.CASE_UPDATED
        )
        if actor.role == M8ActorRole.SAFETY_OFFICER:
            if current_case.status == M8OperationalCaseStatus.APPEALED:
                actions.extend(
                    M8NotificationConversationActionV1(
                        action=kind,
                        current_case_version=current_case.case_version,
                    )
                    for kind in (
                        M8NotificationConversationActionKind.RESOLVE_APPEAL_UPHELD,
                        M8NotificationConversationActionKind.RESOLVE_APPEAL_OVERTURNED,
                    )
                )
            if (
                current_case.status == M8OperationalCaseStatus.APPEAL_RESOLVED
                and not outcome_notifications
            ):
                actions.append(
                    M8NotificationConversationActionV1(
                        action=M8NotificationConversationActionKind.SEND_APPEAL_OUTCOME,
                        current_case_version=current_case.case_version,
                    )
                )
            if current_case.status == M8OperationalCaseStatus.CONFIRMED:
                actions.append(
                    M8NotificationConversationActionV1(
                        action=M8NotificationConversationActionKind.SEND_CASE_UPDATE,
                        current_case_version=current_case.case_version,
                    )
                )
        elif actor.role == M8ActorRole.STUDENT:
            appeal_replies = tuple(
                item
                for item in replies
                if item.reply_kind == M8NotificationReplyKind.APPEAL_REQUEST
            )
            if appeal_replies and current_case.status == M8OperationalCaseStatus.CONFIRMED:
                latest = max(appeal_replies, key=lambda item: item.received_at)
                actions.append(
                    M8NotificationConversationActionV1(
                        action=M8NotificationConversationActionKind.RETRY_APPEAL,
                        current_case_version=current_case.case_version,
                        target_notification_id=latest.notification_id,
                        supporting_authority_id=latest.reply_authority_id,
                        supporting_document_sha256=latest.reply_document_sha256,
                    )
                )
            else:
                reply_target = next(
                    (
                        item
                        for item in reversed(
                            sorted(
                                case_updated,
                                key=lambda value: (
                                    value.audit_event.notification_authority.plan.planned_at
                                ),
                            )
                        )
                        if item.status == M8NotificationStatus.DELIVERED
                        and item.audit_event.notification_authority.plan.target
                        .inbound_response_supported
                    ),
                    None,
                )
                if reply_target is not None:
                    for kind in (
                        M8NotificationConversationActionKind.SUBMIT_EXPLANATION,
                        M8NotificationConversationActionKind.SUBMIT_APPEAL,
                    ):
                        actions.append(
                            M8NotificationConversationActionV1(
                                action=kind,
                                current_case_version=current_case.case_version,
                                target_notification_id=reply_target.notification_id,
                            )
                        )
            ack_target = next(
                (
                    item
                    for item in outcome_notifications
                    if item.status == M8NotificationStatus.DELIVERED
                ),
                None,
            )
            if ack_target is not None:
                actions.append(
                    M8NotificationConversationActionV1(
                        action=M8NotificationConversationActionKind.ACKNOWLEDGE_OUTCOME,
                        current_case_version=current_case.case_version,
                        target_notification_id=ack_target.notification_id,
                    )
                )

        known_times = tuple(item.occurred_at for item in events if item.occurred_at is not None)
        last_activity = max(known_times) if known_times else None
        if current_case.status == M8OperationalCaseStatus.APPEALED:
            pending = "SAFETY_OFFICER"
            progress = "学生申诉已保存，现在等待安全负责人复核。"
        elif (
            current_case.status == M8OperationalCaseStatus.APPEAL_RESOLVED
            and not outcome_notifications
        ):
            pending = "SAFETY_OFFICER"
            progress = "申诉已处理，等待安全负责人发送处理结果。"
        elif any(item.status == M8NotificationStatus.DELIVERED for item in outcome_notifications):
            pending = "STUDENT"
            progress = "处理结果已送达，等待学生确认。"
        elif any(item.status == M8NotificationStatus.DELIVERED for item in case_updated):
            pending = "STUDENT"
            progress = "案件消息已送达，学生可提交说明或申诉。"
        else:
            pending = "NONE"
            progress = f"案件当前状态为 {current_case.status.value}，暂无待办动作。"
        latest_title = events[-1].title if events else "案件会话已建立"
        summary = M8NotificationConversationSummaryV1(
            case_id=case_id,
            case_status=current_case.status,
            case_version=current_case.case_version,
            location_id=authority.location_id,
            notification_count=len(case_notifications),
            reply_count=reply_count,
            last_activity_at=last_activity,
            latest_title=latest_title,
            latest_progress=progress,
            pending_actor_role=pending,
        )
        return M8NotificationConversationV1(
            case_id=case_id,
            case_status=current_case.status,
            case_version=current_case.case_version,
            location_id=authority.location_id,
            summary=summary,
            events=events,
            actions=tuple(actions),
        )

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
        with self._operation_lock:
            path = self.artifact_root / PLATFORM_SCENARIO_STATE_NAME
            body = canonical_json(run.model_dump(mode="json"))
            self._replace_text_atomically(path, body)
            snapshots = self.artifact_root / "scenario-runs"
            snapshots.mkdir(parents=True, exist_ok=True)
            self._replace_text_atomically(snapshots / f"{run.run_id}.json", body)

    def _write_run_source(self, source: M8RunSourceRefV1) -> None:
        snapshots = self.artifact_root / "scenario-runs"
        snapshots.mkdir(parents=True, exist_ok=True)
        body = canonical_json(
            source.model_dump(mode="json", exclude_computed_fields=True)
        )
        self._replace_text_atomically(snapshots / f"{source.run_id}.source.json", body)

    def _is_evaluation_run(self, run_id: str) -> bool:
        return (self.artifact_root / "scenario-runs" / f"{run_id}.source.json").is_file()

    def _run_input_relative_path(self, run_id: str) -> str:
        source_path = self.artifact_root / "scenario-runs" / f"{run_id}.source.json"
        if source_path.is_file():
            try:
                source = M8RunSourceRefV1.model_validate_json(source_path.read_bytes())
                media_path = (self.project_root / source.relative_path).absolute()
                media_path.relative_to(self.project_root)
                if not media_path.is_file():
                    raise OSError("evaluation run media is absent")
                hasher = hashlib.sha256()
                with media_path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
                if digest != source.media_sha256:
                    raise ValueError("evaluation run media hash changed")
                return source.relative_path
            except (OSError, TypeError, ValueError):
                raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from None
        try:
            return self.input_media_path.relative_to(self.project_root).as_posix()
        except ValueError:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from None

    @staticmethod
    def _replace_text_atomically(path: Path, body: str) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(body, encoding="utf-8")
            temporary.replace(path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _read_run_snapshot(self, run_id: str) -> M8PlatformScenarioRunV1:
        return M8PlatformScenarioRunV1.model_validate_json(
            (self.artifact_root / "scenario-runs" / f"{run_id}.json").read_bytes()
        )

    def scenario_source_video(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
    ) -> PilotUiVideoSource:
        actor = self._actor(principal)
        if actor.role not in {M8ActorRole.OPERATIONS, M8ActorRole.SAFETY_OFFICER}:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        run = self._read_run_snapshot(run_id)
        service = self._pilot_service_for(run)
        relative_path = self._run_input_relative_path(run_id)
        video = next(
            (
                item
                for item in service.dashboard().videos
                if item.relative_path == relative_path
            ),
            None,
        )
        if video is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND)
        return service.video_source(video.video_id)

    def _pilot_service_for(self, run: M8PlatformScenarioRunV1) -> PilotUiService:
        return (
            self.model_pilot_service
            if run.recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
            else self.fixture_pilot_service
        )

    def _pilot_jobs_for(self, run: M8PlatformScenarioRunV1) -> PilotUiJobManager:
        return (
            self.model_pilot_jobs
            if run.recognition_mode == M8PlatformRecognitionMode.FULL_MODEL
            else self.fixture_pilot_jobs
        )

    @staticmethod
    def _model_manifest(component: str, profile) -> ModelManifest:
        return ModelManifest(
            component=component,
            provider=profile.provider,
            model=profile.model,
            revision=profile.revision,
            quantization=profile.quantization,
            weights_sha256=None,
            license_id="no-weights",
            provider_revision_guarantee=True,
        )

    def _model_components(
        self,
        run: M8PlatformScenarioRunV1,
        manifest: RunManifest,
    ) -> tuple[M8PlatformModelComponentV1, ...]:
        fixture = run.recognition_mode == M8PlatformRecognitionMode.DEMO_FIXTURE
        screening = manifest.models["screening"]
        perception_pipeline = build_expected_perception_manifest(self.model_pilot_service.config)
        pose = perception_pipeline.pose
        tracker = perception_pipeline.tracker
        pipeline_model = " + ".join(
            value
            for value in (
                perception_pipeline.detector.model,
                pose.model if pose is not None else None,
                tracker.model,
            )
            if value is not None
        )
        pipeline_revision = " + ".join(
            value
            for value in (
                perception_pipeline.detector.revision,
                pose.revision if pose is not None else None,
                tracker.revision,
            )
            if value is not None
        )
        return (
            M8PlatformModelComponentV1(
                component="PERCEPTION",
                source=(
                    M8PlatformExecutionSource.FIXTURE
                    if fixture
                    else M8PlatformExecutionSource.MODEL
                ),
                provider=("labcourt-fixture" if fixture else "HuggingFace + Roboflow"),
                model=("recorded-ppe-perception-v1" if fixture else pipeline_model),
                revision=("1.0.0" if fixture else pipeline_revision),
                manifest_id=(
                    platform_manifest("platform-recorded-ppe-perception-fixture-v1")
                    if fixture
                    else perception_pipeline.manifest_id
                ),
            ),
            M8PlatformModelComponentV1(
                component="SCREENING",
                source=(
                    M8PlatformExecutionSource.FIXTURE
                    if fixture
                    else M8PlatformExecutionSource.MODEL
                ),
                provider=screening.provider,
                model=screening.model,
                revision=screening.revision,
                manifest_id=screening.model_manifest_id,
            ),
        )

    @staticmethod
    def _document_sha256(value: object) -> str:
        document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
        return hashlib.sha256(document.encode("utf-8")).hexdigest()

    def _pilot_ppe_authorities(
        self,
        run: M8PlatformScenarioRunV1,
    ) -> tuple[Case, EvidencePack, StreamManifest, str]:
        source_case, source_pack, stream, _ = self._pilot_ppe_base_authorities(run)
        if not source_case.screening_results:
            raise ValueError("Pilot projection is missing screening authority")
        service = self._pilot_service_for(run)
        run_root = self.project_root / service.config.run.workspace / run.run_id
        raw_response = source_case.screening_results[-1].parsed_output
        raw_path = run_root / "model_responses" / f"{raw_response.response_id}.json"
        raw_bytes = raw_path.read_bytes()
        if hashlib.sha256(raw_bytes).hexdigest() != raw_response.response_content_sha256:
            raise ValueError("Pilot raw screening response hash does not match its authority")
        return (
            source_case,
            source_pack,
            stream,
            raw_path.relative_to(self.project_root).as_posix(),
        )

    def _pilot_ppe_base_authorities(
        self,
        run: M8PlatformScenarioRunV1,
    ) -> tuple[Case, EvidencePack, StreamManifest, RunManifest]:
        run_id = run.run_id
        service = self._pilot_service_for(run)
        run_root = self.project_root / service.config.run.workspace / run_id
        a2 = PilotA2Report.model_validate_json((run_root / "pilot/a2-report.json").read_bytes())
        if a2.run_id != run_id or len(a2.evidence_packs) != 1:
            raise ValueError("Pilot A2 report does not contain one PPE authority")
        summary = a2.evidence_packs[0]
        manifest = RunManifest.model_validate_json(
            (run_root / "pilot/run-manifest.json").read_bytes()
        )
        if len(manifest.streams) != 1 or manifest.streams[0].input_file_sha256 != a2.video_sha256:
            raise ValueError("Pilot run manifest video conflicts with its A2 authority")
        pointer = ProjectionCurrentPointer.model_validate_json(
            (run_root / "projections/current.json").read_bytes()
        )
        case_path = (
            run_root
            / "projections/generations"
            / pointer.generation_id
            / "cases"
            / f"{summary.case_id}.json"
        )
        source_case = Case.model_validate_json(case_path.read_bytes())
        packs = tuple(
            pack for pack in source_case.evidence_packs if pack.pack_id == summary.pack_id
        )
        if source_case.event.event_id != summary.event_id or len(packs) != 1:
            raise ValueError("Pilot projection is missing event or evidence authority")
        return (
            source_case,
            packs[0],
            manifest.streams[0],
            manifest,
        )

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
            self.artifact_root / "scenario-runs",
        ]
        return tuple(values)


__all__ = ["M8PlatformDemoService"]
