"""Authenticated multi-media evaluation orchestration over the existing Pilot/M4 path."""

from __future__ import annotations

import hashlib
import math
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from labcourt.adapters.opencv_video import (
    VerifiedVideoInput,
    probe_caller_attested_stream_manifest,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m8_evaluation_repository import (
    SQLiteM8EvaluationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m8_access_cases import M8ActorAuthorityV1, M8ActorRole
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_evaluation import (
    MAX_M8_EVALUATION_MEDIA_BYTES,
    M8EvaluationActualRoute,
    M8EvaluationCampaignCreateRequestV1,
    M8EvaluationCampaignState,
    M8EvaluationCampaignV1,
    M8EvaluationDashboardV1,
    M8EvaluationDeliveryState,
    M8EvaluationGroundTruthImportRequestV1,
    M8EvaluationGroundTruthV1,
    M8EvaluationMediaAssetV1,
    M8EvaluationMediaImportRequestV1,
    M8EvaluationMediaOrigin,
    M8EvaluationReviewState,
    M8EvaluationRunSourceKind,
    M8EvaluationRunState,
    M8EvaluationRunV1,
    M8RunSourceRefV1,
)
from labcourt.contracts.m8_hearing_api import M8HearingEligibility, M8HearingL5Status
from labcourt.contracts.m8_platform_demo import M8PlatformScenarioRunV1
from labcourt.exceptions import EvidenceMissing, LabCourtError
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode
from labcourt.services.m8_platform_demo import M8PlatformDemoService

_MAX_PILOT_FRAMES = 108_000
_QUEUE_POLL_SECONDS = 0.25
_READ_ROLES = {
    M8ActorRole.OPERATIONS,
    M8ActorRole.SAFETY_OFFICER,
    M8ActorRole.LEADER,
}


class M8EvaluationService:
    """Persist a FIFO queue while reusing the one authoritative Pilot/M4 implementation."""

    def __init__(
        self,
        *,
        project_root: Path,
        repository: SQLiteM8EvaluationRepository,
        operations_repository: SQLiteM8OperationsRepository,
        platform_service: M8PlatformDemoService,
        clock: Callable[[], datetime] | None = None,
        start_worker: bool = True,
    ) -> None:
        self.project_root = project_root.absolute()
        self._repository = repository
        self._operations = operations_repository
        self._platform = platform_service
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._inputs = self.project_root / "inputs"
        self._import_root = self.project_root / "evaluation-import"
        self._inputs.mkdir(parents=True, exist_ok=True)
        self._import_root.mkdir(parents=True, exist_ok=True)
        config_payload = self._platform.model_pilot_service.config.model_dump(
            mode="json", exclude_computed_fields=True
        )
        self.config_sha256 = sha256_hex(["m8-evaluation-config", 1, config_payload])
        self.model_profile_sha256 = sha256_hex(
            [
                "m8-evaluation-model-profile",
                1,
                config_payload.get("perception"),
                config_payload.get("screening"),
                config_payload.get("providers"),
                config_payload.get("hearing"),
            ]
        )
        self._recover_interrupted_runs()
        if start_worker:
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="labcourt-m8-evaluation-fifo",
                daemon=True,
            )
            self._thread.start()
            self._wake.set()

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def dashboard(self, principal: M8ApiPrincipalV1) -> M8EvaluationDashboardV1:
        self._require_read(principal)
        with self._lock:
            self._refresh_waiting_runs()
            return M8EvaluationDashboardV1(
                media=self._repository.list_media(),
                ground_truth=self._repository.list_current_ground_truth(),
                campaigns=self._repository.list_campaigns(),
                runs=self._repository.list_runs(),
            )

    def media(self, principal: M8ApiPrincipalV1) -> tuple[M8EvaluationMediaAssetV1, ...]:
        self._require_read(principal)
        return self._repository.list_media()

    def upload_media(
        self,
        principal: M8ApiPrincipalV1,
        *,
        display_name: str,
        body: bytes,
    ) -> M8EvaluationMediaAssetV1:
        actor = self._require_role(principal, M8ActorRole.OPERATIONS)
        if not isinstance(body, bytes) or not 0 < len(body) <= MAX_M8_EVALUATION_MEDIA_BYTES:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        return self._publish_media(
            display_name=display_name,
            body=body,
            origin=M8EvaluationMediaOrigin.WEB_UPLOAD,
            actor_id=actor.actor_id,
        )

    def import_media(
        self,
        principal: M8ApiPrincipalV1,
        request: M8EvaluationMediaImportRequestV1,
    ) -> tuple[M8EvaluationMediaAssetV1, ...]:
        actor = self._require_role(principal, M8ActorRole.OPERATIONS)
        imported: list[M8EvaluationMediaAssetV1] = []
        for relative in request.relative_paths:
            source = (self.project_root / relative).absolute()
            root = self._inputs if relative.startswith("inputs/") else self._import_root
            try:
                source.relative_to(root)
            except ValueError:
                raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST) from None
            body = self._read_bounded(source)
            imported.append(
                self._publish_media(
                    display_name=source.name,
                    body=body,
                    origin=M8EvaluationMediaOrigin.SERVER_DIRECTORY,
                    actor_id=actor.actor_id,
                )
            )
        return tuple(imported)

    def put_ground_truth(
        self,
        principal: M8ApiPrincipalV1,
        asset_id: str,
        truth: M8EvaluationGroundTruthV1,
    ) -> M8EvaluationGroundTruthV1:
        actor = self._require_role(principal, M8ActorRole.SAFETY_OFFICER)
        if truth.asset_id != asset_id or truth.reviewer_actor_id != actor.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        asset = self._repository.get_media(asset_id)
        if any(item.end_frame_exclusive > asset.frame_count for item in truth.intervals):
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        try:
            prior = self._repository.get_current_ground_truth(asset_id)
        except EvidenceMissing:
            prior = None
        expected = prior.revision if prior is not None else None
        if truth.revision != (expected or 0) + 1:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        return self._repository.put_ground_truth(truth, expected)

    def import_ground_truth(
        self,
        principal: M8ApiPrincipalV1,
        request: M8EvaluationGroundTruthImportRequestV1,
    ) -> tuple[M8EvaluationGroundTruthV1, ...]:
        return tuple(
            self.put_ground_truth(principal, truth.asset_id, truth) for truth in request.labels
        )

    def campaigns(self, principal: M8ApiPrincipalV1) -> tuple[M8EvaluationCampaignV1, ...]:
        self._require_read(principal)
        return self._repository.list_campaigns()

    def create_campaign(
        self,
        principal: M8ApiPrincipalV1,
        request: M8EvaluationCampaignCreateRequestV1,
    ) -> M8EvaluationCampaignV1:
        actor = self._require_role(principal, M8ActorRole.OPERATIONS)
        for asset_id in request.asset_ids:
            self._repository.get_media(asset_id)
        now = self._utc_now()
        campaign_id = f"evaluation-campaign-{uuid.uuid4().hex[:16]}"
        manifest_id = sha256_hex(
            [
                "m8-evaluation-campaign",
                1,
                campaign_id,
                request.model_dump(mode="json", exclude_computed_fields=True),
                self.config_sha256,
                self.model_profile_sha256,
            ]
        )
        campaign = M8EvaluationCampaignV1(
            campaign_id=campaign_id,
            revision=1,
            title=request.title,
            asset_ids=request.asset_ids,
            repetitions=request.repetitions,
            state=M8EvaluationCampaignState.DRAFT,
            created_by_actor_id=actor.actor_id,
            created_at=now,
            config_sha256=self.config_sha256,
            model_profile_sha256=self.model_profile_sha256,
            campaign_manifest_id=manifest_id,
        )
        return self._repository.put_campaign(campaign, None)

    def start_campaign(
        self,
        principal: M8ApiPrincipalV1,
        campaign_id: str,
    ) -> M8EvaluationCampaignV1:
        self._require_role(principal, M8ActorRole.OPERATIONS)
        readiness = self._platform.model_readiness(principal)
        if not readiness.full_model_ready:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        with self._lock:
            campaign = self._repository.get_campaign(campaign_id)
            if campaign.state != M8EvaluationCampaignState.DRAFT:
                raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
            now = self._utc_now()
            run_ids: list[str] = []
            ordinal = 0
            for asset_id in campaign.asset_ids:
                asset = self._repository.get_media(asset_id)
                for repetition in range(1, campaign.repetitions + 1):
                    run_id = f"evaluation-{uuid.uuid4().hex[:16]}"
                    source = M8RunSourceRefV1(
                        run_id=run_id,
                        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
                        asset_id=asset.asset_id,
                        media_sha256=asset.media_sha256,
                        relative_path=asset.relative_path,
                        frame_count=asset.frame_count,
                        source_manifest_id=asset.media_manifest_id,
                    )
                    try:
                        truth = self._repository.get_current_ground_truth(asset_id)
                    except EvidenceMissing:
                        truth = None
                    eligible = bool(
                        truth is not None
                        and truth.review_state == M8EvaluationReviewState.HUMAN_CONFIRMED
                    )
                    run_manifest = sha256_hex(
                        [
                            "m8-evaluation-run",
                            1,
                            campaign.campaign_manifest_id,
                            source.model_dump(mode="json", exclude_computed_fields=True),
                            ordinal,
                            repetition,
                            self.config_sha256,
                            self.model_profile_sha256,
                        ]
                    )
                    run = M8EvaluationRunV1(
                        run_id=run_id,
                        revision=1,
                        campaign_id=campaign.campaign_id,
                        source=source,
                        ordinal=ordinal,
                        repetition=repetition,
                        state=M8EvaluationRunState.QUEUED,
                        ground_truth_id=truth.ground_truth_id if eligible and truth else None,
                        accuracy_metrics_eligible=eligible,
                        delivery_state=M8EvaluationDeliveryState.PENDING_POLICY,
                        queued_at=now,
                        config_sha256=self.config_sha256,
                        model_profile_sha256=self.model_profile_sha256,
                        run_manifest_id=run_manifest,
                    )
                    self._repository.put_run(run, None)
                    run_ids.append(run_id)
                    ordinal += 1
            started = campaign.model_copy(
                update={
                    "revision": campaign.revision + 1,
                    "run_ids": tuple(run_ids),
                    "state": M8EvaluationCampaignState.QUEUED,
                    "started_at": now,
                }
            )
            published = self._repository.put_campaign(started, campaign.revision)
            self._wake.set()
            return published

    def campaign(self, principal: M8ApiPrincipalV1, campaign_id: str) -> M8EvaluationCampaignV1:
        self._require_read(principal)
        with self._lock:
            self._refresh_waiting_runs()
            self._refresh_campaign(campaign_id)
            return self._repository.get_campaign(campaign_id)

    def run(self, principal: M8ApiPrincipalV1, run_id: str) -> M8EvaluationRunV1:
        self._require_read(principal)
        with self._lock:
            run = self._repository.get_run(run_id)
            if run.hearing_case_id is not None and (
                run.state == M8EvaluationRunState.AWAITING_HEARING or run.l5_status is None
            ):
                run = self._refresh_hearing(run)
            return run

    def _publish_media(
        self,
        *,
        display_name: str,
        body: bytes,
        origin: M8EvaluationMediaOrigin,
        actor_id: str,
    ) -> M8EvaluationMediaAssetV1:
        if not display_name.casefold().endswith(".mp4"):
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        digest = hashlib.sha256(body).hexdigest()
        try:
            return self._repository.get_media(digest)
        except EvidenceMissing:
            pass
        relative = f"inputs/evaluation-{digest}.mp4"
        target = self.project_root / relative
        created = False
        if target.exists():
            if self._file_sha256(target) != digest:
                raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE)
        else:
            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
            try:
                temporary.write_bytes(body)
                temporary.replace(target)
                created = True
            finally:
                if temporary.exists():
                    temporary.unlink()
        try:
            with SecureWorkspace(
                self.project_root, max_file_bytes=MAX_M8_EVALUATION_MEDIA_BYTES
            ) as workspace:
                manifest = probe_caller_attested_stream_manifest(
                    camera_id="camera-recorded-demo-01",
                    stream_id=f"evaluation-{digest[:16]}",
                    input_file_sha256=digest,
                    verified_input=cast(VerifiedVideoInput, workspace),
                    relative_path=relative,
                    max_input_bytes=MAX_M8_EVALUATION_MEDIA_BYTES,
                    max_frame_pixels=self._platform.model_pilot_service.config.storage.max_image_pixels,
                    max_total_decoded_pixels=(
                        self._platform.model_pilot_service.config.storage.max_image_pixels
                        * _MAX_PILOT_FRAMES
                    ),
                )
            if manifest.frame_count > _MAX_PILOT_FRAMES:
                raise ValueError("evaluation video exceeds the Pilot frame budget")
            asset = M8EvaluationMediaAssetV1(
                asset_id=digest,
                display_name=display_name,
                media_sha256=digest,
                size_bytes=len(body),
                relative_path=relative,
                origin=origin,
                codec=manifest.codec,
                width=manifest.width,
                height=manifest.height,
                fps_num=manifest.fps_num,
                fps_den=manifest.fps_den,
                frame_count=manifest.frame_count,
                duration_millis=(
                    manifest.frame_count * 1000 * manifest.fps_den + manifest.fps_num - 1
                )
                // manifest.fps_num,
                imported_by_actor_id=actor_id,
                imported_at=self._utc_now(),
                media_manifest_id=sha256_hex(
                    [
                        "m8-evaluation-media-manifest",
                        1,
                        manifest.model_dump(mode="json", exclude_computed_fields=True),
                    ]
                ),
            )
            return self._repository.put_media(asset)
        except (LabCourtError, OSError, TypeError, ValueError):
            if created and target.exists():
                target.unlink()
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST) from None

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            self._wake.clear()
            if self._stop.is_set():
                return
            while not self._stop.is_set():
                with self._lock:
                    queued = sorted(
                        (
                            item
                            for item in self._repository.list_runs()
                            if item.state == M8EvaluationRunState.QUEUED
                        ),
                        key=lambda item: (item.queued_at, item.campaign_id, item.ordinal),
                    )
                    if not queued:
                        break
                    selected = queued[0]
                self._execute_run(selected)

    def _execute_run(self, queued: M8EvaluationRunV1) -> None:
        now = self._utc_now()
        running = queued.model_copy(
            update={
                "revision": queued.revision + 1,
                "state": M8EvaluationRunState.RUNNING,
                "active_stage": "VIDEO",
                "started_at": now,
            }
        )
        running = self._repository.put_run(running, queued.revision)
        self._refresh_campaign(running.campaign_id)
        try:
            self._platform.start_evaluation_scenario(running.source)
            while not self._stop.is_set():
                scenario = self._platform.refresh_evaluation_scenario(running.run_id)
                if scenario.state != "RUNNING":
                    break
                active = next(
                    (item.stage.value for item in scenario.stages if item.state.value == "RUNNING"),
                    running.active_stage,
                )
                if active != running.active_stage:
                    updated = running.model_copy(
                        update={"revision": running.revision + 1, "active_stage": active}
                    )
                    running = self._repository.put_run(updated, running.revision)
                self._stop.wait(_QUEUE_POLL_SECONDS)
            if self._stop.is_set():
                return
            completed = self._project_scenario(running, scenario)
        except M8ApiServiceError as error:
            completed = self._failed_run(running, error.reason_code.value)
        except (LabCourtError, OSError, TypeError, ValueError):
            completed = self._failed_run(running, "EVALUATION_EXECUTION_FAILED")
        self._repository.put_run(completed, running.revision)
        self._refresh_campaign(completed.campaign_id)

    def _project_scenario(
        self,
        running: M8EvaluationRunV1,
        scenario: M8PlatformScenarioRunV1,
    ) -> M8EvaluationRunV1:
        completed_at = self._utc_now()
        receipts = (scenario.raw_response_ref,) if scenario.raw_response_ref else ()
        if scenario.outcome == "HUMAN_REVIEW_REQUIRED":
            hearing_case_id = scenario.hearing_case_id
            prehearing = (
                self._platform.prehearing_preparation(
                    running.run_id,
                    hearing_case_id,
                )
                if hearing_case_id is not None
                else None
            )
            if prehearing is not None:
                assert hearing_case_id is not None
                with self._platform.open_hearing_runtime(running.run_id) as runtime:
                    hearing_view = runtime.view(hearing_case_id)
                return running.model_copy(
                    update={
                        "revision": running.revision + 1,
                        "state": M8EvaluationRunState.SUCCEEDED,
                        "active_stage": None,
                        "actual_route": M8EvaluationActualRoute.HUMAN_REVIEW,
                        "route_reason_code": "NO_NOVEL_CLEAR_FRAME",
                        "case_id": scenario.case_id,
                        "hearing_case_id": scenario.hearing_case_id,
                        "m4_case_status": hearing_view.case_status,
                        "hearing_eligibility": hearing_view.eligibility,
                        "l5_status": hearing_view.l5_status,
                        "completed_at": completed_at,
                        "delivery_state": M8EvaluationDeliveryState.NOT_APPLICABLE,
                        "provider_receipt_refs": receipts,
                    }
                )
            return running.model_copy(
                update={
                    "revision": running.revision + 1,
                    "state": M8EvaluationRunState.SUCCEEDED,
                    "active_stage": None,
                    "actual_route": M8EvaluationActualRoute.HUMAN_REVIEW,
                    "route_reason_code": "SCREENING_MEDIA_LOCAL_ONLY",
                    "completed_at": completed_at,
                    "delivery_state": M8EvaluationDeliveryState.NOT_APPLICABLE,
                    "provider_receipt_refs": receipts,
                }
            )
        if scenario.state == "FAILED":
            failure = scenario.failure_code or "PILOT_RUN_FAILED"
            route = (
                M8EvaluationActualRoute.PROVIDER_FAILURE
                if "PROVIDER" in failure or "SCREENING" in failure
                else M8EvaluationActualRoute.TECHNICAL_FAILURE
            )
            return running.model_copy(
                update={
                    "revision": running.revision + 1,
                    "state": M8EvaluationRunState.FAILED,
                    "active_stage": None,
                    "actual_route": route,
                    "failure_code": failure,
                    "completed_at": completed_at,
                    "delivery_state": M8EvaluationDeliveryState.NOT_APPLICABLE,
                    "provider_receipt_refs": receipts,
                }
            )
        if scenario.outcome == "NO_ACTIONABLE_RISK_ESTABLISHED":
            return running.model_copy(
                update={
                    "revision": running.revision + 1,
                    "state": M8EvaluationRunState.SUCCEEDED,
                    "active_stage": None,
                    "actual_route": M8EvaluationActualRoute.NO_CANDIDATE,
                    "completed_at": completed_at,
                    "delivery_state": M8EvaluationDeliveryState.NOT_APPLICABLE,
                    "provider_receipt_refs": receipts,
                }
            )
        common = {
            "revision": running.revision + 1,
            "active_stage": None,
            "case_id": scenario.case_id,
            "hearing_case_id": scenario.hearing_case_id,
            "notification_id": scenario.notification_id,
            "delivery_state": M8EvaluationDeliveryState.ACTIVATION_REQUIRED,
            "provider_receipt_refs": receipts,
        }
        if scenario.hearing_case_id is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE)
        with self._platform.open_hearing_runtime(running.run_id) as runtime:
            hearing_view = runtime.view(scenario.hearing_case_id)
        common.update(
            {
                "m4_case_status": hearing_view.case_status,
                "hearing_eligibility": hearing_view.eligibility,
                "l5_status": hearing_view.l5_status,
            }
        )
        if scenario.screening_decision == "ESCALATE":
            return running.model_copy(
                update={
                    **common,
                    "state": M8EvaluationRunState.AWAITING_HEARING,
                    "actual_route": M8EvaluationActualRoute.HEARING_REQUIRED,
                }
            )
        return running.model_copy(
            update={
                **common,
                "state": M8EvaluationRunState.SUCCEEDED,
                "actual_route": M8EvaluationActualRoute.FAST_VERDICT,
                "completed_at": completed_at,
            }
        )

    def _failed_run(self, running: M8EvaluationRunV1, code: str) -> M8EvaluationRunV1:
        return running.model_copy(
            update={
                "revision": running.revision + 1,
                "state": M8EvaluationRunState.FAILED,
                "active_stage": None,
                "actual_route": M8EvaluationActualRoute.TECHNICAL_FAILURE,
                "failure_code": code,
                "completed_at": self._utc_now(),
                "delivery_state": M8EvaluationDeliveryState.NOT_APPLICABLE,
            }
        )

    def _refresh_hearing(self, run: M8EvaluationRunV1) -> M8EvaluationRunV1:
        if run.hearing_case_id is None:
            return run
        try:
            with self._platform.open_hearing_runtime(run.run_id) as runtime:
                view = runtime.view(run.hearing_case_id)
        except (LabCourtError, OSError, TypeError, ValueError, M8ApiServiceError):
            return run
        authority_update = {
            "m4_case_status": view.case_status,
            "hearing_eligibility": view.eligibility,
            "l5_status": view.l5_status,
        }
        if view.eligibility == M8HearingEligibility.COMPLETED:
            route = M8EvaluationActualRoute.HEARING_REQUIRED
        elif view.eligibility == M8HearingEligibility.HUMAN_REVIEW:
            route = M8EvaluationActualRoute.HUMAN_REVIEW
        else:
            if all(getattr(run, key) == value for key, value in authority_update.items()):
                return run
            updated = run.model_copy(
                update={
                    "revision": run.revision + 1,
                    **authority_update,
                }
            )
            return self._repository.put_run(updated, run.revision)
        if view.l5_status == M8HearingL5Status.NOT_RUN:
            if all(getattr(run, key) == value for key, value in authority_update.items()):
                return run
            updated = run.model_copy(
                update={
                    "revision": run.revision + 1,
                    **authority_update,
                }
            )
            return self._repository.put_run(updated, run.revision)
        updated = run.model_copy(
            update={
                "revision": run.revision + 1,
                "state": M8EvaluationRunState.SUCCEEDED,
                "actual_route": route,
                "completed_at": self._utc_now(),
                **authority_update,
            }
        )
        updated = self._repository.put_run(updated, run.revision)
        self._refresh_campaign(updated.campaign_id)
        return updated

    def _refresh_waiting_runs(self) -> None:
        for run in self._repository.list_runs():
            if run.hearing_case_id is not None and (
                run.state == M8EvaluationRunState.AWAITING_HEARING or run.l5_status is None
            ):
                self._refresh_hearing(run)

    def _refresh_campaign(self, campaign_id: str) -> None:
        campaign = self._repository.get_campaign(campaign_id)
        if not campaign.run_ids:
            return
        runs = tuple(self._repository.get_run(run_id) for run_id in campaign.run_ids)
        now = self._utc_now()
        active_states = {M8EvaluationRunState.QUEUED, M8EvaluationRunState.RUNNING}
        if any(item.state in active_states for item in runs):
            state = M8EvaluationCampaignState.RUNNING
            completed_at = None
        elif any(item.state == M8EvaluationRunState.AWAITING_HEARING for item in runs):
            state = M8EvaluationCampaignState.AWAITING_HUMAN
            completed_at = None
        elif any(item.state == M8EvaluationRunState.FAILED for item in runs):
            state = M8EvaluationCampaignState.PARTIAL_FAILED
            completed_at = now
        else:
            state = M8EvaluationCampaignState.COMPLETED
            completed_at = now
        if campaign.state == state:
            return
        updated = campaign.model_copy(
            update={
                "revision": campaign.revision + 1,
                "state": state,
                "completed_at": completed_at,
            }
        )
        self._repository.put_campaign(updated, campaign.revision)

    def _recover_interrupted_runs(self) -> None:
        with self._lock:
            campaigns: set[str] = set()
            for run in self._repository.list_runs():
                if run.state != M8EvaluationRunState.RUNNING:
                    continue
                recovered = run.model_copy(
                    update={
                        "revision": run.revision + 1,
                        "state": M8EvaluationRunState.QUEUED,
                        "active_stage": None,
                        "started_at": None,
                    }
                )
                self._repository.put_run(recovered, run.revision)
                campaigns.add(run.campaign_id)
            for campaign_id in campaigns:
                self._refresh_campaign(campaign_id)

    def _require_read(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityV1:
        actor = self._actor(principal)
        if actor.role not in _READ_ROLES:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return actor

    def _require_role(self, principal: M8ApiPrincipalV1, role: M8ActorRole) -> M8ActorAuthorityV1:
        actor = self._actor(principal)
        if actor.role != role:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return actor

    def _actor(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        receipt = self._operations.get_current_actor_authority(principal.actor_id)
        if not receipt.authority.active:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return receipt.authority

    def _read_bounded(self, path: Path) -> bytes:
        try:
            size = path.stat().st_size
        except OSError:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from None
        if not 0 < size <= MAX_M8_EVALUATION_MEDIA_BYTES:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        body = path.read_bytes()
        if len(body) != size:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        return body

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _utc_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise ValueError("M8 evaluation clock must return timezone-aware UTC")
        if not math.isfinite(now.timestamp()):
            raise ValueError("M8 evaluation clock returned an invalid instant")
        return now


__all__ = ["M8EvaluationService"]
