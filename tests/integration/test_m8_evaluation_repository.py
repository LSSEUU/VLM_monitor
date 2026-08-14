from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from labcourt.adapters.storage.sqlite_m8_evaluation_repository import (
    SQLiteM8EvaluationRepository,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus, EvidenceClass, ViolationType
from labcourt.contracts.m8_evaluation import (
    M8EvaluationActualRoute,
    M8EvaluationCampaignState,
    M8EvaluationCampaignV1,
    M8EvaluationDeliveryState,
    M8EvaluationExpectedRoute,
    M8EvaluationGroundTruthV1,
    M8EvaluationLabelIntervalV1,
    M8EvaluationMediaAssetV1,
    M8EvaluationMediaOrigin,
    M8EvaluationPpeState,
    M8EvaluationReviewState,
    M8EvaluationRunSourceKind,
    M8EvaluationRunState,
    M8EvaluationRunV1,
    M8RunSourceRefV1,
)
from labcourt.contracts.m8_hearing_api import M8HearingEligibility, M8HearingL5Status
from labcourt.contracts.m8_platform_demo import (
    M8PlatformExecutionSource,
    M8PlatformModelComponentV1,
    M8PlatformRecognitionMode,
    M8PlatformScenarioKind,
    M8PlatformScenarioRunV1,
    M8PlatformScenarioStage,
    M8PlatformScenarioStageV1,
    M8PlatformStageState,
    M8PlatformVideoProfileV1,
)
from labcourt.services.m8_evaluation import M8EvaluationService

SHA = "a" * 64
MANIFEST = "b" * 64
CONFIG = "c" * 64
MODEL = "d" * 64
NOW = datetime(2026, 8, 13, 8, tzinfo=UTC)


def _repository(tmp_path) -> SQLiteM8EvaluationRepository:
    return SQLiteM8EvaluationRepository.initialize(
        tmp_path / "labcourt.sqlite3",
        5_000,
        MANIFEST,
    )


def test_evaluation_repository_requires_migration_0016_identity(tmp_path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET name = 'm8_evaluation_wrong' WHERE version = 16"
        )

    with pytest.raises(RepositoryIntegrityError, match="migration 0016"):
        SQLiteM8EvaluationRepository(database, 5_000, MANIFEST)


def _asset() -> M8EvaluationMediaAssetV1:
    return M8EvaluationMediaAssetV1(
        asset_id=SHA,
        display_name="grey.mp4",
        media_sha256=SHA,
        size_bytes=1024,
        relative_path=f"inputs/evaluation-{SHA}.mp4",
        origin=M8EvaluationMediaOrigin.SERVER_DIRECTORY,
        codec="h264",
        width=640,
        height=480,
        fps_num=25,
        fps_den=1,
        frame_count=250,
        duration_millis=10_000,
        imported_by_actor_id="operations-demo",
        imported_at=NOW,
        media_manifest_id=MANIFEST,
    )


def test_evaluation_authorities_persist_and_resume_across_restart(tmp_path) -> None:
    repository = _repository(tmp_path)
    asset = repository.put_media(_asset())
    truth = repository.put_ground_truth(
        M8EvaluationGroundTruthV1(
            asset_id=asset.asset_id,
            revision=1,
            violation_type=ViolationType.PPE_GOGGLES_MISSING,
            evidence_class=EvidenceClass.ABSENCE,
            intervals=(
                M8EvaluationLabelIntervalV1(
                    start_frame=0,
                    end_frame_exclusive=250,
                    ppe_state=M8EvaluationPpeState.UNCLEAR,
                ),
            ),
            expected_route=M8EvaluationExpectedRoute.HEARING,
            review_state=M8EvaluationReviewState.HUMAN_CONFIRMED,
            reviewer_actor_id="safety-officer-demo",
            reviewed_at=NOW,
            label_manifest_id=MANIFEST,
        ),
        None,
    )
    campaign = repository.put_campaign(
        M8EvaluationCampaignV1(
            campaign_id="evaluation-campaign-01",
            revision=1,
            title="真实灰区回归",
            asset_ids=(asset.asset_id,),
            run_ids=(),
            repetitions=1,
            state=M8EvaluationCampaignState.DRAFT,
            created_by_actor_id="operations-demo",
            created_at=NOW,
            config_sha256=CONFIG,
            model_profile_sha256=MODEL,
            campaign_manifest_id=MANIFEST,
        ),
        None,
    )
    source = M8RunSourceRefV1(
        run_id="evaluation-run-01",
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=asset.asset_id,
        media_sha256=asset.media_sha256,
        relative_path=asset.relative_path,
        frame_count=asset.frame_count,
        source_manifest_id=asset.media_manifest_id,
    )
    queued = repository.put_run(
        M8EvaluationRunV1(
            run_id=source.run_id,
            revision=1,
            campaign_id=campaign.campaign_id,
            source=source,
            ordinal=0,
            repetition=1,
            state=M8EvaluationRunState.QUEUED,
            accuracy_metrics_eligible=True,
            ground_truth_id=truth.ground_truth_id,
            delivery_state=M8EvaluationDeliveryState.PENDING_POLICY,
            queued_at=NOW,
            config_sha256=CONFIG,
            model_profile_sha256=MODEL,
            run_manifest_id=MANIFEST,
        ),
        None,
    )
    running = repository.put_run(
        queued.model_copy(
            update={
                "revision": 2,
                "state": M8EvaluationRunState.RUNNING,
                "active_stage": "VIDEO",
                "started_at": NOW,
            }
        ),
        1,
    )
    assert running.revision == 2

    restarted = SQLiteM8EvaluationRepository(tmp_path / "labcourt.sqlite3", 5_000, MANIFEST)
    assert restarted.get_media(asset.asset_id) == asset
    assert restarted.get_current_ground_truth(asset.asset_id) == truth
    assert restarted.get_run(queued.run_id) == running
    assert restarted.list_runs() == (running,)

    config = SimpleNamespace(model_dump=lambda **_kwargs: {"profile": "real"})
    platform = SimpleNamespace(model_pilot_service=SimpleNamespace(config=config))
    service = M8EvaluationService(
        project_root=tmp_path,
        repository=restarted,
        operations_repository=SimpleNamespace(),
        platform_service=platform,
        clock=lambda: NOW,
        start_worker=False,
    )
    recovered = restarted.get_run(queued.run_id)
    assert recovered.revision == 3
    assert recovered.state == M8EvaluationRunState.QUEUED
    assert recovered.started_at is None
    service.close()


def test_terminal_run_requires_real_route_and_retains_source(tmp_path) -> None:
    repository = _repository(tmp_path)
    asset = repository.put_media(_asset())
    campaign = repository.put_campaign(
        M8EvaluationCampaignV1(
            campaign_id="evaluation-campaign-02",
            revision=1,
            title="安全阴性",
            asset_ids=(asset.asset_id,),
            run_ids=("evaluation-run-02",),
            repetitions=1,
            state=M8EvaluationCampaignState.QUEUED,
            created_by_actor_id="operations-demo",
            created_at=NOW,
            started_at=NOW,
            config_sha256=CONFIG,
            model_profile_sha256=MODEL,
            campaign_manifest_id=MANIFEST,
        ),
        None,
    )
    source = M8RunSourceRefV1(
        run_id="evaluation-run-02",
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=asset.asset_id,
        media_sha256=asset.media_sha256,
        relative_path=asset.relative_path,
        frame_count=asset.frame_count,
        source_manifest_id=asset.media_manifest_id,
    )
    queued = repository.put_run(
        M8EvaluationRunV1(
            run_id=source.run_id,
            revision=1,
            campaign_id=campaign.campaign_id,
            source=source,
            ordinal=0,
            repetition=1,
            state=M8EvaluationRunState.QUEUED,
            accuracy_metrics_eligible=False,
            delivery_state=M8EvaluationDeliveryState.PENDING_POLICY,
            queued_at=NOW,
            config_sha256=CONFIG,
            model_profile_sha256=MODEL,
            run_manifest_id=MANIFEST,
        ),
        None,
    )
    running = repository.put_run(
        queued.model_copy(
            update={
                "revision": 2,
                "state": M8EvaluationRunState.RUNNING,
                "active_stage": "SCREENING",
                "started_at": NOW,
            }
        ),
        1,
    )
    completed = repository.put_run(
        running.model_copy(
            update={
                "revision": 3,
                "state": M8EvaluationRunState.SUCCEEDED,
                "active_stage": None,
                "actual_route": M8EvaluationActualRoute.NO_CANDIDATE,
                "delivery_state": M8EvaluationDeliveryState.NOT_APPLICABLE,
                "completed_at": NOW,
            }
        ),
        2,
    )
    assert completed.case_id is None
    assert completed.source.asset_id == asset.asset_id


def test_local_only_media_projects_as_completed_human_review_without_provider_call() -> None:
    source = M8RunSourceRefV1(
        run_id="evaluation-local-review-01",
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=SHA,
        media_sha256=SHA,
        relative_path=f"inputs/evaluation-{SHA}.mp4",
        frame_count=250,
        source_manifest_id=MANIFEST,
    )
    running = M8EvaluationRunV1(
        run_id=source.run_id,
        revision=2,
        campaign_id="evaluation-campaign-local-review",
        source=source,
        ordinal=0,
        repetition=1,
        state=M8EvaluationRunState.RUNNING,
        active_stage="SCREENING",
        accuracy_metrics_eligible=False,
        delivery_state=M8EvaluationDeliveryState.PENDING_POLICY,
        queued_at=NOW,
        started_at=NOW,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
        run_manifest_id=MANIFEST,
    )
    scenario = M8PlatformScenarioRunV1(
        run_id=source.run_id,
        scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
        state="SUCCEEDED",
        stages=tuple(
            M8PlatformScenarioStageV1(
                stage=stage,
                state=M8PlatformStageState.COMPLETE,
                summary="complete",
            )
            for stage in M8PlatformScenarioStage
        ),
        recognition_mode=M8PlatformRecognitionMode.FULL_MODEL,
        model_components=tuple(
            M8PlatformModelComponentV1(
                component=component,
                source=M8PlatformExecutionSource.MODEL,
                provider="real-provider",
                model="real-model",
                revision="pinned-revision",
                manifest_id=MANIFEST,
            )
            for component in ("PERCEPTION", "SCREENING")
        ),
        outcome="HUMAN_REVIEW_REQUIRED",
    )
    service = object.__new__(M8EvaluationService)
    service._clock = lambda: NOW
    projected = service._project_scenario(running, scenario)
    validated = M8EvaluationRunV1.model_validate(projected.model_dump(mode="json"))
    assert validated.state == M8EvaluationRunState.SUCCEEDED
    assert validated.actual_route == M8EvaluationActualRoute.HUMAN_REVIEW
    assert validated.route_reason_code == "SCREENING_MEDIA_LOCAL_ONLY"
    assert validated.failure_code is None
    assert validated.provider_receipt_refs == ()


def test_completed_prehearing_gate_projects_human_review_with_case_authorities() -> None:
    source = M8RunSourceRefV1(
        run_id="evaluation-prehearing-review-01",
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=SHA,
        media_sha256=SHA,
        relative_path=f"inputs/evaluation-{SHA}.mp4",
        frame_count=250,
        source_manifest_id=MANIFEST,
    )
    running = M8EvaluationRunV1(
        run_id=source.run_id,
        revision=2,
        campaign_id="evaluation-campaign-prehearing-review",
        source=source,
        ordinal=0,
        repetition=1,
        state=M8EvaluationRunState.RUNNING,
        active_stage="CASE",
        accuracy_metrics_eligible=False,
        delivery_state=M8EvaluationDeliveryState.PENDING_POLICY,
        queued_at=NOW,
        started_at=NOW,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
        run_manifest_id=MANIFEST,
    )
    scenario = M8PlatformScenarioRunV1(
        run_id=source.run_id,
        scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
        state="SUCCEEDED",
        stages=tuple(
            M8PlatformScenarioStageV1(
                stage=stage,
                state=M8PlatformStageState.COMPLETE,
                summary="complete",
            )
            for stage in M8PlatformScenarioStage
        ),
        case_id="platform-prehearing-case",
        hearing_case_id="m4-prehearing-case",
        case_status="PENDING_VERIFICATION",
        recognition_mode=M8PlatformRecognitionMode.FULL_MODEL,
        model_components=tuple(
            M8PlatformModelComponentV1(
                component=component,
                source=M8PlatformExecutionSource.MODEL,
                provider="real-provider",
                model="real-model",
                revision="pinned-revision",
                manifest_id=MANIFEST,
            )
            for component in ("PERCEPTION", "SCREENING")
        ),
        outcome="ACTIONABLE_RISK",
        video_profile=M8PlatformVideoProfileV1(
            input_file_sha256=SHA,
            fps_num=25,
            fps_den=1,
            frame_count=250,
            width=640,
            height=480,
            duration_millis=10_000,
        ),
        perception_preview_url=(
            f"/api/m8/demo/scenario-runs/{source.run_id}/perception-preview"
        ),
        model_or_fixture_id="real-screening-model",
        raw_response_ref="runs/evaluation-prehearing-review-01/model-response.json",
        screening_decision="ESCALATE",
        screening_summary="objective evidence remains insufficient",
        rule_judgment="GENERAL_RISK",
    )
    hearing_view = SimpleNamespace(
        case_status=CaseStatus.HUMAN_REVIEW,
        eligibility=M8HearingEligibility.HUMAN_REVIEW,
        l5_status=M8HearingL5Status.NOT_RUN,
    )

    class _RuntimeContext:
        def __enter__(self):
            return SimpleNamespace(view=lambda _case_id: hearing_view)

        def __exit__(self, *_args):
            return False

    service = object.__new__(M8EvaluationService)
    service._clock = lambda: NOW
    service._platform = SimpleNamespace(
        prehearing_preparation=lambda _run_id, _case_id: object(),
        open_hearing_runtime=lambda _run_id: _RuntimeContext(),
    )

    projected = service._project_scenario(running, scenario)
    validated = M8EvaluationRunV1.model_validate(projected.model_dump(mode="json"))
    assert validated.state == M8EvaluationRunState.SUCCEEDED
    assert validated.actual_route == M8EvaluationActualRoute.HUMAN_REVIEW
    assert validated.route_reason_code == "NO_NOVEL_CLEAR_FRAME"
    assert validated.case_id == scenario.case_id
    assert validated.hearing_case_id == scenario.hearing_case_id
    assert validated.m4_case_status == CaseStatus.HUMAN_REVIEW
    assert validated.hearing_eligibility == M8HearingEligibility.HUMAN_REVIEW
    assert validated.l5_status == M8HearingL5Status.NOT_RUN
    assert validated.provider_receipt_refs == (scenario.raw_response_ref,)


def test_legacy_run_without_additive_m4_projection_remains_canonical(tmp_path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(tmp_path)
    asset = repository.put_media(_asset())
    source = M8RunSourceRefV1(
        run_id="evaluation-legacy-run-01",
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=asset.asset_id,
        media_sha256=asset.media_sha256,
        relative_path=asset.relative_path,
        frame_count=asset.frame_count,
        source_manifest_id=asset.media_manifest_id,
    )
    run = M8EvaluationRunV1(
        run_id=source.run_id,
        revision=1,
        campaign_id="evaluation-legacy-campaign-01",
        source=source,
        ordinal=0,
        repetition=1,
        state=M8EvaluationRunState.QUEUED,
        accuracy_metrics_eligible=False,
        delivery_state=M8EvaluationDeliveryState.PENDING_POLICY,
        queued_at=NOW,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
        run_manifest_id=MANIFEST,
    )
    payload = run.model_dump(mode="json", exclude_computed_fields=True)
    for field in (
        "m4_case_status",
        "hearing_eligibility",
        "l5_status",
        "route_reason_code",
    ):
        payload.pop(field)
    raw = canonical_json(payload)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO m8_evaluation_run_versions(
                run_id, revision, campaign_id, asset_id, state,
                document_sha256, run_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.run_id,
                run.revision,
                run.campaign_id,
                run.source.asset_id,
                run.state.value,
                digest,
                raw,
            ),
        )
    loaded = repository.get_run(run.run_id)
    assert loaded.m4_case_status is None
    assert loaded.hearing_eligibility is None
    assert loaded.l5_status is None
    assert loaded.route_reason_code is None
