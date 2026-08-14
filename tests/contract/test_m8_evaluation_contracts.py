from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import EvidenceClass, ViolationType
from labcourt.contracts.m8_evaluation import (
    M8EvaluationCampaignCreateRequestV1,
    M8EvaluationExpectedRoute,
    M8EvaluationGroundTruthV1,
    M8EvaluationLabelIntervalV1,
    M8EvaluationMediaAssetV1,
    M8EvaluationMediaOrigin,
    M8EvaluationPpeState,
    M8EvaluationReviewState,
    M8EvaluationRunSourceKind,
    M8LiveIngestSessionV1,
    M8LiveIngestStartRequestV1,
    M8LiveIngestState,
    M8RunSourceRefV1,
)

SHA = "a" * 64
MANIFEST = "b" * 64
NOW = datetime(2026, 8, 13, tzinfo=UTC)


def _asset() -> M8EvaluationMediaAssetV1:
    return M8EvaluationMediaAssetV1(
        asset_id=SHA,
        display_name="real-grey.mp4",
        media_sha256=SHA,
        size_bytes=1_024,
        relative_path=f"inputs/evaluation-{SHA}.mp4",
        origin=M8EvaluationMediaOrigin.WEB_UPLOAD,
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


def test_media_identity_and_real_campaign_are_closed() -> None:
    asset = _asset()
    assert asset.asset_id == asset.media_sha256
    campaign = M8EvaluationCampaignCreateRequestV1(
        title="真实 PPE 灰区回归",
        asset_ids=(SHA,),
        repetitions=2,
        explicit_human_confirmation=True,
    )
    assert campaign.execution_profile == "REAL_MODELS"
    assert campaign.notification_delivery == "LIVE_SANDBOX"
    with pytest.raises(ValidationError):
        _asset().model_copy(update={"asset_id": "c" * 64})


def test_human_truth_is_distinct_from_machine_output() -> None:
    truth = M8EvaluationGroundTruthV1(
        asset_id=SHA,
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
    )
    assert truth.machine_output_is_ground_truth is False
    assert len(truth.ground_truth_id) == 64
    with pytest.raises(ValidationError):
        truth.model_copy(update={"reviewed_at": None})


def test_run_source_binds_exact_content_and_live_segment() -> None:
    recorded = M8RunSourceRefV1(
        run_id="evaluation-run-001",
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=SHA,
        media_sha256=SHA,
        relative_path=f"inputs/evaluation-{SHA}.mp4",
        frame_count=250,
        source_manifest_id=MANIFEST,
    )
    assert recorded.capture_segment_id is None
    with pytest.raises(ValidationError):
        recorded.model_copy(
            update={
                "source_kind": M8EvaluationRunSourceKind.LIVE_CAPTURE_SEGMENT,
            }
        )


def test_live_contract_exposes_measured_realtime_claim_only() -> None:
    request = M8LiveIngestStartRequestV1(
        candidate_authority_id=SHA,
        source_id="camera-rtsp-01",
        endpoint_environment_variable="LABCOURT_RTSP_CAMERA_01",
        explicit_human_confirmation=True,
    )
    assert request.analysis_fps == 5
    session = M8LiveIngestSessionV1(
        session_id="live-session-01",
        revision=1,
        candidate_authority_id=SHA,
        source_id=request.source_id,
        endpoint_reference="env:LABCOURT_RTSP_CAMERA_01",
        state=M8LiveIngestState.RUNNING,
        ring_buffer_seconds=60,
        started_at=NOW,
        frames_ingested=9_000,
        frames_analyzed=9_000,
        frames_dropped=0,
        reconnect_count=0,
        backlog_depth=0,
        p95_analysis_latency_ms=1_750,
        observed_duration_millis=1_800_000,
        ingest_manifest_id=MANIFEST,
    )
    assert session.realtime_claim_permitted is True
    assert session.target_analysis_fps == 5
    assert session.target_p95_latency_ms == 2_000
    assert session.life_safety_authority is False
