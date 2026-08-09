from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.pilot_report import PILOT_OPERATOR_DISCLAIMER
from labcourt.contracts.pilot_ui import (
    PilotUiAlertView,
    PilotUiCaseSummary,
    PilotUiDashboard,
    PilotUiErrorResponse,
    PilotUiEvidenceView,
    PilotUiJobStartRequest,
    PilotUiJobStatus,
    PilotUiRunOption,
    PilotUiStageProgress,
    PilotUiTimelineItem,
    PilotUiVideoOption,
)
from labcourt.schema_export import expected_schema_files


def _stages() -> tuple[PilotUiStageProgress, ...]:
    return tuple(
        PilotUiStageProgress(key=key, state="COMPLETE", label=label, summary="已验证")
        for key, label in (
            ("VIDEO", "视频就绪"),
            ("PERCEPTION", "视觉感知"),
            ("EVIDENCE", "证据构建"),
            ("SCREENING", "模型初审"),
            ("REPORT", "案件与告警"),
        )
    )


def _dashboard() -> PilotUiDashboard:
    evidence = PilotUiEvidenceView(
        crop_id="1" * 64,
        role="TEMPORAL",
        frame_index=12,
        time_millis=500,
        integrity="VERIFIED",
        media_url="/api/runs/pilot-001/evidence/" + "1" * 64,
        width=320,
        height=180,
    )
    case = PilotUiCaseSummary(
        case_id="case-001",
        revision=5,
        status="CLOSED",
        violation_type="PPE_GOGGLES_MISSING",
        start_frame=10,
        end_frame_exclusive=20,
        start_time_millis=417,
        end_time_millis=833,
        screening_decision="ESTABLISHED",
        screening_probability=0.92,
        final_decision="ESTABLISHED",
        alert_level="CONFIRMED",
        alert_rescinded=False,
        human_review_required=False,
        appeal_status=None,
        evidence=(evidence,),
    )
    alert = PilotUiAlertView(
        alert_id="2" * 64,
        case_id="case-001",
        level="CONFIRMED",
        final_decision="ESTABLISHED",
        recipients=("safety-officer",),
        rescinded=False,
        production_action_prohibited=True,
    )
    return PilotUiDashboard(
        selected_run_id="pilot-001",
        selected_video_id="3" * 64,
        videos=(
            PilotUiVideoOption(
                video_id="3" * 64,
                display_name="demo.mp4",
                relative_path="inputs/demo.mp4",
                size_bytes=1024,
                matching_run_ids=("pilot-001",),
            ),
        ),
        runs=(
            PilotUiRunOption(
                run_id="pilot-001",
                state="COMPLETE",
                case_count=1,
                alert_count=1,
            ),
        ),
        stages=_stages(),
        preview_kind="SOURCE",
        preview_url="/api/videos/" + "3" * 64,
        fps_num=24,
        fps_den=1,
        frame_count=24,
        duration_millis=1000,
        manifest_id="4" * 64,
        metrics_id="5" * 64,
        cases=(case,),
        timeline=(
            PilotUiTimelineItem(
                item_id="6" * 64,
                kind="EVIDENCE",
                case_id="case-001",
                frame_index=12,
                time_millis=500,
                label="时序证据",
                evidence_crop_id="1" * 64,
                media_url=evidence.media_url,
            ),
        ),
        alerts=(alert,),
        disclaimer=PILOT_OPERATOR_DISCLAIMER,
    )


def test_pilot_ui_dashboard_is_strict_and_exported() -> None:
    dashboard = _dashboard()

    assert PilotUiDashboard.model_validate_json(dashboard.model_dump_json()) == dashboard
    assert dashboard.production_delivery_count == 0
    schemas = expected_schema_files()
    assert "pilot-ui-dashboard.schema.json" in schemas
    assert "pilot-ui-error-response.schema.json" in schemas
    assert "pilot-ui-job-start-request.schema.json" in schemas
    assert "pilot-ui-job-status.schema.json" in schemas


def test_pilot_ui_dashboard_rejects_false_selection_and_timing() -> None:
    payload = _dashboard().model_dump(mode="python")
    payload["selected_run_id"] = "pilot-unknown"
    with pytest.raises(ValidationError, match="selected run"):
        PilotUiDashboard.model_validate(payload)

    payload = _dashboard().model_dump(mode="python")
    payload["duration_millis"] = 999
    with pytest.raises(ValidationError, match="duration"):
        PilotUiDashboard.model_validate(payload)


def test_pilot_ui_dashboard_requires_the_fixed_workflow_order() -> None:
    payload = _dashboard().model_dump(mode="python")
    payload["stages"] = tuple(reversed(payload["stages"]))

    with pytest.raises(ValidationError, match="stage order"):
        PilotUiDashboard.model_validate(payload)


def test_pilot_ui_job_contracts_reject_ambiguous_states() -> None:
    request = PilotUiJobStartRequest(video_id="3" * 64, run_id="pilot-new", resume=True)
    assert PilotUiJobStartRequest.model_validate_json(request.model_dump_json()) == request

    running = PilotUiJobStatus(
        job_id="job-001",
        state="RUNNING",
        run_id="pilot-new",
        video_id="3" * 64,
        active_stage="PERCEPTION",
    )
    assert PilotUiJobStatus.model_validate_json(running.model_dump_json()) == running

    payload = running.model_dump(mode="python")
    payload["state"] = "FAILED"
    payload["active_stage"] = None
    with pytest.raises(ValidationError, match="failure reason"):
        PilotUiJobStatus.model_validate(payload)

    with pytest.raises(ValidationError, match="idle job"):
        PilotUiJobStatus(
            state="IDLE",
            run_id="pilot-new",
            video_id="3" * 64,
        )

    error = PilotUiErrorResponse(reason_code="RUN_NOT_FOUND")
    assert PilotUiErrorResponse.model_validate_json(error.model_dump_json()) == error
