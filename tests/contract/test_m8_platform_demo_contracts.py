from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole, M8AuthorityReferenceKind
from labcourt.contracts.m8_platform_demo import (
    M8PlatformAgentQueryRequestV1,
    M8PlatformExecutionSource,
    M8PlatformModelComponentV1,
    M8PlatformModelReadinessComponentV1,
    M8PlatformModelReadinessV1,
    M8PlatformNotificationDispatchRequestV1,
    M8PlatformNotificationReplyRequestV1,
    M8PlatformRecognitionMode,
    M8PlatformReservationAuthorityV1,
    M8PlatformResetRequestV1,
    M8PlatformScenarioKind,
    M8PlatformScenarioRunV1,
    M8PlatformScenarioStage,
    M8PlatformScenarioStageV1,
    M8PlatformScenarioStartRequestV1,
    M8PlatformStageState,
    M8PlatformVideoProfileV1,
)

SHA = "a" * 64


def test_platform_demo_roles_scenarios_and_authorities_are_closed() -> None:
    assert tuple(M8ActorRole) == (
        M8ActorRole.LEADER,
        M8ActorRole.SAFETY_OFFICER,
        M8ActorRole.STUDENT,
        M8ActorRole.OPERATIONS,
    )
    assert tuple(M8PlatformScenarioKind) == (
        M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
        M8PlatformScenarioKind.SMOKE_TEMPERATURE_EMERGENCY,
    )
    assert M8AuthorityReferenceKind.RESERVATION.value == "RESERVATION"
    assert tuple(M8PlatformRecognitionMode) == (
        M8PlatformRecognitionMode.FULL_MODEL,
        M8PlatformRecognitionMode.DEMO_FIXTURE,
    )


def test_reservation_is_typed_and_explicitly_not_visual_identity() -> None:
    starts_at = datetime(2026, 8, 12, 1, tzinfo=UTC)
    reservation = M8PlatformReservationAuthorityV1(
        reservation_id="reservation-demo",
        actor_id="student-demo",
        location_id="room-301",
        starts_at=starts_at,
        ends_at=starts_at + timedelta(hours=8),
        manifest_id=SHA,
    )
    assert reservation.association_notice == "预约关联，非视觉身份识别"  # noqa: RUF001
    assert reservation.face_recognition_performed is False
    assert reservation.cross_camera_reidentification_performed is False
    with pytest.raises(ValidationError):
        M8PlatformReservationAuthorityV1(
            reservation_id="reservation-demo",
            actor_id="student-demo",
            location_id="room-301",
            starts_at=starts_at,
            ends_at=starts_at,
            manifest_id=SHA,
        )


def test_scenario_run_requires_all_six_stages_in_stable_order() -> None:
    stages = tuple(
        M8PlatformScenarioStageV1(
            stage=stage,
            state=M8PlatformStageState.PENDING,
            summary="尚未生成",
        )
        for stage in M8PlatformScenarioStage
    )
    run = M8PlatformScenarioRunV1(
        run_id="platform-run-001",
        scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
        state="RUNNING",
        stages=stages,
        recognition_mode="FULL_MODEL",
    )
    assert tuple(item.stage for item in run.stages) == tuple(M8PlatformScenarioStage)
    with pytest.raises(ValidationError):
        M8PlatformScenarioRunV1(
            run_id="platform-run-002",
            scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
            state="RUNNING",
            stages=tuple(reversed(stages)),
            recognition_mode="FULL_MODEL",
        )


def test_scenario_stage_progress_is_grouped_bounded_perception_frame_authority() -> None:
    progress = M8PlatformScenarioStageV1(
        stage="PERCEPTION",
        state="RUNNING",
        summary="24 verified worker responses",
        completed_units=24,
        total_units=241,
        unit="FRAME",
    )
    assert progress.completed_units == 24
    assert progress.total_units == 241
    assert progress.unit == "FRAME"

    for update in (
        {"completed_units": 1},
        {"completed_units": 242, "total_units": 241, "unit": "FRAME"},
        {"stage": "VIDEO", "completed_units": 1, "total_units": 241, "unit": "FRAME"},
    ):
        with pytest.raises(ValidationError):
            M8PlatformScenarioStageV1(
                stage=update.pop("stage", "PERCEPTION"),
                state="RUNNING",
                summary="invalid objective progress",
                **update,
            )


def test_ppe_start_requires_explicit_mode_and_fixture_retry_reference() -> None:
    full = M8PlatformScenarioStartRequestV1(
        scenario_kind="PPE_GOGGLES_MISSING",
        recognition_mode="FULL_MODEL",
        explicit_human_confirmation=True,
    )
    assert full.retry_of_run_id is None
    retry = M8PlatformScenarioStartRequestV1(
        scenario_kind="PPE_GOGGLES_MISSING",
        recognition_mode="DEMO_FIXTURE",
        retry_of_run_id="platform-ppe-failed",
        explicit_human_confirmation=True,
    )
    assert retry.retry_of_run_id == "platform-ppe-failed"
    with pytest.raises(ValidationError):
        M8PlatformScenarioStartRequestV1(
            scenario_kind="PPE_GOGGLES_MISSING",
            explicit_human_confirmation=True,
        )
    with pytest.raises(ValidationError):
        M8PlatformScenarioStartRequestV1(
            scenario_kind="SMOKE_TEMPERATURE_EMERGENCY",
            recognition_mode="FULL_MODEL",
            explicit_human_confirmation=True,
        )


def test_model_readiness_and_provenance_are_closed_and_secret_free() -> None:
    perception = M8PlatformModelReadinessComponentV1(
        component="PERCEPTION",
        ready=True,
        provider="HuggingFace",
        model="IDEA-Research/grounding-dino-tiny + usyd-community/vitpose-plus-small",
        revision="pinned",
        manifest_id=SHA,
    )
    screening = M8PlatformModelReadinessComponentV1(
        component="SCREENING",
        ready=False,
        provider="alibaba-cloud-model-studio",
        model="qwen3-vl-plus-2025-12-19",
        revision="2025-12-19",
        manifest_id=SHA,
        failure_code="SCREENING_CREDENTIALS_UNAVAILABLE",
    )
    readiness = M8PlatformModelReadinessV1(
        full_model_ready=False,
        components=(perception, screening),
    )
    assert "api_key" not in readiness.model_dump_json()
    provenance = M8PlatformModelComponentV1(
        component="SCREENING",
        source=M8PlatformExecutionSource.MODEL,
        provider="alibaba-cloud-model-studio",
        model="qwen3-vl-plus-2025-12-19",
        revision="2025-12-19",
        manifest_id=SHA,
    )
    assert provenance.source is M8PlatformExecutionSource.MODEL


def test_video_profile_uses_verified_pilot_timing() -> None:
    profile = M8PlatformVideoProfileV1(
        input_file_sha256=SHA,
        fps_num=24,
        fps_den=1,
        frame_count=241,
        width=1280,
        height=720,
        duration_millis=10_042,
    )
    assert profile.timing_authority == "PILOT_RUN_MANIFEST"
    invalid = profile.model_dump(mode="json") | {"duration_millis": 10_000}
    with pytest.raises(ValidationError):
        M8PlatformVideoProfileV1.model_validate(invalid)


def test_screening_failure_preserves_completed_authorities_without_case() -> None:
    stages = tuple(
        M8PlatformScenarioStageV1(
            stage=stage,
            state=(
                "COMPLETE"
                if index < 3
                else "FAILED"
                if index == 3
                else "PENDING"
            ),
            summary=(
                "SCREENING_PROVIDER_UNAVAILABLE" if index == 3 else "authority retained"
            ),
            completed_units=(241 if stage == M8PlatformScenarioStage.PERCEPTION else None),
            total_units=(241 if stage == M8PlatformScenarioStage.PERCEPTION else None),
            unit=("FRAME" if stage == M8PlatformScenarioStage.PERCEPTION else None),
        )
        for index, stage in enumerate(M8PlatformScenarioStage)
    )
    failed = M8PlatformScenarioRunV1(
        run_id="platform-ppe-screening-unavailable",
        scenario_kind="PPE_GOGGLES_MISSING",
        state="FAILED",
        stages=stages,
        recognition_mode="FULL_MODEL",
        failure_code="SCREENING_PROVIDER_UNAVAILABLE",
        video_profile=M8PlatformVideoProfileV1(
            input_file_sha256=SHA,
            fps_num=24,
            fps_den=1,
            frame_count=241,
            width=1280,
            height=720,
            duration_millis=10_042,
        ),
    )
    assert failed.stages[1].completed_units == 241
    assert failed.stages[3].state == M8PlatformStageState.FAILED
    assert failed.case_id is failed.notification_id is None


@pytest.mark.parametrize(
    ("contract", "payload"),
    [
        (
            M8PlatformScenarioStartRequestV1,
            {"scenario_kind": "PPE_GOGGLES_MISSING", "explicit_human_confirmation": False},
        ),
        (M8PlatformResetRequestV1, {"explicit_human_confirmation": False}),
        (
            M8PlatformNotificationDispatchRequestV1,
            {"kind": "FREE_FORM", "explicit_human_confirmation": True},
        ),
        (
            M8PlatformNotificationReplyRequestV1,
            {
                "reply_kind": "EXPLANATION",
                "body": " ",
                "explicit_human_confirmation": True,
            },
        ),
        (M8PlatformAgentQueryRequestV1, {"query": "  查询案件"}),
    ],
)
def test_platform_write_inputs_reject_implicit_or_free_form_mutation(contract, payload) -> None:
    with pytest.raises(ValidationError):
        contract.model_validate(payload)
