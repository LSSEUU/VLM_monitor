from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import M8ActorRole, M8AuthorityReferenceKind
from labcourt.contracts.m8_platform_demo import (
    M8PlatformAgentQueryRequestV1,
    M8PlatformNotificationDispatchRequestV1,
    M8PlatformNotificationReplyRequestV1,
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
    )
    assert tuple(item.stage for item in run.stages) == tuple(M8PlatformScenarioStage)
    with pytest.raises(ValidationError):
        M8PlatformScenarioRunV1(
            run_id="platform-run-002",
            scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
            state="RUNNING",
            stages=tuple(reversed(stages)),
        )


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
