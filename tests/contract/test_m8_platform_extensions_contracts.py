from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_feishu_platform import (
    M8FeishuPlatformDisplayStatus,
    M8FeishuPlatformStatusV1,
)
from labcourt.contracts.m8_platform_agent import (
    M8AgentRunScenarioPayloadV2,
    M8PlatformAgentActionKindV2,
    M8PlatformProposedActionV2,
)

SHA = "a" * 64
NOW = datetime(2026, 8, 13, 4, 0, tzinfo=UTC)


def test_feishu_unconfigured_projection_keeps_local_fake_truthful() -> None:
    status = M8FeishuPlatformStatusV1(
        display_status=M8FeishuPlatformDisplayStatus.NOT_CONFIGURED,
        assessed_at=NOW,
        test_card_check_available=False,
        external_call_permitted=False,
    )
    assert status.default_channel.value == "LOCAL_OFFLINE_FAKE"
    assert status.default_channel_status == M8FeishuPlatformDisplayStatus.OFFLINE_FAKE
    assert status.real_delivery_confirmed is False
    assert status.secret_material_exposed is False
    with pytest.raises(ValidationError):
        M8FeishuPlatformStatusV1.model_validate(
            status.model_dump(mode="json") | {"external_call_permitted": True}
        )


def test_agent_v2_action_binds_closed_payload_version_and_fence() -> None:
    action = M8PlatformProposedActionV2(
        action_kind=M8PlatformAgentActionKindV2.RUN_SCENARIO,
        target_ref="smoke-temperature-emergency",
        endpoint_path="/api/m8/demo/scenario-runs",
        current_version=1,
        current_fence=SHA,
        impact_summary="写入两路离线模拟信号并建立紧急案件",
        request_payload=M8AgentRunScenarioPayloadV2(
            scenario_kind="SMOKE_TEMPERATURE_EMERGENCY",
            explicit_human_confirmation=True,
        ),
    )
    assert action.requires_confirmation is True
    with pytest.raises(ValidationError):
        M8PlatformProposedActionV2.model_validate(
            action.model_dump(mode="json") | {"action_kind": "RESET_DEMO"}
        )
