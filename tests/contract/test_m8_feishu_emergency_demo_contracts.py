from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.application.m8_feishu_emergency_demo import (
    build_m8_feishu_emergency_demo_probe,
)
from labcourt.contracts.m8_access_cases import M8OperationalRiskLevel
from labcourt.contracts.m8_feishu_emergency_demo import (
    M8FeishuEmergencyDemoProbeReceiptV1,
    M8FeishuEmergencyDemoProbeV1,
)
from labcourt.contracts.m8_feishu_personal_demo import M8FeishuPersonalDemoOutcome
from labcourt.schema_registry import SCHEMA_MODELS

NOW = datetime(2026, 8, 11, 14, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64


def _probe() -> M8FeishuEmergencyDemoProbeV1:
    return build_m8_feishu_emergency_demo_probe(
        app_id_sha256=SHA_A,
        recipient_open_id_sha256=SHA_B,
        requested_at=NOW,
    )


def test_probe_binds_offline_signal_assessment_and_advisory_card() -> None:
    probe = _probe()

    assert probe.poll_result.sample_count == 2
    assert probe.risk_assessment.sample is probe.poll_result.samples[-1]
    assert probe.risk_assessment.risk_level == M8OperationalRiskLevel.EMERGENCY
    assert probe.risk_assessment.create_pending_case_recommended is True
    assert probe.risk_assessment.sample.raw_signal_ref
    assert "SIMULATED" in probe.provider_content_json
    assert "非认证消防检测" in probe.provider_content_json
    assert "建议状态" in probe.provider_content_json
    assert probe.case_transition_permitted is False
    assert probe.notification_transition_permitted is False


def test_probe_rejects_a_non_active_final_smoke_sample() -> None:
    payload = _probe().model_dump(mode="json")
    payload["risk_assessment"]["sample"]["value"] = False

    with pytest.raises(ValidationError):
        M8FeishuEmergencyDemoProbeV1.model_validate(payload)


def test_checked_receipt_has_no_external_or_domain_transition_claim() -> None:
    receipt = M8FeishuEmergencyDemoProbeReceiptV1(
        probe=_probe(),
        outcome=M8FeishuPersonalDemoOutcome.CHECKED,
        completed_at=NOW + timedelta(seconds=1),
        token_call_attempted=False,
        message_call_attempted=False,
    )

    assert receipt.real_delivery_confirmed is False
    assert receipt.case_transition_permitted is False
    assert receipt.notification_transition_permitted is False


def test_emergency_demo_schemas_are_exported() -> None:
    assert SCHEMA_MODELS["m8-feishu-emergency-demo-probe-v1"] is (M8FeishuEmergencyDemoProbeV1)
    assert SCHEMA_MODELS["m8-feishu-emergency-demo-probe-receipt-v1"] is (
        M8FeishuEmergencyDemoProbeReceiptV1
    )
