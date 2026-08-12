from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_feishu_personal_demo import (
    M8FeishuPersonalDemoOutcome,
    M8FeishuPersonalDemoProbeReceiptV1,
    M8FeishuPersonalDemoProbeV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
NOW = datetime(2026, 8, 11, 10, 0, tzinfo=UTC)


def _probe() -> M8FeishuPersonalDemoProbeV1:
    return M8FeishuPersonalDemoProbeV1(
        app_id_sha256=SHA_A,
        recipient_open_id_sha256=SHA_B,
        requested_at=NOW,
        probe_manifest_id=SHA_A,
    )


def test_probe_card_is_visibly_simulated_and_has_no_domain_authority() -> None:
    probe = _probe()

    assert "PERSONAL DEMO" in probe.provider_content_json
    assert "模拟" in probe.provider_content_json
    assert probe.external_call_permitted is False
    assert probe.notification_transition_permitted is False
    assert probe.case_transition_permitted is False
    assert probe.direct_disciplinary_action_permitted is False
    assert len(probe.provider_uuid) == 48


def test_checked_receipt_proves_no_provider_call() -> None:
    receipt = M8FeishuPersonalDemoProbeReceiptV1(
        probe=_probe(),
        outcome=M8FeishuPersonalDemoOutcome.CHECKED,
        completed_at=NOW + timedelta(seconds=1),
        token_call_attempted=False,
        message_call_attempted=False,
    )

    assert receipt.real_delivery_confirmed is False
    assert receipt.provider_http_status is None


def test_accepted_receipt_requires_both_redacted_raw_references() -> None:
    receipt = M8FeishuPersonalDemoProbeReceiptV1(
        probe=_probe(),
        outcome=M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED,
        completed_at=NOW + timedelta(seconds=1),
        token_call_attempted=True,
        message_call_attempted=True,
        provider_http_status=200,
        provider_code=0,
        provider_message_id="om_demo_message",
        token_raw_response_ref="feishu-demo-token-redacted",
        token_raw_response_sha256=SHA_A,
        message_raw_response_ref="feishu-demo-message-response",
        message_raw_response_sha256=SHA_B,
    )

    assert receipt.outcome == M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED
    assert receipt.real_delivery_confirmed is False


def test_receipt_rejects_call_claim_without_evidence() -> None:
    with pytest.raises(ValidationError):
        M8FeishuPersonalDemoProbeReceiptV1(
            probe=_probe(),
            outcome=M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED,
            completed_at=NOW + timedelta(seconds=1),
            token_call_attempted=True,
            message_call_attempted=True,
            provider_http_status=200,
            provider_code=0,
            provider_message_id="om_demo_message",
        )
