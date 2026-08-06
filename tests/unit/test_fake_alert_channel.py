from __future__ import annotations

import pytest

from labcourt.adapters.fake_alert_channel import DeterministicFakeAlertChannel
from labcourt.contracts.alert_policy import AlertChannelIdempotencyGuarantee
from tests.unit.test_m5_case_transitions import _close_with_alert, _ready_case


def test_fake_alert_channel_is_deterministic_and_exactly_idempotent() -> None:
    case = _close_with_alert(_ready_case())
    alert = case.alerts[-1]
    channel = DeterministicFakeAlertChannel()
    capability = channel.capability_authority(
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        config_sha256="b" * 64,
    )

    first = channel.send(alert, case, alert.alert_id)
    second = channel.send(alert, case, alert.alert_id)

    assert first == second
    assert first.accepted
    assert first.idempotency_key == alert.alert_id
    assert first.channel == capability.channel
    assert capability.idempotency_guarantee == AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID
    assert capability.provider_idempotency_key == "alert_id"
    assert capability.run_id == case.run_id
    assert capability.manifest_id == case.manifest_id


def test_fake_alert_channel_rejects_a_different_idempotency_key() -> None:
    case = _close_with_alert(_ready_case())
    alert = case.alerts[-1]
    with pytest.raises(ValueError, match="invalid delivery authority"):
        DeterministicFakeAlertChannel().send(alert, case, "different-alert")
