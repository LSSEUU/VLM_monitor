from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from labcourt.application.m8_feishu_emergency_demo import (
    build_m8_feishu_emergency_demo_probe,
)
from labcourt.contracts.m8_feishu_personal_demo import (
    M8FeishuPersonalDemoOutcome,
    M8FeishuPersonalDemoProbeV1,
)
from labcourt.ports.m8_feishu_http import M8FeishuHttpResponse
from labcourt.services.m8_feishu_personal_demo import M8FeishuPersonalDemoService

APP_ID = b"cli_personal_demo_app"
APP_SECRET = b"personal-demo-app-secret"
OPEN_ID = b"ou_personal_demo_recipient"
TOKEN = "tenant-access-token-not-for-persistence"
NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
SHA_A = "a" * 64


class _Clock:
    def __init__(self) -> None:
        self.current = NOW

    def __call__(self) -> datetime:
        self.current += timedelta(seconds=1)
        return self.current


class _FakeTransport:
    def __init__(self, token_code: int = 0) -> None:
        self.token_code = token_code
        self.token_calls = 0
        self.message_calls = 0

    def acquire_personal_demo_token(
        self,
        app_id: bytes,
        app_secret: bytes,
        timeout_ms: int,
    ) -> M8FeishuHttpResponse:
        assert app_id == APP_ID
        assert app_secret == APP_SECRET
        assert timeout_ms == 5_000
        self.token_calls += 1
        if self.token_code:
            return M8FeishuHttpResponse(
                400,
                b'{"code":99991663,"msg":"invalid app credentials"}',
                "log-token-rejected",
            )
        return M8FeishuHttpResponse(
            200,
            ('{"code":0,"msg":"ok","tenant_access_token":"' + TOKEN + '","expire":7200}').encode(),
            "log-token-accepted",
        )

    def send_personal_demo_card(
        self,
        open_id: bytes,
        tenant_access_token: bytes,
        provider_uuid: str,
        rendered_card: bytes,
        timeout_ms: int,
    ) -> M8FeishuHttpResponse:
        assert open_id == OPEN_ID
        assert tenant_access_token.decode() == TOKEN
        assert len(provider_uuid) == 48
        assert b"PERSONAL DEMO" in rendered_card
        assert timeout_ms == 5_000
        self.message_calls += 1
        return M8FeishuHttpResponse(
            200,
            b'{"code":0,"msg":"ok","data":{"message_id":"om_demo_01"}}',
            "log-message-accepted",
        )


def _probe() -> M8FeishuPersonalDemoProbeV1:
    return M8FeishuPersonalDemoProbeV1(
        app_id_sha256=hashlib.sha256(APP_ID).hexdigest(),
        recipient_open_id_sha256=hashlib.sha256(OPEN_ID).hexdigest(),
        requested_at=NOW,
        probe_manifest_id=SHA_A,
    )


def test_check_validates_inputs_without_transport_call() -> None:
    transport = _FakeTransport()
    run = M8FeishuPersonalDemoService(transport, _Clock()).check(
        _probe(), APP_ID, APP_SECRET, OPEN_ID
    )

    assert run.receipt.outcome == M8FeishuPersonalDemoOutcome.CHECKED
    assert transport.token_calls == 0
    assert transport.message_calls == 0
    assert run.raw_artifacts == ()


def test_send_accepts_one_card_and_redacts_token_artifact() -> None:
    transport = _FakeTransport()
    run = M8FeishuPersonalDemoService(transport, _Clock()).send(
        _probe(), APP_ID, APP_SECRET, OPEN_ID
    )

    assert run.receipt.outcome == M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED
    assert transport.token_calls == 1
    assert transport.message_calls == 1
    assert run.receipt.real_delivery_confirmed is False
    combined = b"".join(raw for _reference, raw in run.raw_artifacts)
    assert TOKEN.encode() not in combined
    assert APP_SECRET not in combined


def test_send_accepts_evidence_bound_simulated_emergency_card() -> None:
    transport = _FakeTransport()
    probe = build_m8_feishu_emergency_demo_probe(
        app_id_sha256=hashlib.sha256(APP_ID).hexdigest(),
        recipient_open_id_sha256=hashlib.sha256(OPEN_ID).hexdigest(),
        requested_at=NOW,
    )
    run = M8FeishuPersonalDemoService(transport, _Clock()).send(probe, APP_ID, APP_SECRET, OPEN_ID)

    assert run.receipt.outcome == M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED
    assert run.receipt.probe is probe
    assert probe.risk_assessment.create_pending_case_recommended is True
    assert run.receipt.case_transition_permitted is False
    assert transport.message_calls == 1


def test_rejected_token_never_attempts_message() -> None:
    transport = _FakeTransport(token_code=99991663)
    run = M8FeishuPersonalDemoService(transport, _Clock()).send(
        _probe(), APP_ID, APP_SECRET, OPEN_ID
    )

    assert run.receipt.outcome == M8FeishuPersonalDemoOutcome.TOKEN_REJECTED
    assert transport.token_calls == 1
    assert transport.message_calls == 0
