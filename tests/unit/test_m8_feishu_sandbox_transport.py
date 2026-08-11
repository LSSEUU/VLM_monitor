from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_feishu_transport import M8FeishuSandboxSendOutcome
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m8_feishu_http import (
    M8FeishuHttpCallStage,
    M8FeishuHttpDeliveryCertainty,
    M8FeishuHttpError,
    M8FeishuHttpFailureCode,
    M8FeishuHttpResponse,
)
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets
from labcourt.services.m8_feishu_sandbox_transport import M8FeishuSandboxSendService
from tests.contract.test_m8_feishu_activation_contracts import (
    BASE_TIME,
    SHA_A,
    SHA_B,
    SHA_C,
    _assessment,
)
from tests.contract.test_m8_feishu_notification_contracts import (
    FAKE_FEISHU_APP_ID,
    FAKE_FEISHU_OPEN_ID,
    _preflight,
)
from tests.contract.test_m8_feishu_transport_contracts import _activation_status


class _ActivationRepository:
    def __init__(self, status: M8FeishuSandboxActivationStatusV1) -> None:
        self.status = status

    def get_current_status(
        self,
        _candidate_authority_id: str,
        assessed_at: datetime,
    ) -> M8FeishuSandboxActivationStatusV1:
        if not self.status.sandbox_external_call_permitted:
            return self.status
        return self.status.model_copy(
            update={
                "current_readiness_assessment": _assessment(assessed_at=assessed_at),
                "assessed_at": assessed_at,
            }
        )


class _SecretResolver:
    def __init__(self, *, app_id: bytes = FAKE_FEISHU_APP_ID) -> None:
        self.app_id = app_id
        self.resolve_count = 0

    def resolve(self, profile, recipient_binding) -> M8FeishuResolvedSecrets:
        self.resolve_count += 1
        return M8FeishuResolvedSecrets(
            profile_id=profile.profile_id,
            binding_authority_id=recipient_binding.binding_authority_id,
            credential_bundle_reference_id=profile.credential_bundle_reference_id,
            app_id=self.app_id,
            app_secret=b"fake_feishu_app_secret",
            open_id=FAKE_FEISHU_OPEN_ID,
        )


class _HttpTransport:
    def __init__(
        self,
        *,
        token_error: M8FeishuHttpError | None = None,
        message_error: M8FeishuHttpError | None = None,
        message_code: int = 0,
    ) -> None:
        self.token_error = token_error
        self.message_error = message_error
        self.message_code = message_code
        self.token_calls = 0
        self.message_calls = 0

    def acquire_tenant_access_token(self, _profile, _secrets) -> M8FeishuHttpResponse:
        self.token_calls += 1
        if self.token_error is not None:
            raise self.token_error
        body = (
            canonical_json(
                {
                    "code": 0,
                    "expire": 7_200,
                    "msg": "success",
                    "tenant_access_token": "t-fake-sandbox-token",
                }
            )
            + "\n"
        ).encode()
        return M8FeishuHttpResponse(200, body, "feishu-token-log-fake-01")

    def send_interactive_message(
        self,
        _preflight,
        _secrets,
        _tenant_access_token: bytes,
        _rendered_card: bytes,
    ) -> M8FeishuHttpResponse:
        self.message_calls += 1
        if self.message_error is not None:
            raise self.message_error
        if self.message_code == 0:
            body = {
                "code": 0,
                "data": {"message_id": "om-fake-sandbox-message-01"},
                "msg": "success",
            }
            status = 200
        else:
            body = {"code": self.message_code, "msg": "provider error"}
            status = 400
        return M8FeishuHttpResponse(
            status,
            (canonical_json(body) + "\n").encode(),
            "feishu-message-log-fake-01",
        )


def _service(
    http: _HttpTransport,
    *,
    resolver: _SecretResolver | None = None,
    status: M8FeishuSandboxActivationStatusV1 | None = None,
) -> M8FeishuSandboxSendService:
    return M8FeishuSandboxSendService(
        _ActivationRepository(status or _activation_status()),
        resolver or _SecretResolver(),
        http,
        lambda: BASE_TIME + timedelta(hours=6),
        SHA_A,
        SHA_B,
        SHA_C,
    )


def test_success_uses_redacted_token_cache_and_returns_real_dispatch_authority() -> None:
    http = _HttpTransport()
    service = _service(http)
    preflight = _preflight()
    card = preflight.card.provider_content_json.encode()

    first = service.send(preflight, card)
    second = service.send(preflight, card)
    assert first.outcome == M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED
    assert first.dispatch_result.disposition == M8NotificationDispatchDisposition.ACCEPTED
    assert first.token_cache_hit is False
    assert second.token_cache_hit is True
    assert http.token_calls == 1
    assert http.message_calls == 2
    assert first.token_acquisition_receipt is not None
    token_raw = service.read_raw_response(first.token_acquisition_receipt.redacted_raw_response_ref)
    assert b"t-fake-sandbox-token" not in token_raw
    assert service.read_raw_response(first.dispatch_result.raw_response_ref)
    service.close()


def test_token_timeout_is_definitely_not_sent_and_never_calls_message() -> None:
    http = _HttpTransport(
        token_error=M8FeishuHttpError(
            M8FeishuHttpCallStage.TOKEN,
            M8FeishuHttpFailureCode.TIMEOUT,
            M8FeishuHttpDeliveryCertainty.DEFINITELY_NOT_SENT,
        )
    )
    result = _service(http).send(
        _preflight(),
        _preflight().card.provider_content_json.encode(),
    )
    assert result.outcome == M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT
    assert result.message_request_attempted is False
    assert result.dispatch_result.disposition == (
        M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
    )
    assert http.message_calls == 0


def test_message_timeout_remains_unknown_delivery() -> None:
    http = _HttpTransport(
        message_error=M8FeishuHttpError(
            M8FeishuHttpCallStage.MESSAGE,
            M8FeishuHttpFailureCode.TIMEOUT,
            M8FeishuHttpDeliveryCertainty.UNKNOWN,
        )
    )
    result = _service(http).send(
        _preflight(),
        _preflight().card.provider_content_json.encode(),
    )
    assert result.outcome == M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN
    assert result.message_request_attempted is True
    assert result.dispatch_result.disposition == M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
    assert result.provider_acceptance_confirmed is False


@pytest.mark.parametrize(
    ("code", "outcome"),
    (
        (230035, M8FeishuSandboxSendOutcome.MESSAGE_PERMISSION_DENIED),
        (230020, M8FeishuSandboxSendOutcome.MESSAGE_RATE_LIMITED),
        (999999, M8FeishuSandboxSendOutcome.MESSAGE_REJECTED),
    ),
)
def test_numeric_provider_code_not_msg_controls_rejection(code: int, outcome) -> None:
    result = _service(_HttpTransport(message_code=code)).send(
        _preflight(),
        _preflight().card.provider_content_json.encode(),
    )
    assert result.outcome == outcome
    assert result.dispatch_result.disposition == (
        M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
    )


def test_invalid_activation_or_secret_hash_blocks_before_http() -> None:
    http = _HttpTransport()
    inactive = _activation_status().model_copy(update={"current_readiness_assessment": None})
    with pytest.raises(ConcurrentModification, match="activation is not current"):
        _service(http, status=inactive).send(
            _preflight(),
            _preflight().card.provider_content_json.encode(),
        )
    assert http.token_calls == 0

    with pytest.raises(ConcurrentModification, match="secret authority mismatch"):
        _service(http, resolver=_SecretResolver(app_id=b"wrong-app-id")).send(
            _preflight(),
            _preflight().card.provider_content_json.encode(),
        )
    assert http.token_calls == 0
