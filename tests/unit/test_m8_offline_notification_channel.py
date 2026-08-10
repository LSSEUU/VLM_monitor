from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from labcourt.adapters.m8_offline_notification_channel import (
    DeterministicOfflineNotificationChannel,
)
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDispatchRequestV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationAudienceKind,
    M8NotificationChannelKind,
    M8NotificationEscalationPolicyAuthorityV1,
    M8NotificationPlanAuthorityV1,
    M8NotificationPurpose,
    M8NotificationTargetAuthorityV1,
    M8NotificationTemplateAuthorityV1,
)
from labcourt.ports.m8_notification_channel import (
    M8NotificationChannelAdapterError,
    M8NotificationChannelAdapterFailureCode,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _capability(
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
) -> M8NotificationChannelCapabilityAuthorityV1:
    simulated = channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
    return M8NotificationChannelCapabilityAuthorityV1(
        adapter_id="m8-local-message-fake" if simulated else "m8-external-message",
        adapter_revision="v1",
        channel=channel,
        request_timeout_ms=1_000,
        network_required=not simulated,
        offline_capable=simulated,
        simulated=simulated,
        inbound_response_supported=True,
        adapter_manifest_id=SHA_D,
    )


def _plan() -> M8NotificationPlanAuthorityV1:
    target = M8NotificationTargetAuthorityV1(
        actor_id="student-01",
        identity_provider_id="labcourt-local-fake",
        external_subject_binding_sha256=SHA_A,
        channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        authority_revision=1,
        active=True,
        inbound_response_supported=True,
        manifest_id=SHA_B,
    )
    return M8NotificationPlanAuthorityV1(
        case_id=SHA_A,
        case_version=1,
        case_authority_sha256=SHA_B,
        case_status=M8OperationalCaseStatus.PENDING_VERIFICATION,
        case_subject_actor_id="student-01",
        risk_level=M8OperationalRiskLevel.GENERAL,
        location_id="room-chem-301",
        purpose=M8NotificationPurpose.CASE_CREATED,
        audience=M8NotificationAudienceKind.CASE_SUBJECT,
        target=target,
        template=M8NotificationTemplateAuthorityV1(
            template_id="case-created-card",
            template_version=1,
            locale="zh-CN",
            effective_at=BASE_TIME - timedelta(days=1),
            content_document_sha256=SHA_C,
            allowed_purposes=(M8NotificationPurpose.CASE_CREATED,),
            allowed_channels=(M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,),
            manifest_id=SHA_D,
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="general-student-response-v1",
            risk_level=M8OperationalRiskLevel.GENERAL,
            response_timeout_seconds=3_600,
            max_delivery_attempts=3,
            escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
            requires_human_send_confirmation=False,
            policy_manifest_id=SHA_D,
        ),
        planned_at=BASE_TIME,
        notification_manifest_id=SHA_E,
    )


def _request(
    card: bytes,
    capability: M8NotificationChannelCapabilityAuthorityV1 | None = None,
) -> M8NotificationDispatchRequestV1:
    selected = capability or _capability()
    plan = _plan()
    return M8NotificationDispatchRequestV1(
        plan=plan,
        source_notification_version=2,
        source_notification_authority_sha256=SHA_C,
        attempt_number=1,
        channel_capability=selected,
        rendered_card_ref="notification-card-01",
        rendered_card_sha256=hashlib.sha256(card).hexdigest(),
        dispatched_at=BASE_TIME + timedelta(minutes=1),
        timeout_ms=selected.request_timeout_ms,
        idempotency_key=plan.notification_id,
        request_manifest_id=SHA_E,
    )


def test_offline_channel_dispatches_delivers_and_replays_exact_raw_responses() -> None:
    card = b'{"badge":"SIMULATED - LOCAL MESSAGE"}'
    adapter = DeterministicOfflineNotificationChannel(_capability())
    request = _request(card)

    dispatched = adapter.dispatch(request, card)
    assert adapter.dispatch(request, card) is dispatched
    assert adapter.replay_dispatch(request.dispatch_request_id) is dispatched
    dispatch_raw = adapter.read_raw_response(dispatched.raw_response_ref)
    dispatch_payload = json.loads(dispatch_raw)
    assert hashlib.sha256(dispatch_raw).hexdigest() == dispatched.raw_response_sha256
    assert dispatch_payload["simulated"] is True
    assert dispatch_payload["external_delivery_confirmed"] is False
    assert dispatched.accepted is True
    assert dispatched.real_delivery_confirmed is False

    conflicting_request = request.model_copy(
        update={"dispatched_at": request.dispatched_at + timedelta(seconds=1)}
    )
    with pytest.raises(M8NotificationChannelAdapterError) as idempotency_error:
        adapter.dispatch(conflicting_request, card)
    assert idempotency_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.REQUEST_MISMATCH
    )

    occurred_at = BASE_TIME + timedelta(minutes=2)
    delivered = adapter.confirm_simulated_delivery(dispatched, occurred_at)
    assert adapter.confirm_simulated_delivery(dispatched, occurred_at) is delivered
    assert adapter.replay_delivery(dispatched.dispatch_result_id) is delivered
    delivery_raw = adapter.read_raw_response(delivered.raw_response_ref)
    delivery_payload = json.loads(delivery_raw)
    assert hashlib.sha256(delivery_raw).hexdigest() == delivered.raw_response_sha256
    assert delivery_payload["simulated"] is True
    assert delivery_payload["real_delivery_confirmed"] is False
    assert delivered.simulated is True
    assert delivered.real_delivery_confirmed is False
    assert adapter.generation_counts == (1, 1)


def test_offline_channel_rejects_capability_card_and_unemitted_dispatch_mismatch() -> None:
    capability = _capability()
    adapter = DeterministicOfflineNotificationChannel(capability)
    card = b'{"badge":"SIMULATED"}'
    request = _request(card)

    with pytest.raises(M8NotificationChannelAdapterError) as card_error:
        adapter.dispatch(request, b"wrong")
    assert card_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.RENDERED_CARD_MISMATCH
    )

    different_capability = capability.model_copy(update={"adapter_revision": "v2"})
    different_request = _request(card, different_capability)
    with pytest.raises(M8NotificationChannelAdapterError) as capability_error:
        adapter.dispatch(different_request, card)
    assert capability_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.CAPABILITY_MISMATCH
    )

    other = DeterministicOfflineNotificationChannel(capability)
    emitted_elsewhere = other.dispatch(request, card)
    with pytest.raises(M8NotificationChannelAdapterError) as result_error:
        adapter.confirm_simulated_delivery(emitted_elsewhere, BASE_TIME + timedelta(minutes=2))
    assert result_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.DISPATCH_RESULT_MISMATCH
    )


def test_offline_channel_has_typed_missing_replay_and_rejects_external_capability() -> None:
    with pytest.raises(M8NotificationChannelAdapterError) as capability_error:
        DeterministicOfflineNotificationChannel(_capability(M8NotificationChannelKind.FEISHU))
    assert capability_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.CAPABILITY_MISMATCH
    )

    adapter = DeterministicOfflineNotificationChannel(_capability())
    with pytest.raises(M8NotificationChannelAdapterError) as dispatch_error:
        adapter.replay_dispatch(SHA_A)
    assert dispatch_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.DISPATCH_REPLAY_NOT_FOUND
    )
    with pytest.raises(M8NotificationChannelAdapterError) as delivery_error:
        adapter.replay_delivery(SHA_A)
    assert delivery_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.DELIVERY_REPLAY_NOT_FOUND
    )
    with pytest.raises(M8NotificationChannelAdapterError) as response_error:
        adapter.read_raw_response("missing-response")
    assert response_error.value.reason_code == (
        M8NotificationChannelAdapterFailureCode.RESPONSE_NOT_FOUND
    )
