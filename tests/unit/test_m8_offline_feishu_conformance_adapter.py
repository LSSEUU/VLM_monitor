from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from labcourt.adapters.m8_offline_feishu_conformance_adapter import (
    DeterministicOfflineFeishuConformanceAdapter,
)
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8ActorScopeKind,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_adapter_commissioning import (
    M8ExternalIdempotencyKey,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterKind,
)
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuCardDispatchPreflightV1,
    M8FeishuConformanceFailureCode,
    M8FeishuConformanceOutcome,
    M8FeishuNotificationCardV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDispatchDisposition,
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
from labcourt.ports.m8_feishu_notification_adapter import (
    M8FeishuConformanceAdapterError,
    M8FeishuConformanceAdapterFailureCode,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _candidate(
    *, adapter_revision: str = "im-v1-2026-04-10"
) -> M8ProductionAdapterCandidateAuthorityV1:
    return M8ProductionAdapterCandidateAuthorityV1(
        adapter_id="m8-feishu-tenant-app",
        adapter_revision=adapter_revision,
        adapter_kind=M8ProductionAdapterKind.EXTERNAL_NOTIFICATION,
        provider_id="feishu-open-platform",
        product_revision="tenant-custom-app-im-v1",
        campus_id="campus-main",
        scope_kind=M8ActorScopeKind.CAMPUS_WIDE,
        scope_location_ids=(),
        declared_license_id="feishu-open-platform-terms-review",
        request_timeout_ms=5_000,
        idempotency_key=M8ExternalIdempotencyKey.NOTIFICATION_ID,
        network_required=True,
        offline_fallback_adapter_id="m8-local-message-fake",
        offline_fallback_revision="v1",
        adapter_manifest_id=SHA_A,
        offline_fallback_manifest_id=SHA_B,
    )


def _profile(*, adapter_revision: str = "im-v1-2026-04-10") -> M8FeishuAdapterProfileV1:
    return M8FeishuAdapterProfileV1(
        candidate=_candidate(adapter_revision=adapter_revision),
        credential_bundle_reference_id="secret-feishu-campus-main",
        app_id_sha256=SHA_C,
        profile_manifest_id=SHA_D,
    )


def _target() -> M8NotificationTargetAuthorityV1:
    return M8NotificationTargetAuthorityV1(
        actor_id="student-01",
        identity_provider_id="campus-idp",
        external_subject_binding_sha256=SHA_E,
        channel=M8NotificationChannelKind.FEISHU,
        authority_revision=1,
        active=True,
        inbound_response_supported=True,
        manifest_id=SHA_A,
    )


def _plan() -> M8NotificationPlanAuthorityV1:
    target = _target()
    return M8NotificationPlanAuthorityV1(
        case_id=SHA_A,
        case_version=2,
        case_authority_sha256=SHA_B,
        case_status=M8OperationalCaseStatus.EVIDENCE_REQUESTED,
        case_subject_actor_id="student-01",
        risk_level=M8OperationalRiskLevel.GENERAL,
        location_id="room-chem-301",
        purpose=M8NotificationPurpose.EVIDENCE_REQUESTED,
        audience=M8NotificationAudienceKind.CASE_SUBJECT,
        target=target,
        template=M8NotificationTemplateAuthorityV1(
            template_id="feishu-case-student-card",
            template_version=1,
            locale="zh-CN",
            effective_at=BASE_TIME - timedelta(days=1),
            content_document_sha256=SHA_C,
            allowed_purposes=(M8NotificationPurpose.EVIDENCE_REQUESTED,),
            allowed_channels=(M8NotificationChannelKind.FEISHU,),
            manifest_id=SHA_D,
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="general-student-response-v1",
            risk_level=M8OperationalRiskLevel.GENERAL,
            response_timeout_seconds=3_600,
            max_delivery_attempts=3,
            escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
            requires_human_send_confirmation=True,
            policy_manifest_id=SHA_D,
        ),
        planned_at=BASE_TIME,
        notification_manifest_id=SHA_E,
    )


def _preflight(*, attempt_number: int = 1) -> M8FeishuCardDispatchPreflightV1:
    plan = _plan()
    profile = _profile()
    card = M8FeishuNotificationCardV1(plan=plan, card_renderer_manifest_id=SHA_A)
    capability = M8NotificationChannelCapabilityAuthorityV1(
        adapter_id=profile.candidate.adapter_id,
        adapter_revision=profile.candidate.adapter_revision,
        channel=M8NotificationChannelKind.FEISHU,
        request_timeout_ms=profile.candidate.request_timeout_ms,
        network_required=True,
        offline_capable=False,
        simulated=False,
        inbound_response_supported=True,
        adapter_manifest_id=profile.candidate.adapter_manifest_id,
    )
    request = M8NotificationDispatchRequestV1(
        plan=plan,
        source_notification_version=2,
        source_notification_authority_sha256=SHA_C,
        attempt_number=attempt_number,
        channel_capability=capability,
        rendered_card_ref=card.raw_card_ref,
        rendered_card_sha256=card.provider_content_sha256,
        dispatched_at=BASE_TIME + timedelta(minutes=1),
        timeout_ms=capability.request_timeout_ms,
        idempotency_key=plan.notification_id,
        request_manifest_id=SHA_B,
    )
    binding = M8FeishuRecipientBindingAuthorityV1(
        target=plan.target,
        profile_id=profile.profile_id,
        receive_id_reference="feishu-open-id-student-01",
        receive_id_sha256=SHA_E,
        mapping_revision=1,
        active=True,
        mapping_manifest_id=SHA_B,
    )
    return M8FeishuCardDispatchPreflightV1(
        notification_request=request,
        profile=profile,
        recipient_binding=binding,
        card=card,
        preflight_manifest_id=SHA_E,
    )


def _card_bytes(preflight: M8FeishuCardDispatchPreflightV1) -> bytes:
    return preflight.card.provider_content_json.encode("utf-8")


def test_success_is_simulated_cached_replayable_and_raw_response_bound() -> None:
    preflight = _preflight()
    card = _card_bytes(preflight)
    adapter = DeterministicOfflineFeishuConformanceAdapter(
        _profile(),
        M8FeishuConformanceOutcome.SUCCESS,
        SHA_D,
    )
    result = adapter.conform(preflight, card)
    repeated = adapter.conform(preflight, card)

    assert repeated == result
    assert adapter.replay(preflight.preflight_id) == result
    assert adapter.provider_generation_count == 1
    assert result.disposition == M8NotificationDispatchDisposition.ACCEPTED
    assert result.provider_acceptance_simulated is True
    assert result.real_send_confirmed is False
    assert result.notification_transition_permitted is False
    raw = adapter.read_raw_response(result.raw_response_ref)
    payload = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == result.raw_response_sha256
    assert payload["code"] == 0
    assert payload["data"]["message_id"] == result.provider_message_id
    assert payload["simulated"] is True


def test_retry_reuses_provider_uuid_without_generating_a_second_provider_send() -> None:
    first = _preflight(attempt_number=1)
    retry = _preflight(attempt_number=2)
    adapter = DeterministicOfflineFeishuConformanceAdapter(
        _profile(),
        M8FeishuConformanceOutcome.SUCCESS,
        SHA_D,
    )
    first_result = adapter.conform(first, _card_bytes(first))
    retry_result = adapter.conform(retry, _card_bytes(retry))

    assert first.provider_uuid == retry.provider_uuid
    assert first_result.provider_message_id == retry_result.provider_message_id
    assert first_result.preflight.preflight_id != retry_result.preflight.preflight_id
    assert adapter.provider_generation_count == 1


@pytest.mark.parametrize(
    ("outcome", "disposition", "failure"),
    (
        (
            M8FeishuConformanceOutcome.PERMISSION_DENIED,
            M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
            M8FeishuConformanceFailureCode.PERMISSION_DENIED,
        ),
        (
            M8FeishuConformanceOutcome.RATE_LIMITED,
            M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
            M8FeishuConformanceFailureCode.RATE_LIMITED,
        ),
        (
            M8FeishuConformanceOutcome.TIMEOUT_UNKNOWN_DELIVERY,
            M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
            M8FeishuConformanceFailureCode.CHANNEL_TIMEOUT,
        ),
    ),
)
def test_failure_scenarios_are_typed_without_sleep_or_delivery_claim(
    outcome: M8FeishuConformanceOutcome,
    disposition: M8NotificationDispatchDisposition,
    failure: M8FeishuConformanceFailureCode,
) -> None:
    preflight = _preflight()
    adapter = DeterministicOfflineFeishuConformanceAdapter(_profile(), outcome, SHA_D)
    result = adapter.conform(preflight, _card_bytes(preflight))
    assert result.disposition == disposition
    assert result.failure_code == failure
    assert result.real_send_confirmed is False
    assert result.delivery_confirmed is False
    assert adapter.provider_generation_count == 1


def test_adapter_rejects_profile_card_and_missing_replay_mismatches() -> None:
    preflight = _preflight()
    adapter = DeterministicOfflineFeishuConformanceAdapter(
        _profile(),
        M8FeishuConformanceOutcome.SUCCESS,
        SHA_D,
    )
    with pytest.raises(M8FeishuConformanceAdapterError) as card_error:
        adapter.conform(preflight, b"{}")
    assert card_error.value.reason_code == M8FeishuConformanceAdapterFailureCode.CARD_BYTES_MISMATCH

    other = DeterministicOfflineFeishuConformanceAdapter(
        _profile(adapter_revision="im-v1-next"),
        M8FeishuConformanceOutcome.SUCCESS,
        SHA_D,
    )
    with pytest.raises(M8FeishuConformanceAdapterError) as profile_error:
        other.conform(preflight, _card_bytes(preflight))
    assert profile_error.value.reason_code == M8FeishuConformanceAdapterFailureCode.PROFILE_MISMATCH

    with pytest.raises(M8FeishuConformanceAdapterError) as replay_error:
        adapter.replay(SHA_A)
    assert replay_error.value.reason_code == (
        M8FeishuConformanceAdapterFailureCode.PREFLIGHT_REPLAY_NOT_FOUND
    )
    with pytest.raises(M8FeishuConformanceAdapterError) as response_error:
        adapter.read_raw_response("missing-feishu-response")
    assert response_error.value.reason_code == (
        M8FeishuConformanceAdapterFailureCode.RAW_RESPONSE_NOT_FOUND
    )
