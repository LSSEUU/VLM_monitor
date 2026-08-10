from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

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
    M8FeishuConformanceResultV1,
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

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _candidate() -> M8ProductionAdapterCandidateAuthorityV1:
    return M8ProductionAdapterCandidateAuthorityV1(
        adapter_id="m8-feishu-tenant-app",
        adapter_revision="im-v1-2026-04-10",
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


def _profile() -> M8FeishuAdapterProfileV1:
    return M8FeishuAdapterProfileV1(
        candidate=_candidate(),
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


def _binding() -> M8FeishuRecipientBindingAuthorityV1:
    return M8FeishuRecipientBindingAuthorityV1(
        target=_target(),
        profile_id=_profile().profile_id,
        receive_id_reference="feishu-open-id-student-01",
        receive_id_sha256=SHA_E,
        mapping_revision=1,
        active=True,
        mapping_manifest_id=SHA_B,
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


def _card() -> M8FeishuNotificationCardV1:
    return M8FeishuNotificationCardV1(plan=_plan(), card_renderer_manifest_id=SHA_A)


def _request(*, attempt_number: int = 1) -> M8NotificationDispatchRequestV1:
    plan = _plan()
    card = _card()
    capability = M8NotificationChannelCapabilityAuthorityV1(
        adapter_id=_candidate().adapter_id,
        adapter_revision=_candidate().adapter_revision,
        channel=M8NotificationChannelKind.FEISHU,
        request_timeout_ms=_candidate().request_timeout_ms,
        network_required=True,
        offline_capable=False,
        simulated=False,
        inbound_response_supported=True,
        adapter_manifest_id=_candidate().adapter_manifest_id,
    )
    return M8NotificationDispatchRequestV1(
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


def _preflight(*, attempt_number: int = 1) -> M8FeishuCardDispatchPreflightV1:
    return M8FeishuCardDispatchPreflightV1(
        notification_request=_request(attempt_number=attempt_number),
        profile=_profile(),
        recipient_binding=_binding(),
        card=_card(),
        preflight_manifest_id=SHA_E,
    )


def _result(
    outcome: M8FeishuConformanceOutcome = M8FeishuConformanceOutcome.SUCCESS,
) -> M8FeishuConformanceResultV1:
    success = outcome == M8FeishuConformanceOutcome.SUCCESS
    return M8FeishuConformanceResultV1(
        preflight=_preflight(),
        outcome=outcome,
        disposition=(
            M8NotificationDispatchDisposition.ACCEPTED
            if success
            else M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT
        ),
        provider_http_status=200 if success else 400,
        provider_code=0 if success else 230035,
        provider_message_id="om-simulated-message-01" if success else None,
        provider_log_id="log-simulated-feishu-01",
        failure_code=(None if success else M8FeishuConformanceFailureCode.PERMISSION_DENIED),
        completed_at=BASE_TIME + timedelta(minutes=1),
        raw_response_ref="feishu-simulated-response-01",
        raw_response_sha256=SHA_A,
        raw_response_size_bytes=128,
        conformance_manifest_id=SHA_B,
    )


def test_profile_pins_official_feishu_custom_app_boundary_without_secrets() -> None:
    profile = _profile()
    assert profile.api_origin == "https://open.feishu.cn"
    assert profile.token_path == "/open-apis/auth/v3/tenant_access_token/internal"
    assert profile.message_path == "/open-apis/im/v1/messages"
    assert profile.required_scope == "im:message:send_as_bot"
    assert profile.receive_id_type == "open_id"
    assert profile.provider_uuid_max_characters == 50
    assert profile.provider_uuid_dedup_window_seconds == 3_600
    assert profile.secret_material_embedded is False
    assert profile.external_call_permitted is False

    payload = profile.model_dump(mode="json")
    payload["api_origin"] = "https://example.invalid"
    with pytest.raises(ValidationError, match="api_origin"):
        M8FeishuAdapterProfileV1.model_validate(payload)
    with pytest.raises(ValidationError, match="Feishu external notification"):
        profile.model_copy(
            update={
                "candidate": _candidate().model_copy(
                    update={"provider_id": "another-message-provider"}
                )
            }
        )


def test_recipient_binding_keeps_clear_open_id_out_of_authority() -> None:
    binding = _binding()
    payload = binding.model_dump(mode="json")
    assert binding.target.channel == M8NotificationChannelKind.FEISHU
    assert binding.receive_id_type == "open_id"
    assert binding.clear_receive_id_persisted is False
    assert "ou_" not in json.dumps(payload)

    payload["receive_id"] = "ou_forbidden"
    with pytest.raises(ValidationError, match="Extra inputs"):
        M8FeishuRecipientBindingAuthorityV1.model_validate(payload)
    with pytest.raises(ValidationError, match="subject binding"):
        binding.model_copy(update={"receive_id_sha256": SHA_A})


def test_card_content_is_deterministic_bounded_and_not_case_authority() -> None:
    card = _card()
    content = json.loads(card.provider_content_json)
    assert content["header"]["title"]["tag"] == "plain_text"
    assert content["elements"][0]["tag"] == "markdown"
    assert "待有权限人员核实" in content["elements"][0]["content"]
    assert "AI" in content["elements"][0]["content"]
    assert card.provider_content_size_bytes <= 30 * 1024
    assert card.reply_event_contract_activated is False
    assert card.real_send_confirmed is False
    assert card.case_transition_permitted is False
    assert card.direct_disciplinary_action_permitted is False


def test_preflight_binds_existing_outbox_request_and_feishu_uuid_without_calling() -> None:
    first = _preflight()
    retry = _preflight(attempt_number=2)
    assert first.provider_uuid == retry.provider_uuid
    assert len(first.provider_uuid) <= 50
    assert first.msg_type == "interactive"
    assert first.content_is_json_encoded_string is True
    assert first.external_call_permitted is False
    assert first.notification_transition_permitted is False

    with pytest.raises(ValidationError, match="rendered card"):
        first.model_copy(
            update={
                "notification_request": _request().model_copy(
                    update={"rendered_card_sha256": SHA_D}
                )
            }
        )


def test_simulated_conformance_result_cannot_claim_real_send_or_notification_transition() -> None:
    result = _result()
    assert result.outcome == M8FeishuConformanceOutcome.SUCCESS
    assert result.provider_acceptance_simulated is True
    assert result.real_send_confirmed is False
    assert result.delivery_confirmed is False
    assert result.notification_transition_permitted is False

    payload = result.model_dump(mode="json")
    payload["real_send_confirmed"] = True
    with pytest.raises(ValidationError, match="real_send_confirmed"):
        M8FeishuConformanceResultV1.model_validate(payload)
    with pytest.raises(ValidationError, match="outcome shape"):
        result.model_copy(update={"provider_message_id": None})


@pytest.mark.parametrize(
    "model",
    (_profile(), _binding(), _card(), _preflight(), _result()),
)
def test_feishu_contracts_validate_as_serialization_schemas(model: BaseModel) -> None:
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )


def test_feishu_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-feishu-adapter-profile-v1": M8FeishuAdapterProfileV1,
        "m8-feishu-card-dispatch-preflight-v1": M8FeishuCardDispatchPreflightV1,
        "m8-feishu-conformance-result-v1": M8FeishuConformanceResultV1,
        "m8-feishu-notification-card-v1": M8FeishuNotificationCardV1,
        "m8-feishu-recipient-binding-authority-v1": M8FeishuRecipientBindingAuthorityV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
