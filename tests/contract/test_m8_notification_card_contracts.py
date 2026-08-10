from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_notification_cards import (
    M8NotificationCardAction,
    M8NotificationWorkflowManifestAuthorityV1,
    M8OfflineNotificationCardV1,
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


def _plan(
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
) -> M8NotificationPlanAuthorityV1:
    simulated = channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
    target = M8NotificationTargetAuthorityV1(
        actor_id="student-01",
        identity_provider_id="labcourt-local-fake" if simulated else "campus-idp",
        external_subject_binding_sha256=SHA_A,
        channel=channel,
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
            allowed_channels=(channel,),
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


def _workflow() -> M8NotificationWorkflowManifestAuthorityV1:
    return M8NotificationWorkflowManifestAuthorityV1(
        card_renderer_manifest_id=SHA_A,
        dispatch_request_manifest_id=SHA_B,
        transition_command_manifest_id=SHA_C,
        raw_storage_manifest_id=SHA_D,
        audit_manifest_id=SHA_E,
        workflow_manifest_id="f" * 64,
    )


def test_offline_card_binds_plan_actions_and_non_authority_disclosures() -> None:
    workflow = _workflow()
    card = M8OfflineNotificationCardV1(
        plan=_plan(),
        card_renderer_manifest_id=workflow.card_renderer_manifest_id,
    )
    assert card.available_actions == (
        M8NotificationCardAction.ACKNOWLEDGE,
        M8NotificationCardAction.REQUEST_APPEAL,
        M8NotificationCardAction.SUBMIT_EXPLANATION,
    )
    assert card.simulated is True
    assert "SIMULATED" in card.display_badge
    assert card.direct_disciplinary_action_permitted is False
    assert card.case_transition_permitted is False
    assert card.external_delivery_claim_permitted is False
    assert card.real_delivery_confirmed is False
    assert len(card.raw_card_ref) <= 64


def test_offline_card_rejects_external_plan_and_serialized_computed_graft() -> None:
    with pytest.raises(ValidationError, match="LOCAL_OFFLINE_FAKE"):
        M8OfflineNotificationCardV1(
            plan=_plan(M8NotificationChannelKind.FEISHU),
            card_renderer_manifest_id=SHA_A,
        )

    card = M8OfflineNotificationCardV1(plan=_plan(), card_renderer_manifest_id=SHA_A)
    payload = card.model_dump(mode="json")
    payload["real_delivery_confirmed"] = True
    with pytest.raises(ValidationError, match="real_delivery_confirmed"):
        M8OfflineNotificationCardV1.model_validate(payload)


@pytest.mark.parametrize(
    "model",
    (_workflow(), M8OfflineNotificationCardV1(plan=_plan(), card_renderer_manifest_id=SHA_A)),
)
def test_notification_card_authorities_round_trip_with_computed_claims(
    model: M8NotificationWorkflowManifestAuthorityV1 | M8OfflineNotificationCardV1,
) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model


def test_workflow_manifest_authority_rejects_computed_identity_graft() -> None:
    workflow = _workflow()
    payload = workflow.model_dump(mode="json")
    payload["workflow_authority_id"] = SHA_A
    with pytest.raises(ValidationError, match="workflow_authority_id"):
        M8NotificationWorkflowManifestAuthorityV1.model_validate(payload)
