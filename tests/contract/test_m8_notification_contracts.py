from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationAudienceKind,
    M8NotificationChannelKind,
    M8NotificationEscalationPolicyAuthorityV1,
    M8NotificationPlanAuthorityV1,
    M8NotificationPurpose,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
    M8NotificationTemplateAuthorityV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
PLANNED_AT = datetime(2026, 8, 10, 8, 30, tzinfo=UTC)


def _target(
    *,
    actor_id: str = "student-01",
    channel: M8NotificationChannelKind = M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
    active: bool = True,
) -> M8NotificationTargetAuthorityV1:
    return M8NotificationTargetAuthorityV1(
        actor_id=actor_id,
        identity_provider_id=(
            "labcourt-local-fake"
            if channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
            else "campus-idp"
        ),
        external_subject_binding_sha256=SHA_A,
        channel=channel,
        authority_revision=1,
        active=active,
        inbound_response_supported=True,
        manifest_id=SHA_B,
    )


def _template() -> M8NotificationTemplateAuthorityV1:
    return M8NotificationTemplateAuthorityV1(
        template_id="case-student-card",
        template_version=1,
        locale="zh-CN",
        effective_at=PLANNED_AT - timedelta(days=1),
        content_document_sha256=SHA_B,
        allowed_purposes=(
            M8NotificationPurpose.CASE_CREATED,
            M8NotificationPurpose.EVIDENCE_REQUESTED,
        ),
        allowed_channels=(M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,),
        manifest_id=SHA_C,
    )


def _policy(
    *,
    risk_level: M8OperationalRiskLevel = M8OperationalRiskLevel.GENERAL,
) -> M8NotificationEscalationPolicyAuthorityV1:
    return M8NotificationEscalationPolicyAuthorityV1(
        policy_rule_id="general-student-response-v1",
        risk_level=risk_level,
        response_timeout_seconds=3600,
        max_delivery_attempts=3,
        escalation_roles=(M8ActorRole.LEADER, M8ActorRole.SAFETY_OFFICER),
        requires_human_send_confirmation=True,
        policy_manifest_id=SHA_C,
    )


def _plan(
    *,
    target: M8NotificationTargetAuthorityV1 | None = None,
    template: M8NotificationTemplateAuthorityV1 | None = None,
    policy: M8NotificationEscalationPolicyAuthorityV1 | None = None,
    risk_level: M8OperationalRiskLevel = M8OperationalRiskLevel.GENERAL,
    audience: M8NotificationAudienceKind = M8NotificationAudienceKind.CASE_SUBJECT,
) -> M8NotificationPlanAuthorityV1:
    return M8NotificationPlanAuthorityV1(
        case_id=SHA_A,
        case_version=2,
        case_authority_sha256=SHA_B,
        case_status=M8OperationalCaseStatus.EVIDENCE_REQUESTED,
        case_subject_actor_id="student-01",
        risk_level=risk_level,
        location_id="room-chem-301",
        purpose=M8NotificationPurpose.EVIDENCE_REQUESTED,
        audience=audience,
        target=target or _target(),
        template=template or _template(),
        escalation_policy=policy or _policy(risk_level=risk_level),
        planned_at=PLANNED_AT,
        notification_manifest_id=SHA_D,
    )


def test_target_authority_marks_local_delivery_as_simulated_and_privacy_safe() -> None:
    target = _target()

    assert target.simulated is True
    assert target.display_badge == "SIMULATED · LOCAL MESSAGE"
    assert len(target.target_authority_id) == 64
    assert "student-01" not in target.external_subject_binding_sha256

    with pytest.raises(ValidationError, match="labcourt-local-fake identity provider"):
        M8NotificationTargetAuthorityV1(
            **{
                **target.model_dump(
                    mode="python", exclude={"simulated", "display_badge", "target_authority_id"}
                ),
                "identity_provider_id": "campus-idp",
            }
        )
    payload = target.model_dump(mode="json")
    payload["simulated"] = False
    with pytest.raises(ValidationError, match="simulated"):
        M8NotificationTargetAuthorityV1.model_validate(payload)
    payload = target.model_dump(
        mode="json", exclude={"simulated", "display_badge", "target_authority_id"}
    )
    payload["authority_revision"] = True
    with pytest.raises(ValidationError):
        M8NotificationTargetAuthorityV1.model_validate(payload)


def test_template_is_versioned_effective_and_cannot_become_a_case_rule() -> None:
    template = _template()

    assert template.ordinary_document_can_define_case_rule is False
    assert len(template.template_authority_id) == 64

    payload = template.model_dump(mode="json")
    payload["ordinary_document_can_define_case_rule"] = True
    with pytest.raises(ValidationError, match="ordinary_document"):
        M8NotificationTemplateAuthorityV1.model_validate(payload)
    with pytest.raises(ValidationError, match="stable order"):
        M8NotificationTemplateAuthorityV1(
            **{
                **template.model_dump(
                    mode="python",
                    exclude={"ordinary_document_can_define_case_rule", "template_authority_id"},
                ),
                "allowed_purposes": tuple(reversed(template.allowed_purposes)),
            }
        )
    with pytest.raises(ValidationError, match="UTC"):
        M8NotificationTemplateAuthorityV1(
            **{
                **template.model_dump(
                    mode="python",
                    exclude={"ordinary_document_can_define_case_rule", "template_authority_id"},
                ),
                "effective_at": datetime(2026, 8, 9, 8, 30),
            }
        )


def test_escalation_policy_is_bounded_and_cannot_transition_a_case() -> None:
    policy = _policy()

    assert policy.case_transition_permitted is False
    assert len(policy.policy_authority_id) == 64

    payload = policy.model_dump(mode="json")
    payload["case_transition_permitted"] = True
    with pytest.raises(ValidationError, match="case_transition_permitted"):
        M8NotificationEscalationPolicyAuthorityV1.model_validate(payload)
    payload = policy.model_dump(
        mode="json", exclude={"case_transition_permitted", "policy_authority_id"}
    )
    payload["response_timeout_seconds"] = True
    with pytest.raises(ValidationError):
        M8NotificationEscalationPolicyAuthorityV1.model_validate(payload)
    payload["response_timeout_seconds"] = 3600
    payload["escalation_roles"] = [M8ActorRole.STUDENT.value]
    with pytest.raises(ValidationError, match="STUDENT"):
        M8NotificationEscalationPolicyAuthorityV1.model_validate(payload)


def test_plan_binds_case_target_template_policy_and_non_decision_flags() -> None:
    plan = _plan()

    assert plan.status == M8NotificationStatus.PLANNED
    assert plan.simulated is True
    assert plan.display_badge == "SIMULATED · LOCAL MESSAGE"
    assert plan.response_due_at == PLANNED_AT + timedelta(hours=1)
    assert plan.direct_disciplinary_action_permitted is False
    assert plan.case_transition_permitted is False
    assert plan.external_delivery_claim_permitted is False
    assert plan.idempotency_key == plan.notification_id
    assert len(plan.notification_id) == 64

    payload = plan.model_dump(mode="json")
    payload["direct_disciplinary_action_permitted"] = True
    with pytest.raises(ValidationError, match="direct_disciplinary"):
        M8NotificationPlanAuthorityV1.model_validate(payload)
    payload = plan.model_dump(
        mode="json",
        exclude={
            "simulated",
            "display_badge",
            "response_due_at",
            "direct_disciplinary_action_permitted",
            "case_transition_permitted",
            "external_delivery_claim_permitted",
            "notification_id",
            "idempotency_key",
        },
    )
    payload["case_version"] = True
    with pytest.raises(ValidationError):
        M8NotificationPlanAuthorityV1.model_validate(payload)


def test_plan_rejects_target_template_policy_and_leader_scope_grafts() -> None:
    with pytest.raises(ValidationError, match="Case subject"):
        _plan(target=_target(actor_id="student-other"))
    with pytest.raises(ValidationError, match="active target"):
        _plan(target=_target(active=False))
    with pytest.raises(ValidationError, match="risk"):
        _plan(policy=_policy(risk_level=M8OperationalRiskLevel.SEVERE))

    external_target = _target(channel=M8NotificationChannelKind.FEISHU)
    with pytest.raises(ValidationError, match="channel"):
        _plan(target=external_target)

    early_template = _template().model_copy(
        update={"effective_at": PLANNED_AT + timedelta(seconds=1)}
    )
    with pytest.raises(ValidationError, match="effective time"):
        _plan(template=early_template)

    with pytest.raises(ValidationError, match="major events"):
        _plan(audience=M8NotificationAudienceKind.LEADER_MAJOR_EVENT)


@pytest.mark.parametrize(
    "model",
    (
        _target(),
        _template(),
        _policy(),
        _plan(),
    ),
)
def test_notification_authorities_round_trip_and_validate_serialization_schema(
    model: M8NotificationTargetAuthorityV1
    | M8NotificationTemplateAuthorityV1
    | M8NotificationEscalationPolicyAuthorityV1
    | M8NotificationPlanAuthorityV1,
) -> None:
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model
    Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
        model.model_dump(mode="json")
    )
