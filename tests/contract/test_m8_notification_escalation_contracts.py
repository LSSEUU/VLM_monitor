from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_notification_escalation import (
    M8NotificationEscalationAssessmentV1,
    M8NotificationEscalationOutcome,
)
from labcourt.contracts.m8_notification_persistence import (
    M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
    M8NotificationAuditEventV1,
    M8NotificationAuthorityV1,
    M8NotificationCommitReceiptV1,
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
SHA_E = "e" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _planned(*, human_confirmation: bool = False) -> M8NotificationCommitReceiptV1:
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
    plan = M8NotificationPlanAuthorityV1(
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
            requires_human_send_confirmation=human_confirmation,
            policy_manifest_id=SHA_D,
        ),
        planned_at=BASE_TIME,
        notification_manifest_id=SHA_E,
    )
    authority = M8NotificationAuthorityV1(
        plan=plan,
        notification_version=1,
        status=M8NotificationStatus.PLANNED,
        notification_manifest_id=SHA_E,
    )
    event = M8NotificationAuditEventV1(
        notification_authority=authority,
        event_sequence=1,
        plan_authority_id=plan.notification_id,
        prior_audit_event_sha256=M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
        audit_manifest_id=SHA_E,
    )
    return M8NotificationCommitReceiptV1(
        audit_event=event,
        raw_artifact_receipts=(),
        repository_manifest_id=SHA_C,
    )


def test_escalation_assessment_is_not_due_then_routes_only_when_overdue() -> None:
    source = _planned()
    before_due = M8NotificationEscalationAssessmentV1(
        source_notification=source,
        evaluated_at=BASE_TIME + timedelta(minutes=59),
        evaluator_manifest_id=SHA_A,
    )
    assert before_due.outcome == M8NotificationEscalationOutcome.NOT_DUE
    assert before_due.routing_roles == ()
    assert before_due.notification_plan_recommended is False

    overdue = M8NotificationEscalationAssessmentV1(
        source_notification=source,
        evaluated_at=BASE_TIME + timedelta(hours=1, seconds=7),
        evaluator_manifest_id=SHA_A,
    )
    assert overdue.outcome == M8NotificationEscalationOutcome.OVERDUE
    assert overdue.overdue_seconds == 7
    assert overdue.routing_roles == (M8ActorRole.SAFETY_OFFICER,)
    assert overdue.notification_plan_recommended is True
    assert overdue.system_queue_permitted_by_policy is True
    assert overdue.case_transition_permitted is False
    assert overdue.direct_disciplinary_action_permitted is False


def test_escalation_assessment_preserves_human_send_policy() -> None:
    assessment = M8NotificationEscalationAssessmentV1(
        source_notification=_planned(human_confirmation=True),
        evaluated_at=BASE_TIME + timedelta(hours=2),
        evaluator_manifest_id=SHA_A,
    )
    assert assessment.notification_plan_recommended is True
    assert assessment.system_queue_permitted_by_policy is False


def test_escalation_assessment_rejects_non_utc_and_computed_graft() -> None:
    source = _planned()
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        M8NotificationEscalationAssessmentV1(
            source_notification=source,
            evaluated_at=datetime(2026, 8, 10, 10, 0),
            evaluator_manifest_id=SHA_A,
        )

    assessment = M8NotificationEscalationAssessmentV1(
        source_notification=source,
        evaluated_at=BASE_TIME + timedelta(hours=2),
        evaluator_manifest_id=SHA_A,
    )
    payload = assessment.model_dump(mode="json")
    payload["case_transition_permitted"] = True
    with pytest.raises(ValidationError, match="case_transition_permitted"):
        M8NotificationEscalationAssessmentV1.model_validate(payload)


def test_escalation_assessment_round_trips_all_computed_claims() -> None:
    assessment = M8NotificationEscalationAssessmentV1(
        source_notification=_planned(),
        evaluated_at=BASE_TIME + timedelta(hours=2),
        evaluator_manifest_id=SHA_A,
    )
    assert (
        M8NotificationEscalationAssessmentV1.model_validate_json(assessment.model_dump_json())
        == assessment
    )
