from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
    M8NotificationAuditEventKind,
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
BASE_TIME = datetime(2026, 8, 10, 10, 0, tzinfo=UTC)


def _plan(*, human_confirmation: bool = False) -> M8NotificationPlanAuthorityV1:
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
            template_id="case-student-card",
            template_version=1,
            locale="zh-CN",
            effective_at=BASE_TIME - timedelta(days=1),
            content_document_sha256=SHA_B,
            allowed_purposes=(M8NotificationPurpose.EVIDENCE_REQUESTED,),
            allowed_channels=(M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,),
            manifest_id=SHA_C,
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="general-student-response-v1",
            risk_level=M8OperationalRiskLevel.GENERAL,
            response_timeout_seconds=3600,
            max_delivery_attempts=3,
            escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
            requires_human_send_confirmation=human_confirmation,
            policy_manifest_id=SHA_C,
        ),
        planned_at=BASE_TIME,
        notification_manifest_id=SHA_D,
    )


def _queue_command(plan: M8NotificationPlanAuthorityV1) -> M8NotificationTransitionCommandV1:
    return M8NotificationTransitionCommandV1(
        notification_id=plan.notification_id,
        source_notification_version=1,
        source_notification_authority_sha256=SHA_D,
        source_status=M8NotificationStatus.PLANNED,
        action=M8NotificationAction.QUEUE,
        initiator_kind=M8NotificationInitiatorKind.SYSTEM,
        system_authority_id=SHA_A,
        supporting_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.NOTIFICATION_REPLY,
                authority_id="notification-policy-01",
                document_sha256=SHA_E,
            ),
        ),
        explicit_human_confirmation=False,
        occurred_at=BASE_TIME + timedelta(seconds=1),
        command_manifest_id=SHA_E,
    )


def _planned_receipt(
    plan: M8NotificationPlanAuthorityV1 | None = None,
) -> M8NotificationCommitReceiptV1:
    selected = plan or _plan()
    authority = M8NotificationAuthorityV1(
        plan=selected,
        notification_version=1,
        status=M8NotificationStatus.PLANNED,
        notification_manifest_id=SHA_D,
    )
    event = M8NotificationAuditEventV1(
        notification_authority=authority,
        event_sequence=1,
        plan_authority_id=selected.notification_id,
        prior_audit_event_sha256=M8_NOTIFICATION_AUDIT_GENESIS_SHA256,
        audit_manifest_id=SHA_E,
    )
    return M8NotificationCommitReceiptV1(
        audit_event=event,
        repository_manifest_id=SHA_C,
    )


def _queued_receipt(
    planned: M8NotificationCommitReceiptV1 | None = None,
) -> M8NotificationCommitReceiptV1:
    before = planned or _planned_receipt()
    command = _queue_command(before.audit_event.notification_authority.plan)
    authority = M8NotificationAuthorityV1(
        plan=before.audit_event.notification_authority.plan,
        notification_version=2,
        status=M8NotificationStatus.QUEUED,
        prior_notification_document_sha256=before.notification_document_sha256,
        last_transition_command_id=command.command_id,
        last_initiator_authority_id=SHA_A,
        notification_manifest_id=SHA_D,
    )
    event = M8NotificationAuditEventV1(
        notification_authority=authority,
        event_sequence=2,
        transition_command=command,
        prior_audit_event_sha256=before.audit_event_sha256,
        audit_manifest_id=SHA_E,
    )
    return M8NotificationCommitReceiptV1(
        audit_event=event,
        repository_manifest_id=SHA_C,
    )


def test_planned_receipt_is_genesis_bound_and_content_addressed() -> None:
    receipt = _planned_receipt()

    assert receipt.notification_version == 1
    assert receipt.status == M8NotificationStatus.PLANNED
    assert receipt.audit_event.event_kind == M8NotificationAuditEventKind.NOTIFICATION_PLANNED
    assert receipt.audit_event.prior_audit_event_sha256 == M8_NOTIFICATION_AUDIT_GENESIS_SHA256
    assert (
        receipt.notification_id == receipt.audit_event.notification_authority.plan.notification_id
    )
    assert len(receipt.notification_document_sha256) == 64
    assert len(receipt.commit_receipt_id) == 64

    with pytest.raises(ValidationError, match="genesis"):
        M8NotificationAuditEventV1(
            notification_authority=receipt.audit_event.notification_authority,
            event_sequence=1,
            plan_authority_id=receipt.notification_id,
            prior_audit_event_sha256=SHA_A,
            audit_manifest_id=SHA_E,
        )


def test_transition_receipt_exactly_binds_command_prior_and_initiator() -> None:
    planned = _planned_receipt()
    queued = _queued_receipt(planned)

    assert queued.notification_version == 2
    assert queued.status == M8NotificationStatus.QUEUED
    assert queued.audit_event.event_kind == M8NotificationAuditEventKind.NOTIFICATION_TRANSITIONED
    assert (
        queued.audit_event.notification_authority.prior_notification_document_sha256
        == planned.notification_document_sha256
    )
    assert queued.audit_event.prior_audit_event_sha256 == planned.audit_event_sha256
    assert queued.audit_event.transition_command is not None
    assert (
        queued.audit_event.notification_authority.last_transition_command_id
        == queued.audit_event.transition_command.command_id
    )

    forged = queued.audit_event.notification_authority.model_copy(
        update={"last_initiator_authority_id": SHA_B}
    )
    with pytest.raises(ValidationError, match="exactly bind"):
        M8NotificationAuditEventV1(
            notification_authority=forged,
            event_sequence=2,
            transition_command=queued.audit_event.transition_command,
            prior_audit_event_sha256=planned.audit_event_sha256,
            audit_manifest_id=SHA_E,
        )


def test_system_queue_respects_human_confirmation_policy() -> None:
    planned = _planned_receipt(_plan(human_confirmation=True))
    command = _queue_command(planned.audit_event.notification_authority.plan)
    authority = M8NotificationAuthorityV1(
        plan=planned.audit_event.notification_authority.plan,
        notification_version=2,
        status=M8NotificationStatus.QUEUED,
        prior_notification_document_sha256=planned.notification_document_sha256,
        last_transition_command_id=command.command_id,
        last_initiator_authority_id=SHA_A,
        notification_manifest_id=SHA_D,
    )
    with pytest.raises(ValidationError, match="human send confirmation"):
        M8NotificationAuditEventV1(
            notification_authority=authority,
            event_sequence=2,
            transition_command=command,
            prior_audit_event_sha256=planned.audit_event_sha256,
            audit_manifest_id=SHA_E,
        )


def test_persistence_computed_claims_and_strict_versions_fail_closed() -> None:
    receipt = _queued_receipt()
    payload = receipt.model_dump(mode="json")
    payload["commit_receipt_id"] = SHA_A
    with pytest.raises(ValidationError, match="commit_receipt_id"):
        M8NotificationCommitReceiptV1.model_validate(payload)

    authority_payload = receipt.audit_event.notification_authority.model_dump(
        mode="json",
        exclude={"notification_id", "case_id", "notification_authority_id"},
    )
    authority_payload["notification_version"] = True
    with pytest.raises(ValidationError):
        M8NotificationAuthorityV1.model_validate(authority_payload)


@pytest.mark.parametrize("receipt", (_planned_receipt(), _queued_receipt()))
def test_notification_persistence_round_trip_and_serialization_schemas(
    receipt: M8NotificationCommitReceiptV1,
) -> None:
    restored = M8NotificationCommitReceiptV1.model_validate_json(receipt.model_dump_json())
    assert restored == receipt
    for model in (
        receipt.audit_event.notification_authority,
        receipt.audit_event,
        receipt,
    ):
        Draft202012Validator(type(model).model_json_schema(mode="serialization")).validate(
            model.model_dump(mode="json")
        )
