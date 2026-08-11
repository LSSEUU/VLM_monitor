"""Offline student notification workflow for the confirmed PPE Demo Case."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.m8_offline_notification_channel import (
    DeterministicOfflineNotificationChannel,
)
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole, M8OperationalCaseStatus
from labcourt.contracts.m8_notification_cards import (
    M8NotificationWorkflowManifestAuthorityV1,
    M8OfflineNotificationCardV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
)
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
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
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoPpeCaseReceiptV1,
    M8PersonalDemoPpeNotificationReceiptV1,
)
from labcourt.services.m8_notifications import M8NotificationService

_BUSY_TIMEOUT_MS = 5_000
_PLANNED_AT = datetime(2026, 8, 11, 10, 0, tzinfo=UTC)
_ROUTED_AT = _PLANNED_AT + timedelta(seconds=1)
_DELIVERED_AT = _ROUTED_AT + timedelta(seconds=2)


def _manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _workflow() -> M8NotificationWorkflowManifestAuthorityV1:
    return M8NotificationWorkflowManifestAuthorityV1(
        card_renderer_manifest_id=_manifest("labcourt-personal-demo-card-renderer-v1"),
        dispatch_request_manifest_id=_manifest("labcourt-personal-demo-dispatch-request-v1"),
        transition_command_manifest_id=_manifest(
            "labcourt-personal-demo-notification-transition-v1"
        ),
        raw_storage_manifest_id=_manifest("labcourt-personal-demo-notification-raw-store-v1"),
        audit_manifest_id=_manifest("labcourt-personal-demo-notification-audit-v1"),
        workflow_manifest_id=_manifest("labcourt-personal-demo-notification-workflow-v1"),
    )


def _channel() -> DeterministicOfflineNotificationChannel:
    return DeterministicOfflineNotificationChannel(
        M8NotificationChannelCapabilityAuthorityV1(
            adapter_id="m8-local-message-fake",
            adapter_revision="personal-demo-v1",
            channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
            request_timeout_ms=1_000,
            network_required=False,
            offline_capable=True,
            simulated=True,
            inbound_response_supported=True,
            adapter_manifest_id=_manifest("labcourt-personal-demo-local-message-adapter-v1"),
        )
    )


def _student_target() -> M8NotificationTargetAuthorityV1:
    return M8NotificationTargetAuthorityV1(
        actor_id="student-demo",
        identity_provider_id="labcourt-local-fake",
        external_subject_binding_sha256=_manifest(
            "labcourt-personal-demo-student-local-message"
        ),
        channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        authority_revision=1,
        active=True,
        inbound_response_supported=True,
        manifest_id=_manifest("labcourt-personal-demo-student-notification-target-v1"),
    )


@dataclass(frozen=True, slots=True)
class M8PersonalDemoPpeNotificationRun:
    receipt: M8PersonalDemoPpeNotificationReceiptV1
    card: M8OfflineNotificationCardV1


def route_m8_personal_demo_ppe_notification(
    database_path: Path,
    ppe_receipt: M8PersonalDemoPpeCaseReceiptV1,
) -> M8PersonalDemoPpeNotificationRun:
    """Queue one simulated student card for an explicitly confirmed PPE Case."""

    if not isinstance(ppe_receipt, M8PersonalDemoPpeCaseReceiptV1):
        raise TypeError("M8 personal Demo PPE notification requires a typed PPE Case receipt")
    bootstrap = bootstrap_m8_personal_demo(database_path)
    repository_manifest_id = bootstrap.projection.topology_receipt.repository_manifest_id
    operations = SQLiteM8OperationsRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    case = operations.get_current_operational_case(ppe_receipt.case_id)
    authority = case.audit_event.case_authority
    if (
        case.status != M8OperationalCaseStatus.CONFIRMED
        or authority.subject_actor_id != "student-demo"
        or authority.create_command.source_ids != (ppe_receipt.source_id,)
        or case.audit_event.transition_intent is None
    ):
        raise ValueError("M8 personal Demo student notification requires confirmed PPE authority")
    notifications = SQLiteM8NotificationRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    service = M8NotificationService(notifications, operations, _channel(), _workflow())
    target = _student_target()
    target_commit = service.publish_target(target, None)
    plan = M8NotificationPlanAuthorityV1(
        case_id=case.case_id,
        case_version=case.case_version,
        case_authority_sha256=case.case_document_sha256,
        case_status=case.status,
        case_subject_actor_id=authority.subject_actor_id,
        risk_level=authority.risk_level,
        location_id=authority.location_id,
        purpose=M8NotificationPurpose.CASE_UPDATED,
        audience=M8NotificationAudienceKind.CASE_SUBJECT,
        target=target,
        template=M8NotificationTemplateAuthorityV1(
            template_id="ppe-case-confirmed-student-card",
            template_version=1,
            locale="zh-CN",
            effective_at=_PLANNED_AT - timedelta(days=1),
            content_document_sha256=_manifest(
                "labcourt-personal-demo-ppe-student-card-content-v1"
            ),
            allowed_purposes=(M8NotificationPurpose.CASE_UPDATED,),
            allowed_channels=(M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,),
            manifest_id=_manifest("labcourt-personal-demo-ppe-student-card-template-v1"),
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="ppe-student-response-personal-demo-v1",
            risk_level=authority.risk_level,
            response_timeout_seconds=86_400,
            max_delivery_attempts=1,
            escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
            requires_human_send_confirmation=False,
            policy_manifest_id=_manifest(
                "labcourt-personal-demo-ppe-student-notification-policy-v1"
            ),
        ),
        planned_at=_PLANNED_AT,
        notification_manifest_id=_manifest(
            "labcourt-personal-demo-ppe-student-notification-plan-v1"
        ),
    )
    service.create_notification(plan)
    current = notifications.get_current_notification(plan.notification_id)
    if current.status == M8NotificationStatus.PLANNED:
        current = service.queue_as_system(
            plan.notification_id,
            _ROUTED_AT,
            authority.create_command.trigger_authorities,
        )
    if current.status != M8NotificationStatus.QUEUED or current.notification_version != 2:
        raise ValueError("M8 personal Demo student notification advanced past QUEUED")
    card, _card_bytes = service.render_card(plan.notification_id)
    receipt = M8PersonalDemoPpeNotificationReceiptV1(
        ppe_case_receipt_id=ppe_receipt.ppe_case_receipt_id,
        case_id=case.case_id,
        source_case_version=case.case_version,
        source_case_authority_sha256=case.case_document_sha256,
        target_commit_receipt_id=target_commit.commit_receipt_id,
        target_authority_id=target.target_authority_id,
        notification_id=current.notification_id,
        notification_commit_receipt_id=current.commit_receipt_id,
        routed_at=_ROUTED_AT,
        offline_card_id=card.card_id,
        notification_manifest_id=_manifest(
            "labcourt-personal-demo-ppe-notification-routing-receipt-v1"
        ),
    )
    return M8PersonalDemoPpeNotificationRun(receipt=receipt, card=card)


def deliver_m8_personal_demo_ppe_notification(
    database_path: Path,
    route_receipt: M8PersonalDemoPpeNotificationReceiptV1,
) -> M8NotificationCommitReceiptV1:
    """Advance the exact student card through the simulated offline channel."""

    if not isinstance(route_receipt, M8PersonalDemoPpeNotificationReceiptV1):
        raise TypeError("M8 personal Demo PPE delivery requires a typed route receipt")
    bootstrap = bootstrap_m8_personal_demo(database_path)
    repository_manifest_id = bootstrap.projection.topology_receipt.repository_manifest_id
    operations = SQLiteM8OperationsRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    notifications = SQLiteM8NotificationRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    current = notifications.get_current_notification(route_receipt.notification_id)
    plan = current.audit_event.notification_authority.plan
    case = operations.get_current_operational_case(route_receipt.case_id)
    if (
        plan.notification_id != route_receipt.notification_id
        or plan.case_id != route_receipt.case_id
        or plan.case_version != route_receipt.source_case_version
        or plan.case_authority_sha256 != route_receipt.source_case_authority_sha256
        or plan.target.target_authority_id != route_receipt.target_authority_id
        or plan.target.actor_id != route_receipt.target_actor_id
        or case.case_version != route_receipt.source_case_version
        or case.case_document_sha256 != route_receipt.source_case_authority_sha256
    ):
        raise ValueError("M8 personal Demo PPE delivery route authority changed")
    if current.status == M8NotificationStatus.DELIVERED:
        return current
    channel = _channel()
    service = M8NotificationService(notifications, operations, channel, _workflow())
    supporting = case.audit_event.case_authority.create_command.trigger_authorities
    if current.status == M8NotificationStatus.QUEUED:
        current = service.dispatch(route_receipt.notification_id, supporting)
    if current.status == M8NotificationStatus.SENT:
        transition = current.audit_event.transition_command
        dispatch_result = transition.dispatch_result if transition is not None else None
        if dispatch_result is None:
            raise ValueError("M8 personal Demo PPE sent notification lacks dispatch authority")
        raw_card = notifications.read_raw_artifact(dispatch_result.request.rendered_card_ref)
        if channel.dispatch(dispatch_result.request, raw_card) != dispatch_result:
            raise ValueError("M8 personal Demo PPE dispatch replay changed")
        current = service.confirm_simulated_delivery(
            route_receipt.notification_id,
            _DELIVERED_AT,
            supporting,
        )
    if current.status != M8NotificationStatus.DELIVERED:
        raise ValueError("M8 personal Demo PPE notification did not reach simulated delivery")
    return current


__all__ = [
    "M8PersonalDemoPpeNotificationRun",
    "deliver_m8_personal_demo_ppe_notification",
    "route_m8_personal_demo_ppe_notification",
]
