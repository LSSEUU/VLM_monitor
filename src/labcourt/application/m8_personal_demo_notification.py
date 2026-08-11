"""Route the simulated emergency Case into one offline Demo notification."""

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
from labcourt.contracts.m8_personal_demo import M8PersonalDemoNotificationReceiptV1
from labcourt.services.m8_notifications import M8NotificationService

_BUSY_TIMEOUT_MS = 5_000
_PLANNED_AT = datetime(2026, 8, 10, 9, 1, tzinfo=UTC)
_ROUTED_AT = _PLANNED_AT + timedelta(seconds=1)


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


def _target() -> M8NotificationTargetAuthorityV1:
    return M8NotificationTargetAuthorityV1(
        actor_id="safety-officer-demo",
        identity_provider_id="labcourt-local-fake",
        external_subject_binding_sha256=_manifest(
            "labcourt-personal-demo-safety-officer-local-message"
        ),
        channel=M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,
        authority_revision=1,
        active=True,
        inbound_response_supported=True,
        manifest_id=_manifest("labcourt-personal-demo-notification-target-v1"),
    )


def _channel() -> DeterministicOfflineNotificationChannel:
    capability = M8NotificationChannelCapabilityAuthorityV1(
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
    return DeterministicOfflineNotificationChannel(capability)


@dataclass(frozen=True, slots=True)
class M8PersonalDemoNotificationRun:
    receipt: M8PersonalDemoNotificationReceiptV1
    card: M8OfflineNotificationCardV1


def route_m8_personal_demo_notification(
    database_path: Path,
) -> M8PersonalDemoNotificationRun:
    """Create and queue one exact simulated safety-responder notification."""

    bootstrap = bootstrap_m8_personal_demo(database_path)
    repository_manifest_id = bootstrap.projection.topology_receipt.repository_manifest_id
    operations = SQLiteM8OperationsRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    case = operations.get_current_operational_case(bootstrap.receipt.case_id)
    if case.case_version != 1 or case.status != M8OperationalCaseStatus.PENDING_VERIFICATION:
        raise ValueError(
            "M8 personal Demo notification requires the original pending-verification Case"
        )
    notifications = SQLiteM8NotificationRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    workflow = _workflow()
    service = M8NotificationService(notifications, operations, _channel(), workflow)
    target = _target()
    target_commit = service.publish_target(target, None)
    authority = case.audit_event.case_authority
    plan = M8NotificationPlanAuthorityV1(
        case_id=case.case_id,
        case_version=case.case_version,
        case_authority_sha256=case.case_document_sha256,
        case_status=case.status,
        case_subject_actor_id=authority.subject_actor_id,
        risk_level=authority.risk_level,
        location_id=authority.location_id,
        purpose=M8NotificationPurpose.CASE_ACTION_REQUIRED,
        audience=M8NotificationAudienceKind.SAFETY_RESPONDER,
        target=target,
        template=M8NotificationTemplateAuthorityV1(
            template_id="emergency-case-action-required-card",
            template_version=1,
            locale="zh-CN",
            effective_at=_PLANNED_AT - timedelta(days=1),
            content_document_sha256=_manifest("labcourt-personal-demo-emergency-card-content-v1"),
            allowed_purposes=(M8NotificationPurpose.CASE_ACTION_REQUIRED,),
            allowed_channels=(M8NotificationChannelKind.LOCAL_OFFLINE_FAKE,),
            manifest_id=_manifest("labcourt-personal-demo-emergency-card-template-v1"),
        ),
        escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
            policy_rule_id="emergency-safety-response-personal-demo-v1",
            risk_level=authority.risk_level,
            response_timeout_seconds=300,
            max_delivery_attempts=1,
            escalation_roles=(M8ActorRole.LEADER,),
            requires_human_send_confirmation=False,
            policy_manifest_id=_manifest("labcourt-personal-demo-emergency-notification-policy-v1"),
        ),
        planned_at=_PLANNED_AT,
        notification_manifest_id=_manifest("labcourt-personal-demo-emergency-notification-plan-v1"),
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
        raise ValueError("M8 personal Demo notification has already advanced past QUEUED")
    card, _card_bytes = service.render_card(plan.notification_id)
    receipt = M8PersonalDemoNotificationReceiptV1(
        case_id=case.case_id,
        source_case_authority_sha256=case.case_document_sha256,
        target_commit_receipt_id=target_commit.commit_receipt_id,
        target_authority_id=target.target_authority_id,
        notification_id=current.notification_id,
        notification_commit_receipt_id=current.commit_receipt_id,
        routed_at=_ROUTED_AT,
        offline_card_id=card.card_id,
        notification_manifest_id=_manifest(
            "labcourt-personal-demo-notification-routing-receipt-v1"
        ),
    )
    return M8PersonalDemoNotificationRun(receipt=receipt, card=card)


__all__ = [
    "M8PersonalDemoNotificationRun",
    "route_m8_personal_demo_notification",
]
