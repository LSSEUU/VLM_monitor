"""Project persisted emergency cases into activation-gated Feishu notifications."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_feishu_live import (
    M8FeishuAlertBridgeOutcome,
    M8FeishuAlertBridgeReceiptV1,
    M8FeishuReminderOutcome,
    M8FeishuReminderReceiptV1,
)
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.contracts.m8_feishu_platform import (
    M8FeishuPlatformDisplayStatus,
    M8FeishuPlatformStatusV1,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
from labcourt.contracts.m8_notifications import (
    M8NotificationAudienceKind,
    M8NotificationChannelKind,
    M8NotificationEscalationPolicyAuthorityV1,
    M8NotificationPlanAuthorityV1,
    M8NotificationPurpose,
    M8NotificationStatus,
    M8NotificationTemplateAuthorityV1,
)
from labcourt.ports.m8_feishu_live import M8FeishuLiveRepository
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_notifications import M8NotificationService

ManifestFactory = Callable[[str], Sha256Hex]


class M8FeishuAlertBridgeService:
    """Create a separate FEISHU authority without changing the local fake notification."""

    def __init__(
        self,
        live: M8FeishuLiveRepository,
        operations: M8OperationsRepository,
        notifications: M8NotificationRepository,
        notification_service: M8NotificationService,
        platform_status: Callable[[], M8FeishuPlatformStatusV1],
        binding_resolver: Callable[[str], M8FeishuRecipientBindingAuthorityV1],
        clock: Callable[[], datetime],
        manifest: ManifestFactory,
    ) -> None:
        self._live = live
        self._operations = operations
        self._notifications = notifications
        self._service = notification_service
        self._platform_status = platform_status
        self._binding_resolver = binding_resolver
        self._clock = clock
        self._manifest = manifest

    def bridge_current_emergencies(self) -> tuple[M8FeishuAlertBridgeReceiptV1, ...]:
        results = []
        current_notifications = self._notifications.list_current_notifications(20_000)
        for case in self._operations.list_current_operational_cases(10_000):
            authority = case.audit_event.case_authority
            if (
                authority.risk_level != M8OperationalRiskLevel.EMERGENCY
                or case.status != M8OperationalCaseStatus.PENDING_VERIFICATION
            ):
                continue
            source = next(
                (
                    item
                    for item in current_notifications
                    if item.audit_event.notification_authority.plan.case_id == case.case_id
                    and item.audit_event.notification_authority.plan.target.channel
                    == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
                ),
                None,
            )
            if source is None:
                continue
            prior = self._live.alert_bridge(case.case_id, case.case_version)
            if prior is not None:
                results.append(
                    M8FeishuAlertBridgeReceiptV1(
                        source_case_id=prior.source_case_id,
                        source_case_version=prior.source_case_version,
                        source_notification_id=prior.source_notification_id,
                        outcome=M8FeishuAlertBridgeOutcome.ALREADY_PROJECTED,
                        assessed_at=self._clock(),
                    )
                )
                continue
            results.append(self._bridge(case, source.notification_id))
        return tuple(results)

    def queue_existing_notification(
        self, source_notification_id: str
    ) -> M8FeishuAlertBridgeReceiptV1:
        source = self._notifications.get_current_notification(source_notification_id)
        case = self._operations.get_current_operational_case(
            source.audit_event.notification_authority.plan.case_id
        )
        prior = self._live.alert_bridge(case.case_id, case.case_version)
        return prior if prior is not None else self._bridge(case, source_notification_id)

    def assess_reminder(
        self, source_notification_id: str
    ) -> M8FeishuReminderReceiptV1 | None:
        source = self._notifications.get_current_notification(source_notification_id)
        source_plan = source.audit_event.notification_authority.plan
        # A reminder is a terminal derivative of the initial emergency alert;
        # it must never itself become the source of another reminder.
        if source_plan.purpose != M8NotificationPurpose.CASE_ACTION_REQUIRED:
            return None
        audit = self._notifications.list_notification_audit(source_notification_id)
        dispatch = next(
            (
                event.transition_command.dispatch_result
                for event in reversed(audit)
                if event.transition_command is not None
                and event.transition_command.dispatch_result is not None
            ),
            None,
        )
        if dispatch is None or self._clock() < dispatch.completed_at + timedelta(minutes=2):
            return None
        prior = self._live.reminder(dispatch.request.dispatch_request_id)
        if prior is not None:
            return prior
        case = self._operations.get_current_operational_case(source_plan.case_id)
        if source.status == M8NotificationStatus.ACKNOWLEDGED:
            outcome = M8FeishuReminderOutcome.CANCELLED_ACKNOWLEDGED
            reminder_id = None
        elif case.status != M8OperationalCaseStatus.PENDING_VERIFICATION:
            outcome = M8FeishuReminderOutcome.CANCELLED_CASE_RESOLVED
            reminder_id = None
        elif dispatch.disposition == M8NotificationDispatchDisposition.UNKNOWN_DELIVERY:
            outcome = M8FeishuReminderOutcome.SUPPRESSED_UNKNOWN_DELIVERY
            reminder_id = None
        elif dispatch.disposition == M8NotificationDispatchDisposition.ACCEPTED:
            reminder = self._create_notification(
                source.audit_event.notification_authority.plan.case_id,
                M8NotificationPurpose.ESCALATION,
            )
            outcome = M8FeishuReminderOutcome.QUEUED
            reminder_id = reminder.notification_id
        else:
            return None
        return self._live.commit_reminder(
            M8FeishuReminderReceiptV1(
                source_dispatch_request_id=dispatch.request.dispatch_request_id,
                source_notification_id=source_notification_id,
                outcome=outcome,
                reminder_notification_id=reminder_id,
                assessed_at=self._clock(),
            )
        )

    def _bridge(self, case: object, source_notification_id: str) -> M8FeishuAlertBridgeReceiptV1:
        from labcourt.contracts.m8_case_persistence import M8OperationalCaseCommitReceiptV1

        if not isinstance(case, M8OperationalCaseCommitReceiptV1):
            raise TypeError("M8 Feishu alert bridge requires a typed case")
        status = self._platform_status()
        route = self._live.current_duty_route()
        if (
            status.display_status != M8FeishuPlatformDisplayStatus.ACTIVE
            or route is None
            or not route.active
            or route.activation_revision != status.activation_revision
            or route.activation_status_id != status.activation_status_id
        ):
            receipt = M8FeishuAlertBridgeReceiptV1(
                source_case_id=case.case_id,
                source_case_version=case.case_version,
                source_notification_id=source_notification_id,
                outcome=M8FeishuAlertBridgeOutcome.FEISHU_NOT_AVAILABLE,
                assessed_at=self._clock(),
            )
        else:
            notification = self._create_notification(
                case.case_id, M8NotificationPurpose.CASE_ACTION_REQUIRED
            )
            receipt = M8FeishuAlertBridgeReceiptV1(
                source_case_id=case.case_id,
                source_case_version=case.case_version,
                source_notification_id=source_notification_id,
                outcome=M8FeishuAlertBridgeOutcome.QUEUED,
                queued_notification_id=notification.notification_id,
                duty_route_id=route.route_id,
                assessed_at=self._clock(),
            )
        return self._live.commit_alert_bridge(receipt)

    def _create_notification(
        self, case_id: str, purpose: M8NotificationPurpose
    ) -> M8NotificationCommitReceiptV1:
        route = self._live.current_duty_route()
        if route is None or not route.active:
            raise ValueError("M8 Feishu notification requires the current duty route")
        case = self._operations.get_current_operational_case(case_id)
        authority = case.audit_event.case_authority
        binding = self._binding_resolver(route.recipient_binding_authority_id)
        current_target = self._notifications.get_current_target_authority(
            route.actor_id, M8NotificationChannelKind.FEISHU
        ).target
        if (
            not binding.active
            or not current_target.active
            or binding.target != current_target
            or current_target.external_subject_binding_sha256
            != self._binding_sha(route.recipient_binding_authority_id)
        ):
            raise ValueError("M8 Feishu notification target changed after activation")
        # A notification consumes the recipient authority approved by the
        # current activation.  Publishing a fresh target revision for every
        # message would invalidate that activation before delivery starts.
        target = current_target
        now = self._clock()
        plan = M8NotificationPlanAuthorityV1(
            case_id=case.case_id,
            case_version=case.case_version,
            case_authority_sha256=case.case_document_sha256,
            case_status=case.status,
            case_subject_actor_id=authority.subject_actor_id,
            risk_level=authority.risk_level,
            location_id=authority.location_id,
            purpose=purpose,
            audience=M8NotificationAudienceKind.SAFETY_RESPONDER,
            target=target,
            template=M8NotificationTemplateAuthorityV1(
                template_id=f"platform-feishu-{purpose.value.casefold()}-card",
                template_version=1,
                locale="zh-CN",
                effective_at=now - timedelta(days=1),
                content_document_sha256=self._manifest(
                    f"platform-feishu-card-{purpose.value}-{case.case_id}-{case.case_version}"
                ),
                allowed_purposes=(purpose,),
                allowed_channels=(M8NotificationChannelKind.FEISHU,),
                manifest_id=self._manifest("platform-feishu-notification-template-v1"),
            ),
            escalation_policy=M8NotificationEscalationPolicyAuthorityV1(
                policy_rule_id=f"platform-feishu-{purpose.value.casefold()}-response-v1",
                risk_level=authority.risk_level,
                response_timeout_seconds=120,
                max_delivery_attempts=1,
                escalation_roles=(M8ActorRole.SAFETY_OFFICER,),
                # Both bridge purposes are bounded emergency automation:
                # the initial action card and its one-shot two-minute reminder.
                # Ordinary notification forwarding uses the separate explicit
                # dispatch API and retains human confirmation there.
                requires_human_send_confirmation=False,
                policy_manifest_id=self._manifest("platform-feishu-notification-policy-v1"),
            ),
            planned_at=now,
            notification_manifest_id=self._manifest(
                f"platform-feishu-notification-{purpose.value}-{case.case_id}-{case.case_version}"
            ),
        )
        current = self._service.create_notification(plan)
        if current.status == M8NotificationStatus.PLANNED:
            current = self._service.queue_as_system(
                current.notification_id,
                now,
                authority.create_command.trigger_authorities,
            )
        return current

    def _binding_sha(self, binding_authority_id: str) -> str:
        route = self._live.current_duty_route()
        if route is None or route.recipient_binding_authority_id != binding_authority_id:
            raise ValueError("M8 Feishu duty route binding changed")
        status = self._platform_status()
        if status.display_status != M8FeishuPlatformDisplayStatus.ACTIVE:
            raise ValueError("M8 Feishu activation changed")
        binding = self._binding_resolver(binding_authority_id)
        if not binding.active or binding.binding_authority_id != binding_authority_id:
            raise ValueError("M8 Feishu recipient binding is not current")
        return binding.receive_id_sha256


__all__ = ["M8FeishuAlertBridgeService"]
