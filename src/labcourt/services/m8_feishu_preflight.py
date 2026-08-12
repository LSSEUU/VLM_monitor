"""Read-only Feishu conformance orchestration over the persisted M8 notification outbox."""

from __future__ import annotations

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuCardDispatchPreflightV1,
    M8FeishuConformanceResultV1,
    M8FeishuNotificationCardV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notification_cards import M8NotificationWorkflowManifestAuthorityV1
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDispatchRequestV1,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind, M8NotificationStatus
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m8_feishu_notification_adapter import M8FeishuConformanceAdapter
from labcourt.ports.m8_notification_repository import M8NotificationRepository


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu {name} must be lowercase SHA-256 hex")
    return value


class M8FeishuPreflightService:
    """Build and simulate an exact Feishu envelope without mutating the outbox."""

    def __init__(
        self,
        notification_repository: M8NotificationRepository,
        adapter: M8FeishuConformanceAdapter,
        workflow: M8NotificationWorkflowManifestAuthorityV1,
        preflight_manifest_id: Sha256Hex,
    ) -> None:
        if not isinstance(workflow, M8NotificationWorkflowManifestAuthorityV1):
            raise TypeError("M8 Feishu preflight requires a typed workflow authority")
        if adapter is None:
            raise TypeError("M8 Feishu preflight requires an explicit conformance adapter")
        self._notifications = notification_repository
        self._adapter = adapter
        self._workflow = workflow
        self._preflight_manifest_id = _validate_sha256(
            preflight_manifest_id,
            "preflight manifest",
        )

    def conform(
        self,
        notification_id: str,
        recipient_binding: M8FeishuRecipientBindingAuthorityV1,
    ) -> M8FeishuConformanceResultV1:
        if not isinstance(recipient_binding, M8FeishuRecipientBindingAuthorityV1):
            raise TypeError("M8 Feishu preflight requires a typed recipient binding")
        before = self._notifications.get_current_notification(notification_id)
        if before.status != M8NotificationStatus.QUEUED:
            raise ConcurrentModification("M8 Feishu preflight requires current QUEUED notification")
        queue_transition = before.audit_event.transition_command
        if queue_transition is None:
            raise ConcurrentModification("M8 Feishu preflight requires a queue transition")
        profile = self._adapter.profile_authority()
        candidate = profile.candidate
        plan = before.audit_event.notification_authority.plan
        if plan.target.channel != M8NotificationChannelKind.FEISHU:
            raise ConcurrentModification("M8 Feishu preflight requires a FEISHU notification")
        card = M8FeishuNotificationCardV1(
            plan=plan,
            card_renderer_manifest_id=self._workflow.card_renderer_manifest_id,
        )
        card_bytes = card.provider_content_json.encode("utf-8")
        attempt_number = 1 + sum(
            event.transition_command is not None
            and event.transition_command.dispatch_result is not None
            for event in self._notifications.list_notification_audit(notification_id)
        )
        capability = M8NotificationChannelCapabilityAuthorityV1(
            adapter_id=candidate.adapter_id,
            adapter_revision=candidate.adapter_revision,
            channel=M8NotificationChannelKind.FEISHU,
            request_timeout_ms=candidate.request_timeout_ms,
            network_required=True,
            offline_capable=False,
            simulated=False,
            inbound_response_supported=True,
            adapter_manifest_id=candidate.adapter_manifest_id,
        )
        request = M8NotificationDispatchRequestV1(
            plan=plan,
            source_notification_version=before.notification_version,
            source_notification_authority_sha256=before.notification_document_sha256,
            attempt_number=attempt_number,
            channel_capability=capability,
            rendered_card_ref=card.raw_card_ref,
            rendered_card_sha256=card.provider_content_sha256,
            dispatched_at=queue_transition.occurred_at,
            timeout_ms=capability.request_timeout_ms,
            idempotency_key=before.notification_id,
            request_manifest_id=self._workflow.dispatch_request_manifest_id,
        )
        preflight = M8FeishuCardDispatchPreflightV1(
            notification_request=request,
            profile=profile,
            recipient_binding=recipient_binding,
            card=card,
            preflight_manifest_id=self._preflight_manifest_id,
        )
        result = self._adapter.conform(preflight, card_bytes)
        after = self._notifications.get_current_notification(notification_id)
        if after.commit_receipt_id != before.commit_receipt_id:
            raise ConcurrentModification("M8 Feishu outbox changed during preflight")
        return result

    def read_raw_response(self, raw_response_ref: str) -> bytes:
        return self._adapter.read_raw_response(raw_response_ref)


__all__ = ["M8FeishuPreflightService"]
