"""Bounded coordinator for activation-gated Feishu alert and Agent delivery."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_live import (
    M8FeishuLiveFailureCode,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuWorkerState,
)
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.contracts.m8_notifications import M8NotificationChannelKind, M8NotificationStatus
from labcourt.ports.m8_feishu_live import M8FeishuLiveRepository
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.services.m8_feishu_agent_reply_delivery import (
    M8FeishuAgentReplyDeliveryWorker,
)
from labcourt.services.m8_feishu_alert_bridge import M8FeishuAlertBridgeService
from labcourt.services.m8_feishu_interactive_outbox import M8FeishuInteractiveOutboxRunner


class M8FeishuDeliveryWorker:
    """Project alerts and perform at most one provider attempt per claimed item."""

    def __init__(
        self,
        live: M8FeishuLiveRepository,
        notifications: M8NotificationRepository,
        alert_bridge: M8FeishuAlertBridgeService,
        interactive: M8FeishuInteractiveOutboxRunner,
        agent_replies: M8FeishuAgentReplyDeliveryWorker,
        binding_resolver: Callable[[str], M8FeishuRecipientBindingAuthorityV1],
        worker_token: bytes,
        clock: Callable[[], datetime],
        runtime_manifest_id: Sha256Hex,
    ) -> None:
        if not 32 <= len(worker_token) <= 256:
            raise ValueError("M8 Feishu delivery worker token must be 32 through 256 bytes")
        self._live = live
        self._notifications = notifications
        self._bridge = alert_bridge
        self._interactive = interactive
        self._agent_replies = agent_replies
        self._binding_resolver = binding_resolver
        self._worker_token = worker_token
        self._clock = clock
        self._runtime_manifest = runtime_manifest_id

    def run_one_cycle(self) -> int:
        self._heartbeat(M8FeishuWorkerState.BUSY)
        completed = 0
        try:
            projected = self._bridge.bridge_current_emergencies()
            completed += sum(item.queued_notification_id is not None for item in projected)
            route = self._live.current_duty_route()
            if route is None or not route.active:
                raise ValueError("M8 Feishu delivery worker requires a current duty route")
            binding = self._binding_resolver(route.recipient_binding_authority_id)
            for notification in self._notifications.list_notifications_by_status(
                M8NotificationStatus.QUEUED, 100
            ):
                plan = notification.audit_event.notification_authority.plan
                if plan.target.channel != M8NotificationChannelKind.FEISHU:
                    continue
                self._interactive.run_one(notification.notification_id, binding, self._worker_token)
                completed += 1
            for reminder_status in (
                M8NotificationStatus.SENT,
                M8NotificationStatus.DELIVERED,
                M8NotificationStatus.ACKNOWLEDGED,
            ):
                for notification in self._notifications.list_notifications_by_status(
                    reminder_status, 100
                ):
                    if (
                        notification.audit_event.notification_authority.plan.target.channel
                        != M8NotificationChannelKind.FEISHU
                    ):
                        continue
                    receipt = self._bridge.assess_reminder(notification.notification_id)
                    completed += int(receipt is not None)
            completed += int(self._agent_replies.run_one(self._worker_token) is not None)
        except Exception:
            self._heartbeat(
                M8FeishuWorkerState.FAILED,
                M8FeishuLiveFailureCode.WORKER_UNAVAILABLE,
            )
            raise
        self._heartbeat(M8FeishuWorkerState.READY)
        return completed

    def record_ready(self) -> None:
        self._heartbeat(M8FeishuWorkerState.READY)

    def _heartbeat(
        self,
        state: M8FeishuWorkerState,
        failure: M8FeishuLiveFailureCode | None = None,
    ) -> None:
        self._live.record_heartbeat(
            M8FeishuRuntimeHeartbeatV1(
                component="DELIVERY_WORKER",
                worker_state=state,
                observed_at=self._clock(),
                failure_code=failure,
                runtime_manifest_id=self._runtime_manifest,
            )
        )


__all__ = ["M8FeishuDeliveryWorker"]
