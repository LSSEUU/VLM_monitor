"""Typed HTTP façade for Feishu runtime, duty routing, dispatches, and channels."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from pydantic import BaseModel

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_live import (
    M8FeishuConversationChannelProjectionV1,
    M8FeishuDutyRouteRevisionRequestV1,
    M8FeishuDutyRouteV1,
    M8FeishuLiveConnectionState,
    M8FeishuNotificationDispatchRequestV1,
    M8FeishuQueuedDispatchReceiptV1,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuRuntimeStatusV2,
    M8FeishuTestCardDispatchRequestV1,
    M8FeishuWorkerState,
)
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.contracts.m8_feishu_platform import M8FeishuPlatformStatusV1
from labcourt.ports.m8_feishu_live import M8FeishuLiveRepository
from labcourt.services.m8_feishu_alert_bridge import M8FeishuAlertBridgeService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
    M8OperationsApiService,
)

TestDispatcher = Callable[[M8FeishuDutyRouteV1], BaseModel]


class M8FeishuLiveApiService:
    def __init__(
        self,
        live: M8FeishuLiveRepository,
        operations: M8OperationsApiService,
        notifications: M8NotificationApiService,
        platform_status: Callable[[], M8FeishuPlatformStatusV1],
        actor_authority: Callable[[str], M8ActorAuthorityCommitReceiptV1],
        recipient_binding: Callable[[str], M8FeishuRecipientBindingAuthorityV1],
        alert_bridge: M8FeishuAlertBridgeService,
        test_dispatcher: TestDispatcher | None,
        clock: Callable[[], datetime],
        repository_manifest_id: Sha256Hex,
    ) -> None:
        self._live = live
        self._operations = operations
        self._notifications = notifications
        self._platform_status = platform_status
        self._actor_authority = actor_authority
        self._recipient_binding = recipient_binding
        self._bridge = alert_bridge
        self._test_dispatcher = test_dispatcher
        self._clock = clock
        self._repository_manifest_id = repository_manifest_id

    def runtime_status(self, principal: M8ApiPrincipalV1) -> M8FeishuRuntimeStatusV2:
        actor = self._operations.session(principal).authority
        if actor.role not in {M8ActorRole.OPERATIONS, M8ActorRole.SAFETY_OFFICER}:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        assessed_at = self._clock()
        connection = self._fresh_heartbeat("LONG_CONNECTION", assessed_at)
        authority = self._fresh_heartbeat("AUTHORITY_WORKER", assessed_at)
        delivery = self._fresh_heartbeat("DELIVERY_WORKER", assessed_at)
        route = self._live.current_duty_route()
        platform = self._platform_status()
        available = (
            platform.display_status.value == "ACTIVE"
            and connection is not None
            and connection.connection_state == M8FeishuLiveConnectionState.READY
            and authority is not None
            and authority.worker_state == M8FeishuWorkerState.READY
            and delivery is not None
            and delivery.worker_state == M8FeishuWorkerState.READY
            and route is not None
            and route.active
        )
        return M8FeishuRuntimeStatusV2(
            platform=platform,
            connection=connection,
            authority_worker=authority,
            delivery_worker=delivery,
            duty_route=route,
            assessed_at=assessed_at,
            live_dispatch_available=available,
        )

    def duty_route(self, principal: M8ApiPrincipalV1) -> M8FeishuDutyRouteV1 | None:
        actor = self._operations.session(principal).authority
        if actor.role not in {M8ActorRole.OPERATIONS, M8ActorRole.SAFETY_OFFICER}:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return self._live.current_duty_route()

    def revise_duty_route(
        self,
        principal: M8ApiPrincipalV1,
        request: M8FeishuDutyRouteRevisionRequestV1,
    ) -> M8FeishuDutyRouteV1:
        operator = self._operations.session(principal).authority
        if operator.role != M8ActorRole.OPERATIONS:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        status = self._platform_status()
        if (
            status.display_status.value != "ACTIVE"
            or status.activation_revision != request.activation_revision
            or status.activation_status_id != request.activation_status_id
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        actor = self._actor_authority(request.actor_id)
        binding = self._recipient_binding(request.recipient_binding_authority_id)
        if (
            actor.authority.role != M8ActorRole.SAFETY_OFFICER
            or not actor.authority.active
            or not binding.active
            or binding.target.actor_id != actor.authority.actor_id
            or binding.binding_authority_id != request.recipient_binding_authority_id
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        current = self._live.current_duty_route()
        current_revision = None if current is None else current.route_revision
        if current_revision != request.expected_prior_revision:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        route = M8FeishuDutyRouteV1(
            actor_id=actor.authority.actor_id,
            actor_authority_commit_receipt_id=actor.commit_receipt_id,
            recipient_binding_authority_id=binding.binding_authority_id,
            activation_revision=request.activation_revision,
            activation_status_id=request.activation_status_id,
            route_revision=1 if current is None else current.route_revision + 1,
            prior_route_id=None if current is None else current.route_id,
            committed_at=self._clock(),
            repository_manifest_id=self._repository_manifest_id,
        )
        return self._live.commit_duty_route(route)

    def dispatch_test_card(
        self,
        principal: M8ApiPrincipalV1,
        request: M8FeishuTestCardDispatchRequestV1,
    ) -> BaseModel:
        actor = self._operations.session(principal).authority
        if actor.role != M8ActorRole.OPERATIONS:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        runtime = self.runtime_status(principal)
        route = runtime.duty_route
        if (
            not runtime.live_dispatch_available
            or route is None
            or request.activation_revision != route.activation_revision
            or request.activation_status_id != route.activation_status_id
            or request.duty_route_id != route.route_id
            or request.duty_route_revision != route.route_revision
            or self._test_dispatcher is None
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        return self._test_dispatcher(route)

    def dispatch_notification(
        self,
        principal: M8ApiPrincipalV1,
        notification_id: str,
        request: M8FeishuNotificationDispatchRequestV1,
    ) -> M8FeishuQueuedDispatchReceiptV1:
        actor = self._operations.session(principal).authority
        if actor.role != M8ActorRole.SAFETY_OFFICER:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        source = self._notifications.notification(principal, notification_id)
        route = self._live.current_duty_route()
        status = self._platform_status()
        if (
            source.notification_version != request.notification_version
            or source.notification_document_sha256 != request.notification_authority_sha256
            or route is None
            or route.route_id != request.duty_route_id
            or route.route_revision != request.duty_route_revision
            or route.activation_revision != request.activation_revision
            or route.activation_status_id != request.activation_status_id
            or status.display_status.value != "ACTIVE"
        ):
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        bridged = self._bridge.queue_existing_notification(notification_id)
        if bridged.queued_notification_id is None:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION)
        return M8FeishuQueuedDispatchReceiptV1(
            dispatch_kind="EXISTING_NOTIFICATION",
            notification_id=bridged.queued_notification_id,
            source_notification_id=notification_id,
            outbox_ref=f"m8-notification-outbox-{bridged.queued_notification_id[:24]}",
            duty_route_id=route.route_id,
            queued_at=self._clock(),
        )

    def channel_projection(
        self, principal: M8ApiPrincipalV1, conversation_id: str
    ) -> M8FeishuConversationChannelProjectionV1 | None:
        actor = self._operations.session(principal).authority
        projection = self._live.channel_projection(conversation_id)
        if projection is not None and projection.actor_id != actor.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return projection

    def _fresh_heartbeat(
        self, component: str, assessed_at: datetime
    ) -> M8FeishuRuntimeHeartbeatV1 | None:
        heartbeat = self._live.latest_heartbeat(component)
        if heartbeat is None or assessed_at - heartbeat.observed_at > timedelta(seconds=30):
            return None
        return heartbeat


__all__ = ["M8FeishuLiveApiService"]
