"""Application orchestration for the M8 notification closed loop."""

from __future__ import annotations

import hashlib
from datetime import datetime

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.m8_access_cases import M8ActorAuthorityV1, M8AuthorityReference
from labcourt.contracts.m8_notification_cards import (
    M8NotificationWorkflowManifestAuthorityV1,
    M8OfflineNotificationCardV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationDispatchRequestV1,
    M8NotificationInitiatorKind,
    M8NotificationReplyAuthorityV1,
    M8NotificationReplyKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationCommitReceiptV1,
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationPlanAuthorityV1,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
)
from labcourt.ports.m8_notification_channel import M8NotificationChannelAdapter
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository


class M8NotificationService:
    """Coordinate exact notification authorities without mutating operational Cases."""

    def __init__(
        self,
        notification_repository: M8NotificationRepository,
        operations_repository: M8OperationsRepository,
        channel: M8NotificationChannelAdapter,
        workflow: M8NotificationWorkflowManifestAuthorityV1,
    ) -> None:
        if not isinstance(workflow, M8NotificationWorkflowManifestAuthorityV1):
            raise TypeError("M8 notification service requires a typed workflow authority")
        self._notifications = notification_repository
        self._operations = operations_repository
        self._channel = channel
        self._workflow = workflow

    def publish_target(
        self,
        target: M8NotificationTargetAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8NotificationTargetCommitReceiptV1:
        return self._notifications.publish_target_authority(target, expected_prior_revision)

    def create_notification(
        self,
        plan: M8NotificationPlanAuthorityV1,
    ) -> M8NotificationCommitReceiptV1:
        return self._notifications.create_notification(plan, self._workflow.audit_manifest_id)

    def queue_as_system(
        self,
        notification_id: str,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        return self._queue_or_retry(
            notification_id,
            M8NotificationAction.QUEUE,
            occurred_at,
            supporting_authorities,
            actor=None,
        )

    def queue_as_actor(
        self,
        notification_id: str,
        actor_id: str,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        return self._queue_or_retry(
            notification_id,
            M8NotificationAction.QUEUE,
            occurred_at,
            supporting_authorities,
            actor=self._actor(actor_id),
        )

    def retry_as_system(
        self,
        notification_id: str,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        return self._queue_or_retry(
            notification_id,
            M8NotificationAction.RETRY,
            occurred_at,
            supporting_authorities,
            actor=None,
        )

    def retry_as_actor(
        self,
        notification_id: str,
        actor_id: str,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        return self._queue_or_retry(
            notification_id,
            M8NotificationAction.RETRY,
            occurred_at,
            supporting_authorities,
            actor=self._actor(actor_id),
        )

    def render_card(
        self,
        notification_id: str,
    ) -> tuple[M8OfflineNotificationCardV1, bytes]:
        before = self._notifications.get_current_notification(notification_id)
        card = M8OfflineNotificationCardV1(
            plan=before.audit_event.notification_authority.plan,
            card_renderer_manifest_id=self._workflow.card_renderer_manifest_id,
        )
        encoded = (canonical_json(card.model_dump(mode="json")) + "\n").encode("utf-8")
        return card, encoded

    def dispatch(
        self,
        notification_id: str,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        before = self._notifications.get_current_notification(notification_id)
        if before.status == M8NotificationStatus.SENT:
            return before
        card = M8OfflineNotificationCardV1(
            plan=before.audit_event.notification_authority.plan,
            card_renderer_manifest_id=self._workflow.card_renderer_manifest_id,
        )
        card_bytes = (canonical_json(card.model_dump(mode="json")) + "\n").encode("utf-8")
        transition = before.audit_event.transition_command
        if transition is None:
            raise ValueError("M8 notification dispatch requires a queued transition")
        attempt_number = 1 + sum(
            event.transition_command is not None
            and event.transition_command.dispatch_result is not None
            for event in self._notifications.list_notification_audit(notification_id)
        )
        capability = self._channel.capability_authority()
        request = M8NotificationDispatchRequestV1(
            plan=before.audit_event.notification_authority.plan,
            source_notification_version=before.notification_version,
            source_notification_authority_sha256=before.notification_document_sha256,
            attempt_number=attempt_number,
            channel_capability=capability,
            rendered_card_ref=card.raw_card_ref,
            rendered_card_sha256=hashlib.sha256(card_bytes).hexdigest(),
            dispatched_at=transition.occurred_at,
            timeout_ms=capability.request_timeout_ms,
            idempotency_key=before.notification_id,
            request_manifest_id=self._workflow.dispatch_request_manifest_id,
        )
        result = self._channel.dispatch(request, card_bytes)
        raw_response = self._channel.read_raw_response(result.raw_response_ref)
        action = (
            M8NotificationAction.RECORD_SENT
            if result.accepted
            else M8NotificationAction.RECORD_FAILED
        )
        command = M8NotificationTransitionCommandV1(
            notification_id=before.notification_id,
            source_notification_version=before.notification_version,
            source_notification_authority_sha256=before.notification_document_sha256,
            source_status=before.status,
            action=action,
            initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
            dispatch_result=result,
            supporting_authorities=supporting_authorities,
            explicit_human_confirmation=False,
            occurred_at=result.completed_at,
            command_manifest_id=self._workflow.transition_command_manifest_id,
        )
        return self._notifications.transition_notification(
            command,
            (card_bytes, raw_response),
            self._workflow.raw_storage_manifest_id,
            self._workflow.audit_manifest_id,
        )

    def confirm_simulated_delivery(
        self,
        notification_id: str,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        before = self._notifications.get_current_notification(notification_id)
        if before.status == M8NotificationStatus.DELIVERED:
            return before
        transition = before.audit_event.transition_command
        dispatch_result = transition.dispatch_result if transition is not None else None
        if dispatch_result is None:
            raise ValueError("M8 notification delivery requires the current sent dispatch")
        delivery = self._channel.confirm_simulated_delivery(dispatch_result, occurred_at)
        raw_response = self._channel.read_raw_response(delivery.raw_response_ref)
        command = M8NotificationTransitionCommandV1(
            notification_id=before.notification_id,
            source_notification_version=before.notification_version,
            source_notification_authority_sha256=before.notification_document_sha256,
            source_status=before.status,
            action=M8NotificationAction.RECORD_DELIVERED,
            initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
            delivery_receipt=delivery,
            supporting_authorities=supporting_authorities,
            explicit_human_confirmation=False,
            occurred_at=delivery.occurred_at,
            command_manifest_id=self._workflow.transition_command_manifest_id,
        )
        return self._notifications.transition_notification(
            command,
            (raw_response,),
            self._workflow.raw_storage_manifest_id,
            self._workflow.audit_manifest_id,
        )

    def acknowledge(
        self,
        notification_id: str,
        actor_id: str,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        before = self._notifications.get_current_notification(notification_id)
        command = self._actor_command(
            before,
            self._actor(actor_id),
            M8NotificationAction.ACKNOWLEDGE,
            occurred_at,
            supporting_authorities,
        )
        return self._commit_without_raw(command)

    def respond(
        self,
        notification_id: str,
        actor_id: str,
        reply_kind: M8NotificationReplyKind,
        reply_document_sha256: str,
        raw_reply: bytes,
        received_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
    ) -> M8NotificationCommitReceiptV1:
        if not isinstance(raw_reply, bytes):
            raise TypeError("M8 notification response raw reply must be exact bytes")
        before = self._notifications.get_current_notification(notification_id)
        actor = self._actor(actor_id)
        plan = before.audit_event.notification_authority.plan
        raw_sha256 = hashlib.sha256(raw_reply).hexdigest()
        raw_ref_identity = sha256_hex([before.notification_id, actor.actor_id, raw_sha256])
        reply = M8NotificationReplyAuthorityV1(
            notification_id=before.notification_id,
            target_authority_id=plan.target.target_authority_id,
            actor_id=actor.actor_id,
            channel=plan.target.channel,
            reply_kind=reply_kind,
            reply_document_sha256=reply_document_sha256,
            raw_reply_ref=f"m8-reply-{raw_ref_identity[:40]}",
            raw_reply_sha256=raw_sha256,
            received_at=received_at,
            simulated=plan.simulated,
            reply_manifest_id=self._workflow.workflow_manifest_id,
        )
        command = self._actor_command(
            before,
            actor,
            M8NotificationAction.RESPOND,
            received_at,
            supporting_authorities,
            reply=reply,
        )
        return self._notifications.transition_notification(
            command,
            (raw_reply,),
            self._workflow.raw_storage_manifest_id,
            self._workflow.audit_manifest_id,
        )

    def _queue_or_retry(
        self,
        notification_id: str,
        action: M8NotificationAction,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
        actor: M8ActorAuthorityV1 | None,
    ) -> M8NotificationCommitReceiptV1:
        before = self._notifications.get_current_notification(notification_id)
        command = M8NotificationTransitionCommandV1(
            notification_id=before.notification_id,
            source_notification_version=before.notification_version,
            source_notification_authority_sha256=before.notification_document_sha256,
            source_status=before.status,
            action=action,
            initiator_kind=(
                M8NotificationInitiatorKind.SYSTEM
                if actor is None
                else M8NotificationInitiatorKind.ACTOR
            ),
            actor_authority=actor,
            system_authority_id=(self._workflow.workflow_authority_id if actor is None else None),
            supporting_authorities=supporting_authorities,
            explicit_human_confirmation=actor is not None,
            occurred_at=occurred_at,
            command_manifest_id=self._workflow.transition_command_manifest_id,
        )
        return self._commit_without_raw(command)

    def _actor_command(
        self,
        before: M8NotificationCommitReceiptV1,
        actor: M8ActorAuthorityV1,
        action: M8NotificationAction,
        occurred_at: datetime,
        supporting_authorities: tuple[M8AuthorityReference, ...],
        *,
        reply: M8NotificationReplyAuthorityV1 | None = None,
    ) -> M8NotificationTransitionCommandV1:
        return M8NotificationTransitionCommandV1(
            notification_id=before.notification_id,
            source_notification_version=before.notification_version,
            source_notification_authority_sha256=before.notification_document_sha256,
            source_status=before.status,
            action=action,
            initiator_kind=M8NotificationInitiatorKind.ACTOR,
            actor_authority=actor,
            reply=reply,
            supporting_authorities=supporting_authorities,
            explicit_human_confirmation=True,
            occurred_at=occurred_at,
            command_manifest_id=self._workflow.transition_command_manifest_id,
        )

    def _commit_without_raw(
        self,
        command: M8NotificationTransitionCommandV1,
    ) -> M8NotificationCommitReceiptV1:
        return self._notifications.transition_notification(
            command,
            (),
            self._workflow.raw_storage_manifest_id,
            self._workflow.audit_manifest_id,
        )

    def _actor(self, actor_id: str) -> M8ActorAuthorityV1:
        return self._operations.get_current_actor_authority(actor_id).authority


__all__ = ["M8NotificationService"]
