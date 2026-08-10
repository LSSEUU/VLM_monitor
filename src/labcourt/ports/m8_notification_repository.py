"""Persistence port for M8 notification targets and append-only lifecycle authority."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_notification_lifecycle import M8NotificationTransitionCommandV1
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationAuditEventV1,
    M8NotificationCommitReceiptV1,
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationPlanAuthorityV1,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
)


class M8NotificationRepository(Protocol):
    def publish_target_authority(
        self,
        target: M8NotificationTargetAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8NotificationTargetCommitReceiptV1: ...

    def get_current_target_authority(
        self,
        actor_id: str,
        channel: M8NotificationChannelKind,
    ) -> M8NotificationTargetCommitReceiptV1: ...

    def create_notification(
        self,
        plan: M8NotificationPlanAuthorityV1,
        audit_manifest_id: str,
    ) -> M8NotificationCommitReceiptV1: ...

    def get_current_notification(
        self,
        notification_id: str,
    ) -> M8NotificationCommitReceiptV1: ...

    def transition_notification(
        self,
        command: M8NotificationTransitionCommandV1,
        raw_artifacts: tuple[bytes, ...],
        raw_storage_manifest_id: str,
        audit_manifest_id: str,
    ) -> M8NotificationCommitReceiptV1: ...

    def list_notifications_by_status(
        self,
        status: M8NotificationStatus,
        limit: int,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]: ...

    def list_current_notifications(
        self,
        limit: int,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]: ...

    def list_notification_audit(
        self,
        notification_id: str,
    ) -> tuple[M8NotificationAuditEventV1, ...]: ...

    def read_raw_artifact(self, raw_artifact_ref: str) -> bytes: ...


__all__ = ["M8NotificationRepository"]
