"""Persistence port for exclusive M8 notification dispatch calls."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from labcourt.contracts.m8_access_cases import M8AuthorityReference
from labcourt.contracts.m8_notification_dispatch_claims import (
    M8NotificationDispatchCallFenceReceiptV1,
    M8NotificationDispatchClaimReceiptV1,
    M8NotificationDispatchClaimStatusV1,
    M8NotificationDispatchCompletionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
)


class M8NotificationDispatchClaimRepository(Protocol):
    def claim_dispatch(
        self,
        request: M8NotificationDispatchRequestV1,
        worker_owner_token: bytes,
        lease_expires_at: datetime,
        claim_manifest_id: str,
    ) -> M8NotificationDispatchClaimReceiptV1: ...

    def fence_dispatch_call(
        self,
        claim_id: str,
        worker_owner_token: bytes,
        dispatch_authorization_id: str,
        fenced_at: datetime,
        call_fence_manifest_id: str,
    ) -> M8NotificationDispatchCallFenceReceiptV1: ...

    def complete_dispatch(
        self,
        claim_id: str,
        call_fence_id: str,
        worker_owner_token: bytes,
        dispatch_result: M8NotificationDispatchResultV1,
        raw_artifacts: tuple[bytes, ...],
        raw_storage_manifest_id: str,
        supporting_authorities: tuple[M8AuthorityReference, ...],
        command_manifest_id: str,
        audit_manifest_id: str,
        committed_at: datetime,
        completion_manifest_id: str,
    ) -> M8NotificationDispatchCompletionReceiptV1: ...

    def get_dispatch_claim_status(
        self,
        claim_id: str,
        assessed_at: datetime,
    ) -> M8NotificationDispatchClaimStatusV1: ...

    def get_dispatch_claim_status_for_source(
        self,
        notification_id: str,
        source_notification_version: int,
        assessed_at: datetime,
    ) -> M8NotificationDispatchClaimStatusV1: ...


__all__ = ["M8NotificationDispatchClaimRepository"]
