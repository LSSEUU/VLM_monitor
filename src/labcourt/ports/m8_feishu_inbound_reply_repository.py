"""Atomic persistence port for correlated Feishu notification replies."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_feishu_inbound_reply import (
    M8FeishuInboundReplyCommitReceiptV1,
    M8FeishuInboundReplyCorrelationAuthorityV1,
)
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1


class M8FeishuInboundReplyRepository(Protocol):
    def get_notification_chain_by_provider_message_id(
        self,
        provider_message_id: str,
        adapter_id: str,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]: ...

    def commit_reply(
        self,
        correlation_authority: M8FeishuInboundReplyCorrelationAuthorityV1,
        notification_raw_storage_manifest_id: str,
        notification_audit_manifest_id: str,
        transition_command_manifest_id: str,
        reply_commit_manifest_id: str,
    ) -> M8FeishuInboundReplyCommitReceiptV1: ...

    def get_reply_by_provider_message_id(
        self,
        provider_message_id: str,
    ) -> M8FeishuInboundReplyCommitReceiptV1: ...


__all__ = ["M8FeishuInboundReplyRepository"]
