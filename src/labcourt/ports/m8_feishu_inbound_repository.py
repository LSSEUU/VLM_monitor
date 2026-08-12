"""Persistence port for verified Feishu inbound message evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from labcourt.contracts.m8_feishu_inbound import (
    M8FeishuInboundMessageCommitReceiptV1,
    M8FeishuInboundMessageVerificationReceiptV1,
)


class M8FeishuInboundRepository(Protocol):
    def commit_verification(
        self,
        verification_receipt: M8FeishuInboundMessageVerificationReceiptV1,
        raw_artifacts: tuple[bytes, bytes, bytes],
        raw_storage_manifest_id: str,
        committed_at: datetime,
        commit_manifest_id: str,
    ) -> M8FeishuInboundMessageCommitReceiptV1: ...

    def get_by_provider_message_id(
        self,
        provider_message_id: str,
    ) -> M8FeishuInboundMessageCommitReceiptV1: ...

    def read_raw_artifact(self, raw_artifact_ref: str) -> bytes: ...


__all__ = ["M8FeishuInboundRepository"]
