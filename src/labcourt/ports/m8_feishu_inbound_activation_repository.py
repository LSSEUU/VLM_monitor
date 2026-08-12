"""Persistence port for current Feishu sandbox webhook ingress authority."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from labcourt.contracts.m8_adapter_commissioning import M8AdapterActivationIntentV1
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundRevocationReason,
    M8FeishuInboundSandboxActivationCommitReceiptV1,
    M8FeishuInboundSandboxActivationRevocationCommitReceiptV1,
    M8FeishuInboundSandboxActivationStatusV1,
    M8FeishuInboundSandboxRuntimeConfigV1,
)


class M8FeishuInboundActivationRepository(Protocol):
    def commit_inbound_activation(
        self,
        activation_intent: M8AdapterActivationIntentV1,
        runtime_config: M8FeishuInboundSandboxRuntimeConfigV1,
        runtime_config_bytes: bytes,
        runtime_config_storage_manifest_id: str,
        current_assessed_at: datetime,
        committed_at: datetime,
    ) -> M8FeishuInboundSandboxActivationCommitReceiptV1: ...

    def get_inbound_activation(
        self,
        activation_commit_id: str,
    ) -> M8FeishuInboundSandboxActivationCommitReceiptV1: ...

    def get_current_inbound_status(
        self,
        candidate_authority_id: str,
        assessed_at: datetime,
    ) -> M8FeishuInboundSandboxActivationStatusV1: ...

    def revoke_inbound_activation(
        self,
        activation_commit_id: str,
        revoker_actor_id: str,
        reason: M8FeishuInboundRevocationReason,
        reason_ref: str,
        revoked_at: datetime,
        revocation_manifest_id: str,
    ) -> M8FeishuInboundSandboxActivationRevocationCommitReceiptV1: ...

    def read_inbound_runtime_config(self, runtime_config_ref: str) -> bytes: ...


__all__ = ["M8FeishuInboundActivationRepository"]
