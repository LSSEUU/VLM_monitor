"""Persistence port for current Feishu sandbox activation and its kill switch."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from labcourt.contracts.m8_adapter_commissioning import M8AdapterActivationIntentV1
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxActivationCommitReceiptV1,
    M8FeishuSandboxActivationRevocationCommitReceiptV1,
    M8FeishuSandboxActivationStatusV1,
    M8FeishuSandboxRevocationReason,
    M8FeishuSandboxRuntimeConfigV1,
)


class M8FeishuActivationRepository(Protocol):
    def commit_activation(
        self,
        activation_intent: M8AdapterActivationIntentV1,
        runtime_config: M8FeishuSandboxRuntimeConfigV1,
        runtime_config_bytes: bytes,
        runtime_config_storage_manifest_id: str,
        current_assessed_at: datetime,
        committed_at: datetime,
    ) -> M8FeishuSandboxActivationCommitReceiptV1: ...

    def get_activation(
        self,
        activation_commit_id: str,
    ) -> M8FeishuSandboxActivationCommitReceiptV1: ...

    def get_current_status(
        self,
        candidate_authority_id: str,
        assessed_at: datetime,
    ) -> M8FeishuSandboxActivationStatusV1: ...

    def revoke_activation(
        self,
        activation_commit_id: str,
        revoker_actor_id: str,
        reason: M8FeishuSandboxRevocationReason,
        reason_ref: str,
        revoked_at: datetime,
        revocation_manifest_id: str,
    ) -> M8FeishuSandboxActivationRevocationCommitReceiptV1: ...

    def read_runtime_config(self, runtime_config_ref: str) -> bytes: ...


__all__ = ["M8FeishuActivationRepository"]
