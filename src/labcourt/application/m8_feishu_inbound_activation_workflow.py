"""Pure builders for Feishu sandbox webhook ingress persistence authorities."""

from __future__ import annotations

from datetime import datetime

from labcourt.contracts.m8_adapter_commissioning import (
    M8AdapterActivationIntentV1,
    M8AdapterReadinessAssessmentV1,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundRevocationReason,
    M8FeishuInboundSandboxActivationCommitReceiptV1,
    M8FeishuInboundSandboxActivationRevocationCommitReceiptV1,
    M8FeishuInboundSandboxRuntimeConfigV1,
    m8_feishu_inbound_runtime_config_bytes,
)


def build_feishu_inbound_sandbox_activation_commit(
    activation_intent: M8AdapterActivationIntentV1,
    runtime_config: M8FeishuInboundSandboxRuntimeConfigV1,
    runtime_config_bytes: bytes,
    current_readiness_assessment: M8AdapterReadinessAssessmentV1,
    current_operations_actor_receipt: M8ActorAuthorityCommitReceiptV1,
    current_safety_actor_receipt: M8ActorAuthorityCommitReceiptV1,
    activation_revision: int,
    prior_activation_commit_id: str | None,
    committed_at: datetime,
    runtime_config_storage_manifest_id: str,
    repository_manifest_id: str,
) -> M8FeishuInboundSandboxActivationCommitReceiptV1:
    """Build ingress authority only from the exact canonical runtime bytes."""

    if not isinstance(runtime_config_bytes, bytes):
        raise TypeError("M8 Feishu inbound runtime config artifact must be exact bytes")
    if runtime_config_bytes != m8_feishu_inbound_runtime_config_bytes(runtime_config):
        raise ValueError("M8 Feishu inbound runtime config artifact is not canonical")
    return M8FeishuInboundSandboxActivationCommitReceiptV1(
        activation_intent=activation_intent,
        runtime_config=runtime_config,
        current_readiness_assessment=current_readiness_assessment,
        current_operations_actor_receipt=current_operations_actor_receipt,
        current_safety_actor_receipt=current_safety_actor_receipt,
        activation_revision=activation_revision,
        prior_activation_commit_id=prior_activation_commit_id,
        committed_at=committed_at,
        runtime_config_storage_manifest_id=runtime_config_storage_manifest_id,
        repository_manifest_id=repository_manifest_id,
    )


def build_feishu_inbound_sandbox_activation_revocation_commit(
    activation_receipt: M8FeishuInboundSandboxActivationCommitReceiptV1,
    revoked_by_actor_receipt: M8ActorAuthorityCommitReceiptV1,
    reason: M8FeishuInboundRevocationReason,
    reason_ref: str,
    revoked_at: datetime,
    revocation_manifest_id: str,
    repository_manifest_id: str,
) -> M8FeishuInboundSandboxActivationRevocationCommitReceiptV1:
    """Build a human kill-switch receipt without starting or stopping a listener."""

    return M8FeishuInboundSandboxActivationRevocationCommitReceiptV1(
        activation_receipt=activation_receipt,
        revoked_by_actor_receipt=revoked_by_actor_receipt,
        reason=reason,
        reason_ref=reason_ref,
        revoked_at=revoked_at,
        revocation_manifest_id=revocation_manifest_id,
        repository_manifest_id=repository_manifest_id,
    )


__all__ = [
    "build_feishu_inbound_sandbox_activation_commit",
    "build_feishu_inbound_sandbox_activation_revocation_commit",
]
