"""Current-authority orchestration for verified Feishu student explanations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_inbound_reply import (
    M8FeishuInboundReplyCommitReceiptV1,
    M8FeishuInboundReplyCorrelationAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationReplyAuthorityV1,
    M8NotificationReplyKind,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_feishu_activation_repository import M8FeishuActivationRepository
from labcourt.ports.m8_feishu_inbound_reply_repository import (
    M8FeishuInboundReplyRepository,
)
from labcourt.ports.m8_feishu_inbound_repository import M8FeishuInboundRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu inbound reply {name} must be lowercase SHA-256 hex")
    return value


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu inbound reply {name} must be timezone-aware UTC")
    return value


class M8FeishuInboundReplyService:
    """Map one persisted Feishu text reply to one generic explanation transition."""

    def __init__(
        self,
        inbound_repository: M8FeishuInboundRepository,
        reply_repository: M8FeishuInboundReplyRepository,
        activation_repository: M8FeishuActivationRepository,
        operations_repository: M8OperationsRepository,
        clock: Callable[[], datetime],
        correlation_manifest_id: Sha256Hex,
        notification_raw_storage_manifest_id: Sha256Hex,
        notification_audit_manifest_id: Sha256Hex,
        transition_command_manifest_id: Sha256Hex,
        reply_commit_manifest_id: Sha256Hex,
    ) -> None:
        if any(
            port is None
            for port in (
                inbound_repository,
                reply_repository,
                activation_repository,
                operations_repository,
            )
        ):
            raise TypeError("M8 Feishu inbound reply service requires explicit ports")
        if not callable(clock):
            raise TypeError("M8 Feishu inbound reply service requires a clock")
        self._inbound = inbound_repository
        self._replies = reply_repository
        self._activations = activation_repository
        self._operations = operations_repository
        self._clock = clock
        self._correlation_manifest_id = _validate_sha256(
            correlation_manifest_id,
            "correlation manifest",
        )
        self._raw_storage_manifest_id = _validate_sha256(
            notification_raw_storage_manifest_id,
            "notification raw storage manifest",
        )
        self._audit_manifest_id = _validate_sha256(
            notification_audit_manifest_id,
            "notification audit manifest",
        )
        self._command_manifest_id = _validate_sha256(
            transition_command_manifest_id,
            "transition command manifest",
        )
        self._commit_manifest_id = _validate_sha256(
            reply_commit_manifest_id,
            "reply commit manifest",
        )

    def correlate_and_commit(
        self,
        provider_message_id: str,
    ) -> M8FeishuInboundReplyCommitReceiptV1:
        try:
            return self._replies.get_reply_by_provider_message_id(provider_message_id)
        except EvidenceMissing:
            pass

        inbound = self._inbound.get_by_provider_message_id(provider_message_id)
        verified = inbound.verification_receipt
        profile = verified.profile.outbound_profile
        notification_chain = self._replies.get_notification_chain_by_provider_message_id(
            verified.provider_parent_message_id,
            profile.candidate.adapter_id,
        )
        plan = notification_chain[0].audit_event.notification_authority.plan
        if plan.target.channel != M8NotificationChannelKind.FEISHU:
            raise ConcurrentModification(
                "M8 Feishu inbound reply parent is not a FEISHU notification"
            )
        correlated_at = _require_utc(self._clock(), "correlation time")
        activation = self._activations.get_current_status(
            profile.candidate.candidate_authority_id,
            correlated_at,
        )
        matches = tuple(
            (binding, target_receipt)
            for binding, target_receipt in zip(
                activation.activation_receipt.runtime_config.recipient_allowlist,
                activation.current_recipient_target_receipts,
                strict=True,
            )
            if binding.target == plan.target
            and binding.receive_id_sha256 == verified.sender_open_id_sha256
        )
        if len(matches) != 1:
            raise EvidenceMissing(
                "M8 Feishu inbound reply has no exact current recipient binding"
            )
        binding, target_receipt = matches[0]
        actor_receipt = self._operations.get_current_actor_authority(plan.target.actor_id)
        reply = M8NotificationReplyAuthorityV1(
            notification_id=plan.notification_id,
            target_authority_id=plan.target.target_authority_id,
            actor_id=plan.target.actor_id,
            channel=M8NotificationChannelKind.FEISHU,
            reply_kind=M8NotificationReplyKind.EXPLANATION,
            reply_document_sha256=verified.content_document_sha256,
            raw_reply_ref=verified.content_document_ref,
            raw_reply_sha256=verified.content_document_sha256,
            received_at=verified.ingress_request.received_at,
            simulated=False,
            reply_manifest_id=self._correlation_manifest_id,
        )
        correlation = M8FeishuInboundReplyCorrelationAuthorityV1(
            inbound_commit=inbound,
            notification_commit_chain=notification_chain,
            activation_status=activation,
            recipient_binding=binding,
            current_target_receipt=target_receipt,
            current_actor_receipt=actor_receipt,
            reply=reply,
            correlated_at=correlated_at,
            correlation_manifest_id=self._correlation_manifest_id,
        )
        return self._replies.commit_reply(
            correlation,
            self._raw_storage_manifest_id,
            self._audit_manifest_id,
            self._command_manifest_id,
            self._commit_manifest_id,
        )


__all__ = ["M8FeishuInboundReplyService"]
