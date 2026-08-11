"""Exact Feishu inbound-to-notification reply correlation authorities."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8ActorScopeKind,
    M8AuthorityReference,
    M8AuthorityReferenceKind,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundMessageCommitReceiptV1
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationDispatchDisposition,
    M8NotificationInitiatorKind,
    M8NotificationReplyAuthorityV1,
    M8NotificationReplyKind,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationCommitReceiptV1,
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import M8NotificationChannelKind, M8NotificationStatus
from labcourt.contracts.references import ReferenceToken

MAX_M8_FEISHU_REPLY_NOTIFICATION_CHAIN = 16
_REPLY_SOURCE_STATUSES = {
    M8NotificationStatus.SENT,
    M8NotificationStatus.DELIVERED,
    M8NotificationStatus.ACKNOWLEDGED,
}


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu inbound reply {name} must be timezone-aware UTC")
    return value


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(
                f"serialized {name} conflicts with derived M8 Feishu reply authority"
            )


class M8FeishuInboundReplyCorrelationAuthorityV1(FrozenContractModel):
    """Current-authority proof that one verified Feishu message is a student explanation."""

    schema_version: Literal["m8-feishu-inbound-reply-correlation-authority-v1"] = (
        "m8-feishu-inbound-reply-correlation-authority-v1"
    )
    inbound_commit: M8FeishuInboundMessageCommitReceiptV1
    notification_commit_chain: tuple[M8NotificationCommitReceiptV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_FEISHU_REPLY_NOTIFICATION_CHAIN,
    )
    activation_status: M8FeishuSandboxActivationStatusV1
    recipient_binding: M8FeishuRecipientBindingAuthorityV1
    current_target_receipt: M8NotificationTargetCommitReceiptV1
    current_actor_receipt: M8ActorAuthorityCommitReceiptV1
    reply: M8NotificationReplyAuthorityV1
    correlated_at: datetime
    correlation_manifest_id: Sha256Hex

    @field_validator("correlated_at")
    @classmethod
    def validate_correlated_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "correlated_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "provider_message_id",
                "reply_correlation_message_id",
                "notification_id",
                "actor_id",
                "reply_kind_inferred",
                "human_reply_explicit",
                "notification_reply_commit_permitted",
                "automatic_appeal_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "correlation_authority_document_sha256",
                "correlation_authority_id",
            ),
        )
        authority = handler(payload)
        _verify_computed_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_exact_correlation(self) -> Self:
        verified = self.inbound_commit.verification_receipt
        outbound = self.notification_commit_chain[0]
        current = self.notification_commit_chain[-1]
        outbound_command = outbound.audit_event.transition_command
        if (
            outbound.status != M8NotificationStatus.SENT
            or outbound_command is None
            or outbound_command.action != M8NotificationAction.RECORD_SENT
            or outbound_command.dispatch_result is None
            or outbound_command.dispatch_result.disposition
            != M8NotificationDispatchDisposition.ACCEPTED
        ):
            raise ValueError("M8 Feishu reply correlation requires an accepted SENT authority")
        dispatch = outbound_command.dispatch_result
        if dispatch.provider_receipt_id != verified.provider_parent_message_id:
            raise ValueError("M8 Feishu reply parent does not match the outbound provider message")
        if verified.ingress_request.received_at < dispatch.completed_at:
            raise ValueError("M8 Feishu reply cannot predate the outbound provider message")

        plan = outbound.audit_event.notification_authority.plan
        prior = outbound
        for successor in self.notification_commit_chain[1:]:
            authority = successor.audit_event.notification_authority
            if (
                successor.notification_id != prior.notification_id
                or successor.notification_version != prior.notification_version + 1
                or authority.plan != plan
                or authority.prior_notification_document_sha256
                != prior.notification_document_sha256
                or successor.audit_event.prior_audit_event_sha256 != prior.audit_event_sha256
            ):
                raise ValueError("M8 Feishu reply notification authority chain is not contiguous")
            prior = successor
        if current.status not in _REPLY_SOURCE_STATUSES:
            raise ValueError("M8 Feishu reply notification is not in a response-eligible state")

        config = self.activation_status.activation_receipt.runtime_config
        if verified.profile.outbound_profile != config.profile:
            raise ValueError("M8 Feishu inbound reply belongs to another adapter profile")
        candidate = config.profile.candidate
        capability = dispatch.request.channel_capability
        if (
            capability.adapter_id != candidate.adapter_id
            or capability.adapter_revision != candidate.adapter_revision
            or capability.channel != M8NotificationChannelKind.FEISHU
        ):
            raise ValueError("M8 Feishu reply outbound message belongs to another adapter")
        binding_pairs = tuple(
            zip(
                config.recipient_allowlist,
                self.activation_status.current_recipient_target_receipts,
                strict=True,
            )
        )
        if (self.recipient_binding, self.current_target_receipt) not in binding_pairs:
            raise ValueError("M8 Feishu reply recipient is not in the current activation status")
        if not self.activation_status.recipient_authority_current:
            raise ValueError("M8 Feishu reply recipient authority is no longer current")
        if (
            self.recipient_binding.target != plan.target
            or self.current_target_receipt.target != plan.target
            or not plan.target.active
            or not plan.target.inbound_response_supported
        ):
            raise ValueError("M8 Feishu reply does not bind the current planned target")
        if verified.sender_open_id_sha256 != self.recipient_binding.receive_id_sha256:
            raise ValueError("M8 Feishu reply sender does not match the current recipient binding")

        actor = self.current_actor_receipt.authority
        if (
            actor.actor_id != plan.target.actor_id
            or actor.role != M8ActorRole.STUDENT
            or actor.scope_kind != M8ActorScopeKind.SELF_ONLY
            or actor.scope_location_ids
            or not actor.active
        ):
            raise ValueError("M8 Feishu reply requires the current active target student")
        expected_reply = (
            plan.notification_id,
            plan.target.target_authority_id,
            actor.actor_id,
            M8NotificationChannelKind.FEISHU,
            M8NotificationReplyKind.EXPLANATION,
            verified.content_document_sha256,
            verified.content_document_ref,
            verified.content_document_sha256,
            verified.ingress_request.received_at,
            False,
            self.correlation_manifest_id,
        )
        observed_reply = (
            self.reply.notification_id,
            self.reply.target_authority_id,
            self.reply.actor_id,
            self.reply.channel,
            self.reply.reply_kind,
            self.reply.reply_document_sha256,
            self.reply.raw_reply_ref,
            self.reply.raw_reply_sha256,
            self.reply.received_at,
            self.reply.simulated,
            self.reply.reply_manifest_id,
        )
        if observed_reply != expected_reply:
            raise ValueError("M8 Feishu reply authority does not exactly bind inbound content")
        if (
            self.correlated_at < self.inbound_commit.committed_at
            or self.correlated_at < self.activation_status.assessed_at
        ):
            raise ValueError("M8 Feishu reply correlation predates a required current authority")
        current_command = current.audit_event.transition_command
        if current_command is not None and self.correlated_at < current_command.occurred_at:
            raise ValueError("M8 Feishu reply correlation predates the current notification")
        repository_manifests = {
            self.inbound_commit.repository_manifest_id,
            self.activation_status.repository_manifest_id,
            self.current_target_receipt.repository_manifest_id,
            self.current_actor_receipt.repository_manifest_id,
            *(item.repository_manifest_id for item in self.notification_commit_chain),
        }
        if len(repository_manifests) != 1:
            raise ValueError("M8 Feishu reply correlation authorities cross repositories")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_message_id(self) -> ReferenceToken:
        return self.inbound_commit.provider_message_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reply_correlation_message_id(self) -> ReferenceToken:
        return self.inbound_commit.verification_receipt.provider_parent_message_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_id(self) -> Sha256Hex:
        return self.notification_commit_chain[0].notification_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def actor_id(self) -> ReferenceToken:
        return self.current_actor_receipt.authority.actor_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reply_kind_inferred(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def human_reply_explicit(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_reply_commit_permitted(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_appeal_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def correlation_authority_document_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-reply-correlation-authority-document",
                1,
                self.inbound_commit.commit_receipt_id,
                tuple(item.commit_receipt_id for item in self.notification_commit_chain),
                self.activation_status.status_id,
                self.recipient_binding.binding_authority_id,
                self.current_target_receipt.commit_receipt_id,
                self.current_actor_receipt.commit_receipt_id,
                self.reply.reply_authority_id,
                _canonical_utc(self.correlated_at),
                self.correlation_manifest_id,
                self.reply_kind_inferred,
                self.human_reply_explicit,
                self.notification_reply_commit_permitted,
                self.automatic_appeal_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def correlation_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-reply-correlation-authority",
                1,
                self.provider_message_id,
                self.reply_correlation_message_id,
                self.notification_id,
                self.actor_id,
                self.correlation_authority_document_sha256,
            ]
        )

    def supporting_authority(self) -> M8AuthorityReference:
        """Return the exact generic-notification support reference for this authority."""

        return M8AuthorityReference(
            kind=M8AuthorityReferenceKind.NOTIFICATION_REPLY,
            authority_id=self.correlation_authority_id,
            document_sha256=self.correlation_authority_document_sha256,
        )


class M8FeishuInboundReplyCommitReceiptV1(FrozenContractModel):
    """Proof that one correlation authority produced exactly one generic reply transition."""

    schema_version: Literal["m8-feishu-inbound-reply-commit-receipt-v1"] = (
        "m8-feishu-inbound-reply-commit-receipt-v1"
    )
    correlation_authority: M8FeishuInboundReplyCorrelationAuthorityV1
    notification_commit: M8NotificationCommitReceiptV1
    reply_commit_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "provider_message_deduplication_key",
                "notification_reply_committed",
                "automatic_replay_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_exact_commit(self) -> Self:
        correlation = self.correlation_authority
        before = correlation.notification_commit_chain[-1]
        command = self.notification_commit.audit_event.transition_command
        if (
            command is None
            or command.action != M8NotificationAction.RESPOND
            or command.initiator_kind != M8NotificationInitiatorKind.ACTOR
            or command.actor_authority != correlation.current_actor_receipt.authority
            or command.reply != correlation.reply
            or command.supporting_authorities != (correlation.supporting_authority(),)
            or command.explicit_human_confirmation is not True
            or command.occurred_at != correlation.correlated_at
        ):
            raise ValueError("M8 Feishu reply commit does not bind the exact correlation authority")
        expected_source = (
            before.notification_id,
            before.notification_version,
            before.notification_document_sha256,
            before.status,
        )
        observed_source = (
            command.notification_id,
            command.source_notification_version,
            command.source_notification_authority_sha256,
            command.source_status,
        )
        if (
            observed_source != expected_source
            or self.notification_commit.status != M8NotificationStatus.RESPONDED
        ):
            raise ValueError("M8 Feishu reply commit does not follow the correlated notification")
        if (
            self.notification_commit.repository_manifest_id
            != self.correlation_authority.inbound_commit.repository_manifest_id
        ):
            raise ValueError("M8 Feishu reply commit crosses repositories")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_message_deduplication_key(self) -> ReferenceToken:
        return self.correlation_authority.provider_message_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_reply_committed(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_replay_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-reply-commit-receipt",
                1,
                self.correlation_authority.correlation_authority_id,
                self.notification_commit.commit_receipt_id,
                self.provider_message_deduplication_key,
                self.reply_commit_manifest_id,
                self.notification_reply_committed,
                self.automatic_replay_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "MAX_M8_FEISHU_REPLY_NOTIFICATION_CHAIN",
    "M8FeishuInboundReplyCommitReceiptV1",
    "M8FeishuInboundReplyCorrelationAuthorityV1",
]
