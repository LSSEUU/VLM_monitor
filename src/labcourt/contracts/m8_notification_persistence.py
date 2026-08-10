"""M8 append-only notification version, audit event, and commit receipts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationPlanAuthorityV1,
    M8NotificationStatus,
)

M8_NOTIFICATION_AUDIT_GENESIS_SHA256 = "0" * 64


class M8NotificationAuditEventKind(StrEnum):
    NOTIFICATION_PLANNED = "NOTIFICATION_PLANNED"
    NOTIFICATION_TRANSITIONED = "NOTIFICATION_TRANSITIONED"


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
                f"serialized {name} conflicts with derived M8 notification persistence authority"
            )


def _initiator_authority_id(command: M8NotificationTransitionCommandV1) -> Sha256Hex:
    if command.initiator_kind == M8NotificationInitiatorKind.ACTOR:
        actor = command.actor_authority
        if actor is None:
            raise ValueError("M8 notification actor command lacks actor authority")
        return actor.actor_authority_id
    if command.initiator_kind == M8NotificationInitiatorKind.SYSTEM:
        if command.system_authority_id is None:
            raise ValueError("M8 notification system command lacks system authority")
        return command.system_authority_id
    if command.dispatch_result is not None:
        return command.dispatch_result.request.channel_capability.capability_authority_id
    if command.delivery_receipt is not None:
        return command.delivery_receipt.delivery_receipt_id
    raise ValueError("M8 notification channel command lacks channel authority")


class M8NotificationAuthorityV1(FrozenContractModel):
    """One immutable version in an M8 notification lifecycle."""

    schema_version: Literal["m8-notification-authority-v1"] = "m8-notification-authority-v1"
    plan: M8NotificationPlanAuthorityV1
    notification_version: int = Field(gt=0, strict=True)
    status: M8NotificationStatus
    prior_notification_document_sha256: Sha256Hex | None = None
    last_transition_command_id: Sha256Hex | None = None
    last_initiator_authority_id: Sha256Hex | None = None
    last_dispatch_result_id: Sha256Hex | None = None
    last_delivery_receipt_id: Sha256Hex | None = None
    last_reply_authority_id: Sha256Hex | None = None
    notification_manifest_id: Sha256Hex

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
                "notification_id",
                "case_id",
                "notification_authority_id",
            ),
        )
        authority = handler(payload)
        _verify_computed_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_version_shape(self) -> Self:
        transition_fields = (
            self.prior_notification_document_sha256,
            self.last_transition_command_id,
            self.last_initiator_authority_id,
        )
        if self.notification_version == 1:
            if self.status != M8NotificationStatus.PLANNED:
                raise ValueError("M8 first notification version must be PLANNED")
            if any(value is not None for value in transition_fields):
                raise ValueError("M8 first notification version cannot declare transition fields")
            if any(
                value is not None
                for value in (
                    self.last_dispatch_result_id,
                    self.last_delivery_receipt_id,
                    self.last_reply_authority_id,
                )
            ):
                raise ValueError("M8 first notification version cannot declare channel artifacts")
        elif any(value is None for value in transition_fields):
            raise ValueError("M8 later notification version requires complete transition fields")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_id(self) -> Sha256Hex:
        return self.plan.notification_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_id(self) -> Sha256Hex:
        return self.plan.case_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-authority",
                1,
                self.plan.notification_id,
                self.notification_version,
                self.status,
                self.prior_notification_document_sha256,
                self.last_transition_command_id,
                self.last_initiator_authority_id,
                self.last_dispatch_result_id,
                self.last_delivery_receipt_id,
                self.last_reply_authority_id,
                self.notification_manifest_id,
            ]
        )


class M8NotificationAuditEventV1(FrozenContractModel):
    """Append-only audit event binding one exact notification authority version."""

    schema_version: Literal["m8-notification-audit-event-v1"] = "m8-notification-audit-event-v1"
    notification_authority: M8NotificationAuthorityV1
    event_sequence: int = Field(gt=0, strict=True)
    plan_authority_id: Sha256Hex | None = None
    transition_command: M8NotificationTransitionCommandV1 | None = None
    resolved_actor_document_sha256: Sha256Hex | None = None
    prior_audit_event_sha256: Sha256Hex
    audit_manifest_id: Sha256Hex

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
                "event_kind",
                "notification_document_sha256",
                "audit_event_sha256",
                "audit_event_id",
            ),
        )
        event = handler(payload)
        _verify_computed_claims(event, claims)
        return event

    @model_validator(mode="after")
    def validate_event_binding(self) -> Self:
        authority = self.notification_authority
        if self.event_sequence != authority.notification_version:
            raise ValueError("M8 notification audit sequence must equal notification version")
        if authority.notification_version == 1:
            if (
                self.plan_authority_id != authority.plan.notification_id
                or self.transition_command is not None
                or self.resolved_actor_document_sha256 is not None
                or self.prior_audit_event_sha256 != M8_NOTIFICATION_AUDIT_GENESIS_SHA256
            ):
                raise ValueError("M8 notification plan audit event has invalid genesis shape")
            return self

        command = self.transition_command
        if command is None or self.plan_authority_id is not None:
            raise ValueError("M8 notification transition audit requires exactly one command")
        if self.prior_audit_event_sha256 == M8_NOTIFICATION_AUDIT_GENESIS_SHA256:
            raise ValueError("M8 notification transition cannot use audit genesis")
        expected = (
            authority.notification_id,
            authority.notification_version,
            authority.status,
            authority.last_transition_command_id,
            authority.last_initiator_authority_id,
            authority.last_dispatch_result_id,
            authority.last_delivery_receipt_id,
            authority.last_reply_authority_id,
        )
        actual = (
            command.notification_id,
            command.target_notification_version,
            command.target_status,
            command.command_id,
            _initiator_authority_id(command),
            (
                command.dispatch_result.dispatch_result_id
                if command.dispatch_result is not None
                else None
            ),
            (
                command.delivery_receipt.delivery_receipt_id
                if command.delivery_receipt is not None
                else None
            ),
            command.reply.reply_authority_id if command.reply is not None else None,
        )
        if expected != actual:
            raise ValueError(
                "M8 notification authority does not exactly bind its transition command"
            )
        plan = authority.plan
        if (
            command.action in {M8NotificationAction.QUEUE, M8NotificationAction.RETRY}
            and plan.escalation_policy.requires_human_send_confirmation
            and command.initiator_kind == M8NotificationInitiatorKind.SYSTEM
        ):
            raise ValueError("M8 notification policy requires human send confirmation")
        if (
            command.actor_authority is not None
            and command.action
            in {
                M8NotificationAction.ACKNOWLEDGE,
                M8NotificationAction.RESPOND,
            }
            and command.actor_authority.actor_id != plan.target.actor_id
        ):
            raise ValueError("M8 notification response actor must be the notification target")
        if command.delivery_receipt is not None and (
            command.delivery_receipt.target_authority_id != plan.target.target_authority_id
            or command.delivery_receipt.channel != plan.target.channel
        ):
            raise ValueError("M8 notification delivery receipt does not bind the planned target")
        if command.reply is not None and (
            command.reply.target_authority_id != plan.target.target_authority_id
            or command.reply.channel != plan.target.channel
        ):
            raise ValueError("M8 notification reply does not bind the planned target")
        actor_document_required = command.initiator_kind == M8NotificationInitiatorKind.ACTOR
        if actor_document_required != (self.resolved_actor_document_sha256 is not None):
            raise ValueError("M8 notification actor transition must bind resolved actor document")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_kind(self) -> M8NotificationAuditEventKind:
        if self.notification_authority.notification_version == 1:
            return M8NotificationAuditEventKind.NOTIFICATION_PLANNED
        return M8NotificationAuditEventKind.NOTIFICATION_TRANSITIONED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.notification_authority.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_event_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-audit-event-document",
                1,
                self.notification_authority.notification_authority_id,
                self.notification_document_sha256,
                self.event_sequence,
                self.plan_authority_id,
                self.transition_command.command_id if self.transition_command is not None else None,
                self.resolved_actor_document_sha256,
                self.prior_audit_event_sha256,
                self.audit_manifest_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_event_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-audit-event",
                1,
                self.notification_authority.notification_id,
                self.event_sequence,
                self.event_kind,
                self.audit_event_sha256,
            ]
        )


class M8NotificationCommitReceiptV1(FrozenContractModel):
    """Atomic receipt for one notification version and audit event."""

    schema_version: Literal["m8-notification-commit-receipt-v1"] = (
        "m8-notification-commit-receipt-v1"
    )
    audit_event: M8NotificationAuditEventV1
    repository_manifest_id: Sha256Hex

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
                "notification_id",
                "notification_version",
                "status",
                "notification_authority_id",
                "notification_document_sha256",
                "audit_event_id",
                "audit_event_sha256",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_id(self) -> Sha256Hex:
        return self.audit_event.notification_authority.notification_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_version(self) -> int:
        return self.audit_event.notification_authority.notification_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status(self) -> M8NotificationStatus:
        return self.audit_event.notification_authority.status

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_authority_id(self) -> Sha256Hex:
        return self.audit_event.notification_authority.notification_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_document_sha256(self) -> Sha256Hex:
        return self.audit_event.notification_document_sha256

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_event_id(self) -> Sha256Hex:
        return self.audit_event.audit_event_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_event_sha256(self) -> Sha256Hex:
        return self.audit_event.audit_event_sha256

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-commit-receipt",
                1,
                self.notification_id,
                self.notification_version,
                self.status,
                self.notification_authority_id,
                self.notification_document_sha256,
                self.audit_event_id,
                self.audit_event_sha256,
                self.repository_manifest_id,
            ]
        )


__all__ = [
    "M8_NOTIFICATION_AUDIT_GENESIS_SHA256",
    "M8NotificationAuditEventKind",
    "M8NotificationAuditEventV1",
    "M8NotificationAuthorityV1",
    "M8NotificationCommitReceiptV1",
]
