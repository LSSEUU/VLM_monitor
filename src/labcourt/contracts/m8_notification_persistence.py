"""M8 append-only notification version, audit event, and commit receipts."""

from __future__ import annotations

from enum import StrEnum
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
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationPlanAuthorityV1,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

M8_NOTIFICATION_AUDIT_GENESIS_SHA256 = "0" * 64
MAX_M8_NOTIFICATION_RAW_ARTIFACT_BYTES = 1024 * 1024
MAX_M8_NOTIFICATION_RAW_ARTIFACTS_PER_TRANSITION = 2


class M8NotificationAuditEventKind(StrEnum):
    NOTIFICATION_PLANNED = "NOTIFICATION_PLANNED"
    NOTIFICATION_TRANSITIONED = "NOTIFICATION_TRANSITIONED"


class M8NotificationTargetCommitReceiptV1(FrozenContractModel):
    """Append receipt for one persisted notification target revision."""

    schema_version: Literal["m8-notification-target-commit-receipt-v1"] = (
        "m8-notification-target-commit-receipt-v1"
    )
    target: M8NotificationTargetAuthorityV1
    prior_target_authority_id: Sha256Hex | None = None
    prior_document_sha256: Sha256Hex | None = None
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
            ("target_document_sha256", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_prior_shape(self) -> Self:
        if self.target.authority_revision == 1:
            if self.prior_target_authority_id is not None or self.prior_document_sha256 is not None:
                raise ValueError(
                    "M8 first notification target revision cannot declare prior authority"
                )
        elif self.prior_target_authority_id is None or self.prior_document_sha256 is None:
            raise ValueError("M8 later notification target revision requires prior authority")
        if (self.prior_target_authority_id is None) != (self.prior_document_sha256 is None):
            raise ValueError("M8 notification target prior fields must be present together")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.target.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-target-commit-receipt",
                1,
                self.target.target_authority_id,
                self.target_document_sha256,
                self.prior_target_authority_id,
                self.prior_document_sha256,
                self.repository_manifest_id,
            ]
        )


class M8NotificationRawArtifactCommitReceiptV1(FrozenContractModel):
    """Metadata receipt binding exact persisted channel/card/reply bytes."""

    schema_version: Literal["m8-notification-raw-artifact-commit-receipt-v1"] = (
        "m8-notification-raw-artifact-commit-receipt-v1"
    )
    raw_artifact_ref: ReferenceToken
    raw_artifact_sha256: Sha256Hex
    raw_artifact_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_NOTIFICATION_RAW_ARTIFACT_BYTES,
        strict=True,
    )
    raw_storage_manifest_id: Sha256Hex
    repository_manifest_id: Sha256Hex

    @field_validator("raw_artifact_ref")
    @classmethod
    def validate_raw_artifact_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification raw artifact")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("commit_receipt_id",))
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-raw-artifact-commit-receipt",
                1,
                self.raw_artifact_ref,
                self.raw_artifact_sha256,
                self.raw_artifact_size_bytes,
                self.raw_storage_manifest_id,
                self.repository_manifest_id,
            ]
        )


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
    raw_artifact_receipts: tuple[M8NotificationRawArtifactCommitReceiptV1, ...] = Field(
        max_length=MAX_M8_NOTIFICATION_RAW_ARTIFACTS_PER_TRANSITION
    )
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
                "raw_artifact_inventory_sha256",
                "total_raw_artifact_size_bytes",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_raw_artifact_inventory(self) -> Self:
        command = self.audit_event.transition_command
        if command is None:
            expected: tuple[tuple[str, str], ...] = ()
        elif command.dispatch_result is not None:
            request = command.dispatch_result.request
            expected = (
                (request.rendered_card_ref, request.rendered_card_sha256),
                (
                    command.dispatch_result.raw_response_ref,
                    command.dispatch_result.raw_response_sha256,
                ),
            )
        elif command.delivery_receipt is not None:
            expected = (
                (
                    command.delivery_receipt.raw_response_ref,
                    command.delivery_receipt.raw_response_sha256,
                ),
            )
        elif command.reply is not None:
            expected = ((command.reply.raw_reply_ref, command.reply.raw_reply_sha256),)
        else:
            expected = ()
        observed = tuple(
            (item.raw_artifact_ref, item.raw_artifact_sha256) for item in self.raw_artifact_receipts
        )
        if observed != expected or len({item[0] for item in observed}) != len(observed):
            raise ValueError("M8 notification raw artifact receipts do not bind the command")
        if any(
            item.repository_manifest_id != self.repository_manifest_id
            for item in self.raw_artifact_receipts
        ):
            raise ValueError("M8 notification raw artifact repository manifest conflicts")
        return self

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
    def raw_artifact_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-raw-artifact-inventory",
                1,
                [item.commit_receipt_id for item in self.raw_artifact_receipts],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_raw_artifact_size_bytes(self) -> int:
        return sum(item.raw_artifact_size_bytes for item in self.raw_artifact_receipts)

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
                self.raw_artifact_inventory_sha256,
                self.total_raw_artifact_size_bytes,
                self.repository_manifest_id,
            ]
        )


__all__ = [
    "M8_NOTIFICATION_AUDIT_GENESIS_SHA256",
    "MAX_M8_NOTIFICATION_RAW_ARTIFACTS_PER_TRANSITION",
    "MAX_M8_NOTIFICATION_RAW_ARTIFACT_BYTES",
    "M8NotificationAuditEventKind",
    "M8NotificationAuditEventV1",
    "M8NotificationAuthorityV1",
    "M8NotificationCommitReceiptV1",
    "M8NotificationRawArtifactCommitReceiptV1",
    "M8NotificationTargetCommitReceiptV1",
]
