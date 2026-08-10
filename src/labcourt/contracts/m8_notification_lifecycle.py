"""M8 notification channel, delivery, reply, and lifecycle command authorities."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8ActorRole,
    M8AuthorityReference,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationPlanAuthorityV1,
    M8NotificationStatus,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_NOTIFICATION_CHANNEL_TIMEOUT_MS = 30_000
MAX_M8_NOTIFICATION_SUPPORTING_AUTHORITIES = 32


class M8NotificationAction(StrEnum):
    ACKNOWLEDGE = "ACKNOWLEDGE"
    QUEUE = "QUEUE"
    RECORD_DELIVERED = "RECORD_DELIVERED"
    RECORD_FAILED = "RECORD_FAILED"
    RECORD_SENT = "RECORD_SENT"
    RESPOND = "RESPOND"
    RETRY = "RETRY"


class M8NotificationInitiatorKind(StrEnum):
    ACTOR = "ACTOR"
    CHANNEL_ADAPTER = "CHANNEL_ADAPTER"
    SYSTEM = "SYSTEM"


class M8NotificationDispatchDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    DEFINITELY_NOT_SENT = "DEFINITELY_NOT_SENT"
    UNKNOWN_DELIVERY = "UNKNOWN_DELIVERY"


class M8NotificationDeliveryDisposition(StrEnum):
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"


class M8NotificationChannelFailureCode(StrEnum):
    CHANNEL_REJECTED = "CHANNEL_REJECTED"
    CHANNEL_TIMEOUT = "CHANNEL_TIMEOUT"
    CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"
    DELIVERY_REJECTED = "DELIVERY_REJECTED"
    RECEIPT_INVALID = "RECEIPT_INVALID"
    UNKNOWN_DELIVERY = "UNKNOWN_DELIVERY"


class M8NotificationReplyKind(StrEnum):
    APPEAL_REQUEST = "APPEAL_REQUEST"
    EXPLANATION = "EXPLANATION"


_ACTION_SOURCE_STATUSES: dict[M8NotificationAction, tuple[M8NotificationStatus, ...]] = {
    M8NotificationAction.QUEUE: (M8NotificationStatus.PLANNED,),
    M8NotificationAction.RECORD_SENT: (M8NotificationStatus.QUEUED,),
    M8NotificationAction.RECORD_DELIVERED: (M8NotificationStatus.SENT,),
    M8NotificationAction.RECORD_FAILED: (
        M8NotificationStatus.QUEUED,
        M8NotificationStatus.SENT,
    ),
    M8NotificationAction.ACKNOWLEDGE: (
        M8NotificationStatus.SENT,
        M8NotificationStatus.DELIVERED,
    ),
    M8NotificationAction.RESPOND: (
        M8NotificationStatus.SENT,
        M8NotificationStatus.DELIVERED,
        M8NotificationStatus.ACKNOWLEDGED,
    ),
    M8NotificationAction.RETRY: (M8NotificationStatus.FAILED,),
}
_ACTION_TARGET_STATUS = {
    M8NotificationAction.QUEUE: M8NotificationStatus.QUEUED,
    M8NotificationAction.RECORD_SENT: M8NotificationStatus.SENT,
    M8NotificationAction.RECORD_DELIVERED: M8NotificationStatus.DELIVERED,
    M8NotificationAction.RECORD_FAILED: M8NotificationStatus.FAILED,
    M8NotificationAction.ACKNOWLEDGE: M8NotificationStatus.ACKNOWLEDGED,
    M8NotificationAction.RESPOND: M8NotificationStatus.RESPONDED,
    M8NotificationAction.RETRY: M8NotificationStatus.QUEUED,
}


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 {name} must be timezone-aware UTC")
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
                f"serialized {name} conflicts with derived M8 notification lifecycle authority"
            )


def _require_stable_authorities(values: tuple[M8AuthorityReference, ...]) -> None:
    keys = tuple((item.kind.value, item.authority_id, item.document_sha256) for item in values)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError("M8 notification supporting authorities must be unique and stable")


class M8NotificationChannelCapabilityAuthorityV1(FrozenContractModel):
    """Pinned adapter behavior for one notification channel."""

    schema_version: Literal["m8-notification-channel-capability-authority-v1"] = (
        "m8-notification-channel-capability-authority-v1"
    )
    adapter_id: ReferenceToken
    adapter_revision: ReferenceToken
    channel: M8NotificationChannelKind
    request_timeout_ms: int = Field(
        gt=0,
        le=MAX_M8_NOTIFICATION_CHANNEL_TIMEOUT_MS,
        strict=True,
    )
    network_required: StrictBool
    offline_capable: StrictBool
    simulated: StrictBool
    inbound_response_supported: StrictBool
    provider_idempotency_key: Literal["notification_id"] = "notification_id"
    adapter_manifest_id: Sha256Hex

    @field_validator("adapter_id", "adapter_revision")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification channel capability")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("capability_authority_id",))
        capability = handler(payload)
        _verify_computed_claims(capability, claims)
        return capability

    @model_validator(mode="after")
    def validate_channel_mode(self) -> Self:
        if self.channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE:
            if self.network_required or not self.offline_capable or not self.simulated:
                raise ValueError(
                    "M8 local fake channel must be offline, simulated, and network-free"
                )
        elif not self.network_required or self.offline_capable or self.simulated:
            raise ValueError(
                "M8 external channel must require network and cannot claim offline simulation"
            )
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def capability_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-channel-capability-authority",
                1,
                self.adapter_id,
                self.adapter_revision,
                self.channel,
                self.request_timeout_ms,
                self.network_required,
                self.offline_capable,
                self.simulated,
                self.inbound_response_supported,
                self.provider_idempotency_key,
                self.adapter_manifest_id,
            ]
        )


class M8NotificationDispatchRequestV1(FrozenContractModel):
    """One bounded send attempt over an exact rendered card artifact."""

    schema_version: Literal["m8-notification-dispatch-request-v1"] = (
        "m8-notification-dispatch-request-v1"
    )
    plan: M8NotificationPlanAuthorityV1
    source_notification_version: int = Field(gt=0, strict=True)
    source_notification_authority_sha256: Sha256Hex
    source_status: Literal[M8NotificationStatus.QUEUED] = M8NotificationStatus.QUEUED
    attempt_number: int = Field(gt=0, strict=True)
    channel_capability: M8NotificationChannelCapabilityAuthorityV1
    rendered_card_ref: ReferenceToken
    rendered_card_sha256: Sha256Hex
    dispatched_at: datetime
    timeout_ms: int = Field(gt=0, le=MAX_M8_NOTIFICATION_CHANNEL_TIMEOUT_MS, strict=True)
    idempotency_key: Sha256Hex
    request_manifest_id: Sha256Hex

    @field_validator("rendered_card_ref")
    @classmethod
    def validate_rendered_card_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 rendered notification card")

    @field_validator("dispatched_at")
    @classmethod
    def validate_dispatched_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification dispatched_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("external_delivery_claim_permitted", "dispatch_request_id"),
        )
        request = handler(payload)
        _verify_computed_claims(request, claims)
        return request

    @model_validator(mode="after")
    def validate_dispatch_scope(self) -> Self:
        if self.channel_capability.channel != self.plan.target.channel:
            raise ValueError("M8 notification dispatch channel does not match its target")
        if self.channel_capability.simulated != self.plan.simulated:
            raise ValueError("M8 notification dispatch simulation claim does not match its plan")
        if self.timeout_ms != self.channel_capability.request_timeout_ms:
            raise ValueError("M8 notification timeout does not match channel capability")
        if self.idempotency_key != self.plan.notification_id:
            raise ValueError("M8 notification idempotency key must equal notification_id")
        if self.attempt_number > self.plan.escalation_policy.max_delivery_attempts:
            raise ValueError("M8 notification dispatch exceeds the policy attempt bound")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_delivery_claim_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dispatch_request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-dispatch-request",
                1,
                self.plan.notification_id,
                self.source_notification_version,
                self.source_notification_authority_sha256,
                self.source_status,
                self.attempt_number,
                self.channel_capability.capability_authority_id,
                self.rendered_card_ref,
                self.rendered_card_sha256,
                _canonical_utc(self.dispatched_at),
                self.timeout_ms,
                self.idempotency_key,
                self.request_manifest_id,
                self.external_delivery_claim_permitted,
            ]
        )


class M8NotificationDispatchResultV1(FrozenContractModel):
    """Typed send acceptance/failure with an exact raw channel response reference."""

    schema_version: Literal["m8-notification-dispatch-result-v1"] = (
        "m8-notification-dispatch-result-v1"
    )
    request: M8NotificationDispatchRequestV1
    disposition: M8NotificationDispatchDisposition
    provider_receipt_id: ReferenceToken | None = None
    raw_response_ref: ReferenceToken
    raw_response_sha256: Sha256Hex
    failure_code: M8NotificationChannelFailureCode | None = None
    completed_at: datetime
    result_manifest_id: Sha256Hex

    @field_validator("provider_receipt_id")
    @classmethod
    def validate_provider_receipt_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 notification provider receipt")

    @field_validator("raw_response_ref")
    @classmethod
    def validate_raw_response_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification raw response")

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification dispatch completed_at")

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
                "accepted",
                "simulated",
                "real_delivery_confirmed",
                "dispatch_result_id",
            ),
        )
        result = handler(payload)
        _verify_computed_claims(result, claims)
        return result

    @model_validator(mode="after")
    def validate_result_shape(self) -> Self:
        if self.completed_at < self.request.dispatched_at:
            raise ValueError("M8 notification dispatch cannot complete before it starts")
        if self.disposition == M8NotificationDispatchDisposition.ACCEPTED:
            if self.provider_receipt_id is None or self.failure_code is not None:
                raise ValueError("M8 accepted dispatch requires receipt and no failure")
        elif self.failure_code is None:
            raise ValueError("M8 unsuccessful dispatch requires a typed failure")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def accepted(self) -> bool:
        return self.disposition == M8NotificationDispatchDisposition.ACCEPTED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return self.request.channel_capability.simulated

    @computed_field  # type: ignore[prop-decorator]
    @property
    def real_delivery_confirmed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dispatch_result_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-dispatch-result",
                1,
                self.request.dispatch_request_id,
                self.disposition,
                self.provider_receipt_id,
                self.raw_response_ref,
                self.raw_response_sha256,
                self.failure_code,
                _canonical_utc(self.completed_at),
                self.result_manifest_id,
                self.accepted,
                self.simulated,
                self.real_delivery_confirmed,
            ]
        )


class M8NotificationDeliveryReceiptV1(FrozenContractModel):
    """Provider delivery/failure event, distinct from dispatch acceptance."""

    schema_version: Literal["m8-notification-delivery-receipt-v1"] = (
        "m8-notification-delivery-receipt-v1"
    )
    notification_id: Sha256Hex
    dispatch_result_id: Sha256Hex
    target_authority_id: Sha256Hex
    channel: M8NotificationChannelKind
    disposition: M8NotificationDeliveryDisposition
    provider_delivery_id: ReferenceToken | None = None
    failure_code: M8NotificationChannelFailureCode | None = None
    occurred_at: datetime
    raw_response_ref: ReferenceToken
    raw_response_sha256: Sha256Hex
    simulated: StrictBool
    receipt_manifest_id: Sha256Hex

    @field_validator("provider_delivery_id")
    @classmethod
    def validate_provider_delivery_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 notification delivery receipt")

    @field_validator("raw_response_ref")
    @classmethod
    def validate_raw_response_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification delivery raw response")

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification delivery occurred_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("real_delivery_confirmed", "case_transition_permitted", "delivery_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_delivery_shape(self) -> Self:
        expected_simulated = self.channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
        if self.simulated != expected_simulated:
            raise ValueError("M8 notification delivery simulation claim conflicts with channel")
        if self.disposition == M8NotificationDeliveryDisposition.DELIVERED:
            if self.provider_delivery_id is None or self.failure_code is not None:
                raise ValueError("M8 delivered receipt requires provider ID and no failure")
        elif self.failure_code is None:
            raise ValueError("M8 failed delivery requires a typed failure")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def real_delivery_confirmed(self) -> bool:
        return (
            self.disposition == M8NotificationDeliveryDisposition.DELIVERED and not self.simulated
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def delivery_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-delivery-receipt",
                1,
                self.notification_id,
                self.dispatch_result_id,
                self.target_authority_id,
                self.channel,
                self.disposition,
                self.provider_delivery_id,
                self.failure_code,
                _canonical_utc(self.occurred_at),
                self.raw_response_ref,
                self.raw_response_sha256,
                self.simulated,
                self.receipt_manifest_id,
                self.real_delivery_confirmed,
                self.case_transition_permitted,
            ]
        )


class M8NotificationReplyAuthorityV1(FrozenContractModel):
    """Privacy-safe inbound reply reference; never a direct Case command."""

    schema_version: Literal["m8-notification-reply-authority-v1"] = (
        "m8-notification-reply-authority-v1"
    )
    notification_id: Sha256Hex
    target_authority_id: Sha256Hex
    actor_id: ReferenceToken
    channel: M8NotificationChannelKind
    reply_kind: M8NotificationReplyKind
    reply_document_sha256: Sha256Hex
    raw_reply_ref: ReferenceToken
    raw_reply_sha256: Sha256Hex
    received_at: datetime
    simulated: StrictBool
    reply_manifest_id: Sha256Hex

    @field_validator("actor_id", "raw_reply_ref")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 notification reply reference")

    @field_validator("received_at")
    @classmethod
    def validate_received_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification reply received_at")

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
                "direct_disciplinary_action_permitted",
                "case_transition_permitted",
                "reply_authority_id",
            ),
        )
        reply = handler(payload)
        _verify_computed_claims(reply, claims)
        return reply

    @model_validator(mode="after")
    def validate_simulation_claim(self) -> Self:
        expected_simulated = self.channel == M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
        if self.simulated != expected_simulated:
            raise ValueError("M8 notification reply simulation claim conflicts with channel")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reply_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-reply-authority",
                1,
                self.notification_id,
                self.target_authority_id,
                self.actor_id,
                self.channel,
                self.reply_kind,
                self.reply_document_sha256,
                self.raw_reply_ref,
                self.raw_reply_sha256,
                _canonical_utc(self.received_at),
                self.simulated,
                self.reply_manifest_id,
                self.direct_disciplinary_action_permitted,
                self.case_transition_permitted,
            ]
        )


class M8NotificationTransitionCommandV1(FrozenContractModel):
    """Fenced notification transition; it can never mutate a Case."""

    schema_version: Literal["m8-notification-transition-command-v1"] = (
        "m8-notification-transition-command-v1"
    )
    notification_id: Sha256Hex
    source_notification_version: int = Field(gt=0, strict=True)
    source_notification_authority_sha256: Sha256Hex
    source_status: M8NotificationStatus
    action: M8NotificationAction
    initiator_kind: M8NotificationInitiatorKind
    actor_authority: M8ActorAuthorityV1 | None = None
    system_authority_id: Sha256Hex | None = None
    dispatch_result: M8NotificationDispatchResultV1 | None = None
    delivery_receipt: M8NotificationDeliveryReceiptV1 | None = None
    reply: M8NotificationReplyAuthorityV1 | None = None
    supporting_authorities: tuple[M8AuthorityReference, ...] = Field(
        min_length=1,
        max_length=MAX_M8_NOTIFICATION_SUPPORTING_AUTHORITIES,
    )
    explicit_human_confirmation: StrictBool
    occurred_at: datetime
    command_manifest_id: Sha256Hex

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "notification transition occurred_at")

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
                "target_status",
                "target_notification_version",
                "direct_disciplinary_action_permitted",
                "case_transition_permitted",
                "command_id",
            ),
        )
        command = handler(payload)
        _verify_computed_claims(command, claims)
        return command

    @model_validator(mode="after")
    def validate_transition_shape(self) -> Self:
        if self.source_status not in _ACTION_SOURCE_STATUSES[self.action]:
            raise ValueError("M8 notification action is not allowed from the source status")
        _require_stable_authorities(self.supporting_authorities)
        self._validate_initiator()
        self._validate_action_artifacts()
        return self

    def _validate_initiator(self) -> None:
        if self.initiator_kind == M8NotificationInitiatorKind.ACTOR:
            if self.actor_authority is None or self.system_authority_id is not None:
                raise ValueError("M8 actor notification action requires only actor authority")
            if not self.actor_authority.active or self.explicit_human_confirmation is not True:
                raise ValueError("M8 actor notification action requires active explicit authority")
            if self.action in {M8NotificationAction.QUEUE, M8NotificationAction.RETRY} and (
                self.actor_authority.role != M8ActorRole.SAFETY_OFFICER
            ):
                raise ValueError("M8 notification queue/retry actor must be SAFETY_OFFICER")
        elif self.initiator_kind == M8NotificationInitiatorKind.SYSTEM:
            if self.system_authority_id is None or self.actor_authority is not None:
                raise ValueError("M8 system notification action requires only system authority")
            if self.action not in {M8NotificationAction.QUEUE, M8NotificationAction.RETRY}:
                raise ValueError("M8 system may only queue or retry a notification")
            if self.explicit_human_confirmation is not False:
                raise ValueError("M8 system notification action cannot claim human confirmation")
        else:
            if self.actor_authority is not None or self.system_authority_id is not None:
                raise ValueError("M8 channel action cannot carry actor or system authority")
            if self.action not in {
                M8NotificationAction.RECORD_SENT,
                M8NotificationAction.RECORD_DELIVERED,
                M8NotificationAction.RECORD_FAILED,
            }:
                raise ValueError("M8 channel adapter cannot execute this notification action")
            if self.explicit_human_confirmation is not False:
                raise ValueError("M8 channel action cannot claim human confirmation")

    def _validate_action_artifacts(self) -> None:
        dispatch = self.dispatch_result
        delivery = self.delivery_receipt
        reply = self.reply
        if self.action == M8NotificationAction.RECORD_SENT:
            if (
                dispatch is None
                or not dispatch.accepted
                or delivery is not None
                or reply is not None
            ):
                raise ValueError("M8 RECORD_SENT requires only an accepted dispatch result")
        elif self.action == M8NotificationAction.RECORD_DELIVERED:
            if (
                delivery is None
                or delivery.disposition != M8NotificationDeliveryDisposition.DELIVERED
                or dispatch is not None
                or reply is not None
            ):
                raise ValueError("M8 RECORD_DELIVERED requires only a delivered receipt")
        elif self.action == M8NotificationAction.RECORD_FAILED:
            queued_failure = (
                self.source_status == M8NotificationStatus.QUEUED
                and dispatch is not None
                and not dispatch.accepted
                and delivery is None
            )
            sent_failure = (
                self.source_status == M8NotificationStatus.SENT
                and delivery is not None
                and delivery.disposition == M8NotificationDeliveryDisposition.FAILED
                and dispatch is None
            )
            if not (queued_failure or sent_failure) or reply is not None:
                raise ValueError("M8 RECORD_FAILED requires an exact channel failure receipt")
        elif self.action == M8NotificationAction.RESPOND:
            if reply is None or dispatch is not None or delivery is not None:
                raise ValueError("M8 RESPOND requires only a reply authority")
        elif any(value is not None for value in (dispatch, delivery, reply)):
            raise ValueError("M8 notification action carries an unexpected channel artifact")

        for artifact_notification_id in (
            dispatch.request.plan.notification_id if dispatch is not None else None,
            delivery.notification_id if delivery is not None else None,
            reply.notification_id if reply is not None else None,
        ):
            if (
                artifact_notification_id is not None
                and artifact_notification_id != self.notification_id
            ):
                raise ValueError("M8 notification action artifact belongs to another notification")
        if dispatch is not None and (
            dispatch.request.source_notification_version != self.source_notification_version
            or dispatch.request.source_notification_authority_sha256
            != self.source_notification_authority_sha256
            or dispatch.request.source_status != self.source_status
        ):
            raise ValueError("M8 notification dispatch does not bind the command source fence")
        if (
            reply is not None
            and self.actor_authority is not None
            and reply.actor_id != self.actor_authority.actor_id
        ):
            raise ValueError("M8 notification reply actor does not match the transition actor")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_status(self) -> M8NotificationStatus:
        return _ACTION_TARGET_STATUS[self.action]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_notification_version(self) -> int:
        return self.source_notification_version + 1

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def command_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-transition-command",
                1,
                self.notification_id,
                self.source_notification_version,
                self.source_notification_authority_sha256,
                self.source_status,
                self.action,
                self.initiator_kind,
                (
                    self.actor_authority.actor_authority_id
                    if self.actor_authority is not None
                    else None
                ),
                self.system_authority_id,
                self.dispatch_result.dispatch_result_id
                if self.dispatch_result is not None
                else None,
                (
                    self.delivery_receipt.delivery_receipt_id
                    if self.delivery_receipt is not None
                    else None
                ),
                self.reply.reply_authority_id if self.reply is not None else None,
                [item.model_dump(mode="json") for item in self.supporting_authorities],
                self.explicit_human_confirmation,
                _canonical_utc(self.occurred_at),
                self.command_manifest_id,
                self.target_status,
                self.target_notification_version,
                self.direct_disciplinary_action_permitted,
                self.case_transition_permitted,
            ]
        )


__all__ = [
    "MAX_M8_NOTIFICATION_CHANNEL_TIMEOUT_MS",
    "MAX_M8_NOTIFICATION_SUPPORTING_AUTHORITIES",
    "M8NotificationAction",
    "M8NotificationChannelCapabilityAuthorityV1",
    "M8NotificationChannelFailureCode",
    "M8NotificationDeliveryDisposition",
    "M8NotificationDeliveryReceiptV1",
    "M8NotificationDispatchDisposition",
    "M8NotificationDispatchRequestV1",
    "M8NotificationDispatchResultV1",
    "M8NotificationInitiatorKind",
    "M8NotificationReplyAuthorityV1",
    "M8NotificationReplyKind",
    "M8NotificationTransitionCommandV1",
]
