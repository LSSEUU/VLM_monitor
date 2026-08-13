"""Typed authorities for live Feishu ingress, cards, routing, and Agent replies."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, StrictBool, computed_field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole, M8OperationalCaseAction
from labcourt.contracts.m8_feishu_platform import M8FeishuPlatformStatusV1
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M8FeishuLiveConnectionState(StrEnum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    READY = "READY"
    RECONNECTING = "RECONNECTING"
    FAILED = "FAILED"


class M8FeishuWorkerState(StrEnum):
    NOT_RUNNING = "NOT_RUNNING"
    READY = "READY"
    BUSY = "BUSY"
    FAILED = "FAILED"


class M8FeishuInboundJobState(StrEnum):
    QUEUED = "QUEUED"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class M8FeishuCardStage(StrEnum):
    AWAITING_ACK = "AWAITING_ACK"
    ACTIONS_AVAILABLE = "ACTIONS_AVAILABLE"
    AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"
    COMPLETED = "COMPLETED"
    STALE = "STALE"
    FAILED = "FAILED"


class M8FeishuLiveFailureCode(StrEnum):
    ACTOR_NOT_BOUND = "ACTOR_NOT_BOUND"
    AUTHORITY_CHANGED = "AUTHORITY_CHANGED"
    CARD_EXPIRED = "CARD_EXPIRED"
    DUPLICATE_ACTION = "DUPLICATE_ACTION"
    INVALID_EVENT = "INVALID_EVENT"
    QWEN_UNAVAILABLE = "QWEN_UNAVAILABLE"
    SEND_REJECTED = "SEND_REJECTED"
    SEND_UNCERTAIN = "SEND_UNCERTAIN"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    WORKER_UNAVAILABLE = "WORKER_UNAVAILABLE"


class M8FeishuInboundEventKind(StrEnum):
    DIRECT_MESSAGE = "DIRECT_MESSAGE"
    CARD_ACTION = "CARD_ACTION"


class M8FeishuTurnOrigin(StrEnum):
    WEB = "WEB"
    FEISHU = "FEISHU"


class M8FeishuDispatchKind(StrEnum):
    TEST_CARD = "TEST_CARD"
    EXISTING_NOTIFICATION = "EXISTING_NOTIFICATION"
    EMERGENCY_ALERT = "EMERGENCY_ALERT"
    ESCALATION_REMINDER = "ESCALATION_REMINDER"
    AGENT_REPLY = "AGENT_REPLY"


class M8FeishuAlertBridgeOutcome(StrEnum):
    QUEUED = "QUEUED"
    FEISHU_NOT_AVAILABLE = "FEISHU_NOT_AVAILABLE"
    ALREADY_PROJECTED = "ALREADY_PROJECTED"


class M8FeishuReminderOutcome(StrEnum):
    QUEUED = "QUEUED"
    CANCELLED_ACKNOWLEDGED = "CANCELLED_ACKNOWLEDGED"
    SUPPRESSED_UNKNOWN_DELIVERY = "SUPPRESSED_UNKNOWN_DELIVERY"


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu {field_name} must be timezone-aware UTC")
    return value


class M8FeishuDutyRouteRevisionRequestV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-duty-route-revision-request-v1"] = (
        "m8-feishu-duty-route-revision-request-v1"
    )
    actor_id: ReferenceToken
    recipient_binding_authority_id: Sha256Hex
    activation_revision: int = Field(gt=0, strict=True)
    activation_status_id: Sha256Hex
    expected_prior_revision: int | None = Field(default=None, gt=0, strict=True)
    explicit_human_confirmation: Literal[True]


class M8FeishuDutyRouteV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-duty-route-v1"] = "m8-feishu-duty-route-v1"
    actor_id: ReferenceToken
    actor_role: Literal[M8ActorRole.SAFETY_OFFICER] = M8ActorRole.SAFETY_OFFICER
    actor_authority_commit_receipt_id: Sha256Hex
    recipient_binding_authority_id: Sha256Hex
    activation_revision: int = Field(gt=0, strict=True)
    activation_status_id: Sha256Hex
    route_revision: int = Field(gt=0, strict=True)
    prior_route_id: Sha256Hex | None = None
    active: StrictBool = True
    committed_at: datetime
    repository_manifest_id: Sha256Hex

    @field_validator("committed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "duty-route committed_at")

    @model_validator(mode="after")
    def validate_revision_chain(self) -> Self:
        if (self.route_revision == 1) != (self.prior_route_id is None):
            raise ValueError("M8 Feishu duty-route prior reference conflicts with revision")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def route_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-duty-route",
                1,
                self.actor_id,
                self.actor_authority_commit_receipt_id,
                self.recipient_binding_authority_id,
                self.activation_revision,
                self.activation_status_id,
                self.route_revision,
                self.prior_route_id,
                self.active,
                self.committed_at.isoformat(),
                self.repository_manifest_id,
            ]
        )


class M8FeishuRuntimeHeartbeatV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-runtime-heartbeat-v1"] = (
        "m8-feishu-runtime-heartbeat-v1"
    )
    component: Literal["LONG_CONNECTION", "AUTHORITY_WORKER", "DELIVERY_WORKER"]
    connection_state: M8FeishuLiveConnectionState | None = None
    worker_state: M8FeishuWorkerState | None = None
    observed_at: datetime
    failure_code: M8FeishuLiveFailureCode | None = None
    detail_ref: ReferenceToken | None = None
    runtime_manifest_id: Sha256Hex

    @field_validator("observed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "runtime observed_at")

    @model_validator(mode="after")
    def validate_component_state(self) -> Self:
        if self.component == "LONG_CONNECTION":
            if self.connection_state is None or self.worker_state is not None:
                raise ValueError("M8 Feishu long connection requires only connection_state")
        elif self.worker_state is None or self.connection_state is not None:
            raise ValueError("M8 Feishu worker heartbeat requires only worker_state")
        failed = self.connection_state == M8FeishuLiveConnectionState.FAILED or (
            self.worker_state == M8FeishuWorkerState.FAILED
        )
        if failed != (self.failure_code is not None):
            raise ValueError("M8 Feishu runtime failure detail conflicts with state")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def heartbeat_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-runtime-heartbeat",
                1,
                self.component,
                self.connection_state,
                self.worker_state,
                self.observed_at.isoformat(),
                self.failure_code,
                self.detail_ref,
                self.runtime_manifest_id,
            ]
        )


class M8FeishuRuntimeStatusV2(FrozenContractModel):
    schema_version: Literal["m8-feishu-runtime-status-v2"] = "m8-feishu-runtime-status-v2"
    platform: M8FeishuPlatformStatusV1
    connection: M8FeishuRuntimeHeartbeatV1 | None = None
    authority_worker: M8FeishuRuntimeHeartbeatV1 | None = None
    delivery_worker: M8FeishuRuntimeHeartbeatV1 | None = None
    duty_route: M8FeishuDutyRouteV1 | None = None
    assessed_at: datetime
    live_dispatch_available: StrictBool
    secret_material_exposed: Literal[False] = False
    clear_external_id_exposed: Literal[False] = False

    @field_validator("assessed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "runtime status assessed_at")

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        expected = (
            self.platform.display_status.value == "ACTIVE"
            and self.connection is not None
            and self.connection.connection_state == M8FeishuLiveConnectionState.READY
            and self.authority_worker is not None
            and self.authority_worker.worker_state == M8FeishuWorkerState.READY
            and self.delivery_worker is not None
            and self.delivery_worker.worker_state == M8FeishuWorkerState.READY
            and self.duty_route is not None
            and self.duty_route.active
        )
        if self.live_dispatch_available != expected:
            raise ValueError("M8 Feishu live availability is not derived from current authorities")
        return self


class M8FeishuInboundEventV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-inbound-event-v1"] = "m8-feishu-inbound-event-v1"
    event_kind: M8FeishuInboundEventKind
    provider_event_id: ReferenceToken
    provider_message_id: ReferenceToken
    sender_open_id_sha256: Sha256Hex
    chat_id_sha256: Sha256Hex
    received_at: datetime
    raw_event_ref: ReferenceToken
    raw_event_sha256: Sha256Hex
    content_ref: ReferenceToken | None = None
    content_sha256: Sha256Hex | None = None
    action_token_sha256: Sha256Hex | None = None
    ingress_manifest_id: Sha256Hex
    clear_sender_identifier_persisted: Literal[False] = False

    @field_validator("provider_event_id", "provider_message_id", "raw_event_ref")
    @classmethod
    def validate_refs(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu inbound event reference")

    @field_validator("received_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "inbound received_at")

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        direct = self.event_kind == M8FeishuInboundEventKind.DIRECT_MESSAGE
        if direct != (self.content_ref is not None and self.content_sha256 is not None):
            raise ValueError("M8 Feishu direct messages require exact content authority")
        if direct == (self.action_token_sha256 is not None):
            raise ValueError("M8 Feishu card actions require only an action token hash")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def inbound_event_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-event",
                1,
                self.event_kind,
                self.provider_event_id,
                self.provider_message_id,
                self.sender_open_id_sha256,
                self.chat_id_sha256,
                self.received_at.isoformat(),
                self.raw_event_ref,
                self.raw_event_sha256,
                self.content_ref,
                self.content_sha256,
                self.action_token_sha256,
                self.ingress_manifest_id,
                self.clear_sender_identifier_persisted,
            ]
        )


class M8FeishuInboundJobV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-inbound-job-v1"] = "m8-feishu-inbound-job-v1"
    inbound_event: M8FeishuInboundEventV1
    state: M8FeishuInboundJobState
    state_revision: int = Field(gt=0, le=3, strict=True)
    actor_id: ReferenceToken | None = None
    conversation_id: Sha256Hex | None = None
    turn_id: Sha256Hex | None = None
    failure_code: M8FeishuLiveFailureCode | None = None
    occurred_at: datetime
    repository_manifest_id: Sha256Hex

    @field_validator("occurred_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "inbound job occurred_at")

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        expected_revision = {
            M8FeishuInboundJobState.QUEUED: 1,
            M8FeishuInboundJobState.CLAIMED: 2,
            M8FeishuInboundJobState.COMPLETED: 3,
            M8FeishuInboundJobState.FAILED: 3,
        }[self.state]
        if self.state_revision != expected_revision:
            raise ValueError("M8 Feishu inbound job revision conflicts with state")
        terminal_failure = self.state == M8FeishuInboundJobState.FAILED
        if terminal_failure != (self.failure_code is not None):
            raise ValueError("M8 Feishu inbound job failure conflicts with state")
        if self.state == M8FeishuInboundJobState.COMPLETED and (
            self.actor_id is None or self.conversation_id is None or self.turn_id is None
        ):
            raise ValueError("M8 Feishu completed inbound job requires Agent authorities")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def job_event_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-inbound-job",
                1,
                self.inbound_event.inbound_event_id,
                self.state,
                self.state_revision,
                self.actor_id,
                self.conversation_id,
                self.turn_id,
                self.failure_code,
                self.occurred_at.isoformat(),
                self.repository_manifest_id,
            ]
        )


class M8FeishuConversationChannelProjectionV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-conversation-channel-projection-v1"] = (
        "m8-feishu-conversation-channel-projection-v1"
    )
    conversation_id: Sha256Hex
    actor_id: ReferenceToken
    channel: Literal["FEISHU_P2P"] = "FEISHU_P2P"
    binding_revision: int = Field(gt=0, strict=True)
    chat_id_sha256: Sha256Hex
    turn_origins: dict[Sha256Hex, M8FeishuTurnOrigin] = Field(default_factory=dict)
    bound_at: datetime

    @field_validator("bound_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "conversation bound_at")


class M8FeishuCardActionIntentV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-card-action-intent-v1"] = (
        "m8-feishu-card-action-intent-v1"
    )
    notification_id: Sha256Hex
    notification_version: int = Field(gt=0, strict=True)
    case_id: Sha256Hex
    case_version: int = Field(gt=0, strict=True)
    case_authority_sha256: Sha256Hex
    actor_id: ReferenceToken
    action: M8OperationalCaseAction
    stage: Literal[M8FeishuCardStage.AWAITING_CONFIRMATION] = (
        M8FeishuCardStage.AWAITING_CONFIRMATION
    )
    confirmation_token_sha256: Sha256Hex
    created_at: datetime
    expires_at: datetime
    intent_manifest_id: Sha256Hex

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "card-action time")

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        if self.expires_at != self.created_at + timedelta(minutes=10):
            raise ValueError("M8 Feishu card confirmation must expire after ten minutes")
        if self.action not in {
            M8OperationalCaseAction.CONFIRM,
            M8OperationalCaseAction.REJECT,
            M8OperationalCaseAction.REQUEST_EVIDENCE,
        }:
            raise ValueError("M8 Feishu card action is outside the closed first-release set")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def intent_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-card-action-intent",
                1,
                self.notification_id,
                self.notification_version,
                self.case_id,
                self.case_version,
                self.case_authority_sha256,
                self.actor_id,
                self.action,
                self.confirmation_token_sha256,
                self.created_at.isoformat(),
                self.expires_at.isoformat(),
                self.intent_manifest_id,
            ]
        )


class M8FeishuCardActionReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-card-action-receipt-v1"] = (
        "m8-feishu-card-action-receipt-v1"
    )
    intent: M8FeishuCardActionIntentV1
    stage: Literal[
        M8FeishuCardStage.COMPLETED,
        M8FeishuCardStage.STALE,
        M8FeishuCardStage.FAILED,
    ]
    resulting_case_version: int | None = Field(default=None, gt=0, strict=True)
    case_commit_receipt_id: Sha256Hex | None = None
    failure_code: M8FeishuLiveFailureCode | None = None
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "card-action completed_at")

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        success = self.stage == M8FeishuCardStage.COMPLETED
        if success != (
            self.resulting_case_version is not None and self.case_commit_receipt_id is not None
        ):
            raise ValueError("M8 Feishu completed card action requires exact case receipt")
        if success == (self.failure_code is not None):
            raise ValueError("M8 Feishu card action failure conflicts with stage")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def action_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-card-action-receipt",
                1,
                self.intent.intent_id,
                self.stage,
                self.resulting_case_version,
                self.case_commit_receipt_id,
                self.failure_code,
                self.completed_at.isoformat(),
            ]
        )


class M8FeishuAlertBridgeReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-alert-bridge-receipt-v1"] = (
        "m8-feishu-alert-bridge-receipt-v1"
    )
    source_case_id: Sha256Hex
    source_case_version: int = Field(gt=0, strict=True)
    source_notification_id: Sha256Hex
    outcome: M8FeishuAlertBridgeOutcome
    queued_notification_id: Sha256Hex | None = None
    duty_route_id: Sha256Hex | None = None
    assessed_at: datetime

    @field_validator("assessed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "alert bridge assessed_at")

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        queued = self.outcome == M8FeishuAlertBridgeOutcome.QUEUED
        if queued != (
            self.queued_notification_id is not None and self.duty_route_id is not None
        ):
            raise ValueError("M8 Feishu queued alert bridge requires dispatch authorities")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def bridge_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-alert-bridge-receipt",
                1,
                self.source_case_id,
                self.source_case_version,
                self.source_notification_id,
                self.outcome,
                self.queued_notification_id,
                self.duty_route_id,
                self.assessed_at.isoformat(),
            ]
        )


class M8FeishuReminderReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-reminder-receipt-v1"] = (
        "m8-feishu-reminder-receipt-v1"
    )
    source_dispatch_request_id: Sha256Hex
    source_notification_id: Sha256Hex
    outcome: M8FeishuReminderOutcome
    reminder_notification_id: Sha256Hex | None = None
    assessed_at: datetime

    @field_validator("assessed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "reminder assessed_at")

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (self.outcome == M8FeishuReminderOutcome.QUEUED) != (
            self.reminder_notification_id is not None
        ):
            raise ValueError("M8 Feishu queued reminder requires notification authority")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reminder_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-reminder-receipt",
                1,
                self.source_dispatch_request_id,
                self.source_notification_id,
                self.outcome,
                self.reminder_notification_id,
                self.assessed_at.isoformat(),
            ]
        )


class M8FeishuAgentReplyEnvelopeV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-agent-reply-envelope-v1"] = (
        "m8-feishu-agent-reply-envelope-v1"
    )
    actor_id: ReferenceToken
    conversation_id: Sha256Hex
    turn_id: Sha256Hex
    recipient_binding_authority_id: Sha256Hex
    reply_to_provider_message_id: ReferenceToken
    content_ref: ReferenceToken
    content_sha256: Sha256Hex
    content_size_bytes: int = Field(gt=0, le=30 * 1024, strict=True)
    queued_at: datetime
    envelope_manifest_id: Sha256Hex

    @field_validator("reply_to_provider_message_id", "content_ref")
    @classmethod
    def validate_refs(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu Agent reply reference")

    @field_validator("queued_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "Agent reply queued_at")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outbox_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-agent-reply-envelope",
                1,
                self.actor_id,
                self.conversation_id,
                self.turn_id,
                self.recipient_binding_authority_id,
                self.reply_to_provider_message_id,
                self.content_ref,
                self.content_sha256,
                self.content_size_bytes,
                self.queued_at.isoformat(),
                self.envelope_manifest_id,
            ]
        )


class M8FeishuAgentReplyCompletionV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-agent-reply-completion-v1"] = (
        "m8-feishu-agent-reply-completion-v1"
    )
    envelope: M8FeishuAgentReplyEnvelopeV1
    disposition: M8NotificationDispatchDisposition
    provider_message_id: ReferenceToken | None = None
    failure_code: M8FeishuLiveFailureCode | None = None
    completed_at: datetime
    raw_response_ref: ReferenceToken
    raw_response_sha256: Sha256Hex
    completion_manifest_id: Sha256Hex

    @field_validator("completed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "Agent reply completed_at")

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        accepted = self.disposition == M8NotificationDispatchDisposition.ACCEPTED
        if accepted != (self.provider_message_id is not None and self.failure_code is None):
            raise ValueError("M8 Feishu Agent reply acceptance requires provider receipt")
        if not accepted and self.failure_code is None:
            raise ValueError("M8 Feishu Agent reply failure requires typed failure")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def completion_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-agent-reply-completion",
                1,
                self.envelope.outbox_id,
                self.disposition,
                self.provider_message_id,
                self.failure_code,
                self.completed_at.isoformat(),
                self.raw_response_ref,
                self.raw_response_sha256,
                self.completion_manifest_id,
            ]
        )


class M8FeishuTestCardDispatchRequestV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-test-card-dispatch-request-v1"] = (
        "m8-feishu-test-card-dispatch-request-v1"
    )
    activation_revision: int = Field(gt=0, strict=True)
    activation_status_id: Sha256Hex
    duty_route_id: Sha256Hex
    duty_route_revision: int = Field(gt=0, strict=True)
    explicit_human_confirmation: Literal[True]


class M8FeishuNotificationDispatchRequestV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-notification-dispatch-request-v1"] = (
        "m8-feishu-notification-dispatch-request-v1"
    )
    notification_version: int = Field(gt=0, strict=True)
    notification_authority_sha256: Sha256Hex
    activation_revision: int = Field(gt=0, strict=True)
    activation_status_id: Sha256Hex
    duty_route_id: Sha256Hex
    duty_route_revision: int = Field(gt=0, strict=True)
    explicit_human_confirmation: Literal[True]


class M8FeishuQueuedDispatchReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-queued-dispatch-receipt-v1"] = (
        "m8-feishu-queued-dispatch-receipt-v1"
    )
    dispatch_kind: M8FeishuDispatchKind
    notification_id: Sha256Hex | None = None
    source_notification_id: Sha256Hex | None = None
    outbox_ref: ReferenceToken
    duty_route_id: Sha256Hex
    queued_at: datetime
    network_call_attempted: Literal[False] = False
    real_delivery_confirmed: Literal[False] = False

    @field_validator("queued_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _utc(value, "dispatch queued_at")


__all__ = [
    "M8FeishuAgentReplyCompletionV1",
    "M8FeishuAgentReplyEnvelopeV1",
    "M8FeishuAlertBridgeOutcome",
    "M8FeishuAlertBridgeReceiptV1",
    "M8FeishuCardActionIntentV1",
    "M8FeishuCardActionReceiptV1",
    "M8FeishuCardStage",
    "M8FeishuConversationChannelProjectionV1",
    "M8FeishuDispatchKind",
    "M8FeishuDutyRouteRevisionRequestV1",
    "M8FeishuDutyRouteV1",
    "M8FeishuInboundEventKind",
    "M8FeishuInboundEventV1",
    "M8FeishuInboundJobState",
    "M8FeishuInboundJobV1",
    "M8FeishuLiveConnectionState",
    "M8FeishuLiveFailureCode",
    "M8FeishuNotificationDispatchRequestV1",
    "M8FeishuQueuedDispatchReceiptV1",
    "M8FeishuReminderOutcome",
    "M8FeishuReminderReceiptV1",
    "M8FeishuRuntimeHeartbeatV1",
    "M8FeishuRuntimeStatusV2",
    "M8FeishuTestCardDispatchRequestV1",
    "M8FeishuTurnOrigin",
    "M8FeishuWorkerState",
]
