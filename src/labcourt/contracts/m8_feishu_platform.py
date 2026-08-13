"""Secret-free platform projection over existing Feishu authorities."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, StrictBool, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
    M8CommissioningEvidenceKind,
    M8CommissioningReadiness,
)
from labcourt.contracts.m8_feishu_personal_demo import M8FeishuPersonalDemoProbeReceiptV1
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.contracts.m8_notifications import M8NotificationChannelKind
from labcourt.contracts.references import ReferenceToken


class M8FeishuPlatformDisplayStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INVALIDATED = "INVALIDATED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    OFFLINE_FAKE = "OFFLINE_FAKE"
    READINESS_BLOCKED = "READINESS_BLOCKED"
    READY_NOT_ACTIVE = "READY_NOT_ACTIVE"
    REVOKED = "REVOKED"


class M8FeishuInboundDisplayStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INVALIDATED = "INVALIDATED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    REVOKED = "REVOKED"


class M8FeishuLastAuditedAttemptV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-last-audited-attempt-v1"] = (
        "m8-feishu-last-audited-attempt-v1"
    )
    notification_id: Sha256Hex
    notification_version: int = Field(gt=0, strict=True)
    dispatch_request_id: Sha256Hex
    dispatch_result_id: Sha256Hex
    disposition: M8NotificationDispatchDisposition
    completed_at: datetime
    raw_response_ref: ReferenceToken
    audit_event_id: Sha256Hex
    real_delivery_confirmed: Literal[False] = False
    automatic_retry_permitted: Literal[False] = False

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("M8 Feishu audited attempt time must be UTC")
        return value


class M8FeishuPlatformStatusV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-platform-status-v1"] = "m8-feishu-platform-status-v1"
    display_status: M8FeishuPlatformDisplayStatus
    default_channel: Literal[M8NotificationChannelKind.LOCAL_OFFLINE_FAKE] = (
        M8NotificationChannelKind.LOCAL_OFFLINE_FAKE
    )
    default_channel_status: Literal[M8FeishuPlatformDisplayStatus.OFFLINE_FAKE] = (
        M8FeishuPlatformDisplayStatus.OFFLINE_FAKE
    )
    candidate_authority_id: Sha256Hex | None = None
    readiness: M8CommissioningReadiness | None = None
    readiness_assessment_id: Sha256Hex | None = None
    missing_evidence_kinds: tuple[M8CommissioningEvidenceKind, ...] = ()
    failed_evidence_kinds: tuple[M8CommissioningEvidenceKind, ...] = ()
    expired_evidence_kinds: tuple[M8CommissioningEvidenceKind, ...] = ()
    activation_revision: int | None = Field(default=None, gt=0, strict=True)
    activation_status_id: Sha256Hex | None = None
    recipient_binding_count: int = Field(default=0, ge=0, le=32, strict=True)
    inbound_status: M8FeishuInboundDisplayStatus = M8FeishuInboundDisplayStatus.NOT_CONFIGURED
    inbound_status_id: Sha256Hex | None = None
    last_audited_attempt: M8FeishuLastAuditedAttemptV1 | None = None
    assessed_at: datetime
    test_card_check_available: StrictBool
    external_call_permitted: StrictBool
    real_delivery_confirmed: Literal[False] = False
    secret_material_exposed: Literal[False] = False
    clear_external_id_exposed: Literal[False] = False
    production_activation_claimed: Literal[False] = False

    @field_validator("assessed_at")
    @classmethod
    def validate_assessed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("M8 Feishu platform assessment time must be UTC")
        return value

    @model_validator(mode="after")
    def validate_closed_state(self) -> Self:
        configured = self.candidate_authority_id is not None
        if configured != (self.readiness is not None and self.readiness_assessment_id is not None):
            raise ValueError("M8 Feishu configured status requires a complete readiness projection")
        active = self.display_status == M8FeishuPlatformDisplayStatus.ACTIVE
        if active != self.external_call_permitted or active != self.test_card_check_available:
            raise ValueError("M8 Feishu external capability must require current ACTIVE authority")
        if active and (
            self.activation_revision is None
            or self.activation_status_id is None
            or self.recipient_binding_count < 1
        ):
            raise ValueError("M8 Feishu ACTIVE status requires current activation and recipients")
        if self.display_status == M8FeishuPlatformDisplayStatus.NOT_CONFIGURED and configured:
            raise ValueError("M8 Feishu NOT_CONFIGURED cannot cite a candidate")
        return self


class M8FeishuTestCardCheckRequestV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-test-card-check-request-v1"] = (
        "m8-feishu-test-card-check-request-v1"
    )
    activation_revision: int = Field(gt=0, strict=True)
    activation_status_id: Sha256Hex
    explicit_human_confirmation: Literal[True]


class M8FeishuTestCardCheckReceiptV1(FrozenContractModel):
    """An activation-fenced CHECK_ONLY receipt; it never sends the card."""

    schema_version: Literal["m8-feishu-test-card-check-receipt-v1"] = (
        "m8-feishu-test-card-check-receipt-v1"
    )
    activation_revision: int = Field(gt=0, strict=True)
    activation_status_id: Sha256Hex
    probe_receipt: M8FeishuPersonalDemoProbeReceiptV1
    external_call_attempted: Literal[False] = False
    notification_transition_permitted: Literal[False] = False
    case_transition_permitted: Literal[False] = False
    automatic_retry_permitted: Literal[False] = False
    real_delivery_confirmed: Literal[False] = False

    @model_validator(mode="after")
    def validate_check_only(self) -> Self:
        receipt = self.probe_receipt
        if (
            receipt.outcome.value != "CHECKED"
            or receipt.token_call_attempted
            or receipt.message_call_attempted
        ):
            raise ValueError("M8 Feishu platform test-card receipt must remain CHECK_ONLY")
        return self


__all__ = [
    "M8FeishuInboundDisplayStatus",
    "M8FeishuLastAuditedAttemptV1",
    "M8FeishuPlatformDisplayStatus",
    "M8FeishuPlatformStatusV1",
    "M8FeishuTestCardCheckReceiptV1",
    "M8FeishuTestCardCheckRequestV1",
]
