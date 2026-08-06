"""Adjudicated alert and emergency incident contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import AlertLevel, SafetySignalType


class AlertDecision(FrozenContractModel):
    alert_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    level: AlertLevel
    recipients: tuple[str, ...]
    policy_rule_ids: tuple[str, ...]
    suppressed_by_cooldown: StrictBool = False
    merged_into_alert_id: str | None = None
    human_review_required: StrictBool = False
    rescinded: StrictBool = False


class EmergencySafetyIncident(FrozenContractModel):
    incident_id: str = Field(min_length=1)
    signal_id: str = Field(min_length=1)
    signal_type: SafetySignalType
    zone_id: str = Field(min_length=1)
    level: Literal[AlertLevel.EMERGENCY] = AlertLevel.EMERGENCY
    certification_id: str | None = None
    delivery_idempotency_key: str = Field(min_length=1)
    adjudicated: Literal[False] = False

    @model_validator(mode="after")
    def validate_emergency_incident(self) -> EmergencySafetyIncident:
        if self.level != AlertLevel.EMERGENCY:
            raise ValueError("safety incidents must use EMERGENCY level")
        if self.adjudicated:
            raise ValueError("an immediate safety incident is not an adjudicated alert")
        return self


class DeliveryReceipt(FrozenContractModel):
    alert_id: str = Field(min_length=1)
    channel: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    accepted: StrictBool
    provider_receipt_ref: str | None = None
