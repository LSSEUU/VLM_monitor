"""Typed Feishu card for the offline simulated-smoke demonstration."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Literal, Self

from pydantic import Field, StrictBool, computed_field, field_validator, model_validator
from pydantic.functional_validators import ModelWrapValidatorHandler

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8OperationalRiskLevel
from labcourt.contracts.m8_feishu_personal_demo import M8FeishuPersonalDemoOutcome
from labcourt.contracts.m8_operations import M8SensorType
from labcourt.contracts.m8_sensor_signals import (
    M8SensorPollResultV1,
    M8SensorRiskAssessmentV1,
)


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu emergency demo {name} must be UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class M8FeishuEmergencyDemoProbeV1(FrozenContractModel):
    """One simulated emergency advisory card with no case authority."""

    schema_version: Literal["m8-feishu-emergency-demo-probe-v1"] = (
        "m8-feishu-emergency-demo-probe-v1"
    )
    display_badge: Literal["PERSONAL DEMO · SIMULATED · NOT CERTIFIED FIRE DETECTION"] = (
        "PERSONAL DEMO · SIMULATED · NOT CERTIFIED FIRE DETECTION"
    )
    app_id_sha256: Sha256Hex
    recipient_open_id_sha256: Sha256Hex
    requested_at: datetime
    poll_result: M8SensorPollResultV1
    risk_assessment: M8SensorRiskAssessmentV1
    timeout_ms: int = Field(default=5_000, ge=1_000, le=10_000, strict=True)
    probe_manifest_id: Sha256Hex
    simulated: Literal[True] = True
    certified_fire_detection_claim_permitted: Literal[False] = False
    external_call_permitted: Literal[False] = False
    notification_transition_permitted: Literal[False] = False
    case_transition_permitted: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "requested_at")

    @model_validator(mode="after")
    def validate_scenario_binding(self) -> Self:
        samples = self.poll_result.samples
        assessment = self.risk_assessment
        if not samples or assessment.sample != samples[-1]:
            raise ValueError("M8 Feishu emergency demo must assess the final polled sample")
        if (
            assessment.sample.sensor_type != M8SensorType.SMOKE
            or assessment.sample.value is not True
            or not assessment.sample.simulated
        ):
            raise ValueError("M8 Feishu emergency demo requires active simulated smoke")
        if (
            assessment.risk_level != M8OperationalRiskLevel.EMERGENCY
            or not assessment.create_pending_case_recommended
            or assessment.response_deadline_seconds is None
            or not assessment.human_verification_required
            or assessment.life_safety_action_permitted
            or assessment.certified_fire_detection_claim_permitted
            or assessment.direct_disciplinary_action_permitted
        ):
            raise ValueError("M8 Feishu emergency demo advisory authority is invalid")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_uuid(self) -> str:
        return sha256_hex(
            [
                "m8-feishu-emergency-demo-provider-uuid",
                1,
                self.app_id_sha256,
                self.recipient_open_id_sha256,
                self.risk_assessment.risk_assessment_id,
                _canonical_utc(self.requested_at),
                self.probe_manifest_id,
            ]
        )[:48]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_content_json(self) -> str:
        assessment = self.risk_assessment
        sample = assessment.sample
        return canonical_json(
            {
                "config": {"wide_screen_mode": True},
                "elements": (
                    {
                        "content": (
                            "**演示标识**: SIMULATED / 非认证消防检测\n"
                            "**风险等级**: 紧急 (候选)\n"
                            f"**地点**: {sample.location_id}\n"
                            "**信号**: 离线模拟烟雾传感器已激活\n"
                            "**建议状态**: 建立待核实案件\n"
                            f"**建议响应时限**: {assessment.response_deadline_seconds} 秒\n\n"
                            "本卡片仅用于 PERSONAL DEMO。信号、设备和地点均为模拟数据, "
                            "不构成认证消防检测, 也不会自动建案、定责、处分或结案; "
                            "必须由有权限的安全负责人核实。"
                        ),
                        "tag": "markdown",
                    },
                ),
                "header": {
                    "template": "red",
                    "title": {
                        "content": "PERSONAL DEMO | LabCourt 模拟紧急安全提醒",
                        "tag": "plain_text",
                    },
                },
            }
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_content_sha256(self) -> Sha256Hex:
        return hashlib.sha256(self.provider_content_json.encode("utf-8")).hexdigest()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def probe_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-emergency-demo-probe",
                1,
                self.app_id_sha256,
                self.recipient_open_id_sha256,
                _canonical_utc(self.requested_at),
                self.poll_result.result_id,
                self.risk_assessment.risk_assessment_id,
                self.provider_content_sha256,
                self.timeout_ms,
                self.probe_manifest_id,
                self.simulated,
                self.certified_fire_detection_claim_permitted,
                self.external_call_permitted,
                self.notification_transition_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8FeishuEmergencyDemoProbeReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-emergency-demo-probe-receipt-v1"] = (
        "m8-feishu-emergency-demo-probe-receipt-v1"
    )
    probe: M8FeishuEmergencyDemoProbeV1
    outcome: M8FeishuPersonalDemoOutcome
    completed_at: datetime
    token_call_attempted: StrictBool
    message_call_attempted: StrictBool
    provider_http_status: int | None = Field(default=None, ge=100, le=599, strict=True)
    provider_code: int | None = Field(default=None, strict=True)
    provider_log_id: str | None = None
    provider_message_id: str | None = None
    token_raw_response_ref: str | None = None
    token_raw_response_sha256: Sha256Hex | None = None
    message_raw_response_ref: str | None = None
    message_raw_response_sha256: Sha256Hex | None = None
    real_delivery_confirmed: Literal[False] = False
    notification_transition_permitted: Literal[False] = False
    case_transition_permitted: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "completed_at")

    @model_validator(mode="wrap")
    @classmethod
    def validate_computed_claim(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        claimed: object | None = None
        present = False
        if isinstance(value, dict):
            payload = dict(value)
            present = "probe_receipt_id" in payload
            claimed = payload.pop("probe_receipt_id", None)
            value = payload
        receipt = handler(value)
        if present and claimed != receipt.probe_receipt_id:
            raise ValueError("serialized emergency demo receipt ID conflicts with authority")
        return receipt

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        if self.completed_at < self.probe.requested_at:
            raise ValueError("M8 Feishu emergency demo completion precedes request")
        token_raw = (
            self.token_raw_response_ref is not None and self.token_raw_response_sha256 is not None
        )
        message_raw = (
            self.message_raw_response_ref is not None
            and self.message_raw_response_sha256 is not None
        )
        if (self.token_raw_response_ref is None) != (self.token_raw_response_sha256 is None):
            raise ValueError("M8 Feishu emergency demo token raw reference is incomplete")
        if (self.message_raw_response_ref is None) != (self.message_raw_response_sha256 is None):
            raise ValueError("M8 Feishu emergency demo message raw reference is incomplete")
        if self.outcome == M8FeishuPersonalDemoOutcome.CHECKED:
            if any(
                (
                    self.token_call_attempted,
                    self.message_call_attempted,
                    token_raw,
                    message_raw,
                    self.provider_http_status is not None,
                    self.provider_code is not None,
                    self.provider_log_id is not None,
                    self.provider_message_id is not None,
                )
            ):
                raise ValueError("M8 Feishu emergency demo check cannot claim a call")
            return self
        if not self.token_call_attempted or not token_raw:
            raise ValueError("M8 Feishu emergency demo send requires token evidence")
        token_only = self.outcome in {
            M8FeishuPersonalDemoOutcome.TOKEN_REJECTED,
            M8FeishuPersonalDemoOutcome.TOKEN_RESPONSE_INVALID,
            M8FeishuPersonalDemoOutcome.TOKEN_TRANSPORT_FAILED,
        }
        if token_only:
            if self.message_call_attempted or message_raw:
                raise ValueError("M8 Feishu emergency token outcome cannot claim a message call")
        elif not self.message_call_attempted or not message_raw:
            raise ValueError("M8 Feishu emergency message outcome requires message evidence")
        if self.outcome == M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED and (
            self.provider_http_status != 200
            or self.provider_code != 0
            or not self.provider_message_id
        ):
            raise ValueError("M8 Feishu emergency demo acceptance shape is invalid")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def probe_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-emergency-demo-probe-receipt",
                1,
                self.probe.probe_id,
                self.outcome,
                _canonical_utc(self.completed_at),
                self.token_call_attempted,
                self.message_call_attempted,
                self.provider_http_status,
                self.provider_code,
                self.provider_log_id,
                self.provider_message_id,
                self.token_raw_response_ref,
                self.token_raw_response_sha256,
                self.message_raw_response_ref,
                self.message_raw_response_sha256,
                self.real_delivery_confirmed,
                self.notification_transition_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "M8FeishuEmergencyDemoProbeReceiptV1",
    "M8FeishuEmergencyDemoProbeV1",
]
