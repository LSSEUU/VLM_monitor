"""Typed one-card Feishu connectivity probe for a personal demonstration."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, StrictBool, computed_field, field_validator, model_validator
from pydantic.functional_validators import ModelWrapValidatorHandler

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu personal demo {name} must be UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class M8FeishuPersonalDemoOutcome(StrEnum):
    CHECKED = "CHECKED"
    MESSAGE_ACCEPTED = "MESSAGE_ACCEPTED"
    MESSAGE_REJECTED = "MESSAGE_REJECTED"
    MESSAGE_RESPONSE_INVALID = "MESSAGE_RESPONSE_INVALID"
    MESSAGE_TRANSPORT_FAILED = "MESSAGE_TRANSPORT_FAILED"
    TOKEN_REJECTED = "TOKEN_REJECTED"
    TOKEN_RESPONSE_INVALID = "TOKEN_RESPONSE_INVALID"
    TOKEN_TRANSPORT_FAILED = "TOKEN_TRANSPORT_FAILED"


class M8FeishuPersonalDemoProbeV1(FrozenContractModel):
    """Static, visibly simulated card request with no domain authority."""

    schema_version: Literal["m8-feishu-personal-demo-probe-v1"] = (
        "m8-feishu-personal-demo-probe-v1"
    )
    display_badge: Literal["PERSONAL DEMO · SIMULATED SAFETY EVENT"] = (
        "PERSONAL DEMO · SIMULATED SAFETY EVENT"
    )
    app_id_sha256: Sha256Hex
    recipient_open_id_sha256: Sha256Hex
    requested_at: datetime
    timeout_ms: int = Field(default=5_000, ge=1_000, le=10_000, strict=True)
    probe_manifest_id: Sha256Hex
    simulated: Literal[True] = True
    external_call_permitted: Literal[False] = False
    notification_transition_permitted: Literal[False] = False
    case_transition_permitted: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "requested_at")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_uuid(self) -> str:
        return sha256_hex(
            [
                "m8-feishu-personal-demo-provider-uuid",
                1,
                self.app_id_sha256,
                self.recipient_open_id_sha256,
                _canonical_utc(self.requested_at),
                self.probe_manifest_id,
            ]
        )[:48]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_content_json(self) -> str:
        return canonical_json(
            {
                "config": {"wide_screen_mode": True},
                "elements": (
                    {
                        "content": (
                            "**风险等级**: 一般\n"
                            "**地点**: 化学实验室 301 (演示)\n"
                            "**事件**: 模拟检测到未佩戴护目镜\n"
                            "**状态**: 待安全负责人核实\n\n"
                            "此卡片仅验证 LabCourt 与飞书企业自建应用的连通性。"
                            "事件、人员和地点均为模拟数据; AI 不作为定责或处分依据。"
                        ),
                        "tag": "markdown",
                    },
                ),
                "header": {
                    "template": "orange",
                    "title": {
                        "content": "PERSONAL DEMO | LabCourt 实验室安全提醒",
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
                "m8-feishu-personal-demo-probe",
                1,
                self.app_id_sha256,
                self.recipient_open_id_sha256,
                _canonical_utc(self.requested_at),
                self.timeout_ms,
                self.probe_manifest_id,
                self.simulated,
                self.external_call_permitted,
                self.notification_transition_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8FeishuPersonalDemoProbeReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-feishu-personal-demo-probe-receipt-v1"] = (
        "m8-feishu-personal-demo-probe-receipt-v1"
    )
    probe: M8FeishuPersonalDemoProbeV1
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
            raise ValueError("serialized probe receipt ID conflicts with derived authority")
        return receipt

    @model_validator(mode="after")
    def validate_outcome_shape(self) -> Self:
        if self.completed_at < self.probe.requested_at:
            raise ValueError("M8 Feishu personal demo completion precedes request")
        token_raw = (
            self.token_raw_response_ref is not None
            and self.token_raw_response_sha256 is not None
        )
        message_raw = (
            self.message_raw_response_ref is not None
            and self.message_raw_response_sha256 is not None
        )
        if (self.token_raw_response_ref is None) != (self.token_raw_response_sha256 is None):
            raise ValueError("M8 Feishu personal demo token raw reference is incomplete")
        if (self.message_raw_response_ref is None) != (
            self.message_raw_response_sha256 is None
        ):
            raise ValueError("M8 Feishu personal demo message raw reference is incomplete")
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
                raise ValueError("M8 Feishu personal demo check cannot claim a provider call")
            return self
        if not self.token_call_attempted or not token_raw:
            raise ValueError("M8 Feishu personal demo send requires token-call evidence")
        token_only = self.outcome in {
            M8FeishuPersonalDemoOutcome.TOKEN_REJECTED,
            M8FeishuPersonalDemoOutcome.TOKEN_RESPONSE_INVALID,
            M8FeishuPersonalDemoOutcome.TOKEN_TRANSPORT_FAILED,
        }
        if token_only:
            if self.message_call_attempted or message_raw:
                raise ValueError("M8 Feishu token outcome cannot claim a message call")
        elif not self.message_call_attempted or not message_raw:
            raise ValueError("M8 Feishu message outcome requires message-call evidence")
        if self.outcome == M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED and (
            self.provider_http_status != 200
            or self.provider_code != 0
            or not self.provider_message_id
        ):
            raise ValueError("M8 Feishu personal demo acceptance shape is invalid")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def probe_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-personal-demo-probe-receipt",
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
    "M8FeishuPersonalDemoOutcome",
    "M8FeishuPersonalDemoProbeReceiptV1",
    "M8FeishuPersonalDemoProbeV1",
]
