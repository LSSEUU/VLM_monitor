"""Typed, secret-free receipts for an activated Feishu sandbox send."""

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
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_feishu_notification import (
    MAX_M8_FEISHU_RAW_RESPONSE_BYTES,
    M8FeishuCardDispatchPreflightV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelFailureCode,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchResultV1,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M8FeishuSandboxSendOutcome(StrEnum):
    MESSAGE_ACCEPTED = "MESSAGE_ACCEPTED"
    MESSAGE_PERMISSION_DENIED = "MESSAGE_PERMISSION_DENIED"
    MESSAGE_RATE_LIMITED = "MESSAGE_RATE_LIMITED"
    MESSAGE_REJECTED = "MESSAGE_REJECTED"
    MESSAGE_RESPONSE_INVALID = "MESSAGE_RESPONSE_INVALID"
    MESSAGE_TIMEOUT_UNKNOWN = "MESSAGE_TIMEOUT_UNKNOWN"
    MESSAGE_TRANSPORT_UNKNOWN = "MESSAGE_TRANSPORT_UNKNOWN"
    TOKEN_REJECTED = "TOKEN_REJECTED"
    TOKEN_RESPONSE_INVALID = "TOKEN_RESPONSE_INVALID"
    TOKEN_TIMEOUT = "TOKEN_TIMEOUT"
    TOKEN_UNAVAILABLE = "TOKEN_UNAVAILABLE"


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu transport {name} must be timezone-aware UTC")
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
    if not any(present for present, _claimed in claims.values()):
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(
                f"serialized {name} conflicts with derived M8 Feishu transport authority"
            )


class M8FeishuTokenAcquisitionReceiptV1(FrozenContractModel):
    """Redacted successful token acquisition; token material is hash-only."""

    schema_version: Literal["m8-feishu-token-acquisition-receipt-v1"] = (
        "m8-feishu-token-acquisition-receipt-v1"
    )
    profile_id: Sha256Hex
    credential_bundle_reference_id: ReferenceToken
    app_id_sha256: Sha256Hex
    tenant_access_token_sha256: Sha256Hex
    acquired_at: datetime
    expires_at: datetime
    provider_http_status: Literal[200] = 200
    provider_code: Literal[0] = 0
    provider_log_id: ReferenceToken
    redacted_raw_response_ref: ReferenceToken
    redacted_raw_response_sha256: Sha256Hex
    redacted_raw_response_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_FEISHU_RAW_RESPONSE_BYTES,
        strict=True,
    )
    raw_response_redacted: Literal[True] = True
    token_secret_persisted: Literal[False] = False
    token_manifest_id: Sha256Hex

    @field_validator(
        "credential_bundle_reference_id",
        "provider_log_id",
        "redacted_raw_response_ref",
    )
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M8 Feishu token receipt reference")

    @field_validator("acquired_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return _require_utc(value, "token time")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("token_receipt_id",))
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        if self.expires_at <= self.acquired_at:
            raise ValueError("M8 Feishu token expiry must follow acquisition")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def token_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-token-acquisition-receipt",
                1,
                self.profile_id,
                self.credential_bundle_reference_id,
                self.app_id_sha256,
                self.tenant_access_token_sha256,
                _canonical_utc(self.acquired_at),
                _canonical_utc(self.expires_at),
                self.provider_http_status,
                self.provider_code,
                self.provider_log_id,
                self.redacted_raw_response_ref,
                self.redacted_raw_response_sha256,
                self.redacted_raw_response_size_bytes,
                self.raw_response_redacted,
                self.token_secret_persisted,
                self.token_manifest_id,
            ]
        )


class M8FeishuSandboxSendReceiptV1(FrozenContractModel):
    """Activated real sandbox attempt with exact generic dispatch authority."""

    schema_version: Literal["m8-feishu-sandbox-send-receipt-v1"] = (
        "m8-feishu-sandbox-send-receipt-v1"
    )
    preflight: M8FeishuCardDispatchPreflightV1
    activation_status: M8FeishuSandboxActivationStatusV1
    outcome: M8FeishuSandboxSendOutcome
    token_acquisition_receipt: M8FeishuTokenAcquisitionReceiptV1 | None = None
    token_cache_hit: StrictBool
    message_request_attempted: StrictBool
    provider_http_status: int | None = Field(default=None, ge=100, le=599, strict=True)
    provider_code: int | None = Field(default=None, strict=True)
    provider_log_id: ReferenceToken | None = None
    dispatch_result: M8NotificationDispatchResultV1
    raw_response_size_bytes: int = Field(
        gt=0,
        le=MAX_M8_FEISHU_RAW_RESPONSE_BYTES,
        strict=True,
    )
    send_manifest_id: Sha256Hex

    @field_validator("provider_log_id")
    @classmethod
    def validate_provider_log_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 Feishu provider log")

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
                "simulated",
                "provider_acceptance_confirmed",
                "real_delivery_confirmed",
                "notification_transition_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "send_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_send_shape(self) -> Self:
        status = self.activation_status
        activation = status.activation_receipt
        config = activation.runtime_config
        if not status.sandbox_external_call_permitted:
            raise ValueError("M8 Feishu send requires current sandbox activation")
        if (
            self.preflight.profile != config.profile
            or self.preflight.recipient_binding.binding_authority_id
            not in config.recipient_binding_ids
        ):
            raise ValueError("M8 Feishu send preflight is outside the activated allowlist")
        if self.dispatch_result.request != self.preflight.notification_request:
            raise ValueError("M8 Feishu send dispatch result belongs to another request")
        if self.raw_response_size_bytes <= 0:
            raise ValueError("M8 Feishu send requires a bounded raw response")
        token_expected = self.outcome not in {
            M8FeishuSandboxSendOutcome.TOKEN_REJECTED,
            M8FeishuSandboxSendOutcome.TOKEN_RESPONSE_INVALID,
            M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT,
            M8FeishuSandboxSendOutcome.TOKEN_UNAVAILABLE,
        }
        if (self.token_acquisition_receipt is not None) != token_expected:
            raise ValueError("M8 Feishu send token receipt conflicts with outcome")
        if self.token_cache_hit and self.token_acquisition_receipt is None:
            raise ValueError("M8 Feishu token cache hit requires an acquisition receipt")
        if self.token_acquisition_receipt is not None:
            token = self.token_acquisition_receipt
            if (
                token.profile_id != config.profile.profile_id
                or token.credential_bundle_reference_id
                != config.profile.credential_bundle_reference_id
                or token.app_id_sha256 != config.profile.app_id_sha256
            ):
                raise ValueError("M8 Feishu send token belongs to another profile")

        expected = {
            M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED: (
                True,
                M8NotificationDispatchDisposition.ACCEPTED,
                None,
            ),
            M8FeishuSandboxSendOutcome.MESSAGE_PERMISSION_DENIED: (
                True,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8NotificationChannelFailureCode.CHANNEL_REJECTED,
            ),
            M8FeishuSandboxSendOutcome.MESSAGE_RATE_LIMITED: (
                True,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8NotificationChannelFailureCode.CHANNEL_REJECTED,
            ),
            M8FeishuSandboxSendOutcome.MESSAGE_REJECTED: (
                True,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8NotificationChannelFailureCode.CHANNEL_REJECTED,
            ),
            M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID: (
                True,
                M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
                M8NotificationChannelFailureCode.RECEIPT_INVALID,
            ),
            M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN: (
                True,
                M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
                M8NotificationChannelFailureCode.UNKNOWN_DELIVERY,
            ),
            M8FeishuSandboxSendOutcome.MESSAGE_TRANSPORT_UNKNOWN: (
                True,
                M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
                M8NotificationChannelFailureCode.UNKNOWN_DELIVERY,
            ),
            M8FeishuSandboxSendOutcome.TOKEN_REJECTED: (
                False,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8NotificationChannelFailureCode.CHANNEL_REJECTED,
            ),
            M8FeishuSandboxSendOutcome.TOKEN_RESPONSE_INVALID: (
                False,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8NotificationChannelFailureCode.RECEIPT_INVALID,
            ),
            M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT: (
                False,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8NotificationChannelFailureCode.CHANNEL_TIMEOUT,
            ),
            M8FeishuSandboxSendOutcome.TOKEN_UNAVAILABLE: (
                False,
                M8NotificationDispatchDisposition.DEFINITELY_NOT_SENT,
                M8NotificationChannelFailureCode.CHANNEL_UNAVAILABLE,
            ),
        }[self.outcome]
        attempted, disposition, failure = expected
        if (
            self.message_request_attempted != attempted
            or self.dispatch_result.disposition != disposition
            or self.dispatch_result.failure_code != failure
        ):
            raise ValueError("M8 Feishu send receipt conflicts with outcome shape")
        if self.outcome == M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED and (
            self.provider_http_status != 200
            or self.provider_code != 0
            or self.provider_log_id is None
        ):
            raise ValueError("M8 Feishu send receipt conflicts with outcome shape")
        if self.outcome in {
            M8FeishuSandboxSendOutcome.MESSAGE_PERMISSION_DENIED,
            M8FeishuSandboxSendOutcome.MESSAGE_RATE_LIMITED,
        }:
            expected_code = (
                230035
                if self.outcome == M8FeishuSandboxSendOutcome.MESSAGE_PERMISSION_DENIED
                else 230020
            )
            if (
                self.provider_http_status != 400
                or self.provider_code != expected_code
                or self.provider_log_id is None
            ):
                raise ValueError("M8 Feishu send receipt conflicts with outcome shape")
        if self.outcome in {
            M8FeishuSandboxSendOutcome.MESSAGE_REJECTED,
            M8FeishuSandboxSendOutcome.TOKEN_REJECTED,
        } and (
            self.provider_http_status is None
            or self.provider_code is None
            or self.provider_code == 0
        ):
            raise ValueError("M8 Feishu send receipt conflicts with outcome shape")
        if (
            self.outcome
            in {
                M8FeishuSandboxSendOutcome.MESSAGE_RESPONSE_INVALID,
                M8FeishuSandboxSendOutcome.TOKEN_RESPONSE_INVALID,
            }
            and self.provider_http_status is None
        ):
            raise ValueError("M8 Feishu send receipt conflicts with outcome shape")
        if self.outcome in {
            M8FeishuSandboxSendOutcome.MESSAGE_TIMEOUT_UNKNOWN,
            M8FeishuSandboxSendOutcome.MESSAGE_TRANSPORT_UNKNOWN,
            M8FeishuSandboxSendOutcome.TOKEN_TIMEOUT,
            M8FeishuSandboxSendOutcome.TOKEN_UNAVAILABLE,
        } and any(
            item is not None
            for item in (self.provider_http_status, self.provider_code, self.provider_log_id)
        ):
            raise ValueError("M8 Feishu send receipt conflicts with outcome shape")
        token_hash = (
            self.token_acquisition_receipt.tenant_access_token_sha256
            if self.token_acquisition_receipt is not None
            else None
        )
        if self.dispatch_result.raw_response_sha256 == token_hash:
            raise ValueError("M8 Feishu send cannot persist token material as raw response")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_acceptance_confirmed(self) -> bool:
        return self.outcome == M8FeishuSandboxSendOutcome.MESSAGE_ACCEPTED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def real_delivery_confirmed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_transition_permitted(self) -> bool:
        return True

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
    def send_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-sandbox-send-receipt",
                1,
                self.preflight.preflight_id,
                self.activation_status.status_id,
                self.outcome,
                (
                    self.token_acquisition_receipt.token_receipt_id
                    if self.token_acquisition_receipt is not None
                    else None
                ),
                self.token_cache_hit,
                self.message_request_attempted,
                self.provider_http_status,
                self.provider_code,
                self.provider_log_id,
                self.dispatch_result.dispatch_result_id,
                self.raw_response_size_bytes,
                self.send_manifest_id,
                self.simulated,
                self.provider_acceptance_confirmed,
                self.real_delivery_confirmed,
                self.notification_transition_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "M8FeishuSandboxSendOutcome",
    "M8FeishuSandboxSendReceiptV1",
    "M8FeishuTokenAcquisitionReceiptV1",
]
