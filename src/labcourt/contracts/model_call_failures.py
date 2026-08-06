"""Durable authority for provider outcomes that are safe to retry.

An expired claim without one of these authorities has an unknown delivery
outcome and must be handled by provider-free recovery.  The authority is
written only with the aggregate backlog transition that closes the failed
business attempt.
"""

from __future__ import annotations

from datetime import datetime, timedelta
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
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import BacklogReasonCode, BacklogStatus
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.screening import VLMCallRequest


class VLMProviderFailureCode(StrEnum):
    FIXTURE_MISSING = "FIXTURE_MISSING"
    PROVIDER_OUTAGE = "PROVIDER_OUTAGE"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
    EXPIRED_CLAIM_REQUIRES_RECOVERY = "EXPIRED_CLAIM_REQUIRES_RECOVERY"
    REQUEST_IDENTITY_MISMATCH = "REQUEST_IDENTITY_MISMATCH"
    PROMPT_MISSING = "PROMPT_MISSING"
    PROMPT_INTEGRITY_FAILURE = "PROMPT_INTEGRITY_FAILURE"
    MEDIA_POLICY_REJECTED = "MEDIA_POLICY_REJECTED"
    MEDIA_INTEGRITY_FAILURE = "MEDIA_INTEGRITY_FAILURE"
    RESPONSE_ENVELOPE_INVALID = "RESPONSE_ENVELOPE_INVALID"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    RESPONSE_TOKEN_BUDGET_EXCEEDED = "RESPONSE_TOKEN_BUDGET_EXCEEDED"
    RESPONSE_COST_BUDGET_EXCEEDED = "RESPONSE_COST_BUDGET_EXCEEDED"
    RESPONSE_PERSISTENCE_FAILURE = "RESPONSE_PERSISTENCE_FAILURE"


class VLMDeliveryCertainty(StrEnum):
    """Whether an adapter can prove what happened at the provider boundary."""

    UNKNOWN = "UNKNOWN"
    DEFINITELY_NOT_SENT = "DEFINITELY_NOT_SENT"
    COMPLETED = "COMPLETED"


class ModelCallFailureClosureKind(StrEnum):
    INITIAL_BACKLOG = "INITIAL_BACKLOG"
    RETRY_FAILURE = "RETRY_FAILURE"


class ModelCallFailureAuthority(FrozenContractModel):
    """Append-only proof that one known provider outcome closed atomically."""

    authority_version: Literal[1] = 1
    run_id: ReferenceToken
    request: VLMCallRequest
    claim_owner_sha256: Sha256Hex
    claim_lease_expires_at: datetime
    claim_takeover_count: int = Field(ge=0, strict=True)
    failure_code: VLMProviderFailureCode
    delivery_certainty: Literal[
        VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        VLMDeliveryCertainty.COMPLETED,
    ]
    backlog_reason_code: BacklogReasonCode
    backlog_item_id: Sha256Hex
    backlog_version: int = Field(gt=0, strict=True)
    backlog_status: Literal[BacklogStatus.PENDING, BacklogStatus.EXHAUSTED]
    backlog_attempt_count: int = Field(ge=0, strict=True)
    retry_generation: int = Field(ge=0, strict=True)
    closure_kind: ModelCallFailureClosureKind
    completion_receipt_id: Sha256Hex | None = None
    closure_case_revision: int = Field(gt=0, strict=True)
    closure_audit_sequence: int = Field(ge=0, strict=True)
    closure_audit_entry_hash: Sha256Hex
    manifest_id: Sha256Hex
    recorded_at: datetime

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "model call failure run reference")

    @field_validator("claim_lease_expires_at", "recorded_at")
    @classmethod
    def validate_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("model call failure timestamps must be timezone-aware UTC")
        if value.utcoffset() != timedelta(0):
            raise ValueError("model call failure timestamps must use UTC")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        computed_names = ("request_document_sha256", "authority_id")
        claims = {name: payload.pop(name, None) for name in computed_names}
        present = {name: name in value for name in computed_names}
        authority = handler(payload)
        for name in computed_names:
            if present[name] and (
                not isinstance(claims[name], str) or claims[name] != getattr(authority, name)
            ):
                raise ValueError(f"serialized model call failure {name} conflicts with its content")
        return authority

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_document_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "model-call-failure-request-document",
                1,
                self.request.model_dump(mode="json"),
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "model-call-failure-authority",
                1,
                self.run_id,
                self.request_document_sha256,
                self.claim_owner_sha256,
                self.claim_lease_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                self.claim_takeover_count,
                self.failure_code.value,
                self.delivery_certainty.value,
                self.backlog_reason_code.value,
                self.backlog_item_id,
                self.backlog_version,
                self.backlog_status.value,
                self.backlog_attempt_count,
                self.retry_generation,
                self.closure_kind.value,
                self.completion_receipt_id,
                self.closure_case_revision,
                self.closure_audit_sequence,
                self.closure_audit_entry_hash,
                self.manifest_id,
                self.recorded_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ]
        )

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.request.run_id != self.run_id or self.request.manifest_id != self.manifest_id:
            raise ValueError("model call failure request is outside the authority scope")
        definitely_not_sent = {
            VLMProviderFailureCode.FIXTURE_MISSING,
            VLMProviderFailureCode.PROVIDER_OUTAGE,
            VLMProviderFailureCode.PROVIDER_TIMEOUT,
            VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH,
            VLMProviderFailureCode.PROMPT_MISSING,
            VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE,
            VLMProviderFailureCode.MEDIA_POLICY_REJECTED,
            VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE,
        }
        completed = {
            VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID,
            VLMProviderFailureCode.RESPONSE_TOO_LARGE,
            VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
            VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
            VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE,
        }
        if (
            self.failure_code in definitely_not_sent
            and self.delivery_certainty != VLMDeliveryCertainty.DEFINITELY_NOT_SENT
        ) or (
            self.failure_code in completed
            and self.delivery_certainty != VLMDeliveryCertainty.COMPLETED
        ):
            raise ValueError("model call failure code conflicts with delivery certainty")
        if self.failure_code not in definitely_not_sent | completed:
            raise ValueError("unknown-delivery failures cannot grant retry authority")
        expected_reason = (
            BacklogReasonCode.PROVIDER_UNAVAILABLE
            if self.failure_code
            in {
                VLMProviderFailureCode.FIXTURE_MISSING,
                VLMProviderFailureCode.PROVIDER_OUTAGE,
                VLMProviderFailureCode.PROVIDER_TIMEOUT,
            }
            else BacklogReasonCode.BUDGET_EXCEEDED
            if self.failure_code
            in {
                VLMProviderFailureCode.RESPONSE_TOO_LARGE,
                VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
                VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
            }
            else BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
        )
        if self.backlog_reason_code != expected_reason:
            raise ValueError("model call failure code conflicts with backlog reason")
        context = self.request.backlog_retry_context
        if self.closure_kind == ModelCallFailureClosureKind.INITIAL_BACKLOG:
            if (
                context is not None
                or self.backlog_version != 1
                or self.backlog_attempt_count != 0
                or self.completion_receipt_id is not None
            ):
                raise ValueError("initial model call failure closure has retry-only fields")
        elif (
            context is None
            or context.backlog_item_id != self.backlog_item_id
            or context.retry_generation != self.retry_generation
            or self.backlog_attempt_count <= 0
            or self.completion_receipt_id is None
        ):
            raise ValueError("retry model call failure closure lacks its exact retry authority")
        return self


__all__ = [
    "ModelCallFailureAuthority",
    "ModelCallFailureClosureKind",
    "VLMDeliveryCertainty",
    "VLMProviderFailureCode",
]
