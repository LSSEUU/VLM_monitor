"""Additive M8 contracts for the local, synthetic Qwen hearing demonstration."""

from __future__ import annotations

from datetime import datetime
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
from labcourt.contracts.enums import CaseStatus, ScreeningDecision, VlmRole
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_hearing_api import (
    M8HearingL5Status,
    M8HearingModelMode,
    M8HearingProviderSelectionV1,
    M8HearingStartRequestV1,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef


class M8QwenHearingDemoEvidenceRole(StrEnum):
    PRIMARY = "PRIMARY"
    SUPPLEMENTARY = "SUPPLEMENTARY"


class M8QwenHearingDemoAttemptOutcome(StrEnum):
    COMPLETED = "COMPLETED"
    AUDITABLE_FAILURE = "AUDITABLE_FAILURE"
    CONFIGURATION_FAILED = "CONFIGURATION_FAILED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class M8QwenHearingDemoDeliveryState(StrEnum):
    COMPLETED = "COMPLETED"
    DEFINITELY_NOT_SENT = "DEFINITELY_NOT_SENT"
    UNKNOWN = "UNKNOWN"


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
            raise ValueError(f"serialized {name} conflicts with derived Qwen demo content")


class M8QwenHearingDemoEvidenceV1(FrozenContractModel):
    """Secret-free provenance for one generated demo image."""

    schema_version: Literal["m8-qwen-hearing-demo-evidence-v1"] = "m8-qwen-hearing-demo-evidence-v1"
    role: M8QwenHearingDemoEvidenceRole
    artifact_ref: ArtifactRef
    source_file_sha256: Sha256Hex
    canonical_media_sha256: Sha256Hex
    prompt_sha256: Sha256Hex
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)
    size_bytes: int = Field(gt=0, strict=True)
    synthetic: Literal[True] = True
    model_generated: Literal[True] = True
    machine_weak_label: Literal[True] = True
    ground_truth: Literal[False] = False
    real_person_depicted: Literal[False] = False
    authorized_for_external_model: Literal[True] = True
    preauthorized_acquisition_catalog: bool = Field(strict=True)

    @model_validator(mode="after")
    def validate_role_policy(self) -> Self:
        expected_catalog = self.role == M8QwenHearingDemoEvidenceRole.SUPPLEMENTARY
        if self.preauthorized_acquisition_catalog != expected_catalog:
            raise ValueError("only supplementary evidence belongs to the acquisition catalog")
        return self


class M8QwenHearingDemoPreparationV1(FrozenContractModel):
    """Reproducible preparation authority before any external hearing call."""

    schema_version: Literal["m8-qwen-hearing-demo-preparation-v1"] = (
        "m8-qwen-hearing-demo-preparation-v1"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    config_sha256: Sha256Hex
    manifest_id: Sha256Hex
    screening_probability: float = Field(default=0.5, ge=0.5, le=0.5, strict=True)
    screening_decision: Literal[ScreeningDecision.ESCALATE] = ScreeningDecision.ESCALATE
    case_status: Literal[CaseStatus.ESCALATED] = CaseStatus.ESCALATED
    model_mode: Literal[M8HearingModelMode.OPENAI_COMPATIBLE_QWEN] = (
        M8HearingModelMode.OPENAI_COMPATIBLE_QWEN
    )
    provider_selections: tuple[M8HearingProviderSelectionV1, ...] = Field(
        min_length=3,
        max_length=3,
    )
    evidence: tuple[M8QwenHearingDemoEvidenceV1, ...] = Field(min_length=2, max_length=2)
    start_request: M8HearingStartRequestV1
    external_call_permitted: Literal[False] = False
    api_key_persisted: Literal[False] = False
    raw_model_response_content_exposed: Literal[False] = False
    machine_weak_labels_are_ground_truth: Literal[False] = False

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M8 Qwen hearing demo reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("preparation_id",))
        preparation = handler(payload)
        _verify_computed_claims(preparation, claims)
        return preparation

    @model_validator(mode="after")
    def validate_preparation(self) -> Self:
        if tuple(item.role for item in self.evidence) != (
            M8QwenHearingDemoEvidenceRole.PRIMARY,
            M8QwenHearingDemoEvidenceRole.SUPPLEMENTARY,
        ):
            raise ValueError("demo evidence must use primary/supplementary order")
        if self.start_request.run_id != self.run_id or self.start_request.case_id != self.case_id:
            raise ValueError("demo start request differs from its prepared Case")
        if (
            self.start_request.source_status != CaseStatus.ESCALATED
            or self.start_request.model_mode != M8HearingModelMode.OPENAI_COMPATIBLE_QWEN
            or self.start_request.request_manifest_id != self.manifest_id
        ):
            raise ValueError("demo start request is not the exact prepared real-mode authority")
        if tuple(item.role.value for item in self.provider_selections) != (
            "PROSECUTOR",
            "DEFENDER",
            "JUDGE",
        ):
            raise ValueError("demo provider selections must use hearing role order")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def preparation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-qwen-hearing-demo-preparation",
                1,
                self.model_dump(mode="json", exclude={"preparation_id"}),
            ]
        )


class M8QwenHearingProviderReceiptV1(FrozenContractModel):
    """Secret-free linkage from one provider envelope to frozen M4 authority."""

    schema_version: Literal["m8-qwen-hearing-provider-receipt-v1"] = (
        "m8-qwen-hearing-provider-receipt-v1"
    )
    role: VlmRole
    provider_profile: ReferenceToken
    provider_response_id: str = Field(min_length=1, max_length=512)
    labcourt_response_id: Sha256Hex
    raw_response_ref: str = Field(min_length=1, max_length=1_024)
    content_sha256: Sha256Hex
    input_tokens: int = Field(ge=0, strict=True)
    output_tokens: int = Field(ge=0, strict=True)
    latency_ms: int = Field(ge=0, strict=True)
    estimated_cost_cny: float = Field(ge=0, strict=True)

    @field_validator("provider_profile")
    @classmethod
    def validate_profile(cls, value: str) -> str:
        return require_reference_token(value, "M8 Qwen provider profile")

    @field_validator("provider_response_id", "raw_response_ref")
    @classmethod
    def validate_public_provider_text(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("provider receipt text must be trimmed visible text")
        return value

    @model_validator(mode="after")
    def validate_role(self) -> Self:
        if self.role not in {VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE}:
            raise ValueError("provider receipt requires one hearing role")
        return self


class M8QwenHearingDemoAttemptReceiptV1(FrozenContractModel):
    """Auditable outcome of at most one explicit real-provider start attempt."""

    schema_version: Literal["m8-qwen-hearing-demo-attempt-receipt-v1"] = (
        "m8-qwen-hearing-demo-attempt-receipt-v1"
    )
    preparation_id: Sha256Hex
    attempted_at: datetime
    outcome: M8QwenHearingDemoAttemptOutcome
    delivery_state: M8QwenHearingDemoDeliveryState
    api_http_status: int | None = Field(default=None, ge=100, le=599, strict=True)
    reason_code: str | None = Field(default=None, min_length=1, max_length=128)
    view_id: Sha256Hex | None = None
    hearing_session_id: Sha256Hex | None = None
    role_response_ids: tuple[Sha256Hex, ...] = Field(default=(), max_length=30)
    provider_receipts: tuple[M8QwenHearingProviderReceiptV1, ...] = Field(
        default=(),
        max_length=30,
    )
    typed_failure_ids: tuple[Sha256Hex, ...] = Field(default=(), max_length=30)
    l5_status: M8HearingL5Status
    external_call_attempted: bool = Field(strict=True)
    silent_fallback_used: Literal[False] = False
    api_key_persisted: Literal[False] = False
    raw_model_response_content_exposed: Literal[False] = False

    @field_validator("attempted_at")
    @classmethod
    def validate_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("demo attempt time must be timezone-aware")
        return value

    @field_validator("reason_code")
    @classmethod
    def validate_reason_code(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip()
            or any(
                not (character.isupper() or character.isdigit() or character == "_")
                for character in value
            )
        ):
            raise ValueError("demo attempt reason_code must be a stable uppercase token")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("attempt_receipt_id",))
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        ids = self.role_response_ids
        failures = self.typed_failure_ids
        provider_ids = tuple(item.provider_response_id for item in self.provider_receipts)
        linked_response_ids = tuple(item.labcourt_response_id for item in self.provider_receipts)
        if ids != tuple(dict.fromkeys(ids)) or failures != tuple(dict.fromkeys(failures)):
            raise ValueError("demo attempt references must be unique and stable")
        if provider_ids != tuple(dict.fromkeys(provider_ids)):
            raise ValueError("provider response IDs must be unique and stable")
        if self.outcome == M8QwenHearingDemoAttemptOutcome.COMPLETED:
            if (
                self.delivery_state != M8QwenHearingDemoDeliveryState.COMPLETED
                or self.hearing_session_id is None
                or self.view_id is None
                or len(ids) < 3
                or len(self.provider_receipts) < 3
                or linked_response_ids != ids
                or {item.role for item in self.provider_receipts}
                != {VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE}
                or failures
                or self.reason_code is not None
                or not self.external_call_attempted
            ):
                raise ValueError("completed demo attempt lacks its real hearing closure")
        elif self.outcome == M8QwenHearingDemoAttemptOutcome.CONFIGURATION_FAILED:
            if (
                self.delivery_state != M8QwenHearingDemoDeliveryState.DEFINITELY_NOT_SENT
                or self.reason_code is None
                or self.external_call_attempted
                or self.view_id is not None
                or self.hearing_session_id is not None
                or ids
                or self.provider_receipts
                or failures
                or self.l5_status != M8HearingL5Status.NOT_RUN
            ):
                raise ValueError("configuration failure must prove no provider call occurred")
        elif self.outcome == M8QwenHearingDemoAttemptOutcome.AUDITABLE_FAILURE:
            if (
                self.delivery_state
                not in {
                    M8QwenHearingDemoDeliveryState.DEFINITELY_NOT_SENT,
                    M8QwenHearingDemoDeliveryState.COMPLETED,
                }
                or self.reason_code is None
                or self.view_id is None
                or self.hearing_session_id is None
                or (not failures and self.reason_code != "PROVIDER_RECEIPT_INCOMPLETE")
                or self.external_call_attempted
                != (self.delivery_state == M8QwenHearingDemoDeliveryState.COMPLETED)
            ):
                raise ValueError("auditable failure must bind persisted typed failure authority")
        elif (
            self.delivery_state != M8QwenHearingDemoDeliveryState.UNKNOWN
            or self.reason_code is None
            or self.hearing_session_id is None
        ):
            raise ValueError("recovery-required attempt must preserve unknown delivery")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def attempt_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-qwen-hearing-demo-attempt-receipt",
                1,
                self.model_dump(mode="json", exclude={"attempt_receipt_id"}),
            ]
        )


__all__ = [
    "M8QwenHearingDemoAttemptOutcome",
    "M8QwenHearingDemoAttemptReceiptV1",
    "M8QwenHearingDemoDeliveryState",
    "M8QwenHearingDemoEvidenceRole",
    "M8QwenHearingDemoEvidenceV1",
    "M8QwenHearingDemoPreparationV1",
    "M8QwenHearingProviderReceiptV1",
]
