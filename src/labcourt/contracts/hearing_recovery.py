"""Secret-free reports for provider-free M4 hearing response recovery."""

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
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.hearing_model import derive_hearing_model_response_id
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS = 10_000


class HearingModelResponseRecoveryDisposition(StrEnum):
    VERIFIED = "VERIFIED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DEFERRED = "DEFERRED"
    ANOMALY = "ANOMALY"


class HearingModelResponseRecoveryReason(StrEnum):
    ACTIVE_LEASE_UNEXPIRED = "ACTIVE_LEASE_UNEXPIRED"
    ACTIVE_EXPIRED_NO_JOURNAL = "ACTIVE_EXPIRED_NO_JOURNAL"
    CLAIM_RACE_LOST = "CLAIM_RACE_LOST"
    CLAIM_SCAN_INCOMPLETE = "CLAIM_SCAN_INCOMPLETE"
    CLAIM_RECOVERY_SUPPRESSED = "CLAIM_RECOVERY_SUPPRESSED"
    JOURNAL_ACKNOWLEDGED = "JOURNAL_ACKNOWLEDGED"
    JOURNAL_ALREADY_ABSENT = "JOURNAL_ALREADY_ABSENT"
    CLAIM_AUTHORITY_INVALID = "CLAIM_AUTHORITY_INVALID"
    JOURNAL_INTEGRITY_FAILURE = "JOURNAL_INTEGRITY_FAILURE"
    RESPONSE_INTEGRITY_FAILURE = "RESPONSE_INTEGRITY_FAILURE"
    RESPONSE_CONFLICT = "RESPONSE_CONFLICT"
    DATABASE_OBSERVATION_CONFLICT = "DATABASE_OBSERVATION_CONFLICT"


_OUTCOMES = {
    HearingModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED: (
        HearingModelResponseRecoveryDisposition.DEFERRED
    ),
    HearingModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL: (
        HearingModelResponseRecoveryDisposition.DEFERRED
    ),
    HearingModelResponseRecoveryReason.CLAIM_RACE_LOST: (
        HearingModelResponseRecoveryDisposition.DEFERRED
    ),
    HearingModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE: (
        HearingModelResponseRecoveryDisposition.DEFERRED
    ),
    HearingModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED: (
        HearingModelResponseRecoveryDisposition.DEFERRED
    ),
    HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED: (
        HearingModelResponseRecoveryDisposition.ACKNOWLEDGED
    ),
    HearingModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT: (
        HearingModelResponseRecoveryDisposition.VERIFIED
    ),
    HearingModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID: (
        HearingModelResponseRecoveryDisposition.ANOMALY
    ),
    HearingModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE: (
        HearingModelResponseRecoveryDisposition.ANOMALY
    ),
    HearingModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE: (
        HearingModelResponseRecoveryDisposition.ANOMALY
    ),
    HearingModelResponseRecoveryReason.RESPONSE_CONFLICT: (
        HearingModelResponseRecoveryDisposition.ANOMALY
    ),
    HearingModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT: (
        HearingModelResponseRecoveryDisposition.ANOMALY
    ),
}
_OPAQUE_REASONS = frozenset(
    {
        HearingModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID,
        HearingModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT,
    }
)
_RESPONSE_REASONS = frozenset(
    {
        HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        HearingModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
    }
)


class HearingModelResponseRecoveryItem(FrozenContractModel):
    """One request-level outcome without owner token, path, or response bytes."""

    schema_version: Literal["m4-hearing-model-response-recovery-item-v1"] = (
        "m4-hearing-model-response-recovery-item-v1"
    )
    run_id: ReferenceToken
    request_id: Sha256Hex | None = None
    source_token: Sha256Hex | None = None
    response_id: Sha256Hex | None = None
    response_content_sha256: Sha256Hex | None = None
    disposition: HearingModelResponseRecoveryDisposition
    reason_code: HearingModelResponseRecoveryReason

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "hearing recovery run reference")

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (
            self.request_id or self.source_token or "",
            self.response_id or "",
            self.reason_code.value,
        )

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (self.request_id is None) == (self.source_token is None):
            raise ValueError("hearing recovery requires one canonical or opaque authority")
        if self.disposition != _OUTCOMES[self.reason_code]:
            raise ValueError("hearing recovery reason conflicts with its disposition")
        if self.source_token is not None:
            if self.reason_code not in _OPAQUE_REASONS:
                raise ValueError("only malformed hearing claims may use an opaque token")
            if self.response_id is not None or self.response_content_sha256 is not None:
                raise ValueError("opaque hearing claim cannot bind a response")
            return self
        if (self.response_id is None) != (self.response_content_sha256 is None):
            raise ValueError("hearing response identity requires both hashes")
        if self.reason_code in _RESPONSE_REASONS:
            if self.response_id is None or self.response_content_sha256 is None:
                raise ValueError("terminal hearing recovery requires a response identity")
            assert self.request_id is not None
            if (
                derive_hearing_model_response_id(
                    self.run_id,
                    self.request_id,
                    self.response_content_sha256,
                )
                != self.response_id
            ):
                raise ValueError("hearing response identity is not request/content bound")
        elif self.response_id is not None:
            raise ValueError("non-terminal hearing recovery cannot claim a response")
        return self


class HearingModelResponseRecoveryReport(FrozenContractModel):
    """Bounded provider-free convergence report for M4 request claims."""

    schema_version: Literal["m4-hearing-model-response-recovery-report-v1"] = (
        "m4-hearing-model-response-recovery-report-v1"
    )
    run_id: ReferenceToken
    started_at: datetime
    claim_limit: int = Field(
        gt=0,
        le=MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS,
        strict=True,
    )
    claims_scanned: int = Field(ge=0, strict=True)
    scan_complete: bool = Field(strict=True)
    items: tuple[HearingModelResponseRecoveryItem, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "hearing recovery report run reference")

    @field_validator("started_at")
    @classmethod
    def validate_started_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
            raise ValueError("hearing recovery time must use timezone-aware UTC")
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
        names = ("report_id", "requires_attention", "passed")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        report = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(report, name):
                raise ValueError(f"serialized hearing recovery {name} conflicts")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-model-response-recovery-report",
                1,
                self.run_id,
                self.started_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                self.claim_limit,
                self.claims_scanned,
                self.scan_complete,
                [item.model_dump(mode="json") for item in self.items],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def requires_attention(self) -> bool:
        return (
            not self.scan_complete
            or any(
                item.disposition == HearingModelResponseRecoveryDisposition.ANOMALY
                for item in self.items
            )
            or any(
                item.reason_code == HearingModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL
                for item in self.items
            )
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.requires_attention

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.claims_scanned > self.claim_limit or len(self.items) != self.claims_scanned:
            raise ValueError("hearing recovery report does not cover its bounded scan")
        if any(item.run_id != self.run_id for item in self.items):
            raise ValueError("hearing recovery item belongs to another run")
        keys = tuple(item.sort_key for item in self.items)
        authorities = tuple(key[0] for key in keys)
        if len(authorities) != len(set(authorities)) or keys != tuple(sorted(keys)):
            raise ValueError("hearing recovery items must be unique and stably ordered")
        if not self.scan_complete:
            if self.claims_scanned != self.claim_limit or any(
                item.disposition != HearingModelResponseRecoveryDisposition.ANOMALY
                and item.reason_code != HearingModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
                for item in self.items
            ):
                raise ValueError("incomplete hearing claim scan cannot authorize mutation")
            return self
        anomalies = tuple(
            item
            for item in self.items
            if item.disposition == HearingModelResponseRecoveryDisposition.ANOMALY
        )
        if anomalies and any(
            item.disposition != HearingModelResponseRecoveryDisposition.ANOMALY
            and item.reason_code != HearingModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED
            for item in self.items
        ):
            raise ValueError("hearing claim anomaly must suppress every other recovery")
        return self


__all__ = [
    "MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS",
    "HearingModelResponseRecoveryDisposition",
    "HearingModelResponseRecoveryItem",
    "HearingModelResponseRecoveryReason",
    "HearingModelResponseRecoveryReport",
]
