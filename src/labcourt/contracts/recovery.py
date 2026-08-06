"""Typed, non-sensitive outcomes for bounded M2 startup recovery."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import (
    PurgeDisposition,
    RecoveryArea,
    RecoveryDisposition,
    RecoveryReasonCode,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import PurgeItemResult

RECOVERY_SOURCE_TOKEN_DOMAIN = b"LCREC1\x00"

_QUARANTINE_REASONS = frozenset(
    {
        RecoveryReasonCode.STAGING_QUARANTINED,
        RecoveryReasonCode.ORPHAN_QUARANTINED,
    }
)
_RETAINED_REASONS = frozenset(
    {
        RecoveryReasonCode.REFERENCED_MEDIA,
        RecoveryReasonCode.MINIMUM_AGE_NOT_MET,
    }
)
_ANOMALY_REASONS = frozenset(
    {
        RecoveryReasonCode.UNKNOWN_ENTRY_SHAPE,
        RecoveryReasonCode.UNSAFE_FILESYSTEM_ENTRY,
        RecoveryReasonCode.CONTENT_IDENTITY_MISMATCH,
        RecoveryReasonCode.ENTRY_CHANGED_DURING_RECOVERY,
        RecoveryReasonCode.DEPTH_LIMIT_REACHED,
    }
)


def recovery_source_token(relative_path: str) -> str:
    """Return an opaque deterministic token without exposing a staging locator."""

    canonical = require_safe_relative_posix_path(relative_path)
    return hashlib.sha256(RECOVERY_SOURCE_TOKEN_DOMAIN + canonical.encode("utf-8")).hexdigest()


class RecoveryItemResult(FrozenContractModel):
    """One stable recovery decision without host paths or artifact bytes."""

    run_id: ReferenceToken
    area: RecoveryArea
    source_token: Sha256Hex
    disposition: RecoveryDisposition
    reason_code: RecoveryReasonCode
    content_sha256: Sha256Hex | None = None
    quarantine_relative_path: str | None = None

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "recovery result run_id")

    @field_validator("quarantine_relative_path")
    @classmethod
    def validate_quarantine_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_safe_relative_posix_path(value)

    @model_validator(mode="after")
    def validate_outcome_matrix(self) -> Self:
        if self.disposition == RecoveryDisposition.QUARANTINED:
            if self.reason_code not in _QUARANTINE_REASONS:
                raise ValueError("quarantined recovery requires a quarantine reason")
            if self.content_sha256 is None or self.quarantine_relative_path is None:
                raise ValueError("quarantined recovery requires content identity and locator")
            if self.area == RecoveryArea.FINAL_MEDIA:
                expected_reason = RecoveryReasonCode.ORPHAN_QUARANTINED
                expected_path = f".quarantine/{self.run_id}/frames/{self.content_sha256}.png"
            else:
                expected_reason = RecoveryReasonCode.STAGING_QUARANTINED
                expected_path = (
                    f".quarantine/{self.run_id}/staging/"
                    f"{self.source_token}-{self.content_sha256}.bin"
                )
            if (
                self.reason_code != expected_reason
                or self.quarantine_relative_path != expected_path
            ):
                raise ValueError("quarantine result conflicts with its controlled location")
            return self

        if self.quarantine_relative_path is not None:
            raise ValueError("only quarantined recovery may carry a quarantine locator")
        if self.disposition == RecoveryDisposition.CLEANED:
            if (
                self.area != RecoveryArea.STAGING
                or self.reason_code != RecoveryReasonCode.EMPTY_STAGING_CLEANED
                or self.content_sha256 is not None
            ):
                raise ValueError("cleaned recovery requires an empty staging-directory outcome")
            return self
        if self.disposition == RecoveryDisposition.RETAINED:
            if self.reason_code not in _RETAINED_REASONS:
                raise ValueError("retained recovery requires a retained reason")
            empty_staging_age_hold = (
                self.area == RecoveryArea.STAGING
                and self.reason_code == RecoveryReasonCode.MINIMUM_AGE_NOT_MET
                and self.content_sha256 is None
            )
            if self.content_sha256 is None and not empty_staging_age_hold:
                raise ValueError(
                    "retained recovery requires content identity unless an empty "
                    "staging directory is too young"
                )
            if (
                self.reason_code == RecoveryReasonCode.REFERENCED_MEDIA
                and self.area != RecoveryArea.FINAL_MEDIA
            ):
                raise ValueError("only final media can be retained by a database reference")
            return self

        if self.reason_code not in _ANOMALY_REASONS:
            raise ValueError("recovery anomaly requires an anomaly reason")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.area.value, self.source_token, self.reason_code.value


class RecoveryReport(FrozenContractModel):
    """Bounded run-scoped startup-recovery report in stable item order."""

    run_id: ReferenceToken
    not_modified_after: datetime
    items: tuple[RecoveryItemResult, ...] = Field(default=())

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "recovery report run_id")

    @field_validator("not_modified_after")
    @classmethod
    def validate_cutoff(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recovery cutoff must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_scope_and_stable_order(self) -> Self:
        if any(item.run_id != self.run_id for item in self.items):
            raise ValueError("recovery report items must belong to its run")
        keys = tuple(item.sort_key for item in self.items)
        source_keys = tuple(key[:2] for key in keys)
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("recovery report items must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("recovery report items must use stable order")
        return self


class StartupRecoveryReport(FrozenContractModel):
    """One run-scoped outcome for ordered retention and orphan recovery."""

    run_id: ReferenceToken
    started_at: datetime
    retention_items: tuple[PurgeItemResult, ...] = Field(default=())
    orphan_report: RecoveryReport

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "startup recovery report run_id")

    @field_validator("started_at")
    @classmethod
    def validate_started_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("startup recovery time must be timezone-aware")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_status(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        attention_present = "requires_attention" in payload
        passed_present = "passed" in payload
        claimed_attention = payload.pop("requires_attention", None)
        claimed_passed = payload.pop("passed", None)
        report = handler(payload)
        if attention_present and (
            type(claimed_attention) is not bool or claimed_attention != report.requires_attention
        ):
            raise ValueError(
                "serialized startup recovery requires_attention conflicts with its results"
            )
        if passed_present and (type(claimed_passed) is not bool or claimed_passed != report.passed):
            raise ValueError("serialized startup recovery passed conflicts with its results")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def requires_attention(self) -> bool:
        return any(
            item.disposition == PurgeDisposition.RECOVERY_REQUIRED for item in self.retention_items
        ) or any(
            item.disposition == RecoveryDisposition.ANOMALY for item in self.orphan_report.items
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.requires_attention

    @model_validator(mode="after")
    def validate_scope_time_and_stable_order(self) -> Self:
        if self.orphan_report.run_id != self.run_id or any(
            item.run_id != self.run_id for item in self.retention_items
        ):
            raise ValueError("startup recovery results must belong to its run")
        if self.orphan_report.not_modified_after >= self.started_at:
            raise ValueError("orphan recovery cutoff must be earlier than startup time")
        identities = tuple(item.media_ref.sort_key for item in self.retention_items)
        if len(identities) != len(set(identities)):
            raise ValueError("startup retention results must be unique by media")
        if identities != tuple(sorted(identities)):
            raise ValueError("startup retention results must use stable media order")
        return self


__all__ = [
    "RECOVERY_SOURCE_TOKEN_DOMAIN",
    "RecoveryItemResult",
    "RecoveryReport",
    "StartupRecoveryReport",
    "recovery_source_token",
]
