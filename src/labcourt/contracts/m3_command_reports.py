"""Stable command envelopes for bounded M3 authority operations."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.backlog import BacklogRetryReport
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.m3_operations import M3ProcessReport
from labcourt.contracts.references import ReferenceToken, require_reference_token

_MAX_BUDGET_VALUE = 64 * 1024 * 1024 * 1024
_PROJECTION_DOCUMENT_OVERHEAD_BYTES = 4_096
_PROJECTION_MATERIALIZATION_MULTIPLIER = 8


class M3ProjectionDisposition(StrEnum):
    """Whether the rebuild completed after the authoritative operation."""

    REBUILT = "REBUILT"
    PENDING_REBUILD = "PENDING_REBUILD"


class M3ProjectionReasonCode(StrEnum):
    """Path-free, secret-free reasons why a rebuild remains pending."""

    DATABASE_BYTES_BUDGET_EXCEEDED = "DATABASE_BYTES_BUDGET_EXCEEDED"
    AUDIT_ENTRY_BUDGET_EXCEEDED = "AUDIT_ENTRY_BUDGET_EXCEEDED"
    CASE_BUDGET_EXCEEDED = "CASE_BUDGET_EXCEEDED"
    PACK_BUDGET_EXCEEDED = "PACK_BUDGET_EXCEEDED"
    DOCUMENT_BYTES_BUDGET_EXCEEDED = "DOCUMENT_BYTES_BUDGET_EXCEEDED"
    PROJECTION_FILE_BUDGET_EXCEEDED = "PROJECTION_FILE_BUDGET_EXCEEDED"
    MATERIALIZATION_BUDGET_EXCEEDED = "MATERIALIZATION_BUDGET_EXCEEDED"
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    SNAPSHOT_UNAVAILABLE = "SNAPSHOT_UNAVAILABLE"
    PROJECTION_REBUILD_FAILED = "PROJECTION_REBUILD_FAILED"


class M3ProjectionBudget(FrozenContractModel):
    """Hard limits applied before the full JSON projector is invoked."""

    max_database_bytes: int = Field(gt=0, le=_MAX_BUDGET_VALUE, strict=True)
    max_audit_entries: int = Field(gt=0, le=1_000_000, strict=True)
    max_cases: int = Field(gt=0, le=1_000_000, strict=True)
    max_packs: int = Field(gt=0, le=5_000_000, strict=True)
    max_document_bytes: int = Field(gt=0, le=1024 * 1024 * 1024, strict=True)
    max_projection_file_bytes: int = Field(
        gt=0,
        le=_MAX_BUDGET_VALUE,
        strict=True,
    )
    max_materialization_bytes: int = Field(
        gt=0,
        le=_MAX_BUDGET_VALUE,
        strict=True,
    )


class M3ProjectionCounts(FrozenContractModel):
    """Constant-memory preflight observations from one private DB snapshot."""

    snapshot_database_bytes: int = Field(ge=0, strict=True)
    audit_entries: int = Field(ge=0, strict=True)
    cases: int = Field(ge=0, strict=True)
    packs: int = Field(ge=0, strict=True)
    max_document_bytes: int = Field(ge=0, strict=True)

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
        names = (
            "projected_document_count",
            "largest_jsonl_upper_bound_bytes",
            "materialization_upper_bound_bytes",
        )
        present = {name: name in payload for name in names}
        claims = {name: payload.pop(name, None) for name in names}
        counts = handler(payload)
        for name in names:
            if present[name] and (
                not isinstance(claims[name], int)
                or isinstance(claims[name], bool)
                or claims[name] != getattr(counts, name)
            ):
                raise ValueError(f"serialized projection count {name} conflicts with content")
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def projected_document_count(self) -> int:
        # events.jsonl contains one event per Case, then each Case and pack is
        # independently rendered and audit.jsonl contains every audit entry.
        return self.audit_entries + (2 * self.cases) + self.packs

    @computed_field  # type: ignore[prop-decorator]
    @property
    def largest_jsonl_upper_bound_bytes(self) -> int:
        return max(self.audit_entries, self.cases) * (self.max_document_bytes + 1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def materialization_upper_bound_bytes(self) -> int:
        per_document = self.max_document_bytes + _PROJECTION_DOCUMENT_OVERHEAD_BYTES
        return self.projected_document_count * per_document * _PROJECTION_MATERIALIZATION_MULTIPLIER


class M3ProjectionOutcome(FrozenContractModel):
    """Typed outcome that never erases a preceding authority result."""

    disposition: M3ProjectionDisposition
    reason_code: M3ProjectionReasonCode | None
    budget: M3ProjectionBudget
    counts: M3ProjectionCounts | None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.disposition == M3ProjectionDisposition.REBUILT:
            if self.reason_code is not None or self.counts is None:
                raise ValueError("REBUILT projection requires counts and no failure reason")
            return self
        if self.reason_code is None:
            raise ValueError("PENDING_REBUILD projection requires a controlled reason")
        return self


class M3ProcessCommandReport(FrozenContractModel):
    """CLI-safe envelope preserving the exact process authority report."""

    schema_version: Literal["m3-process-command-report-v1"] = "m3-process-command-report-v1"
    operation: Literal["PROCESS"] = "PROCESS"
    run_id: ReferenceToken
    authority_complete: Literal[True] = True
    perception_mode: Literal["SIMULATED PERCEPTION"] = "SIMULATED PERCEPTION"
    model_mode: Literal["FAKE VLM"] = "FAKE VLM"
    authority_report: M3ProcessReport
    projection: M3ProjectionOutcome

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M3 process command run reference")

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if (
            self.authority_report.run_id != self.run_id
            or self.authority_report.perception_mode != self.perception_mode
            or self.authority_report.model_mode != self.model_mode
        ):
            raise ValueError("M3 process command envelope has inconsistent authority bindings")
        return self


class M3BacklogRetryCommandReport(FrozenContractModel):
    """CLI-safe envelope preserving the exact one-item backlog report."""

    schema_version: Literal["m3-backlog-retry-command-report-v1"] = (
        "m3-backlog-retry-command-report-v1"
    )
    operation: Literal["BACKLOG_RETRY"] = "BACKLOG_RETRY"
    run_id: ReferenceToken
    authority_complete: Literal[True] = True
    perception_mode: Literal["SIMULATED PERCEPTION"] = "SIMULATED PERCEPTION"
    model_mode: Literal["FAKE VLM"] = "FAKE VLM"
    authority_report: BacklogRetryReport
    projection: M3ProjectionOutcome

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M3 backlog command run reference")

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.authority_report.run_id != self.run_id:
            raise ValueError("M3 backlog command envelope has inconsistent run binding")
        return self


__all__ = [
    "M3BacklogRetryCommandReport",
    "M3ProcessCommandReport",
    "M3ProjectionBudget",
    "M3ProjectionCounts",
    "M3ProjectionDisposition",
    "M3ProjectionOutcome",
    "M3ProjectionReasonCode",
]
