"""Bounded command reports for the additive M5 operational boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Self

from pydantic import Field, model_validator

from labcourt.contracts.alert_policy import (
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchReceipt,
    AlertPolicyDisposition,
)
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_precedent_usage import MAX_M5_HEARING_PRECEDENT_EXPOSURES
from labcourt.contracts.m5_precedents import (
    MAX_M5_CONFLICT_PAIR_COUNT,
    MAX_M5_PRECEDENTS,
    M5PrecedentActivationReceipt,
    M5PrecedentConflictBatchReceipt,
)
from labcourt.contracts.references import ReferenceToken


class M5CloseCaseOutcome(FrozenContractModel):
    case_id: ReferenceToken
    source_revision: int = Field(gt=0, strict=True)
    closed_revision: int = Field(gt=0, strict=True)
    disposition: AlertPolicyDisposition
    alert_id: Sha256Hex | None = None
    application_batch_id: Sha256Hex | None = None
    applied_citation_count: int = Field(
        default=0,
        ge=0,
        le=MAX_M5_HEARING_PRECEDENT_EXPOSURES,
        strict=True,
    )
    alert_policy_authority_id: Sha256Hex
    automatic_precedent_id: Sha256Hex
    automatic_precedent_authority_id: Sha256Hex

    @model_validator(mode="after")
    def validate_close_outcome(self) -> Self:
        if self.closed_revision != self.source_revision + 1:
            raise ValueError("M5 close outcome revisions must be adjacent")
        if self.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT:
            if self.alert_id is not None:
                raise ValueError("a no-alert closure cannot report an alert")
        elif self.alert_id is None:
            raise ValueError("an alerting closure must report its alert ID")
        if self.application_batch_id is None and self.applied_citation_count != 0:
            raise ValueError(
                "M5 close outcome cannot report applied citations without an application batch"
            )
        return self


class M5FinalizeCommandReport(FrozenContractModel):
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    selected_count: int = Field(ge=0, le=10_000, strict=True)
    outcomes: tuple[M5CloseCaseOutcome, ...] = Field(max_length=10_000)

    @model_validator(mode="after")
    def validate_complete_stable_outcomes(self) -> Self:
        case_ids = tuple(item.case_id for item in self.outcomes)
        if self.selected_count != len(self.outcomes):
            raise ValueError("M5 finalize report must account for every selected Case")
        if case_ids != tuple(sorted(case_ids)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("M5 finalize outcomes must be unique and stably ordered")
        return self


class M5DispatchCommandReport(FrozenContractModel):
    run_id: ReferenceToken
    selected_count: int = Field(ge=0, le=256, strict=True)
    succeeded_count: int = Field(ge=0, le=256, strict=True)
    retryable_failure_count: int = Field(ge=0, le=256, strict=True)
    unknown_delivery_count: int = Field(ge=0, le=256, strict=True)
    attention_required_count: int = Field(ge=0, le=256, strict=True)
    receipts: tuple[AlertDispatchReceipt, ...] = Field(max_length=256)

    @model_validator(mode="after")
    def validate_complete_stable_receipts(self) -> Self:
        if self.selected_count != len(self.receipts):
            raise ValueError("M5 dispatch report must account for every selected outbox item")
        succeeded = sum(
            item.disposition == AlertDispatchDisposition.SUCCEEDED for item in self.receipts
        )
        retryable = sum(
            item.disposition == AlertDispatchDisposition.RETRYABLE_FAILURE for item in self.receipts
        )
        unknown = sum(
            item.disposition == AlertDispatchDisposition.UNKNOWN_DELIVERY for item in self.receipts
        )
        attention = sum(
            item.continuation == AlertDispatchContinuation.ATTENTION_REQUIRED
            for item in self.receipts
        )
        if (
            self.succeeded_count,
            self.retryable_failure_count,
            self.unknown_delivery_count,
            self.attention_required_count,
        ) != (succeeded, retryable, unknown, attention):
            raise ValueError("M5 dispatch counts do not match receipts")
        if succeeded + retryable + unknown != self.selected_count:
            raise ValueError("M5 dispatch outcome counts must account for every receipt")
        keys = tuple(item.outbox_id for item in self.receipts)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M5 dispatch receipts must be unique and stably ordered")
        return self


class M5PrecedentImportReport(FrozenContractModel):
    run_id: ReferenceToken
    accepted_count: int = Field(ge=0, le=MAX_M5_PRECEDENTS, strict=True)
    precedent_ids: tuple[ReferenceToken, ...] = Field(max_length=MAX_M5_PRECEDENTS)
    authority_ids: tuple[Sha256Hex, ...] = Field(max_length=MAX_M5_PRECEDENTS)

    @model_validator(mode="after")
    def validate_complete_stable_authorities(self) -> Self:
        if self.accepted_count != len(self.precedent_ids) or self.accepted_count != len(
            self.authority_ids
        ):
            raise ValueError("M5 import report must account for every accepted authority")
        if self.precedent_ids != tuple(sorted(set(self.precedent_ids))):
            raise ValueError("M5 import precedent IDs must be unique and stably ordered")
        return self


class M5PrecedentActivationCommandReport(FrozenContractModel):
    run_id: ReferenceToken
    evaluated_at: datetime
    selected_count: int = Field(ge=0, le=MAX_M5_PRECEDENTS, strict=True)
    receipts: tuple[M5PrecedentActivationReceipt, ...] = Field(max_length=MAX_M5_PRECEDENTS)

    @model_validator(mode="after")
    def validate_complete_stable_receipts(self) -> Self:
        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() != UTC.utcoffset(
            self.evaluated_at
        ):
            raise ValueError("M5 activation report timestamp must use timezone-aware UTC")
        if self.selected_count != len(self.receipts):
            raise ValueError("M5 activation report must account for every selected precedent")
        keys = tuple(item.precedent_id for item in self.receipts)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("M5 activation receipts must be unique and stably ordered")
        if any(
            item.run_id != self.run_id or item.evaluated_at != self.evaluated_at
            for item in self.receipts
        ):
            raise ValueError("M5 activation receipt is outside the command scope")
        return self


class M5PrecedentConflictCommandReport(FrozenContractModel):
    run_id: ReferenceToken
    candidate_count: int = Field(ge=0, le=MAX_M5_PRECEDENTS, strict=True)
    evaluated_pair_count: int = Field(ge=0, le=MAX_M5_CONFLICT_PAIR_COUNT, strict=True)
    conflict_edge_count: int = Field(ge=0, le=MAX_M5_CONFLICT_PAIR_COUNT, strict=True)
    causal_cut_id: Sha256Hex
    batch_authority_id: Sha256Hex
    batch_receipt_id: Sha256Hex
    applied_receipts: tuple[M5PrecedentConflictBatchReceipt, ...] = Field(
        min_length=1,
        max_length=1,
    )
    current_conflict_precedent_ids: tuple[ReferenceToken, ...] = Field(max_length=MAX_M5_PRECEDENTS)

    @model_validator(mode="after")
    def validate_stable_conflict_evidence(self) -> Self:
        receipt = self.applied_receipts[0]
        if (
            receipt.run_id != self.run_id
            or receipt.causal_cut_id != self.causal_cut_id
            or receipt.batch_authority_id != self.batch_authority_id
            or receipt.receipt_id != self.batch_receipt_id
            or len(receipt.results) != self.candidate_count
            or self.conflict_edge_count > self.evaluated_pair_count
        ):
            raise ValueError("M5 conflict command report does not close its batch receipt")
        if self.current_conflict_precedent_ids != tuple(
            sorted(set(self.current_conflict_precedent_ids))
        ):
            raise ValueError("M5 current conflict IDs must be unique and stably ordered")
        return self


__all__ = [
    "MAX_M5_CONFLICT_PAIR_COUNT",
    "M5CloseCaseOutcome",
    "M5DispatchCommandReport",
    "M5FinalizeCommandReport",
    "M5PrecedentActivationCommandReport",
    "M5PrecedentConflictCommandReport",
    "M5PrecedentImportReport",
]
