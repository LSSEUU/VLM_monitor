"""Restart-safe full-run report for the v0.2 pilot A5 boundary."""

from __future__ import annotations

from typing import Literal, Self, TypeAlias

from pydantic import ModelWrapValidatorHandler, computed_field, field_validator, model_validator

from labcourt.contracts.backlog import BacklogRetryDisposition, BacklogRetryReport
from labcourt.contracts.base import ContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import CaseStatus, ReproducibilityMode
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.pilot import PilotA2Report, PilotA3Report
from labcourt.contracts.pilot_report import PilotA4PublicationReport
from labcourt.contracts.references import ReferenceToken, require_portable_run_id

PilotA5RunState: TypeAlias = Literal["COMPLETE", "ATTENTION_REQUIRED"]


def derive_pilot_a5_run_state(
    *,
    backlog_retry: BacklogRetryReport,
    screening: PilotA3Report,
    publication: PilotA4PublicationReport,
) -> PilotA5RunState:
    """Derive the CLI attention state from typed stage outcomes only."""

    metrics = publication.metrics
    attention_required = (
        backlog_retry.disposition
        in {
            BacklogRetryDisposition.RETRY_PENDING,
            BacklogRetryDisposition.HUMAN_REVIEW,
        }
        or screening.counts.deferred_to_backlog_cases > 0
        or any(
            outcome.status
            in {
                CaseStatus.BACKLOGGED,
                CaseStatus.ESCALATED,
                CaseStatus.REWORK_REQUIRED,
            }
            for outcome in screening.outcomes
        )
        or publication.dispatch.retryable_failure_count > 0
        or publication.dispatch.unknown_delivery_count > 0
        or publication.dispatch.attention_required_count > 0
        or metrics.human_review_count > 0
        or metrics.unresolved_count > 0
    )
    return "ATTENTION_REQUIRED" if attention_required else "COMPLETE"


class PilotA5RunReport(ContractModel):
    """One bounded A2-to-A4 execution or restart, including one backlog retry."""

    schema_version: Literal["pilot-a5-run-report-v1"] = "pilot-a5-run-report-v1"
    run_id: ReferenceToken
    reproducibility_mode: Literal[ReproducibilityMode.REPLAY_LOCKED]
    state: PilotA5RunState
    evidence: PilotA2Report
    backlog_retry: BacklogRetryReport
    screening: PilotA3Report
    publication: PilotA4PublicationReport
    production_delivery_count: Literal[0] = 0

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot A5 run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_report_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "report_id" in payload
        claimed = payload.pop("report_id", None)
        report = handler(payload)
        if claimed_present and claimed != report.report_id:
            raise ValueError("serialized report_id does not match pilot A5 report")
        return report

    @model_validator(mode="after")
    def validate_run_closure(self) -> PilotA5RunReport:
        metrics = self.publication.metrics
        if (
            self.evidence.run_id != self.run_id
            or self.backlog_retry.run_id != self.run_id
            or self.screening.run_id != self.run_id
            or metrics.run_id != self.run_id
        ):
            raise ValueError("pilot A5 components belong to different runs")
        if (
            self.evidence.run_manifest_id != self.screening.manifest_id
            or self.evidence.run_manifest_id != metrics.manifest_id
            or self.evidence.config_sha256 != metrics.config_sha256
        ):
            raise ValueError("pilot A5 components have inconsistent manifest identity")

        expected_state = derive_pilot_a5_run_state(
            backlog_retry=self.backlog_retry,
            screening=self.screening,
            publication=self.publication,
        )
        if self.state != expected_state:
            raise ValueError("pilot A5 state conflicts with its bounded stage outcomes")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"report_id"})
        return sha256_hex(["pilot-a5-run-report", 1, payload])


__all__ = ["PilotA5RunReport", "PilotA5RunState", "derive_pilot_a5_run_state"]
