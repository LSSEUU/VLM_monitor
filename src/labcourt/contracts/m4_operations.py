"""Stable, secret-free contracts for bounded offline M4 operations."""

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

from labcourt.contracts.acquisition_matrix import acquisition_output_counts_match
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AcquisitionAction,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import Crop, CropRequest
from labcourt.contracts.frames import FrameRef, Sha256Hex
from labcourt.contracts.hearing import (
    MAX_ACQUISITION_RETURNED_FRAMES,
    AcquisitionRequest,
)
from labcourt.contracts.hearing_state import HearingHumanReviewReason
from labcourt.contracts.m3_operations import (
    MAX_FAKE_VLM_FIXTURE_ENTRIES,
    MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES,
    FakeVLMFixtureInput,
    FakeVLMResponseFixtureInput,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M4_PROCESS_CASES = 1_000
MAX_M4_BACKLOG_RECLAIMS = 10_000
MAX_M4_FAKE_ACQUISITION_FIXTURE_ENTRIES = 64
MAX_M4_FAKE_ACQUISITION_FIXTURE_FILE_BYTES = 64 * 1024 * 1024


class M4FakeAcquisitionFixtureInput(FrozenContractModel):
    """Exact, bounded output objects for one content-addressed tool request."""

    request: AcquisitionRequest
    frames: tuple[FrameRef, ...] = Field(
        default=(),
        max_length=MAX_ACQUISITION_RETURNED_FRAMES,
    )
    crops: tuple[Crop, ...] = Field(
        default=(),
        max_length=MAX_ACQUISITION_RETURNED_FRAMES,
    )
    objective_facts: tuple[ObjectiveFact, ...] = Field(
        default=(),
        max_length=MAX_ACQUISITION_RETURNED_FRAMES,
    )
    detections: tuple[Detection, ...] = Field(
        default=(),
        max_length=MAX_ACQUISITION_RETURNED_FRAMES,
    )
    crop_request: CropRequest | None = None

    @model_validator(mode="after")
    def validate_action_output_matrix(self) -> Self:
        identities = (
            tuple(item.frame_id for item in self.frames),
            tuple(item.crop_id for item in self.crops),
            tuple(item.fact_id for item in self.objective_facts),
            tuple(item.detection_id for item in self.detections),
        )
        if any(
            values != tuple(sorted(values)) or len(values) != len(set(values))
            for values in identities
        ):
            raise ValueError("M4 acquisition fixture outputs must be unique and stable")
        action = self.request.action
        if not acquisition_output_counts_match(
            action,
            frames=len(self.frames),
            crops=len(self.crops),
            objective_facts=len(self.objective_facts),
            detections=len(self.detections),
        ):
            raise ValueError("M4 acquisition fixture violates the frozen output matrix")
        if action == AcquisitionAction.RECROP:
            if self.crop_request is None:
                raise ValueError("M4 RECROP fixture requires one crop and its CropRequest")
        elif self.crop_request is not None:
            raise ValueError("only an M4 RECROP fixture may carry a CropRequest")
        return self

    @property
    def sort_key(self) -> str:
        return self.request.request_id


class M4FakeVLMFixtureBundle(FrozenContractModel):
    """Bounded role and acquisition fixtures selected by exact request identity."""

    schema_version: Literal["m4-fake-vlm-fixture-bundle-v1"]
    fixtures: tuple[FakeVLMFixtureInput, ...] = Field(
        max_length=MAX_FAKE_VLM_FIXTURE_ENTRIES,
        repr=False,
    )
    acquisition_fixtures: tuple[M4FakeAcquisitionFixtureInput, ...] = Field(
        default=(),
        max_length=MAX_M4_FAKE_ACQUISITION_FIXTURE_ENTRIES,
        repr=False,
    )

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
            "fixture_bundle_id",
            "fixture_count",
            "acquisition_fixture_count",
            "raw_response_total_bytes",
        )
        present = {name: name in payload for name in names}
        claims = {name: payload.pop(name, None) for name in names}
        bundle = handler(payload)
        for name in names:
            claimed = claims[name]
            actual = getattr(bundle, name)
            expected_type = (
                isinstance(claimed, str)
                if name == "fixture_bundle_id"
                else isinstance(claimed, int) and not isinstance(claimed, bool)
            )
            if present[name] and (not expected_type or claimed != actual):
                raise ValueError(f"serialized M4 fake VLM bundle {name} conflicts with content")
        return bundle

    @model_validator(mode="after")
    def validate_unique_stable_keys_and_total_bytes(self) -> Self:
        keys = tuple(fixture.cache_key for fixture in self.fixtures)
        if len(keys) != len(set(keys)):
            raise ValueError("M4 fake VLM fixture cache keys must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("M4 fake VLM fixtures must use stable cache-key order")
        if self.raw_response_total_bytes > MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES:
            raise ValueError("M4 fake VLM fixture bundle exceeds its total UTF-8 byte limit")
        acquisition_keys = tuple(fixture.sort_key for fixture in self.acquisition_fixtures)
        if acquisition_keys != tuple(sorted(acquisition_keys)) or len(acquisition_keys) != len(
            set(acquisition_keys)
        ):
            raise ValueError("M4 acquisition fixtures must use unique stable request order")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fixture_bundle_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m4-fake-vlm-fixture-bundle",
                1,
                [
                    fixture.model_dump(mode="json", exclude_computed_fields=True)
                    for fixture in self.fixtures
                ],
                [
                    fixture.model_dump(mode="json", exclude_computed_fields=True)
                    for fixture in self.acquisition_fixtures
                ],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fixture_count(self) -> int:
        return len(self.fixtures)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def acquisition_fixture_count(self) -> int:
        return len(self.acquisition_fixtures)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_response_total_bytes(self) -> int:
        return sum(
            len(fixture.raw_response_utf8.encode("utf-8"))
            for fixture in self.fixtures
            if isinstance(fixture, FakeVLMResponseFixtureInput)
        )


class M4ProcessDisposition(StrEnum):
    """Stable distinction between advancement, deferral, transfer, and observation."""

    PROCESSED = "PROCESSED"
    DEFERRED_TO_BACKLOG = "DEFERRED_TO_BACKLOG"
    TRANSFERRED_TO_HUMAN = "TRANSFERRED_TO_HUMAN"
    OBSERVED_EXISTING = "OBSERVED_EXISTING"
    SKIPPED_NOT_HEARING_READY = "SKIPPED_NOT_HEARING_READY"


class M4ProcessCaseOutcome(FrozenContractModel):
    """One case result without prompts, raw responses, paths, or secrets."""

    event_id: ReferenceToken
    case_id: ReferenceToken
    initial_status: CaseStatus
    status: CaseStatus
    revision: int = Field(gt=0, strict=True)
    disposition: M4ProcessDisposition
    pipeline_invoked: bool = Field(strict=True)
    hearing_session_id: ReferenceToken | None = None
    checkpoint_id: ReferenceToken | None = None
    verdict_id: ReferenceToken | None = None
    procedural_review_id: ReferenceToken | None = None
    backlog_item_id: ReferenceToken | None = None
    human_review_reason: HearingHumanReviewReason | None = None
    cache_hit_count: int = Field(ge=0, strict=True)
    recovered_response_count: int = Field(ge=0, strict=True)

    @field_validator(
        "event_id",
        "case_id",
        "hearing_session_id",
        "checkpoint_id",
        "verdict_id",
        "procedural_review_id",
        "backlog_item_id",
    )
    @classmethod
    def validate_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M4 process report reference")

    @model_validator(mode="after")
    def validate_disposition_and_authorities(self) -> Self:
        if self.checkpoint_id is not None and self.hearing_session_id is None:
            raise ValueError("M4 checkpoint reference requires its hearing session")
        if (self.verdict_id is None) != (self.procedural_review_id is None):
            raise ValueError("M4 verdict and procedural review references are inseparable")
        if self.status == CaseStatus.READY_FOR_ALERT_POLICY and (
            self.verdict_id is None or self.procedural_review_id is None
        ):
            raise ValueError("ready M4 outcome requires verdict and review references")
        if self.status == CaseStatus.BACKLOGGED:
            if self.backlog_item_id is None or self.hearing_session_id is None:
                raise ValueError("backlogged M4 outcome requires backlog and hearing references")
        elif self.backlog_item_id is not None:
            raise ValueError("only a backlogged M4 outcome may carry a backlog reference")
        if (
            self.disposition == M4ProcessDisposition.TRANSFERRED_TO_HUMAN
            and self.human_review_reason is None
        ):
            raise ValueError("M4 human transfer requires its typed reason")
        if self.status != CaseStatus.HUMAN_REVIEW and self.human_review_reason is not None:
            raise ValueError("only a human-review M4 outcome may carry a human reason")

        if self.pipeline_invoked:
            if self.initial_status not in {
                CaseStatus.ESCALATED,
                CaseStatus.REWORK_REQUIRED,
                CaseStatus.DELIBERATING,
                CaseStatus.BACKLOGGED,
            }:
                raise ValueError("M4 pipeline was invoked from an unsupported state")
            if self.disposition not in {
                M4ProcessDisposition.PROCESSED,
                M4ProcessDisposition.DEFERRED_TO_BACKLOG,
                M4ProcessDisposition.TRANSFERRED_TO_HUMAN,
            }:
                raise ValueError("invoked M4 pipeline requires an active disposition")
        else:
            if self.initial_status != self.status:
                raise ValueError("observed M4 outcome must preserve the case status")
            if self.cache_hit_count or self.recovered_response_count:
                raise ValueError("observed M4 outcome cannot claim model-call activity")

        if self.disposition == M4ProcessDisposition.PROCESSED:
            if self.status not in {
                CaseStatus.READY_FOR_ALERT_POLICY,
                CaseStatus.REWORK_REQUIRED,
            }:
                raise ValueError("processed M4 case has an unsupported state")
        elif self.disposition == M4ProcessDisposition.DEFERRED_TO_BACKLOG:
            if self.status != CaseStatus.BACKLOGGED:
                raise ValueError("deferred M4 case must be backlogged")
        elif self.disposition == M4ProcessDisposition.TRANSFERRED_TO_HUMAN:
            if self.status != CaseStatus.HUMAN_REVIEW:
                raise ValueError("transferred M4 case must be in human review")
        elif self.disposition == M4ProcessDisposition.OBSERVED_EXISTING:
            if self.pipeline_invoked or self.status not in {
                CaseStatus.READY_FOR_ALERT_POLICY,
                CaseStatus.HUMAN_REVIEW,
            }:
                raise ValueError("observed M4 case must already be terminal")
        elif self.pipeline_invoked or self.status in {
            CaseStatus.ESCALATED,
            CaseStatus.REWORK_REQUIRED,
            CaseStatus.DELIBERATING,
            CaseStatus.BACKLOGGED,
            CaseStatus.READY_FOR_ALERT_POLICY,
            CaseStatus.HUMAN_REVIEW,
        }:
            raise ValueError("skipped M4 case must be outside the hearing slice")
        return self


class M4ProcessCounts(FrozenContractModel):
    """Bounded case and model-call counters for one operation."""

    selected_cases: int = Field(ge=0, le=MAX_M4_PROCESS_CASES, strict=True)
    pipeline_invocations: int = Field(ge=0, le=MAX_M4_PROCESS_CASES, strict=True)
    processed_cases: int = Field(ge=0, le=MAX_M4_PROCESS_CASES, strict=True)
    deferred_to_backlog_cases: int = Field(ge=0, le=MAX_M4_PROCESS_CASES, strict=True)
    transferred_to_human_cases: int = Field(ge=0, le=MAX_M4_PROCESS_CASES, strict=True)
    observed_existing_cases: int = Field(ge=0, le=MAX_M4_PROCESS_CASES, strict=True)
    skipped_not_hearing_ready_cases: int = Field(
        ge=0,
        le=MAX_M4_PROCESS_CASES,
        strict=True,
    )
    cache_hits: int = Field(ge=0, strict=True)
    recovered_responses: int = Field(ge=0, strict=True)


class M4ProcessReport(FrozenContractModel):
    """Bounded run report prominently identifying simulated M4 authority."""

    schema_version: Literal["m4-process-report-v1"] = "m4-process-report-v1"
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    perception_mode: Literal["SIMULATED PERCEPTION"]
    model_mode: Literal["FAKE VLM"]
    precedent_mode: Literal["CONTROLLED FAKE"]
    fixture_bundle_id: Sha256Hex
    fixture_entry_count: int = Field(ge=0, le=MAX_FAKE_VLM_FIXTURE_ENTRIES, strict=True)
    acquisition_fixture_count: int = Field(
        default=0,
        ge=0,
        le=MAX_M4_FAKE_ACQUISITION_FIXTURE_ENTRIES,
        strict=True,
    )
    requested_case_id: ReferenceToken | None
    selection_limit: int = Field(gt=0, le=MAX_M4_PROCESS_CASES, strict=True)
    available_case_count: int = Field(ge=0, strict=True)
    selection_truncated: bool = Field(strict=True)
    outcomes: tuple[M4ProcessCaseOutcome, ...] = Field(max_length=MAX_M4_PROCESS_CASES)
    counts: M4ProcessCounts

    @field_validator("run_id", "requested_case_id")
    @classmethod
    def validate_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M4 process report reference")

    @model_validator(mode="after")
    def validate_selection_and_counts(self) -> Self:
        case_ids = tuple(outcome.case_id for outcome in self.outcomes)
        if case_ids != tuple(sorted(case_ids)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("M4 process outcomes must use unique stable case-ID order")
        selected = len(self.outcomes)
        if selected > self.selection_limit or selected > self.available_case_count:
            raise ValueError("M4 process selection exceeds its reported bound")
        if self.requested_case_id is not None:
            if (
                self.available_case_count != 1
                or selected != 1
                or self.outcomes[0].case_id != self.requested_case_id
                or self.selection_truncated
            ):
                raise ValueError("single-case M4 report has inconsistent selection scope")
        elif self.selection_truncated != (self.available_case_count > selected):
            raise ValueError("M4 process truncation flag conflicts with available cases")
        dispositions = tuple(outcome.disposition for outcome in self.outcomes)
        expected = M4ProcessCounts(
            selected_cases=selected,
            pipeline_invocations=sum(outcome.pipeline_invoked for outcome in self.outcomes),
            processed_cases=dispositions.count(M4ProcessDisposition.PROCESSED),
            deferred_to_backlog_cases=dispositions.count(M4ProcessDisposition.DEFERRED_TO_BACKLOG),
            transferred_to_human_cases=dispositions.count(
                M4ProcessDisposition.TRANSFERRED_TO_HUMAN
            ),
            observed_existing_cases=dispositions.count(M4ProcessDisposition.OBSERVED_EXISTING),
            skipped_not_hearing_ready_cases=dispositions.count(
                M4ProcessDisposition.SKIPPED_NOT_HEARING_READY
            ),
            cache_hits=sum(outcome.cache_hit_count for outcome in self.outcomes),
            recovered_responses=sum(outcome.recovered_response_count for outcome in self.outcomes),
        )
        if self.counts != expected:
            raise ValueError("M4 process counts conflict with case outcomes")
        return self


class M4ProjectionDisposition(StrEnum):
    """Whether post-authority projection publication completed."""

    REBUILT = "REBUILT"
    PENDING_REBUILD = "PENDING_REBUILD"


class M4ProjectionOutcome(FrozenContractModel):
    """Secret-free projection status; authority completion is independent."""

    disposition: M4ProjectionDisposition
    generation_id: Sha256Hex | None = None
    reason_code: ReferenceToken | None = None

    @field_validator("reason_code")
    @classmethod
    def validate_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M4 projection reason")

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        rebuilt = self.disposition == M4ProjectionDisposition.REBUILT
        if rebuilt != (self.generation_id is not None and self.reason_code is None):
            raise ValueError("M4 projection outcome fields conflict with disposition")
        if not rebuilt and self.reason_code is None:
            raise ValueError("pending M4 projection requires a reason code")
        return self


class M4ProcessCommandReport(FrozenContractModel):
    """CLI-safe envelope preserving authority even if projection remains pending."""

    schema_version: Literal["m4-process-command-report-v1"] = "m4-process-command-report-v1"
    operation: Literal["HEARING_PROCESS"] = "HEARING_PROCESS"
    run_id: ReferenceToken
    authority_complete: Literal[True] = True
    perception_mode: Literal["SIMULATED PERCEPTION"] = "SIMULATED PERCEPTION"
    model_mode: Literal["FAKE VLM"] = "FAKE VLM"
    precedent_mode: Literal["CONTROLLED FAKE"] = "CONTROLLED FAKE"
    authority_report: M4ProcessReport
    projection: M4ProjectionOutcome

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M4 process command run reference")

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if (
            self.authority_report.run_id != self.run_id
            or self.authority_report.perception_mode != self.perception_mode
            or self.authority_report.model_mode != self.model_mode
            or self.authority_report.precedent_mode != self.precedent_mode
        ):
            raise ValueError("M4 command envelope has inconsistent authority bindings")
        return self


class M4BacklogRetryDisposition(StrEnum):
    """Stable result of one bounded HEARING worker iteration."""

    NO_WORK = "NO_WORK"
    COMPLETED = "COMPLETED"
    REQUEUED = "REQUEUED"
    EXHAUSTED = "EXHAUSTED"


class M4BacklogRetryReport(FrozenContractModel):
    """Secret-free closure summary for one exact HEARING lease exit.

    The full request, response, and completion documents remain SQLite
    authority.  This report exposes only their content-addressed identities,
    the non-secret lease CAS identity, and the resulting state boundary.
    """

    schema_version: Literal["m4-backlog-retry-report-v1"] = "m4-backlog-retry-report-v1"
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    perception_mode: Literal["SIMULATED PERCEPTION"] = "SIMULATED PERCEPTION"
    model_mode: Literal["FAKE VLM"] = "FAKE VLM"
    precedent_mode: Literal["CONTROLLED FAKE"] = "CONTROLLED FAKE"
    fixture_bundle_id: Sha256Hex
    fixture_entry_count: int = Field(
        ge=0,
        le=MAX_FAKE_VLM_FIXTURE_ENTRIES,
        strict=True,
    )
    acquisition_fixture_count: int = Field(
        default=0,
        ge=0,
        le=MAX_M4_FAKE_ACQUISITION_FIXTURE_ENTRIES,
        strict=True,
    )
    disposition: M4BacklogRetryDisposition
    reclaimed_completion_receipt_ids: tuple[Sha256Hex, ...] = Field(
        default=(),
        max_length=MAX_M4_BACKLOG_RECLAIMS,
    )
    lease: BacklogLeaseIdentity | None = None
    case_id: ReferenceToken | None = None
    role: VlmRole | None = None
    completion_receipt_id: Sha256Hex | None = None
    outcome_id: Sha256Hex | None = None
    source_checkpoint_id: Sha256Hex | None = None
    resulting_checkpoint_id: Sha256Hex | None = None
    backlog_status: BacklogStatus | None = None
    resulting_case_status: CaseStatus | None = None
    resulting_retry_generation: int | None = Field(default=None, ge=0, strict=True)
    human_review_receipt_id: Sha256Hex | None = None

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_report_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M4 backlog retry report reference")

    @model_validator(mode="after")
    def validate_retry_closure(self) -> Self:
        reclaimed = self.reclaimed_completion_receipt_ids
        if reclaimed != tuple(sorted(reclaimed)) or len(reclaimed) != len(set(reclaimed)):
            raise ValueError("M4 reclaimed receipt identities must be unique and stable")

        closure_fields = (
            self.lease,
            self.case_id,
            self.role,
            self.completion_receipt_id,
            self.outcome_id,
            self.source_checkpoint_id,
            self.resulting_checkpoint_id,
            self.backlog_status,
            self.resulting_case_status,
            self.resulting_retry_generation,
        )
        if self.disposition == M4BacklogRetryDisposition.NO_WORK:
            if any(value is not None for value in closure_fields):
                raise ValueError("NO_WORK M4 retry report cannot claim a lease closure")
            if self.human_review_receipt_id is not None:
                raise ValueError("NO_WORK M4 retry report cannot claim human authority")
            return self

        if any(value is None for value in closure_fields):
            raise ValueError("processed M4 retry report requires its exact lease closure")
        assert self.lease is not None
        if self.lease.run_id != self.run_id:
            raise ValueError("M4 retry lease belongs to another run")

        expected = {
            M4BacklogRetryDisposition.COMPLETED: BacklogStatus.COMPLETED,
            M4BacklogRetryDisposition.REQUEUED: BacklogStatus.PENDING,
            M4BacklogRetryDisposition.EXHAUSTED: BacklogStatus.EXHAUSTED,
        }[self.disposition]
        if self.backlog_status != expected:
            raise ValueError("M4 retry disposition conflicts with backlog status")
        if self.disposition == M4BacklogRetryDisposition.REQUEUED:
            if (
                self.resulting_case_status != CaseStatus.BACKLOGGED
                or self.source_checkpoint_id != self.resulting_checkpoint_id
                or self.human_review_receipt_id is not None
            ):
                raise ValueError("requeued M4 retry changed its pending authority")
        elif self.disposition == M4BacklogRetryDisposition.EXHAUSTED:
            if (
                self.resulting_case_status != CaseStatus.HUMAN_REVIEW
                or self.source_checkpoint_id != self.resulting_checkpoint_id
                or self.human_review_receipt_id is None
            ):
                raise ValueError("exhausted M4 retry lacks exact human authority")
        elif self.resulting_case_status not in {CaseStatus.DELIBERATING, CaseStatus.HUMAN_REVIEW}:
            raise ValueError("completed M4 retry has an unsupported Case state")
        return self


class M4BacklogRetryCommandReport(FrozenContractModel):
    """CLI envelope that never lets projection failure erase retry authority."""

    schema_version: Literal["m4-backlog-retry-command-report-v1"] = (
        "m4-backlog-retry-command-report-v1"
    )
    operation: Literal["HEARING_BACKLOG_RETRY"] = "HEARING_BACKLOG_RETRY"
    run_id: ReferenceToken
    authority_complete: Literal[True] = True
    perception_mode: Literal["SIMULATED PERCEPTION"] = "SIMULATED PERCEPTION"
    model_mode: Literal["FAKE VLM"] = "FAKE VLM"
    precedent_mode: Literal["CONTROLLED FAKE"] = "CONTROLLED FAKE"
    authority_report: M4BacklogRetryReport
    projection: M4ProjectionOutcome

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "M4 backlog command run reference")

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if (
            self.authority_report.run_id != self.run_id
            or self.authority_report.perception_mode != self.perception_mode
            or self.authority_report.model_mode != self.model_mode
            or self.authority_report.precedent_mode != self.precedent_mode
        ):
            raise ValueError("M4 backlog command envelope has inconsistent bindings")
        return self


__all__ = [
    "MAX_M4_BACKLOG_RECLAIMS",
    "MAX_M4_FAKE_ACQUISITION_FIXTURE_ENTRIES",
    "MAX_M4_FAKE_ACQUISITION_FIXTURE_FILE_BYTES",
    "MAX_M4_PROCESS_CASES",
    "M4BacklogRetryCommandReport",
    "M4BacklogRetryDisposition",
    "M4BacklogRetryReport",
    "M4FakeAcquisitionFixtureInput",
    "M4FakeVLMFixtureBundle",
    "M4ProcessCaseOutcome",
    "M4ProcessCommandReport",
    "M4ProcessCounts",
    "M4ProcessDisposition",
    "M4ProcessReport",
    "M4ProjectionDisposition",
    "M4ProjectionOutcome",
]
