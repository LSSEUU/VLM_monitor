"""Stable, secret-free contracts for bounded M3 operational entry points."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ArtifactKind, CaseStatus
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

MAX_FAKE_VLM_FIXTURE_ENTRIES = 1_000
MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES = 262_144
MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_M3_PROCESS_CASES = 1_000


class FakeVLMFixtureDisposition(StrEnum):
    """One explicit fake-provider behavior selected by an exact cache key."""

    RESPONSE = "RESPONSE"
    OUTAGE = "OUTAGE"
    TIMEOUT = "TIMEOUT"


class FakeVLMResponseFixtureInput(FrozenContractModel):
    """Exact UTF-8 response and explicit usage receipt for one fake call."""

    disposition: Literal[FakeVLMFixtureDisposition.RESPONSE]
    cache_key: Sha256Hex
    raw_response_utf8: str = Field(
        max_length=MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES,
        repr=False,
    )
    input_tokens: int = Field(ge=0, strict=True)
    output_tokens: int = Field(ge=0, strict=True)
    latency_ms: int = Field(ge=0, strict=True)

    @field_validator("raw_response_utf8", mode="before")
    @classmethod
    def validate_raw_response_bytes(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("fake VLM response must be authored as a UTF-8 string")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("fake VLM response must be valid UTF-8 text") from None
        if len(encoded) > MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES:
            raise ValueError("fake VLM response exceeds the per-entry UTF-8 byte limit")
        return value


class FakeVLMFailureFixtureInput(FrozenContractModel):
    """Explicit provider failure; failure fixtures cannot hide response semantics."""

    disposition: Literal[
        FakeVLMFixtureDisposition.OUTAGE,
        FakeVLMFixtureDisposition.TIMEOUT,
    ]
    cache_key: Sha256Hex


FakeVLMFixtureInput: TypeAlias = Annotated[
    FakeVLMResponseFixtureInput | FakeVLMFailureFixtureInput,
    Field(discriminator="disposition"),
]


class FakeVLMFixtureBundle(FrozenContractModel):
    """Bounded fake inputs with unique, stable exact-cache-key selection."""

    schema_version: Literal["m3-fake-vlm-fixture-bundle-v1"]
    fixtures: tuple[FakeVLMFixtureInput, ...] = Field(
        max_length=MAX_FAKE_VLM_FIXTURE_ENTRIES,
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
        computed_names = (
            "fixture_bundle_id",
            "fixture_count",
            "raw_response_total_bytes",
        )
        present = {name: name in payload for name in computed_names}
        claims = {name: payload.pop(name, None) for name in computed_names}
        bundle = handler(payload)
        for name in computed_names:
            claimed = claims[name]
            actual = getattr(bundle, name)
            valid_type = (
                isinstance(claimed, str)
                if name == "fixture_bundle_id"
                else isinstance(claimed, int) and not isinstance(claimed, bool)
            )
            if present[name] and (not valid_type or claimed != actual):
                raise ValueError(f"serialized fake VLM bundle {name} conflicts with content")
        return bundle

    @model_validator(mode="after")
    def validate_unique_stable_keys_and_total_bytes(self) -> Self:
        keys = tuple(fixture.cache_key for fixture in self.fixtures)
        if len(keys) != len(set(keys)):
            raise ValueError("fake VLM fixture cache keys must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("fake VLM fixtures must use stable cache-key order")
        if self.raw_response_total_bytes > MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES:
            raise ValueError("fake VLM fixture bundle exceeds its total UTF-8 byte limit")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fixture_bundle_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m3-fake-vlm-fixture-bundle",
                1,
                [
                    fixture.model_dump(mode="json", exclude_computed_fields=True)
                    for fixture in self.fixtures
                ],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fixture_count(self) -> int:
        return len(self.fixtures)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_response_total_bytes(self) -> int:
        return sum(
            len(fixture.raw_response_utf8.encode("utf-8"))
            for fixture in self.fixtures
            if isinstance(fixture, FakeVLMResponseFixtureInput)
        )

    def __repr__(self) -> str:
        return (
            "FakeVLMFixtureBundle("
            f"fixture_count={self.fixture_count}, "
            f"fixture_bundle_id={self.fixture_bundle_id})"
        )


class M3ProcessDisposition(StrEnum):
    """Stable distinction between advancement, deferral, observation, and skip."""

    PROCESSED = "PROCESSED"
    DEFERRED_TO_BACKLOG = "DEFERRED_TO_BACKLOG"
    OBSERVED_EXISTING = "OBSERVED_EXISTING"
    SKIPPED_NOT_READY = "SKIPPED_NOT_READY"


class M3ProcessCaseOutcome(FrozenContractModel):
    """One case result without prompts, raw responses, paths, or secrets."""

    event_id: ReferenceToken
    case_id: ReferenceToken
    initial_status: CaseStatus
    status: CaseStatus
    revision: int = Field(gt=0, strict=True)
    disposition: M3ProcessDisposition
    pipeline_invoked: bool = Field(strict=True)
    screening_result_ref: ArtifactRef | None
    verdict_ref: ArtifactRef | None
    procedural_review_ref: ArtifactRef | None
    backlog_item_ref: ArtifactRef | None
    cache_hit_count: int = Field(ge=0, strict=True)
    recovered_response_count: int = Field(ge=0, strict=True)
    repair_attempt_count: int = Field(ge=0, le=1, strict=True)

    @field_validator("event_id", "case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M3 process case reference")

    @model_validator(mode="after")
    def validate_disposition_and_references(self) -> Self:
        expected_kinds = (
            (self.screening_result_ref, ArtifactKind.SCREENING_RESULT),
            (self.verdict_ref, ArtifactKind.VERDICT),
            (self.procedural_review_ref, ArtifactKind.PROCEDURAL_REVIEW),
            (self.backlog_item_ref, ArtifactKind.BACKLOG_ITEM),
        )
        if any(ref is not None and ref.kind != kind for ref, kind in expected_kinds):
            raise ValueError("M3 process outcome contains a mistyped artifact reference")
        if self.verdict_ref is not None and self.screening_result_ref is None:
            raise ValueError("verdict reference requires a screening-result reference")
        if self.procedural_review_ref is not None and self.verdict_ref is None:
            raise ValueError("procedural-review reference requires a verdict reference")
        if self.status == CaseStatus.ESCALATED and self.screening_result_ref is None:
            raise ValueError("ESCALATED outcome requires a screening-result reference")
        if self.status in {
            CaseStatus.READY_FOR_ALERT_POLICY,
            CaseStatus.REWORK_REQUIRED,
        } and any(
            ref is None
            for ref in (
                self.screening_result_ref,
                self.verdict_ref,
                self.procedural_review_ref,
            )
        ):
            raise ValueError("reviewed M3 outcome requires screening, verdict, and review refs")
        if self.status == CaseStatus.BACKLOGGED and self.backlog_item_ref is None:
            raise ValueError("BACKLOGGED outcome requires its current item reference")
        if self.status != CaseStatus.BACKLOGGED and self.backlog_item_ref is not None:
            raise ValueError("only a BACKLOGGED outcome may carry a current item reference")

        if self.pipeline_invoked:
            if self.initial_status not in {CaseStatus.EVIDENCE_READY, CaseStatus.SCREENED}:
                raise ValueError("screening may only be invoked for an M3-ready case")
            if self.disposition not in {
                M3ProcessDisposition.PROCESSED,
                M3ProcessDisposition.DEFERRED_TO_BACKLOG,
            }:
                raise ValueError("invoked screening requires a processing disposition")
        elif any(
            value != 0
            for value in (
                self.cache_hit_count,
                self.recovered_response_count,
                self.repair_attempt_count,
            )
        ):
            raise ValueError("observed cases cannot claim model-call activity")

        if self.disposition == M3ProcessDisposition.PROCESSED:
            if self.status not in {
                CaseStatus.ESCALATED,
                CaseStatus.READY_FOR_ALERT_POLICY,
                CaseStatus.REWORK_REQUIRED,
            }:
                raise ValueError("processed M3 case has an unsupported completion status")
            if self.backlog_item_ref is not None:
                raise ValueError("processed M3 case cannot retain a current backlog reference")
        elif self.disposition == M3ProcessDisposition.DEFERRED_TO_BACKLOG:
            if self.status != CaseStatus.BACKLOGGED or self.backlog_item_ref is None:
                raise ValueError("deferred M3 case requires a current backlog item")
        elif self.disposition == M3ProcessDisposition.OBSERVED_EXISTING:
            if self.pipeline_invoked or self.initial_status != self.status:
                raise ValueError("observed case must preserve its pre-existing status")
            if self.status in {
                CaseStatus.CANDIDATE,
                CaseStatus.EVIDENCE_READY,
                CaseStatus.SCREENED,
            }:
                raise ValueError("an actionable case cannot be reported as observed existing")
        else:
            if (
                self.pipeline_invoked
                or self.initial_status != CaseStatus.CANDIDATE
                or self.status != CaseStatus.CANDIDATE
            ):
                raise ValueError("only an unchanged candidate case may be skipped as not ready")
        return self


class M3ProcessCounts(FrozenContractModel):
    """Explicit bounded-work and model-cache counters."""

    selected_cases: int = Field(ge=0, le=MAX_M3_PROCESS_CASES, strict=True)
    pipeline_invocations: int = Field(ge=0, le=MAX_M3_PROCESS_CASES, strict=True)
    processed_cases: int = Field(ge=0, le=MAX_M3_PROCESS_CASES, strict=True)
    deferred_to_backlog_cases: int = Field(ge=0, le=MAX_M3_PROCESS_CASES, strict=True)
    observed_existing_cases: int = Field(ge=0, le=MAX_M3_PROCESS_CASES, strict=True)
    skipped_not_ready_cases: int = Field(ge=0, le=MAX_M3_PROCESS_CASES, strict=True)
    cache_hits: int = Field(ge=0, strict=True)
    recovered_responses: int = Field(ge=0, strict=True)
    repair_attempts: int = Field(ge=0, strict=True)


class M3ProcessReport(FrozenContractModel):
    """Bounded run report that prominently identifies its simulated M3 authority."""

    schema_version: Literal["m3-process-report-v1"] = "m3-process-report-v1"
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    provider_profile: ReferenceToken
    perception_mode: Literal["SIMULATED PERCEPTION"]
    model_mode: Literal["FAKE VLM"]
    fixture_bundle_id: Sha256Hex
    fixture_entry_count: int = Field(ge=0, le=MAX_FAKE_VLM_FIXTURE_ENTRIES, strict=True)
    requested_case_id: ReferenceToken | None
    selection_limit: int = Field(gt=0, le=MAX_M3_PROCESS_CASES, strict=True)
    available_case_count: int = Field(ge=0, strict=True)
    selection_truncated: bool = Field(strict=True)
    outcomes: tuple[M3ProcessCaseOutcome, ...] = Field(max_length=MAX_M3_PROCESS_CASES)
    counts: M3ProcessCounts

    @field_validator("run_id", "provider_profile", "requested_case_id")
    @classmethod
    def validate_report_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M3 process report reference")

    @model_validator(mode="after")
    def validate_selection_and_counts(self) -> Self:
        keys = tuple(outcome.case_id for outcome in self.outcomes)
        if len(keys) != len(set(keys)):
            raise ValueError("M3 process outcomes must have unique case IDs")
        if keys != tuple(sorted(keys)):
            raise ValueError("M3 process outcomes must use stable case-ID order")
        if any(outcome.event_id == "" for outcome in self.outcomes):
            raise ValueError("M3 process outcomes require event references")

        selected = len(self.outcomes)
        if selected > self.selection_limit or selected > self.available_case_count:
            raise ValueError("M3 process selection exceeds its reported bound")
        if self.requested_case_id is not None:
            if (
                self.available_case_count != 1
                or selected != 1
                or self.outcomes[0].case_id != self.requested_case_id
                or self.selection_truncated
            ):
                raise ValueError("single-case M3 report has inconsistent selection scope")
        elif self.selection_truncated != (self.available_case_count > selected):
            raise ValueError("M3 process truncation flag conflicts with available cases")

        dispositions = tuple(outcome.disposition for outcome in self.outcomes)
        expected = M3ProcessCounts(
            selected_cases=selected,
            pipeline_invocations=sum(outcome.pipeline_invoked for outcome in self.outcomes),
            processed_cases=dispositions.count(M3ProcessDisposition.PROCESSED),
            deferred_to_backlog_cases=dispositions.count(M3ProcessDisposition.DEFERRED_TO_BACKLOG),
            observed_existing_cases=dispositions.count(M3ProcessDisposition.OBSERVED_EXISTING),
            skipped_not_ready_cases=dispositions.count(M3ProcessDisposition.SKIPPED_NOT_READY),
            cache_hits=sum(outcome.cache_hit_count for outcome in self.outcomes),
            recovered_responses=sum(outcome.recovered_response_count for outcome in self.outcomes),
            repair_attempts=sum(outcome.repair_attempt_count for outcome in self.outcomes),
        )
        if self.counts != expected:
            raise ValueError("M3 process counts conflict with case outcomes")
        return self


__all__ = [
    "MAX_FAKE_VLM_FIXTURE_ENTRIES",
    "MAX_FAKE_VLM_FIXTURE_RESPONSE_BYTES",
    "MAX_FAKE_VLM_FIXTURE_TOTAL_RESPONSE_BYTES",
    "MAX_M3_PROCESS_CASES",
    "FakeVLMFailureFixtureInput",
    "FakeVLMFixtureBundle",
    "FakeVLMFixtureDisposition",
    "FakeVLMFixtureInput",
    "FakeVLMResponseFixtureInput",
    "M3ProcessCaseOutcome",
    "M3ProcessCounts",
    "M3ProcessDisposition",
    "M3ProcessReport",
]
