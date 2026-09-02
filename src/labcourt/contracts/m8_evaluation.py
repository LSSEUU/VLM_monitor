"""Additive M8 contracts for real-media evaluation and bounded live ingest."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import Field, computed_field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import CaseStatus, EvidenceClass, ViolationType
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_hearing_api import M8HearingEligibility, M8HearingL5Status
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import (
    ReferenceToken,
    require_portable_run_id,
    require_reference_token,
)

MAX_M8_EVALUATION_ASSETS = 100
MAX_M8_EVALUATION_REPETITIONS = 10
MAX_M8_EVALUATION_MEDIA_BYTES = 1_073_741_824
MAX_M8_EVALUATION_INTERVALS = 2_000
MAX_M8_LIVE_RING_BUFFER_SECONDS = 3_600
M8_LIVE_TARGET_ANALYSIS_FPS = 5
M8_LIVE_TARGET_P95_LATENCY_MS = 2_000

_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{name} must use timezone-aware UTC")
    return value


def _require_mp4_filename(value: str, name: str) -> str:
    if (
        not value
        or len(value) > 255
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or not value.casefold().endswith(".mp4")
    ):
        raise ValueError(f"{name} must be one bounded MP4 filename")
    return value


class M8EvaluationMediaOrigin(StrEnum):
    WEB_UPLOAD = "WEB_UPLOAD"
    SERVER_DIRECTORY = "SERVER_DIRECTORY"
    LIVE_CAPTURE_SEGMENT = "LIVE_CAPTURE_SEGMENT"


class M8EvaluationPpeState(StrEnum):
    WORN = "WORN"
    NOT_WORN = "NOT_WORN"
    UNCLEAR = "UNCLEAR"


class M8EvaluationExpectedRoute(StrEnum):
    NO_CANDIDATE = "NO_CANDIDATE"
    FAST_VERDICT = "FAST_VERDICT"
    HEARING = "HEARING"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class M8EvaluationActualRoute(StrEnum):
    NO_CANDIDATE = "NO_CANDIDATE"
    FAST_VERDICT = "FAST_VERDICT"
    HEARING_REQUIRED = "HEARING_REQUIRED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    TECHNICAL_FAILURE = "TECHNICAL_FAILURE"


class M8EvaluationReviewState(StrEnum):
    DRAFT = "DRAFT"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"


class M8EvaluationCampaignState(StrEnum):
    DRAFT = "DRAFT"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    AWAITING_HUMAN = "AWAITING_HUMAN"
    COMPLETED = "COMPLETED"
    PARTIAL_FAILED = "PARTIAL_FAILED"


class M8EvaluationRunState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    AWAITING_HEARING = "AWAITING_HEARING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class M8EvaluationRunSourceKind(StrEnum):
    RECORDED_ASSET = "RECORDED_ASSET"
    LIVE_CAPTURE_SEGMENT = "LIVE_CAPTURE_SEGMENT"


class M8EvaluationDeliveryState(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING_POLICY = "PENDING_POLICY"
    ACTIVATION_REQUIRED = "ACTIVATION_REQUIRED"
    QUEUED = "QUEUED"
    SENT = "SENT"
    FAILED = "FAILED"


class M8LiveIngestState(StrEnum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class M8EvaluationMediaAssetV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-media-asset-v1"] = "m8-evaluation-media-asset-v1"
    asset_id: Sha256Hex
    display_name: str
    media_sha256: Sha256Hex
    size_bytes: int = Field(gt=0, le=MAX_M8_EVALUATION_MEDIA_BYTES, strict=True)
    relative_path: str
    origin: M8EvaluationMediaOrigin
    codec: str = Field(min_length=1, max_length=64)
    width: int = Field(gt=0, le=32_768, strict=True)
    height: int = Field(gt=0, le=32_768, strict=True)
    fps_num: int = Field(gt=0, strict=True)
    fps_den: int = Field(gt=0, strict=True)
    frame_count: int = Field(gt=0, strict=True)
    duration_millis: int = Field(gt=0, strict=True)
    imported_by_actor_id: ReferenceToken
    imported_at: datetime
    media_manifest_id: Sha256Hex
    machine_output_is_ground_truth: Literal[False] = False

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        return _require_mp4_filename(value, "M8 evaluation display_name")

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        controlled = require_safe_relative_posix_path(value)
        path = PurePosixPath(controlled)
        if (
            len(path.parts) != 2
            or path.parts[0] != "inputs"
            or not path.name.startswith("evaluation-")
            or not path.name.casefold().endswith(".mp4")
        ):
            raise ValueError("M8 evaluation media must use its controlled inputs path")
        return controlled

    @field_validator("imported_by_actor_id")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        return require_reference_token(value, "M8 evaluation importer")

    @field_validator("imported_at")
    @classmethod
    def validate_imported_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M8 evaluation imported_at")

    @model_validator(mode="after")
    def validate_content_identity(self) -> Self:
        if self.asset_id != self.media_sha256:
            raise ValueError("M8 evaluation asset identity must equal its media SHA-256")
        expected_duration = (
            self.frame_count * 1_000 * self.fps_den + self.fps_num - 1
        ) // self.fps_num
        if self.duration_millis != expected_duration:
            raise ValueError("M8 evaluation duration must derive from frame count and FPS")
        return self


class M8EvaluationMediaImportRequestV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-media-import-request-v1"] = (
        "m8-evaluation-media-import-request-v1"
    )
    relative_paths: tuple[str, ...] = Field(default=(), max_length=MAX_M8_EVALUATION_ASSETS)
    explicit_human_confirmation: Literal[True]

    @field_validator("relative_paths")
    @classmethod
    def validate_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        controlled: list[str] = []
        for value in values:
            path = require_safe_relative_posix_path(value)
            if not (
                path.startswith("inputs/") or path.startswith("evaluation-import/")
            ) or not path.casefold().endswith(".mp4"):
                raise ValueError("M8 evaluation import must remain in a configured MP4 root")
            controlled.append(path)
        if tuple(controlled) != tuple(sorted(set(controlled))):
            raise ValueError("M8 evaluation import paths must be unique and stably ordered")
        return tuple(controlled)


class M8EvaluationLabelIntervalV1(FrozenContractModel):
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    ppe_state: M8EvaluationPpeState

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("M8 evaluation label interval must be non-empty")
        return self


class M8EvaluationGroundTruthV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-ground-truth-v1"] = "m8-evaluation-ground-truth-v1"
    asset_id: Sha256Hex
    revision: int = Field(gt=0, strict=True)
    violation_type: ViolationType
    evidence_class: EvidenceClass
    intervals: tuple[M8EvaluationLabelIntervalV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_EVALUATION_INTERVALS,
    )
    expected_route: M8EvaluationExpectedRoute
    review_state: M8EvaluationReviewState
    reviewer_actor_id: ReferenceToken
    reviewed_at: datetime | None = None
    label_manifest_id: Sha256Hex
    machine_output_is_ground_truth: Literal[False] = False

    @field_validator("reviewer_actor_id")
    @classmethod
    def validate_reviewer(cls, value: str) -> str:
        return require_reference_token(value, "M8 evaluation reviewer")

    @field_validator("reviewed_at")
    @classmethod
    def validate_reviewed_at(cls, value: datetime | None) -> datetime | None:
        return _require_utc(value, "M8 evaluation reviewed_at") if value is not None else None

    @model_validator(mode="after")
    def validate_truth(self) -> Self:
        if self.evidence_class != EvidenceClass.ABSENCE:
            raise ValueError("M8 evaluation v1 supports the PPE absence evidence class")
        if self.violation_type != ViolationType.PPE_GOGGLES_MISSING:
            raise ValueError("M8 evaluation v1 supports the goggles-missing scenario")
        if (self.review_state == M8EvaluationReviewState.HUMAN_CONFIRMED) != (
            self.reviewed_at is not None
        ):
            raise ValueError("human-confirmed ground truth requires exactly one review time")
        previous_end = -1
        for interval in self.intervals:
            if interval.start_frame < previous_end:
                raise ValueError("M8 evaluation label intervals must not overlap")
            previous_end = interval.end_frame_exclusive
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ground_truth_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-evaluation-ground-truth",
                1,
                self.asset_id,
                self.revision,
                self.violation_type,
                self.evidence_class,
                tuple(item.model_dump(mode="json") for item in self.intervals),
                self.expected_route,
                self.review_state,
                self.reviewer_actor_id,
                self.reviewed_at.isoformat() if self.reviewed_at else None,
                self.label_manifest_id,
                self.machine_output_is_ground_truth,
            ]
        )


class M8EvaluationGroundTruthImportRequestV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-ground-truth-import-request-v1"] = (
        "m8-evaluation-ground-truth-import-request-v1"
    )
    labels: tuple[M8EvaluationGroundTruthV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_EVALUATION_ASSETS,
    )
    explicit_human_confirmation: Literal[True]

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        asset_ids = tuple(item.asset_id for item in self.labels)
        if asset_ids != tuple(sorted(set(asset_ids))):
            raise ValueError("ground-truth import must use unique stable asset order")
        return self


class M8RunSourceRefV1(FrozenContractModel):
    schema_version: Literal["m8-run-source-ref-v1"] = "m8-run-source-ref-v1"
    run_id: ReferenceToken
    source_kind: M8EvaluationRunSourceKind
    asset_id: Sha256Hex
    media_sha256: Sha256Hex
    relative_path: str
    frame_count: int = Field(gt=0, strict=True)
    source_manifest_id: Sha256Hex
    capture_segment_id: Sha256Hex | None = None

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M8 evaluation source run")

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        controlled = require_safe_relative_posix_path(value)
        if not controlled.startswith("inputs/") or not controlled.casefold().endswith(".mp4"):
            raise ValueError("M8 run source must remain in the controlled inputs root")
        return controlled

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.asset_id != self.media_sha256:
            raise ValueError("M8 run source must bind the content-addressed asset")
        is_segment = self.source_kind == M8EvaluationRunSourceKind.LIVE_CAPTURE_SEGMENT
        if is_segment != (self.capture_segment_id is not None):
            raise ValueError("only live capture sources require a segment identity")
        return self


class M8EvaluationCampaignCreateRequestV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-campaign-create-request-v1"] = (
        "m8-evaluation-campaign-create-request-v1"
    )
    title: str = Field(min_length=1, max_length=120)
    asset_ids: tuple[Sha256Hex, ...] = Field(
        min_length=1,
        max_length=MAX_M8_EVALUATION_ASSETS,
    )
    repetitions: int = Field(
        default=1,
        ge=1,
        le=MAX_M8_EVALUATION_REPETITIONS,
        strict=True,
    )
    execution_profile: Literal["REAL_MODELS"] = "REAL_MODELS"
    notification_delivery: Literal["LIVE_SANDBOX"] = "LIVE_SANDBOX"
    explicit_human_confirmation: Literal[True]

    @field_validator("asset_ids")
    @classmethod
    def validate_assets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("M8 evaluation campaign assets must be unique and stable")
        return values


class M8EvaluationCampaignStartRequestV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-campaign-start-request-v1"] = (
        "m8-evaluation-campaign-start-request-v1"
    )
    explicit_human_confirmation: Literal[True]


class M8EvaluationCampaignV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-campaign-v1"] = "m8-evaluation-campaign-v1"
    campaign_id: ReferenceToken
    revision: int = Field(gt=0, strict=True)
    title: str = Field(min_length=1, max_length=120)
    asset_ids: tuple[Sha256Hex, ...] = Field(
        min_length=1,
        max_length=MAX_M8_EVALUATION_ASSETS,
    )
    run_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M8_EVALUATION_ASSETS * MAX_M8_EVALUATION_REPETITIONS,
    )
    repetitions: int = Field(ge=1, le=MAX_M8_EVALUATION_REPETITIONS, strict=True)
    state: M8EvaluationCampaignState
    created_by_actor_id: ReferenceToken
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    config_sha256: Sha256Hex
    model_profile_sha256: Sha256Hex
    campaign_manifest_id: Sha256Hex

    @field_validator("campaign_id", "created_by_actor_id")
    @classmethod
    def validate_refs(cls, value: str) -> str:
        return require_reference_token(value, "M8 evaluation campaign reference")

    @field_validator("run_ids")
    @classmethod
    def validate_run_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        controlled = tuple(
            require_portable_run_id(value, "M8 evaluation campaign run") for value in values
        )
        if len(controlled) != len(set(controlled)):
            raise ValueError("M8 evaluation campaign runs must be unique")
        return controlled

    @field_validator("created_at", "started_at", "completed_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        return _require_utc(value, "M8 evaluation campaign time") if value else None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        started = self.state != M8EvaluationCampaignState.DRAFT
        terminal = self.state in {
            M8EvaluationCampaignState.COMPLETED,
            M8EvaluationCampaignState.PARTIAL_FAILED,
        }
        if started != (self.started_at is not None):
            raise ValueError("started M8 evaluation campaign requires its start time")
        if terminal != (self.completed_at is not None):
            raise ValueError("terminal M8 evaluation campaign requires its completion time")
        expected_runs = len(self.asset_ids) * self.repetitions
        if self.run_ids and len(self.run_ids) != expected_runs:
            raise ValueError("M8 evaluation campaign run inventory is incomplete")
        if self.created_at > (self.started_at or self.created_at):
            raise ValueError("M8 evaluation campaign cannot start before creation")
        if self.completed_at and self.started_at and self.completed_at < self.started_at:
            raise ValueError("M8 evaluation campaign cannot complete before it starts")
        return self


class M8EvaluationRunV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-run-v1"] = "m8-evaluation-run-v1"
    run_id: ReferenceToken
    revision: int = Field(gt=0, strict=True)
    campaign_id: ReferenceToken
    source: M8RunSourceRefV1
    ordinal: int = Field(ge=0, strict=True)
    repetition: int = Field(ge=1, le=MAX_M8_EVALUATION_REPETITIONS, strict=True)
    state: M8EvaluationRunState
    active_stage: str | None = Field(default=None, min_length=1, max_length=64)
    actual_route: M8EvaluationActualRoute | None = None
    case_id: ReferenceToken | None = None
    hearing_case_id: ReferenceToken | None = None
    m4_case_status: CaseStatus | None = None
    hearing_eligibility: M8HearingEligibility | None = None
    l5_status: M8HearingL5Status | None = None
    notification_id: ReferenceToken | None = None
    ground_truth_id: Sha256Hex | None = None
    accuracy_metrics_eligible: bool = Field(strict=True)
    delivery_state: M8EvaluationDeliveryState
    failure_code: ReferenceToken | None = None
    route_reason_code: ReferenceToken | None = None
    queued_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    config_sha256: Sha256Hex
    model_profile_sha256: Sha256Hex
    provider_receipt_refs: tuple[str, ...] = Field(default=(), max_length=32)
    run_manifest_id: Sha256Hex

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M8 evaluation run")

    @field_validator("campaign_id", "case_id", "hearing_case_id", "notification_id")
    @classmethod
    def validate_refs(cls, value: str | None) -> str | None:
        return (
            require_reference_token(value, "M8 evaluation run reference")
            if value is not None
            else None
        )

    @field_validator("failure_code", "route_reason_code")
    @classmethod
    def validate_reason_code(cls, value: str | None) -> str | None:
        return require_reference_token(value, "M8 evaluation reason") if value is not None else None

    @field_validator("queued_at", "started_at", "completed_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        return _require_utc(value, "M8 evaluation run time") if value else None

    @model_validator(mode="after")
    def validate_run(self) -> Self:
        if self.source.run_id != self.run_id:
            raise ValueError("M8 evaluation run source belongs to another run")
        running = self.state == M8EvaluationRunState.RUNNING
        terminal = self.state in {
            M8EvaluationRunState.SUCCEEDED,
            M8EvaluationRunState.FAILED,
        }
        if (self.state != M8EvaluationRunState.QUEUED) != (self.started_at is not None):
            raise ValueError("started M8 evaluation run requires exactly one start time")
        if terminal != (self.completed_at is not None):
            raise ValueError("terminal M8 evaluation run requires exactly one completion time")
        if running != (self.active_stage is not None):
            raise ValueError("only a running M8 evaluation run exposes an active stage")
        if (self.state == M8EvaluationRunState.FAILED) != (self.failure_code is not None):
            raise ValueError("failed M8 evaluation run requires exactly one failure code")
        routed = terminal or self.state == M8EvaluationRunState.AWAITING_HEARING
        if routed != (self.actual_route is not None):
            raise ValueError(
                "terminal or hearing-waiting M8 evaluation run requires exactly one actual route"
            )
        if (
            self.state == M8EvaluationRunState.AWAITING_HEARING
            and self.actual_route != M8EvaluationActualRoute.HEARING_REQUIRED
        ):
            raise ValueError("hearing-waiting M8 evaluation run requires the hearing route")
        if self.route_reason_code is not None and (
            self.actual_route != M8EvaluationActualRoute.HUMAN_REVIEW
        ):
            raise ValueError("M8 evaluation route reason currently belongs to human review")
        if self.hearing_case_id is not None and self.case_id is None:
            raise ValueError("M8 evaluation hearing projection requires an operational Case")
        if self.accuracy_metrics_eligible != (self.ground_truth_id is not None):
            raise ValueError("only human-confirmed truth may enable accuracy metrics")
        if self.completed_at and self.started_at and self.completed_at < self.started_at:
            raise ValueError("M8 evaluation run cannot complete before it starts")
        return self


class M8EvaluationDashboardV1(FrozenContractModel):
    schema_version: Literal["m8-evaluation-dashboard-v1"] = "m8-evaluation-dashboard-v1"
    media: tuple[M8EvaluationMediaAssetV1, ...] = Field(
        default=(), max_length=MAX_M8_EVALUATION_ASSETS
    )
    ground_truth: tuple[M8EvaluationGroundTruthV1, ...] = Field(
        default=(), max_length=MAX_M8_EVALUATION_ASSETS
    )
    campaigns: tuple[M8EvaluationCampaignV1, ...] = Field(
        default=(), max_length=MAX_M8_EVALUATION_ASSETS
    )
    runs: tuple[M8EvaluationRunV1, ...] = Field(
        default=(),
        max_length=MAX_M8_EVALUATION_ASSETS * MAX_M8_EVALUATION_REPETITIONS,
    )
    import_roots: tuple[Literal["inputs", "evaluation-import"], ...] = (
        "inputs",
        "evaluation-import",
    )
    real_models_required: Literal[True] = True
    fixture_fallback_permitted: Literal[False] = False


class M8LiveIngestStartRequestV1(FrozenContractModel):
    schema_version: Literal["m8-live-ingest-start-request-v1"] = "m8-live-ingest-start-request-v1"
    candidate_authority_id: Sha256Hex
    source_id: ReferenceToken
    endpoint_environment_variable: str
    analysis_fps: Literal[5] = 5
    ring_buffer_seconds: int = Field(
        default=60,
        ge=60,
        le=MAX_M8_LIVE_RING_BUFFER_SECONDS,
        strict=True,
    )
    explicit_human_confirmation: Literal[True]

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 live source")

    @field_validator("endpoint_environment_variable")
    @classmethod
    def validate_endpoint_environment_variable(cls, value: str) -> str:
        if _ENVIRONMENT_NAME.fullmatch(value) is None:
            raise ValueError("M8 live endpoint must use one explicit environment variable")
        return value


class M8LiveIngestSessionV1(FrozenContractModel):
    schema_version: Literal["m8-live-ingest-session-v1"] = "m8-live-ingest-session-v1"
    session_id: ReferenceToken
    revision: int = Field(gt=0, strict=True)
    candidate_authority_id: Sha256Hex
    source_id: ReferenceToken
    endpoint_reference: str
    state: M8LiveIngestState
    analysis_fps: Literal[5] = 5
    ring_buffer_seconds: int = Field(
        ge=60,
        le=MAX_M8_LIVE_RING_BUFFER_SECONDS,
        strict=True,
    )
    started_at: datetime
    stopped_at: datetime | None = None
    frames_ingested: int = Field(ge=0, strict=True)
    frames_analyzed: int = Field(ge=0, strict=True)
    frames_dropped: int = Field(ge=0, strict=True)
    reconnect_count: int = Field(ge=0, strict=True)
    backlog_depth: int = Field(ge=0, strict=True)
    p95_analysis_latency_ms: int | None = Field(default=None, ge=0, strict=True)
    observed_duration_millis: int = Field(ge=0, strict=True)
    failure_code: ReferenceToken | None = None
    ingest_manifest_id: Sha256Hex
    life_safety_authority: Literal[False] = False

    @field_validator("session_id", "source_id")
    @classmethod
    def validate_refs(cls, value: str) -> str:
        return require_reference_token(value, "M8 live ingest reference")

    @field_validator("endpoint_reference")
    @classmethod
    def validate_endpoint_reference(cls, value: str) -> str:
        if not value.startswith("env:") or _ENVIRONMENT_NAME.fullmatch(value[4:]) is None:
            raise ValueError("M8 live session must retain only an environment reference")
        return value

    @field_validator("started_at", "stopped_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        return _require_utc(value, "M8 live ingest time") if value else None

    @field_validator("failure_code")
    @classmethod
    def validate_failure(cls, value: str | None) -> str | None:
        return (
            require_reference_token(value, "M8 live ingest failure") if value is not None else None
        )

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        terminal = self.state in {M8LiveIngestState.STOPPED, M8LiveIngestState.FAILED}
        if terminal != (self.stopped_at is not None):
            raise ValueError("terminal M8 live session requires exactly one stop time")
        if (self.state == M8LiveIngestState.FAILED) != (self.failure_code is not None):
            raise ValueError("failed M8 live session requires exactly one failure code")
        if self.frames_analyzed > self.frames_ingested:
            raise ValueError("M8 live session cannot analyze more frames than it ingested")
        if self.stopped_at and self.stopped_at < self.started_at:
            raise ValueError("M8 live session cannot stop before it starts")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_analysis_fps(self) -> int:
        return M8_LIVE_TARGET_ANALYSIS_FPS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_p95_latency_ms(self) -> int:
        return M8_LIVE_TARGET_P95_LATENCY_MS

    @computed_field  # type: ignore[prop-decorator]
    @property
    def realtime_claim_permitted(self) -> bool:
        return bool(
            self.state in {M8LiveIngestState.RUNNING, M8LiveIngestState.STOPPED}
            and self.observed_duration_millis >= 30 * 60 * 1_000
            and self.frames_analyzed * 1_000
            >= M8_LIVE_TARGET_ANALYSIS_FPS * self.observed_duration_millis
            and self.backlog_depth == 0
            and self.p95_analysis_latency_ms is not None
            and self.p95_analysis_latency_ms <= M8_LIVE_TARGET_P95_LATENCY_MS
        )


class M8CaptureSegmentV1(FrozenContractModel):
    schema_version: Literal["m8-capture-segment-v1"] = "m8-capture-segment-v1"
    segment_id: Sha256Hex
    session_id: ReferenceToken
    asset: M8EvaluationMediaAssetV1
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    lookahead_seconds: Literal[10] = 10
    captured_at: datetime
    capture_manifest_id: Sha256Hex
    immutable: Literal[True] = True

    @field_validator("session_id")
    @classmethod
    def validate_session(cls, value: str) -> str:
        return require_reference_token(value, "M8 capture session")

    @field_validator("captured_at")
    @classmethod
    def validate_captured_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M8 captured_at")

    @model_validator(mode="after")
    def validate_segment(self) -> Self:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("M8 capture segment interval must be non-empty")
        if self.asset.origin != M8EvaluationMediaOrigin.LIVE_CAPTURE_SEGMENT:
            raise ValueError("M8 capture segment must bind a live-capture media asset")
        expected = sha256_hex(
            [
                "m8-capture-segment",
                1,
                self.session_id,
                self.asset.asset_id,
                self.start_frame,
                self.end_frame_exclusive,
                self.lookahead_seconds,
                self.capture_manifest_id,
            ]
        )
        if self.segment_id != expected:
            raise ValueError("M8 capture segment identity does not match its immutable cut")
        return self


__all__ = [
    "MAX_M8_EVALUATION_ASSETS",
    "MAX_M8_EVALUATION_INTERVALS",
    "MAX_M8_EVALUATION_MEDIA_BYTES",
    "MAX_M8_EVALUATION_REPETITIONS",
    "MAX_M8_LIVE_RING_BUFFER_SECONDS",
    "M8CaptureSegmentV1",
    "M8EvaluationActualRoute",
    "M8EvaluationCampaignCreateRequestV1",
    "M8EvaluationCampaignStartRequestV1",
    "M8EvaluationCampaignState",
    "M8EvaluationCampaignV1",
    "M8EvaluationDashboardV1",
    "M8EvaluationDeliveryState",
    "M8EvaluationExpectedRoute",
    "M8EvaluationGroundTruthImportRequestV1",
    "M8EvaluationGroundTruthV1",
    "M8EvaluationLabelIntervalV1",
    "M8EvaluationMediaAssetV1",
    "M8EvaluationMediaImportRequestV1",
    "M8EvaluationMediaOrigin",
    "M8EvaluationPpeState",
    "M8EvaluationReviewState",
    "M8EvaluationRunSourceKind",
    "M8EvaluationRunState",
    "M8EvaluationRunV1",
    "M8LiveIngestSessionV1",
    "M8LiveIngestStartRequestV1",
    "M8LiveIngestState",
    "M8RunSourceRefV1",
]
