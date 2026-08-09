"""Public read-model and command contracts for the local pilot UI."""

from __future__ import annotations

from typing import Literal, Self, TypeAlias

from pydantic import Field, field_validator, model_validator

from labcourt.contracts.base import ContractModel
from labcourt.contracts.enums import (
    AlertLevel,
    AppealStatus,
    CaseStatus,
    ScreeningDecision,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.pilot_report import PILOT_OPERATOR_DISCLAIMER
from labcourt.contracts.references import (
    ReferenceToken,
    require_portable_run_id,
    require_reference_token,
)

PilotUiStageKey: TypeAlias = Literal["VIDEO", "PERCEPTION", "EVIDENCE", "SCREENING", "REPORT"]
PilotUiStageState: TypeAlias = Literal[
    "PENDING", "IN_PROGRESS", "COMPLETE", "ATTENTION_REQUIRED", "UNAVAILABLE"
]
PilotUiRunState: TypeAlias = Literal[
    "INCOMPLETE", "RUNNING", "COMPLETE", "ATTENTION_REQUIRED", "INVALID"
]
PilotUiJobState: TypeAlias = Literal["IDLE", "RUNNING", "SUCCEEDED", "ATTENTION_REQUIRED", "FAILED"]
PilotUiTimelineKind: TypeAlias = Literal["CASE_START", "EVIDENCE", "CASE_END"]

_STAGE_ORDER: tuple[PilotUiStageKey, ...] = (
    "VIDEO",
    "PERCEPTION",
    "EVIDENCE",
    "SCREENING",
    "REPORT",
)


def _require_local_api_url(value: str) -> str:
    if (
        not value.startswith("/api/")
        or ".." in value
        or "\\" in value
        or any(character in value for character in ("\r", "\n", "\x00", "#"))
    ):
        raise ValueError("pilot UI media URL must be a local API path")
    return value


class PilotUiVideoOption(ContractModel):
    video_id: Sha256Hex
    display_name: str = Field(min_length=1, max_length=255)
    relative_path: str
    size_bytes: int = Field(gt=0, strict=True)
    matching_run_ids: tuple[ReferenceToken, ...] = Field(default=(), max_length=100)

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        if value in {".", ".."} or "/" in value or "\\" in value:
            raise ValueError("pilot UI video display name must be one filename")
        if not value.lower().endswith(".mp4"):
            raise ValueError("pilot UI only exposes MP4 video options")
        return value

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        controlled = require_safe_relative_posix_path(value)
        if not controlled.startswith("inputs/") or not controlled.lower().endswith(".mp4"):
            raise ValueError("pilot UI video must remain inside inputs")
        return controlled

    @field_validator("matching_run_ids")
    @classmethod
    def validate_matching_runs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        controlled = tuple(
            require_portable_run_id(value, "pilot UI matching run") for value in values
        )
        if controlled != tuple(sorted(set(controlled))):
            raise ValueError("pilot UI matching runs must be unique and stably ordered")
        return controlled


class PilotUiRunOption(ContractModel):
    run_id: ReferenceToken
    state: PilotUiRunState
    case_count: int = Field(ge=0, strict=True)
    alert_count: int = Field(ge=0, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot UI run")


class PilotUiStageProgress(ContractModel):
    key: PilotUiStageKey
    state: PilotUiStageState
    label: str = Field(min_length=1, max_length=32)
    summary: str = Field(min_length=1, max_length=160)


class PilotUiEvidenceView(ContractModel):
    crop_id: Sha256Hex
    role: Literal["PANORAMA", "SUBJECT", "FOCUS", "TEMPORAL"]
    frame_index: int = Field(ge=0, strict=True)
    time_millis: int = Field(ge=0, strict=True)
    integrity: Literal["VERIFIED", "MISSING", "HASH_MISMATCH", "NOT_AVAILABLE"]
    media_url: str | None = None
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)

    @field_validator("media_url")
    @classmethod
    def validate_media_url(cls, value: str | None) -> str | None:
        return _require_local_api_url(value) if value is not None else None

    @model_validator(mode="after")
    def validate_integrity(self) -> Self:
        if (self.integrity == "VERIFIED") != (self.media_url is not None):
            raise ValueError("only verified pilot UI evidence may expose media")
        return self


class PilotUiCaseSummary(ContractModel):
    case_id: ReferenceToken
    revision: int = Field(gt=0, strict=True)
    status: CaseStatus
    violation_type: ViolationType
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    start_time_millis: int = Field(ge=0, strict=True)
    end_time_millis: int = Field(gt=0, strict=True)
    screening_decision: ScreeningDecision | None = None
    screening_probability: float | None = Field(default=None, ge=0, le=1)
    final_decision: VerdictDecision | None = None
    alert_level: AlertLevel | None = None
    alert_rescinded: bool = Field(default=False, strict=True)
    human_review_required: bool = Field(strict=True)
    appeal_status: AppealStatus | None = None
    evidence: tuple[PilotUiEvidenceView, ...] = Field(max_length=12)

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "pilot UI case")

    @model_validator(mode="after")
    def validate_case(self) -> Self:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("pilot UI case frame interval must be non-empty")
        if self.start_time_millis >= self.end_time_millis:
            raise ValueError("pilot UI case time interval must be non-empty")
        if (self.screening_decision is None) != (self.screening_probability is None):
            raise ValueError("pilot UI screening projection must be complete")
        crop_ids = tuple(item.crop_id for item in self.evidence)
        if len(crop_ids) != len(set(crop_ids)):
            raise ValueError("pilot UI case evidence must be unique")
        return self


class PilotUiTimelineItem(ContractModel):
    item_id: Sha256Hex
    kind: PilotUiTimelineKind
    case_id: ReferenceToken
    frame_index: int = Field(ge=0, strict=True)
    time_millis: int = Field(ge=0, strict=True)
    label: str = Field(min_length=1, max_length=80)
    evidence_crop_id: Sha256Hex | None = None
    media_url: str | None = None

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "pilot UI timeline case")

    @field_validator("media_url")
    @classmethod
    def validate_media_url(cls, value: str | None) -> str | None:
        return _require_local_api_url(value) if value is not None else None

    @model_validator(mode="after")
    def validate_timeline_media(self) -> Self:
        has_evidence = self.evidence_crop_id is not None or self.media_url is not None
        if self.kind == "EVIDENCE":
            if self.evidence_crop_id is None:
                raise ValueError("pilot UI evidence timeline item requires a crop")
        elif has_evidence:
            raise ValueError("pilot UI boundary timeline item cannot claim evidence media")
        return self


class PilotUiAlertView(ContractModel):
    alert_id: Sha256Hex
    case_id: ReferenceToken
    level: AlertLevel
    final_decision: VerdictDecision
    recipients: tuple[ReferenceToken, ...]
    rescinded: bool = Field(strict=True)
    production_action_prohibited: Literal[True] = True

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "pilot UI alert case")

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        controlled = tuple(
            require_reference_token(value, "pilot UI alert recipient") for value in values
        )
        if len(controlled) != len(set(controlled)):
            raise ValueError("pilot UI alert recipients must be unique")
        return controlled


class PilotUiDashboard(ContractModel):
    schema_version: Literal["pilot-ui-dashboard-v1"] = "pilot-ui-dashboard-v1"
    selected_run_id: ReferenceToken | None = None
    selected_video_id: Sha256Hex | None = None
    videos: tuple[PilotUiVideoOption, ...] = Field(max_length=100)
    runs: tuple[PilotUiRunOption, ...] = Field(max_length=100)
    stages: tuple[PilotUiStageProgress, ...] = Field(min_length=5, max_length=5)
    preview_kind: Literal["NONE", "SOURCE", "DEBUG"]
    preview_url: str | None = None
    fps_num: int | None = Field(default=None, gt=0, strict=True)
    fps_den: int | None = Field(default=None, gt=0, strict=True)
    frame_count: int | None = Field(default=None, ge=0, strict=True)
    duration_millis: int | None = Field(default=None, ge=0, strict=True)
    manifest_id: Sha256Hex | None = None
    metrics_id: Sha256Hex | None = None
    cases: tuple[PilotUiCaseSummary, ...]
    timeline: tuple[PilotUiTimelineItem, ...]
    alerts: tuple[PilotUiAlertView, ...]
    production_delivery_count: Literal[0] = 0
    disclaimer: Literal[
        "用于安全辅助与记录，不直接作为处罚依据"  # noqa: RUF001
    ] = PILOT_OPERATOR_DISCLAIMER

    @field_validator("selected_run_id")
    @classmethod
    def validate_selected_run_id(cls, value: str | None) -> str | None:
        return (
            require_portable_run_id(value, "pilot UI selected run") if value is not None else None
        )

    @field_validator("preview_url")
    @classmethod
    def validate_preview_url(cls, value: str | None) -> str | None:
        return _require_local_api_url(value) if value is not None else None

    @model_validator(mode="after")
    def validate_dashboard(self) -> Self:
        if tuple(stage.key for stage in self.stages) != _STAGE_ORDER:
            raise ValueError("pilot UI stage order must match the product workflow")
        video_ids = tuple(item.video_id for item in self.videos)
        if len(video_ids) != len(set(video_ids)):
            raise ValueError("pilot UI videos must be unique")
        run_ids = tuple(item.run_id for item in self.runs)
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("pilot UI runs must be unique")
        if self.selected_video_id is not None and self.selected_video_id not in video_ids:
            raise ValueError("pilot UI selected video is not available")
        if self.selected_run_id is not None and self.selected_run_id not in run_ids:
            raise ValueError("pilot UI selected run is not available")
        timing = (self.fps_num, self.fps_den, self.frame_count, self.duration_millis)
        if any(value is None for value in timing) != all(value is None for value in timing):
            raise ValueError("pilot UI timing projection must be complete when present")
        if self.fps_num is not None:
            assert self.fps_den is not None
            assert self.frame_count is not None
            assert self.duration_millis is not None
            expected_duration = (
                self.frame_count * 1000 * self.fps_den + self.fps_num - 1
            ) // self.fps_num
            if self.duration_millis != expected_duration:
                raise ValueError("pilot UI duration conflicts with manifest timing")
        if (self.preview_kind == "NONE") != (self.preview_url is None):
            raise ValueError("pilot UI preview kind conflicts with its URL")
        case_ids = tuple(item.case_id for item in self.cases)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("pilot UI cases must be unique")
        if any(item.case_id not in case_ids for item in self.timeline) or any(
            item.case_id not in case_ids for item in self.alerts
        ):
            raise ValueError("pilot UI timeline or alert is outside the selected cases")
        kind_order = {"CASE_START": 0, "EVIDENCE": 1, "CASE_END": 2}
        timeline_order = tuple(
            (item.time_millis, kind_order[item.kind], item.item_id) for item in self.timeline
        )
        if timeline_order != tuple(sorted(timeline_order)):
            raise ValueError("pilot UI timeline must be stably ordered")
        if self.selected_run_id is None and any(
            (
                self.manifest_id is not None,
                self.metrics_id is not None,
                bool(self.cases),
                bool(self.timeline),
                bool(self.alerts),
            )
        ):
            raise ValueError("pilot UI cannot expose run authority without a selected run")
        return self


class PilotUiJobStartRequest(ContractModel):
    video_id: Sha256Hex
    run_id: ReferenceToken
    resume: bool = Field(default=True, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot UI job run")


class PilotUiJobStatus(ContractModel):
    schema_version: Literal["pilot-ui-job-status-v1"] = "pilot-ui-job-status-v1"
    job_id: ReferenceToken | None = None
    state: PilotUiJobState = "IDLE"
    run_id: ReferenceToken | None = None
    video_id: Sha256Hex | None = None
    active_stage: PilotUiStageKey | None = None
    reason_code: ReferenceToken | None = None
    report_id: Sha256Hex | None = None

    @field_validator("job_id", "reason_code")
    @classmethod
    def validate_reference(cls, value: str | None) -> str | None:
        return (
            require_reference_token(value, "pilot UI job reference") if value is not None else None
        )

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str | None) -> str | None:
        return require_portable_run_id(value, "pilot UI job run") if value is not None else None

    @model_validator(mode="after")
    def validate_job_state(self) -> Self:
        if self.state == "IDLE":
            if any(
                value is not None
                for value in (
                    self.job_id,
                    self.run_id,
                    self.video_id,
                    self.active_stage,
                    self.reason_code,
                    self.report_id,
                )
            ):
                raise ValueError("idle job cannot claim execution state")
            return self
        if self.job_id is None or self.run_id is None or self.video_id is None:
            raise ValueError("non-idle pilot UI job requires its identity")
        if (self.state == "RUNNING") != (self.active_stage is not None):
            raise ValueError("pilot UI active stage is only valid while running")
        if (self.state == "FAILED") != (self.reason_code is not None):
            raise ValueError("pilot UI failed job requires exactly one failure reason")
        if self.state in {"SUCCEEDED", "ATTENTION_REQUIRED"}:
            if self.report_id is None:
                raise ValueError("completed pilot UI job requires its A5 report")
        elif self.report_id is not None:
            raise ValueError("incomplete pilot UI job cannot claim an A5 report")
        return self


class PilotUiErrorResponse(ContractModel):
    schema_version: Literal["pilot-ui-error-v1"] = "pilot-ui-error-v1"
    status: Literal["FAILED"] = "FAILED"
    reason_code: ReferenceToken

    @field_validator("reason_code")
    @classmethod
    def validate_reason_code(cls, value: str) -> str:
        return require_reference_token(value, "pilot UI error reason")


__all__ = [
    "PilotUiAlertView",
    "PilotUiCaseSummary",
    "PilotUiDashboard",
    "PilotUiErrorResponse",
    "PilotUiEvidenceView",
    "PilotUiJobStartRequest",
    "PilotUiJobState",
    "PilotUiJobStatus",
    "PilotUiRunOption",
    "PilotUiRunState",
    "PilotUiStageKey",
    "PilotUiStageProgress",
    "PilotUiStageState",
    "PilotUiTimelineItem",
    "PilotUiTimelineKind",
    "PilotUiVideoOption",
]
