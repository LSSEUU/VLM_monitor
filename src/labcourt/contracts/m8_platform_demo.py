"""Typed contracts for the offline campus-operations platform Demo."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, computed_field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorRole, M8OperationalCaseStatus
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_notification_lifecycle import M8NotificationReplyKind
from labcourt.contracts.references import (
    ReferenceToken,
    require_portable_run_id,
    require_reference_token,
)


class M8PlatformScenarioKind(StrEnum):
    PPE_GOGGLES_MISSING = "PPE_GOGGLES_MISSING"
    SMOKE_TEMPERATURE_EMERGENCY = "SMOKE_TEMPERATURE_EMERGENCY"


class M8PlatformRecognitionMode(StrEnum):
    FULL_MODEL = "FULL_MODEL"
    DEMO_FIXTURE = "DEMO_FIXTURE"


class M8PlatformExecutionSource(StrEnum):
    MODEL = "MODEL"
    FIXTURE = "FIXTURE"


class M8PlatformScenarioStage(StrEnum):
    VIDEO = "VIDEO"
    PERCEPTION = "PERCEPTION"
    EVIDENCE = "EVIDENCE"
    SCREENING = "SCREENING"
    CASE = "CASE"
    NOTIFICATION = "NOTIFICATION"


class M8PlatformStageState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class M8PlatformAgentActionKind(StrEnum):
    CASE_TRANSITION = "CASE_TRANSITION"
    RUN_SCENARIO = "RUN_SCENARIO"
    RESET_DEMO = "RESET_DEMO"


class M8PlatformLoginRequestV1(FrozenContractModel):
    schema_version: Literal["m8-platform-login-request-v1"] = "m8-platform-login-request-v1"
    role: M8ActorRole


class M8PlatformLoginResponseV1(FrozenContractModel):
    schema_version: Literal["m8-platform-login-response-v1"] = "m8-platform-login-response-v1"
    bearer_token: str = Field(min_length=16, max_length=256)
    session: M8ActorAuthorityCommitReceiptV1
    personal_demo_only: Literal[True] = True
    production_ready: Literal[False] = False


class M8PlatformReservationAuthorityV1(FrozenContractModel):
    schema_version: Literal["m8-platform-reservation-authority-v1"] = (
        "m8-platform-reservation-authority-v1"
    )
    reservation_id: ReferenceToken
    actor_id: ReferenceToken
    location_id: ReferenceToken
    starts_at: datetime
    ends_at: datetime
    active: Literal[True] = True
    association_notice: Literal["预约关联，非视觉身份识别"] = (  # noqa: RUF001
        "预约关联，非视觉身份识别"  # noqa: RUF001
    )
    face_recognition_performed: Literal[False] = False
    cross_camera_reidentification_performed: Literal[False] = False
    manifest_id: Sha256Hex

    @field_validator("reservation_id", "actor_id", "location_id")
    @classmethod
    def validate_refs(cls, value: str) -> str:
        return require_reference_token(value, "M8 platform reservation reference")

    @field_validator("starts_at", "ends_at")
    @classmethod
    def validate_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("M8 platform reservation time must use UTC")
        return value

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if self.starts_at >= self.ends_at:
            raise ValueError("M8 platform reservation requires a positive window")
        return self


class M8PlatformScenarioStartRequestV1(FrozenContractModel):
    schema_version: Literal["m8-platform-scenario-start-request-v1"] = (
        "m8-platform-scenario-start-request-v1"
    )
    scenario_kind: M8PlatformScenarioKind
    recognition_mode: M8PlatformRecognitionMode | None = None
    retry_of_run_id: ReferenceToken | None = None
    explicit_human_confirmation: Literal[True]

    @field_validator("retry_of_run_id")
    @classmethod
    def validate_retry_ref(cls, value: str | None) -> str | None:
        return (
            require_portable_run_id(value, "M8 platform retry run")
            if value is not None
            else None
        )

    @model_validator(mode="after")
    def validate_execution_choice(self) -> Self:
        is_ppe = self.scenario_kind == M8PlatformScenarioKind.PPE_GOGGLES_MISSING
        if is_ppe != (self.recognition_mode is not None):
            raise ValueError("only PPE scenario starts require an explicit recognition mode")
        if self.retry_of_run_id is not None and (
            not is_ppe or self.recognition_mode != M8PlatformRecognitionMode.DEMO_FIXTURE
        ):
            raise ValueError("only explicit PPE fixture fallback may reference a failed run")
        return self


class M8PlatformScenarioStageV1(FrozenContractModel):
    stage: M8PlatformScenarioStage
    state: M8PlatformStageState
    summary: str = Field(min_length=1, max_length=240)
    authority_refs: tuple[ReferenceToken, ...] = Field(default=(), max_length=32)
    completed_units: int | None = Field(default=None, ge=0, strict=True)
    total_units: int | None = Field(default=None, gt=0, strict=True)
    unit: Literal["FRAME"] | None = None

    @field_validator("authority_refs")
    @classmethod
    def validate_authority_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            require_reference_token(value, "M8 platform stage authority") for value in values
        )

    @model_validator(mode="after")
    def validate_objective_progress(self) -> Self:
        values = (self.completed_units, self.total_units, self.unit)
        if all(value is None for value in values):
            return self
        if any(value is None for value in values):
            raise ValueError("M8 platform stage progress must be supplied as one complete group")
        if self.stage != M8PlatformScenarioStage.PERCEPTION or self.unit != "FRAME":
            raise ValueError("only M8 perception may expose objective FRAME progress")
        assert self.completed_units is not None and self.total_units is not None
        if self.completed_units > self.total_units:
            raise ValueError("M8 platform completed units cannot exceed total units")
        return self


class M8PlatformEvidenceViewV1(FrozenContractModel):
    evidence_id: ReferenceToken
    role: Literal["PANORAMA", "SUBJECT", "FOCUS", "TEMPORAL"]
    frame_index: int = Field(ge=0, strict=True)
    media_url: str
    integrity: Literal["VERIFIED", "MISSING", "HASH_MISMATCH", "NOT_AVAILABLE"]

    @field_validator("evidence_id")
    @classmethod
    def validate_evidence_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 platform evidence")

    @field_validator("media_url")
    @classmethod
    def validate_media_url(cls, value: str) -> str:
        if not value.startswith("/api/m8/demo/scenario-runs/") or ".." in value or "\\" in value:
            raise ValueError("M8 platform evidence URL must remain same-origin")
        return value


class M8PlatformVideoProfileV1(FrozenContractModel):
    """Typed playback timing copied from the verified Pilot run manifest."""

    input_file_sha256: Sha256Hex
    fps_num: int = Field(gt=0, strict=True)
    fps_den: int = Field(gt=0, strict=True)
    frame_count: int = Field(gt=0, strict=True)
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)
    duration_millis: int = Field(gt=0, strict=True)
    timing_authority: Literal["PILOT_RUN_MANIFEST"] = "PILOT_RUN_MANIFEST"

    @model_validator(mode="after")
    def validate_duration(self) -> Self:
        expected = (
            self.frame_count * 1000 * self.fps_den + self.fps_num - 1
        ) // self.fps_num
        if self.duration_millis != expected:
            raise ValueError("M8 platform video duration conflicts with Pilot timing")
        return self


class M8PlatformModelComponentV1(FrozenContractModel):
    component: Literal["PERCEPTION", "SCREENING"]
    source: M8PlatformExecutionSource
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=128)
    manifest_id: Sha256Hex


class M8PlatformModelReadinessComponentV1(FrozenContractModel):
    component: Literal["PERCEPTION", "SCREENING"]
    ready: bool
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=128)
    manifest_id: Sha256Hex
    failure_code: ReferenceToken | None = None

    @model_validator(mode="after")
    def validate_failure(self) -> Self:
        if self.ready == (self.failure_code is not None):
            raise ValueError("model readiness failure code must exist exactly when not ready")
        return self


class M8PlatformModelReadinessV1(FrozenContractModel):
    schema_version: Literal["m8-platform-model-readiness-v1"] = (
        "m8-platform-model-readiness-v1"
    )
    full_model_ready: bool
    components: tuple[M8PlatformModelReadinessComponentV1, ...] = Field(
        min_length=2, max_length=2
    )
    fixture_available: Literal[True] = True
    automatic_fallback_permitted: Literal[False] = False

    @model_validator(mode="after")
    def validate_components(self) -> Self:
        if tuple(item.component for item in self.components) != ("PERCEPTION", "SCREENING"):
            raise ValueError("model readiness components must use stable order")
        if self.full_model_ready != all(item.ready for item in self.components):
            raise ValueError("full model readiness must equal component readiness")
        return self


class M8PlatformScenarioRunV1(FrozenContractModel):
    schema_version: Literal["m8-platform-scenario-run-v1"] = "m8-platform-scenario-run-v1"
    run_id: ReferenceToken
    scenario_kind: M8PlatformScenarioKind
    state: Literal["RUNNING", "SUCCEEDED", "FAILED"]
    stages: tuple[M8PlatformScenarioStageV1, ...] = Field(min_length=6, max_length=6)
    case_id: ReferenceToken | None = None
    case_status: M8OperationalCaseStatus | None = None
    notification_id: ReferenceToken | None = None
    recognition_mode: M8PlatformRecognitionMode | None = None
    retry_of_run_id: ReferenceToken | None = None
    model_components: tuple[M8PlatformModelComponentV1, ...] = Field(
        default=(), max_length=2
    )
    outcome: Literal["ACTIONABLE_RISK", "NO_ACTIONABLE_RISK_ESTABLISHED"] | None = None
    evidence: tuple[M8PlatformEvidenceViewV1, ...] = Field(default=(), max_length=24)
    video_profile: M8PlatformVideoProfileV1 | None = None
    perception_preview_url: str | None = None
    model_or_fixture_id: ReferenceToken | None = None
    raw_response_ref: str | None = Field(default=None, max_length=512)
    screening_decision: Literal["ESTABLISHED", "NOT_ESTABLISHED", "ESCALATE"] | None = None
    screening_summary: str | None = Field(default=None, max_length=2_048)
    rule_judgment: Literal[
        "GENERAL_RISK", "EMERGENCY", "NO_ACTIONABLE_RISK_ESTABLISHED"
    ] | None = None
    failure_code: ReferenceToken | None = None
    simulated: Literal[True] = True
    machine_output_is_ground_truth: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M8 platform scenario run")

    @field_validator("perception_preview_url")
    @classmethod
    def validate_preview_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value.startswith("/api/m8/demo/scenario-runs/")
            or not value.endswith("/perception-preview")
            or ".." in value
            or "\\" in value
        ):
            raise ValueError("M8 platform perception preview URL must remain same-origin")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if tuple(item.stage for item in self.stages) != tuple(M8PlatformScenarioStage):
            raise ValueError("M8 platform scenario stages must use the complete stable order")
        if (self.state == "FAILED") != (self.failure_code is not None):
            raise ValueError("M8 platform failed scenario requires exactly one failure code")
        if (self.case_id is None) != (self.case_status is None):
            raise ValueError("M8 platform scenario Case projection must be complete")
        is_ppe = self.scenario_kind == M8PlatformScenarioKind.PPE_GOGGLES_MISSING
        if is_ppe != (self.recognition_mode is not None):
            raise ValueError("PPE runs require an explicit recognition mode")
        if self.retry_of_run_id is not None:
            require_portable_run_id(self.retry_of_run_id, "M8 platform retry run")
            if self.recognition_mode != M8PlatformRecognitionMode.DEMO_FIXTURE:
                raise ValueError("only fixture fallback runs may reference an earlier run")
        if self.model_components and tuple(item.component for item in self.model_components) != (
            "PERCEPTION",
            "SCREENING",
        ):
            raise ValueError("model components must use stable order")
        if self.outcome == "NO_ACTIONABLE_RISK_ESTABLISHED" and any(
            value is not None for value in (self.case_id, self.notification_id)
        ):
            raise ValueError("no-action PPE run cannot create a Case or notification")
        if (
            self.state == "SUCCEEDED"
            and is_ppe
            and self.outcome == "ACTIONABLE_RISK"
            and any(
                value is None
                for value in (
                    self.video_profile,
                    self.perception_preview_url,
                    self.screening_decision,
                    self.screening_summary,
                    self.rule_judgment,
                    self.raw_response_ref,
                )
            )
        ):
            raise ValueError("successful M8 PPE run requires complete Pilot projections")
        if self.state == "SUCCEEDED" and is_ppe and (
            self.outcome is None or len(self.model_components) != 2
        ):
            raise ValueError("successful PPE run requires outcome and component provenance")
        return self


class M8PlatformNotificationDispatchRequestV1(FrozenContractModel):
    schema_version: Literal["m8-platform-notification-dispatch-request-v1"] = (
        "m8-platform-notification-dispatch-request-v1"
    )
    kind: Literal["CASE_UPDATED", "APPEAL_OUTCOME"]
    explicit_human_confirmation: Literal[True]


class M8PlatformNotificationReplyRequestV1(FrozenContractModel):
    schema_version: Literal["m8-platform-notification-reply-request-v1"] = (
        "m8-platform-notification-reply-request-v1"
    )
    reply_kind: M8NotificationReplyKind
    body: str = Field(min_length=1, max_length=2_048)
    explicit_human_confirmation: Literal[True]

    @field_validator("body")
    @classmethod
    def validate_body(cls, value: str) -> str:
        has_control = any(
            ord(character) < 32 and character not in "\n\t" for character in value
        )
        if value != value.strip() or has_control:
            raise ValueError("M8 platform reply must be bounded visible text")
        return value


class M8PlatformAcknowledgementRequestV1(FrozenContractModel):
    schema_version: Literal["m8-platform-acknowledgement-request-v1"] = (
        "m8-platform-acknowledgement-request-v1"
    )
    explicit_human_confirmation: Literal[True]


class M8PlatformAgentQueryRequestV1(FrozenContractModel):
    schema_version: Literal["m8-platform-agent-query-request-v1"] = (
        "m8-platform-agent-query-request-v1"
    )
    query: str = Field(min_length=1, max_length=512)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("M8 platform Agent query must be bounded visible text")
        return value


class M8PlatformProposedActionV1(FrozenContractModel):
    action_kind: M8PlatformAgentActionKind
    target_ref: ReferenceToken
    current_version: int = Field(ge=0, strict=True)
    impact_summary: str = Field(min_length=1, max_length=240)
    requires_confirmation: Literal[True] = True
    request_payload: dict[str, object]

    @field_validator("target_ref")
    @classmethod
    def validate_target_ref(cls, value: str) -> str:
        return require_reference_token(value, "M8 platform Agent target")


class M8PlatformAgentQueryResponseV1(FrozenContractModel):
    schema_version: Literal["m8-platform-agent-query-response-v1"] = (
        "m8-platform-agent-query-response-v1"
    )
    outcome: Literal["ANSWERED", "NO_MATCH"]
    answer: str = Field(min_length=1, max_length=2_048)
    source_refs: tuple[ReferenceToken, ...] = Field(default=(), max_length=32)
    proposed_action: M8PlatformProposedActionV1 | None = None
    model_used: Literal[False] = False
    network_used: Literal[False] = False


class M8PlatformResetRequestV1(FrozenContractModel):
    schema_version: Literal["m8-platform-reset-request-v1"] = "m8-platform-reset-request-v1"
    explicit_human_confirmation: Literal[True]


class M8PlatformResetResponseV1(FrozenContractModel):
    schema_version: Literal["m8-platform-reset-response-v1"] = "m8-platform-reset-response-v1"
    session_id: ReferenceToken
    archived_session_id: ReferenceToken
    archive_ref: str = Field(min_length=1, max_length=512)
    baseline_summary: dict[str, int]


class M8PlatformBootstrapReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-platform-bootstrap-receipt-v1"] = (
        "m8-platform-bootstrap-receipt-v1"
    )
    session_id: ReferenceToken
    topology_commit_receipt_id: Sha256Hex
    source_catalog_commit_receipt_id: Sha256Hex
    actor_commit_receipt_ids: tuple[Sha256Hex, ...] = Field(min_length=4, max_length=4)
    reservation: M8PlatformReservationAuthorityV1
    camera_media_binding_receipt_id: Sha256Hex
    location_count: Literal[4] = 4
    source_count: Literal[3] = 3
    current_case_count: Literal[0] = 0
    current_notification_count: Literal[0] = 0
    bootstrap_manifest_id: Sha256Hex

    @computed_field  # type: ignore[prop-decorator]
    @property
    def bootstrap_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-platform-bootstrap-receipt",
                1,
                self.session_id,
                self.topology_commit_receipt_id,
                self.source_catalog_commit_receipt_id,
                list(self.actor_commit_receipt_ids),
                self.reservation.model_dump(mode="json"),
                self.camera_media_binding_receipt_id,
                self.bootstrap_manifest_id,
            ]
        )


__all__ = [
    "M8PlatformAcknowledgementRequestV1",
    "M8PlatformAgentActionKind",
    "M8PlatformAgentQueryRequestV1",
    "M8PlatformAgentQueryResponseV1",
    "M8PlatformBootstrapReceiptV1",
    "M8PlatformEvidenceViewV1",
    "M8PlatformExecutionSource",
    "M8PlatformLoginRequestV1",
    "M8PlatformLoginResponseV1",
    "M8PlatformModelComponentV1",
    "M8PlatformModelReadinessComponentV1",
    "M8PlatformModelReadinessV1",
    "M8PlatformNotificationDispatchRequestV1",
    "M8PlatformNotificationReplyRequestV1",
    "M8PlatformProposedActionV1",
    "M8PlatformRecognitionMode",
    "M8PlatformReservationAuthorityV1",
    "M8PlatformResetRequestV1",
    "M8PlatformResetResponseV1",
    "M8PlatformScenarioKind",
    "M8PlatformScenarioRunV1",
    "M8PlatformScenarioStage",
    "M8PlatformScenarioStageV1",
    "M8PlatformScenarioStartRequestV1",
    "M8PlatformStageState",
    "M8PlatformVideoProfileV1",
]
