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
    explicit_human_confirmation: Literal[True]


class M8PlatformScenarioStageV1(FrozenContractModel):
    stage: M8PlatformScenarioStage
    state: M8PlatformStageState
    summary: str = Field(min_length=1, max_length=240)
    authority_refs: tuple[ReferenceToken, ...] = Field(default=(), max_length=32)

    @field_validator("authority_refs")
    @classmethod
    def validate_authority_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            require_reference_token(value, "M8 platform stage authority") for value in values
        )


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


class M8PlatformScenarioRunV1(FrozenContractModel):
    schema_version: Literal["m8-platform-scenario-run-v1"] = "m8-platform-scenario-run-v1"
    run_id: ReferenceToken
    scenario_kind: M8PlatformScenarioKind
    state: Literal["RUNNING", "SUCCEEDED", "FAILED"]
    stages: tuple[M8PlatformScenarioStageV1, ...] = Field(min_length=6, max_length=6)
    case_id: ReferenceToken | None = None
    case_status: M8OperationalCaseStatus | None = None
    notification_id: ReferenceToken | None = None
    evidence: tuple[M8PlatformEvidenceViewV1, ...] = Field(default=(), max_length=24)
    model_or_fixture_id: ReferenceToken | None = None
    raw_response_ref: str | None = Field(default=None, max_length=512)
    failure_code: ReferenceToken | None = None
    simulated: Literal[True] = True
    machine_output_is_ground_truth: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M8 platform scenario run")

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if tuple(item.stage for item in self.stages) != tuple(M8PlatformScenarioStage):
            raise ValueError("M8 platform scenario stages must use the complete stable order")
        if (self.state == "FAILED") != (self.failure_code is not None):
            raise ValueError("M8 platform failed scenario requires exactly one failure code")
        if (self.case_id is None) != (self.case_status is None):
            raise ValueError("M8 platform scenario Case projection must be complete")
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
    "M8PlatformLoginRequestV1",
    "M8PlatformLoginResponseV1",
    "M8PlatformNotificationDispatchRequestV1",
    "M8PlatformNotificationReplyRequestV1",
    "M8PlatformProposedActionV1",
    "M8PlatformReservationAuthorityV1",
    "M8PlatformResetRequestV1",
    "M8PlatformResetResponseV1",
    "M8PlatformScenarioKind",
    "M8PlatformScenarioRunV1",
    "M8PlatformScenarioStage",
    "M8PlatformScenarioStageV1",
    "M8PlatformScenarioStartRequestV1",
    "M8PlatformStageState",
]
