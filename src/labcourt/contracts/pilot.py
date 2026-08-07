"""Command and isolated-perception contracts for the v0.2 real-video pilot."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import ContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ViolationType
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    require_portable_run_id,
    require_reference_token,
)

PILOT_PERCEPTION_PROTOCOL_VERSION: Literal["1.0"] = "1.0"
PILOT_PERCEPTION_LABELS = frozenset({"person", "goggles"})


def _pilot_perception_digest(payload: object) -> str:
    return sha256_hex(["pilot-perception-execution-manifest", 1, payload])


class PilotTrackerThresholds(ContractModel):
    """Pinned ByteTrack controls that materially affect anonymous track identity."""

    track_activation_threshold: StrictFloat = Field(ge=0, le=1)
    lost_track_buffer: int = Field(ge=0, le=10_000, strict=True)
    minimum_iou_threshold: StrictFloat = Field(ge=0, le=1)
    minimum_consecutive_frames: int = Field(gt=0, le=10_000, strict=True)


class PilotPerceptionExecutionManifest(ContractModel):
    """Complete identity of one real detector/tracker execution environment."""

    protocol_version: Literal["1.0"] = PILOT_PERCEPTION_PROTOCOL_VERSION
    detector: ModelManifest
    tracker: ModelManifest
    prompts: dict[str, tuple[str, ...]]
    device: str = Field(pattern=r"^(?:cpu|cuda(?::[0-9]+)?)$")
    score_threshold: StrictFloat = Field(ge=0, le=1)
    high_confidence_threshold: StrictFloat = Field(ge=0, le=1)
    bbox_policy: Literal["CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1"] = "CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1"
    tracker_initialization_policy: Literal["ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1"] = (
        "ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1"
    )
    tracker_thresholds: PilotTrackerThresholds
    software_versions: dict[ReferenceToken, str] = Field(min_length=1)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_manifest_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "manifest_id" in payload
        claimed = payload.pop("manifest_id", None)
        manifest = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized manifest_id must be a string")
        if claimed_present and claimed != manifest.manifest_id:
            raise ValueError("serialized manifest_id does not match perception manifest")
        return manifest

    @model_validator(mode="after")
    def validate_execution_identity(self) -> PilotPerceptionExecutionManifest:
        if self.detector.component != "detector":
            raise ValueError("pilot detector manifest must use the detector component")
        if self.tracker.component != "tracker":
            raise ValueError("pilot tracker manifest must use the tracker component")
        if self.detector.weights_sha256 is None:
            raise ValueError("real pilot detector manifest requires a weight SHA-256")
        if set(self.prompts) != PILOT_PERCEPTION_LABELS:
            raise ValueError("pilot perception prompts must define exactly person and goggles")
        if any(not values for values in self.prompts.values()):
            raise ValueError("pilot perception labels require at least one prompt")
        if any(
            not prompt.strip() or len(prompt) > 128
            for prompts in self.prompts.values()
            for prompt in prompts
        ):
            raise ValueError("pilot perception prompts must be bounded non-empty text")
        if self.score_threshold > self.high_confidence_threshold:
            raise ValueError("score threshold cannot exceed high-confidence threshold")
        for component, version in self.software_versions.items():
            require_reference_token(component, "perception software component")
            if not version or len(version) > 128:
                raise ValueError("perception software versions must be bounded non-empty text")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def manifest_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"manifest_id"})
        return _pilot_perception_digest(payload)


class PilotWorkerBox(ContractModel):
    """Unrounded detector coordinates in the worker response."""

    x1: StrictFloat = Field(ge=0)
    y1: StrictFloat = Field(ge=0)
    x2: StrictFloat = Field(gt=0)
    y2: StrictFloat = Field(gt=0)

    @model_validator(mode="after")
    def validate_order(self) -> PilotWorkerBox:
        if self.x1 >= self.x2 or self.y1 >= self.y2:
            raise ValueError("worker bbox must satisfy x1 < x2 and y1 < y2")
        return self


class PilotWorkerDetection(ContractModel):
    """Strict, model-native detection before conversion to the authority contract."""

    label: Literal["person", "goggles"]
    source_label: str = Field(min_length=1, max_length=128)
    bbox: PilotWorkerBox
    score: StrictFloat = Field(ge=0, le=1)
    local_track_id: ReferenceToken | None = None

    @model_validator(mode="after")
    def validate_tracking_scope(self) -> PilotWorkerDetection:
        if self.label == "person" and self.local_track_id is None:
            raise ValueError("every person detection requires a local anonymous track ID")
        if self.label != "person" and self.local_track_id is not None:
            raise ValueError("only person detections may carry a local track ID")
        return self


class PilotPerceptionWorkerRequest(ContractModel):
    """One bounded RGB frame request sent over the local JSONL worker protocol."""

    protocol_version: Literal["1.0"] = PILOT_PERCEPTION_PROTOCOL_VERSION
    kind: Literal["DETECT"] = "DETECT"
    mode: Literal["INFER", "REPLAY"] = "INFER"
    request_id: ReferenceToken
    frame_id: FrameId
    frame_content_sha256: Sha256Hex
    fps_num: int = Field(gt=0, strict=True)
    fps_den: int = Field(gt=0, strict=True)
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)
    image_encoding: Literal["PNG_RGB8_V1"] = "PNG_RGB8_V1"
    image_sha256: Sha256Hex
    image_base64: str = Field(min_length=1, max_length=32 * 1024 * 1024)
    expected_manifest_id: Sha256Hex
    replay_detections: tuple[PilotWorkerDetection, ...] = ()

    @model_validator(mode="after")
    def validate_replay_payload(self) -> PilotPerceptionWorkerRequest:
        if self.mode == "INFER" and self.replay_detections:
            raise ValueError("INFER requests cannot carry replay detections")
        return self


class PilotPerceptionWorkerResponse(ContractModel):
    """Explicit worker success; an empty detection tuple is a real successful result."""

    protocol_version: Literal["1.0"] = PILOT_PERCEPTION_PROTOCOL_VERSION
    kind: Literal["RESULT"] = "RESULT"
    status: Literal["SUCCEEDED"] = "SUCCEEDED"
    request_id: ReferenceToken
    frame_id: FrameId
    frame_content_sha256: Sha256Hex
    manifest_id: Sha256Hex
    detections: tuple[PilotWorkerDetection, ...] = ()


class PilotPerceptionWorkerFailure(ContractModel):
    """Sanitized worker failure; model exceptions never become empty detections."""

    protocol_version: Literal["1.0"] = PILOT_PERCEPTION_PROTOCOL_VERSION
    kind: Literal["RESULT"] = "RESULT"
    status: Literal["FAILED"] = "FAILED"
    request_id: ReferenceToken
    frame_id: FrameId
    frame_content_sha256: Sha256Hex
    manifest_id: Sha256Hex
    error_code: Literal[
        "IMAGE_INVALID",
        "INFERENCE_FAILED",
        "TRACKER_FAILED",
        "REQUEST_INVALID",
    ]


class PilotPerceptionWorkerReady(ContractModel):
    """First JSONL message emitted only after model and weight identity are verified."""

    protocol_version: Literal["1.0"] = PILOT_PERCEPTION_PROTOCOL_VERSION
    kind: Literal["READY"] = "READY"
    manifest: PilotPerceptionExecutionManifest


class PilotPerceptionWorkerStartupFailure(ContractModel):
    """Sanitized failure emitted before READY when the real backend cannot start."""

    protocol_version: Literal["1.0"] = PILOT_PERCEPTION_PROTOCOL_VERSION
    kind: Literal["STARTUP_FAILED"] = "STARTUP_FAILED"
    status: Literal["FAILED"] = "FAILED"
    error_code: Literal[
        "CONFIG_INVALID",
        "DEPENDENCY_INVALID",
        "DEVICE_UNAVAILABLE",
        "MODEL_LOAD_FAILED",
        "WEIGHT_IDENTITY_MISMATCH",
    ]


class PilotPerceptionFrameReceipt(ContractModel):
    """Content-bound raw-response reference and cache fact for one frame."""

    request_id: ReferenceToken
    frame_id: FrameId
    frame_content_sha256: Sha256Hex
    raw_response_ref: str = Field(min_length=1)
    raw_response_sha256: Sha256Hex
    cache_hit: StrictBool

    @field_validator("raw_response_ref")
    @classmethod
    def validate_raw_response_ref(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)


class PilotPerceptionReport(ContractModel):
    """A1 command result; aggregate counts remain deterministic code facts."""

    run_id: ReferenceToken
    frames_processed: int = Field(ge=0, strict=True)
    detection_count: int = Field(ge=0, strict=True)
    person_count: int = Field(ge=0, strict=True)
    goggles_count: int = Field(ge=0, strict=True)
    track_count: int = Field(ge=0, strict=True)
    provider_failures: int = Field(ge=0, strict=True)
    manifest_id: Sha256Hex
    preview_path: str | None = None

    @field_validator("preview_path")
    @classmethod
    def validate_preview_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_safe_relative_posix_path(value)

    @model_validator(mode="after")
    def validate_counts(self) -> PilotPerceptionReport:
        if self.person_count + self.goggles_count != self.detection_count:
            raise ValueError("pilot perception label counts must equal detection_count")
        if self.track_count > self.person_count:
            raise ValueError("pilot track count cannot exceed person detections")
        return self


class PilotRunRequest(ContractModel):
    """Validated, content-bound input for a pilot run or perception preflight."""

    run_id: ReferenceToken
    config_sha256: Sha256Hex
    video_relative_path: str = Field(min_length=1)
    video_sha256: Sha256Hex
    selected_rules: tuple[ViolationType, ...] = Field(min_length=1)
    resume: StrictBool
    max_cases: int = Field(gt=0, le=1_000, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot run_id")

    @field_validator("video_relative_path")
    @classmethod
    def validate_video_relative_path(cls, value: str) -> str:
        controlled = require_safe_relative_posix_path(value)
        if not controlled.lower().endswith(".mp4"):
            raise ValueError("pilot video must use the .mp4 extension")
        return controlled

    @model_validator(mode="after")
    def validate_selected_rules(self) -> PilotRunRequest:
        if len(self.selected_rules) != len(set(self.selected_rules)):
            raise ValueError("selected_rules must be unique")
        return self
