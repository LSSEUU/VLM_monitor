"""Command and isolated-perception contracts for the v0.2 real-video pilot."""

from __future__ import annotations

from typing import Literal, Self, TypeAlias

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
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    ConfirmationPolicy,
    ExecutionLocation,
    PrivacyPolicy,
    ProviderTransport,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m3_operations import (
    MAX_M3_PROCESS_CASES,
    M3ProcessCaseOutcome,
    M3ProcessCounts,
    M3ProcessDisposition,
)
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
PILOT_PERCEPTION_REQUIRED_ARTIFACT_ROLES = (
    "VIDEO_MANIFEST",
    "EXECUTION_MANIFEST",
    "FRAME_BUNDLES",
    "FRAME_RECEIPTS",
    "REPORT",
)
PILOT_PERCEPTION_PREVIEW_ARTIFACT_ROLE = "PREVIEW"
PilotPerceptionArtifactRole: TypeAlias = Literal[
    "VIDEO_MANIFEST",
    "EXECUTION_MANIFEST",
    "FRAME_BUNDLES",
    "FRAME_RECEIPTS",
    "REPORT",
    "PREVIEW",
]
_PILOT_PERCEPTION_ARTIFACT_SUFFIXES = {
    "VIDEO_MANIFEST": "input/video-manifest.json",
    "EXECUTION_MANIFEST": "perception/execution-manifest.json",
    "FRAME_BUNDLES": "perception/frame-bundles.jsonl",
    "FRAME_RECEIPTS": "perception/frame-receipts.jsonl",
    "REPORT": "perception/report.json",
    "PREVIEW": "debug/perception-preview.mp4",
}


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
    pose: ModelManifest | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    prompts: dict[str, tuple[str, ...]]
    device: str = Field(pattern=r"^(?:cpu|cuda(?::[0-9]+)?)$")
    score_threshold: StrictFloat = Field(ge=0, le=1)
    high_confidence_threshold: StrictFloat = Field(ge=0, le=1)
    bbox_policy: Literal["CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1"] = "CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1"
    empty_detection_policy: Literal["TRANSFORMERS_EMPTY_TEXT_LABEL_SENTINEL_V1"] = (
        "TRANSFORMERS_EMPTY_TEXT_LABEL_SENTINEL_V1"
    )
    goggles_nms_iou_threshold: StrictFloat = Field(ge=0, le=1)
    tracker_initialization_policy: Literal["ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1"] = (
        "ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1"
    )
    tracker_thresholds: PilotTrackerThresholds
    pose_dataset_index: Literal[0] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    pose_keypoint_score_threshold: StrictFloat | None = Field(
        default=None,
        ge=0,
        le=1,
        exclude_if=lambda value: value is None,
    )
    pose_minimum_eye_span_ratio: StrictFloat | None = Field(
        default=None,
        gt=0,
        lt=1,
        exclude_if=lambda value: value is None,
    )
    pose_maximum_eye_span_ratio: StrictFloat | None = Field(
        default=None,
        gt=0,
        le=1,
        exclude_if=lambda value: value is None,
    )
    pose_keypoint_policy: Literal["DUAL_EYE_SCORE_AND_GEOMETRY_V1"] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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
        pose_controls = (
            self.pose_dataset_index,
            self.pose_keypoint_score_threshold,
            self.pose_minimum_eye_span_ratio,
            self.pose_maximum_eye_span_ratio,
            self.pose_keypoint_policy,
        )
        if self.pose is None and any(value is not None for value in pose_controls):
            raise ValueError("pose controls require a pose manifest")
        if self.pose is not None:
            if self.pose.component != "pose" or self.pose.weights_sha256 is None:
                raise ValueError("pilot pose manifest requires pinned pose weights")
            if any(value is None for value in pose_controls):
                raise ValueError("pilot pose manifest requires complete fail-closed controls")
            assert self.pose_minimum_eye_span_ratio is not None
            assert self.pose_maximum_eye_span_ratio is not None
            if self.pose_minimum_eye_span_ratio >= self.pose_maximum_eye_span_ratio:
                raise ValueError("pilot pose eye-span bounds must be strictly ordered")
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
    keypoints: tuple[Keypoint, ...] = Field(default=(), max_length=17)
    pose_manifest_id: Sha256Hex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_tracking_scope(self) -> PilotWorkerDetection:
        if self.label == "person" and self.local_track_id is None:
            raise ValueError("every person detection requires a local anonymous track ID")
        if self.label != "person" and self.local_track_id is not None:
            raise ValueError("only person detections may carry a local track ID")
        if self.label != "person" and (self.keypoints or self.pose_manifest_id is not None):
            raise ValueError("only person detections may carry pose output")
        if self.keypoints and self.pose_manifest_id is None:
            raise ValueError("worker keypoints require a pose manifest identity")
        names = tuple(keypoint.name for keypoint in self.keypoints)
        if len(names) != len(set(names)):
            raise ValueError("worker keypoint names must be unique")
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


class PilotPerceptionArtifactReceipt(ContractModel):
    """One immutable A1 output bound into the final completion inventory."""

    role: PilotPerceptionArtifactRole
    artifact_ref: str = Field(min_length=1)
    artifact_sha256: Sha256Hex
    artifact_size_bytes: int = Field(gt=0, le=8 * 1024 * 1024 * 1024, strict=True)

    @field_validator("artifact_ref")
    @classmethod
    def validate_artifact_ref(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "receipt_id" in payload
        claimed = payload.pop("receipt_id", None)
        receipt = handler(payload)
        if claimed_present and claimed != receipt.receipt_id:
            raise ValueError("serialized receipt_id does not match perception artifact")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "pilot-perception-artifact-receipt",
                1,
                self.role,
                self.artifact_ref,
                self.artifact_sha256,
                self.artifact_size_bytes,
            ]
        )


class PilotPerceptionCompletionManifest(ContractModel):
    """Last-written A1 seal proving that every resumable output is present."""

    schema_version: Literal["pilot-perception-completion-v1"] = "pilot-perception-completion-v1"
    run_id: ReferenceToken
    config_sha256: Sha256Hex
    video_sha256: Sha256Hex
    manifest_id: Sha256Hex
    artifacts: tuple[PilotPerceptionArtifactReceipt, ...] = Field(min_length=5, max_length=6)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot completion run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_completion_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "completion_id" in payload
        claimed = payload.pop("completion_id", None)
        manifest = handler(payload)
        if claimed_present and claimed != manifest.completion_id:
            raise ValueError("serialized completion_id does not match perception completion")
        return manifest

    @model_validator(mode="after")
    def validate_exact_artifact_inventory(self) -> PilotPerceptionCompletionManifest:
        roles = tuple(item.role for item in self.artifacts)
        required = PILOT_PERCEPTION_REQUIRED_ARTIFACT_ROLES
        if roles not in (
            required,
            (*required, PILOT_PERCEPTION_PREVIEW_ARTIFACT_ROLE),
        ):
            raise ValueError("pilot completion requires the exact ordered A1 artifact inventory")
        for artifact in self.artifacts:
            suffix = _PILOT_PERCEPTION_ARTIFACT_SUFFIXES[artifact.role]
            if artifact.artifact_ref != f"runs/{self.run_id}/{suffix}":
                raise ValueError("pilot completion artifact path does not match its run and role")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def completion_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "pilot-perception-completion",
                1,
                self.run_id,
                self.config_sha256,
                self.video_sha256,
                self.manifest_id,
                [artifact.receipt_id for artifact in self.artifacts],
            ]
        )


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


class PilotEvidencePackSummary(ContractModel):
    """Privacy-safe A2 projection of one authoritative EvidencePack."""

    event_id: ReferenceToken
    case_id: ReferenceToken
    pack_id: ReferenceToken
    violation_type: Literal[ViolationType.PPE_GOGGLES_MISSING]
    confirmation_policy: Literal[ConfirmationPolicy.STRICT_CAUSAL]
    complete: Literal[True]
    closure_passed: Literal[True]
    panorama_crop_count: int = Field(ge=0, strict=True)
    subject_crop_count: int = Field(ge=0, strict=True)
    focus_crop_count: int = Field(ge=0, strict=True)
    temporal_crop_count: int = Field(ge=0, strict=True)
    cloud_allowed_crop_count: int = Field(ge=0, strict=True)
    local_only_crop_count: int = Field(ge=0, strict=True)
    privacy_policy: Literal[PrivacyPolicy.PPE_PRESERVING_REDACTION]

    @field_validator("event_id", "case_id", "pack_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "pilot A2 evidence reference")

    @model_validator(mode="after")
    def validate_crop_counts(self) -> PilotEvidencePackSummary:
        crop_count = (
            self.panorama_crop_count
            + self.subject_crop_count
            + self.focus_crop_count
            + self.temporal_crop_count
        )
        if self.cloud_allowed_crop_count + self.local_only_crop_count != crop_count:
            raise ValueError("pilot A2 media-access counts must equal total crop count")
        if self.temporal_crop_count == 0:
            raise ValueError("pilot A2 absence evidence requires temporal crops")
        return self


class PilotA2Report(ContractModel):
    """Content-derived A2 result without L0 subject or trajectory persistence."""

    schema_version: Literal["pilot-a2-report-v1"] = "pilot-a2-report-v1"
    run_id: ReferenceToken
    state: Literal["NO_CANDIDATE", "EVIDENCE_READY"]
    config_sha256: Sha256Hex
    video_sha256: Sha256Hex
    perception_manifest_id: Sha256Hex
    perception_completion_id: Sha256Hex
    run_manifest_id: Sha256Hex
    selected_rules: tuple[Literal[ViolationType.PPE_GOGGLES_MISSING], ...] = Field(
        min_length=1,
        max_length=1,
    )
    frames_processed: int = Field(gt=0, strict=True)
    association_count: int = Field(ge=0, strict=True)
    l0_reminder_count: int = Field(ge=0, strict=True)
    suppression_count: int = Field(ge=0, strict=True)
    candidate_event_count: int = Field(ge=0, strict=True)
    evidence_pack_count: int = Field(ge=0, strict=True)
    evidence_packs: tuple[PilotEvidencePackSummary, ...]
    l0_persistence_policy: Literal["AGGREGATE_COUNT_ONLY_NO_SUBJECT_IDS"] = (
        "AGGREGATE_COUNT_ONLY_NO_SUBJECT_IDS"
    )

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot A2 run_id")

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
            raise ValueError("serialized report_id does not match pilot A2 report")
        return report

    @model_validator(mode="after")
    def validate_a2_result(self) -> PilotA2Report:
        if self.selected_rules != (ViolationType.PPE_GOGGLES_MISSING,):
            raise ValueError("pilot A2 supports exactly PPE_GOGGLES_MISSING")
        if self.evidence_pack_count != len(self.evidence_packs):
            raise ValueError("pilot A2 evidence_pack_count must equal its summaries")
        if self.candidate_event_count != self.evidence_pack_count:
            raise ValueError("pilot A2 candidates require one complete EvidencePack each")
        expected_state = "EVIDENCE_READY" if self.evidence_pack_count else "NO_CANDIDATE"
        if self.state != expected_state:
            raise ValueError("pilot A2 state does not match its evidence count")
        event_ids = tuple(item.event_id for item in self.evidence_packs)
        case_ids = tuple(item.case_id for item in self.evidence_packs)
        pack_ids = tuple(item.pack_id for item in self.evidence_packs)
        if any(len(values) != len(set(values)) for values in (event_ids, case_ids, pack_ids)):
            raise ValueError("pilot A2 evidence references must be unique")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"report_id"})
        return sha256_hex(["pilot-a2-report", 1, payload])


class PilotA3Report(ContractModel):
    """Secret-free bounded result of real-provider screening over one pilot run."""

    schema_version: Literal["pilot-a3-report-v1"] = "pilot-a3-report-v1"
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    provider_profile: ReferenceToken
    provider: ReferenceToken
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=256)
    model_manifest_id: Sha256Hex
    execution_location: Literal[ExecutionLocation.EXTERNAL]
    transport: Literal[ProviderTransport.HTTP]
    perception_mode: Literal["REAL PERCEPTION"] = "REAL PERCEPTION"
    model_mode: Literal["OPENAI-COMPATIBLE VLM"] = "OPENAI-COMPATIBLE VLM"
    requested_case_id: ReferenceToken | None
    selection_limit: int = Field(gt=0, le=MAX_M3_PROCESS_CASES, strict=True)
    available_case_count: int = Field(ge=0, strict=True)
    selection_truncated: bool = Field(strict=True)
    outcomes: tuple[M3ProcessCaseOutcome, ...] = Field(max_length=MAX_M3_PROCESS_CASES)
    counts: M3ProcessCounts

    @field_validator("run_id", "provider_profile", "provider", "requested_case_id")
    @classmethod
    def validate_report_references(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "pilot A3 report reference")

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
            raise ValueError("serialized report_id does not match pilot A3 report")
        return report

    @model_validator(mode="after")
    def validate_selection_and_counts(self) -> PilotA3Report:
        keys = tuple(outcome.case_id for outcome in self.outcomes)
        if len(keys) != len(set(keys)):
            raise ValueError("pilot A3 outcomes must have unique case IDs")
        if keys != tuple(sorted(keys)):
            raise ValueError("pilot A3 outcomes must use stable case-ID order")
        selected = len(self.outcomes)
        if selected > self.selection_limit or selected > self.available_case_count:
            raise ValueError("pilot A3 selection exceeds its reported bound")
        if self.requested_case_id is not None:
            if (
                self.available_case_count != 1
                or selected != 1
                or self.outcomes[0].case_id != self.requested_case_id
                or self.selection_truncated
            ):
                raise ValueError("single-case pilot A3 report has inconsistent selection scope")
        elif self.selection_truncated != (self.available_case_count > selected):
            raise ValueError("pilot A3 truncation flag conflicts with available cases")

        dispositions = tuple(outcome.disposition for outcome in self.outcomes)
        expected = M3ProcessCounts(
            selected_cases=selected,
            pipeline_invocations=sum(outcome.pipeline_invoked for outcome in self.outcomes),
            processed_cases=dispositions.count(M3ProcessDisposition.PROCESSED),
            deferred_to_backlog_cases=dispositions.count(
                M3ProcessDisposition.DEFERRED_TO_BACKLOG
            ),
            observed_existing_cases=dispositions.count(
                M3ProcessDisposition.OBSERVED_EXISTING
            ),
            skipped_not_ready_cases=dispositions.count(
                M3ProcessDisposition.SKIPPED_NOT_READY
            ),
            cache_hits=sum(outcome.cache_hit_count for outcome in self.outcomes),
            recovered_responses=sum(
                outcome.recovered_response_count for outcome in self.outcomes
            ),
            repair_attempts=sum(outcome.repair_attempt_count for outcome in self.outcomes),
        )
        if self.counts != expected:
            raise ValueError("pilot A3 counts conflict with case outcomes")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"report_id"})
        return sha256_hex(["pilot-a3-report", 1, payload])


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
