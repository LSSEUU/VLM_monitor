"""Strict application configuration contracts."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Literal, Self

from pydantic import (
    ConfigDict,
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
from labcourt.contracts.enums import (
    AlertLevel,
    ConfirmationPolicy,
    DirectSafetySourceClass,
    ExecutionLocation,
    PilotStage,
    PpeType,
    PrecedentSource,
    PrivacyPolicy,
    ProviderTransport,
    ReproducibilityMode,
    RiskLevel,
    RunMode,
    SafetySignalType,
    TrainingLabelQuality,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.geometry import PolygonInput
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.paths import SAFE_RELATIVE_PATH_PATTERN, require_safe_relative_posix_path
from labcourt.contracts.pilot import PilotTrackerThresholds
from labcourt.contracts.references import ReferenceToken, require_reference_token

_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_REQUIRED_DETECTOR_PROMPTS = {
    "person",
    "goggles",
    "gloves",
    "lab_coat",
    "reagent_bottle",
    "bottle_cap",
    "fume_sash",
    "food",
}


def _config_digest(payload: dict[str, object]) -> str:
    fingerprint = deepcopy(payload)
    run = fingerprint.get("run")
    if isinstance(run, dict):
        run.pop("workspace", None)
    if fingerprint.get("pilot") is None:
        fingerprint.pop("pilot", None)
    perception = fingerprint.get("perception")
    if isinstance(perception, dict):
        for optional_worker_field in (
            "detector_manifest",
            "pose",
            "pose_manifest",
            "tracker_manifest",
            "tracker_thresholds",
            "worker",
        ):
            if perception.get(optional_worker_field) is None:
                perception.pop(optional_worker_field, None)
    return sha256_hex(fingerprint)


class RunConfig(ContractModel):
    mode: RunMode = RunMode.STANDARD
    reproducibility_mode: ReproducibilityMode
    random_seed: int = Field(strict=True)
    workspace: str = Field(
        min_length=1,
        json_schema_extra={"pattern": SAFE_RELATIVE_PATH_PATTERN},
    )
    storage_boundary: Literal["LOCAL_FILESYSTEM"] = "LOCAL_FILESYSTEM"

    @field_validator("workspace")
    @classmethod
    def validate_workspace(cls, value: str) -> str:
        if "://" in value:
            raise ValueError("workspace must not be a URI")
        return require_safe_relative_posix_path(value)


class StorageConfig(ContractModel):
    database_filename: Literal["labcourt.sqlite3"] = "labcourt.sqlite3"
    busy_timeout_ms: int = Field(gt=0, le=60_000, strict=True)
    max_media_bytes: int = Field(gt=0, strict=True)
    max_image_pixels: int = Field(gt=0, strict=True)


class ZoneConfig(ContractModel):
    zone_id: ReferenceToken
    camera_id: ReferenceToken
    polygon: PolygonInput
    risk_level: RiskLevel
    required_ppe: tuple[PpeType, ...] = ()
    reminder_channel: ReferenceToken

    @field_validator("zone_id", "camera_id", "reminder_channel")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "zone or camera reference")

    @model_validator(mode="after")
    def validate_required_ppe(self) -> ZoneConfig:
        if len(self.required_ppe) != len(set(self.required_ppe)):
            raise ValueError("required_ppe values must be unique")
        return self


class L0Config(ContractModel):
    enabled: StrictBool = True
    reminder_cooldown_seconds: StrictFloat = Field(gt=0)
    persist_events: Literal[False] = False


class DetectorConfig(ContractModel):
    model_id: str = Field(min_length=1)
    score_threshold: StrictFloat = Field(ge=0, le=1)
    high_confidence_threshold: StrictFloat = Field(ge=0, le=1)
    prompts: dict[str, tuple[str, ...]]

    @model_validator(mode="after")
    def validate_thresholds_and_prompts(self) -> DetectorConfig:
        if self.score_threshold > self.high_confidence_threshold:
            raise ValueError("score_threshold cannot exceed high_confidence_threshold")
        if not self.prompts or any(not prompts for prompts in self.prompts.values()):
            raise ValueError("every detector label requires at least one prompt")
        if any(
            not prompt.strip() or len(prompt) > 128
            for prompts in self.prompts.values()
            for prompt in prompts
        ):
            raise ValueError("detector prompts must be bounded non-empty text")
        if any(len(prompts) != len(set(prompts)) for prompts in self.prompts.values()):
            raise ValueError("detector prompts must be unique per label")
        missing_prompts = _REQUIRED_DETECTOR_PROMPTS - set(self.prompts)
        if missing_prompts:
            raise ValueError(f"missing detector prompts: {sorted(missing_prompts)}")
        return self


class AssociationConfig(ContractModel):
    iou_threshold: StrictFloat = Field(ge=0, le=1)
    keypoint_threshold: StrictFloat = Field(ge=0, le=1)


class ObservabilityWeights(ContractModel):
    person_confidence: StrictFloat = Field(ge=0, le=1)
    keypoint_visibility: StrictFloat = Field(ge=0, le=1)
    frontality: StrictFloat = Field(ge=0, le=1)
    sharpness: StrictFloat = Field(ge=0, le=1)
    exposure: StrictFloat = Field(ge=0, le=1)
    non_occlusion: StrictFloat = Field(ge=0, le=1)

    @model_validator(mode="after")
    def validate_sum(self) -> ObservabilityWeights:
        if abs(sum(self.model_dump().values()) - 1.0) > 1e-6:
            raise ValueError("observability weights must sum to one")
        return self


class ObservabilityConfig(ContractModel):
    weights: ObservabilityWeights
    clear_frame_threshold: StrictFloat = Field(ge=0, le=1)


class PoseConfig(ContractModel):
    """Pinned fail-closed face-keypoint controls for the local pilot worker."""

    model_id: str = Field(min_length=1)
    dataset_index: Literal[0] = 0
    keypoint_score_threshold: StrictFloat = Field(ge=0, le=1)
    minimum_eye_span_ratio: StrictFloat = Field(gt=0, lt=1)
    maximum_eye_span_ratio: StrictFloat = Field(gt=0, le=1)
    keypoint_policy: Literal["DUAL_EYE_SCORE_AND_GEOMETRY_V1"] = "DUAL_EYE_SCORE_AND_GEOMETRY_V1"

    @model_validator(mode="after")
    def validate_eye_span(self) -> PoseConfig:
        if self.minimum_eye_span_ratio >= self.maximum_eye_span_ratio:
            raise ValueError("pose eye-span bounds must be strictly ordered")
        return self


class PerceptionConfig(ContractModel):
    provider: str = Field(min_length=1)
    detector: DetectorConfig
    association: AssociationConfig
    observability: ObservabilityConfig
    detector_manifest: ModelManifest | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    pose: PoseConfig | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    pose_manifest: ModelManifest | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    tracker_manifest: ModelManifest | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    tracker_thresholds: PilotTrackerThresholds | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    worker: PerceptionWorkerConfig | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_local_worker(self) -> PerceptionConfig:
        local_worker = self.provider == "local-worker"
        worker_fields = (
            self.detector_manifest,
            self.tracker_manifest,
            self.tracker_thresholds,
            self.worker,
        )
        if local_worker and any(value is None for value in worker_fields):
            raise ValueError("local-worker perception requires complete model and worker pins")
        if not local_worker and any(
            value is not None for value in (*worker_fields, self.pose, self.pose_manifest)
        ):
            raise ValueError("worker model pins are allowed only for local-worker perception")
        if not local_worker:
            return self
        assert self.detector_manifest is not None
        assert self.tracker_manifest is not None
        if (self.pose is None) != (self.pose_manifest is None):
            raise ValueError("local-worker pose config and manifest must be supplied together")
        if self.detector_manifest.component != "detector":
            raise ValueError("local-worker detector manifest must use detector component")
        if self.tracker_manifest.component != "tracker":
            raise ValueError("local-worker tracker manifest must use tracker component")
        if self.detector_manifest.model != self.detector.model_id:
            raise ValueError("detector config and manifest model IDs must match")
        if self.detector_manifest.weights_sha256 is None:
            raise ValueError("local-worker detector requires a pinned weight SHA-256")
        if self.pose is not None and self.pose_manifest is not None:
            if self.pose_manifest.component != "pose":
                raise ValueError("local-worker pose manifest must use the pose component")
            if self.pose_manifest.model != self.pose.model_id:
                raise ValueError("pose config and manifest model IDs must match")
            if self.pose_manifest.weights_sha256 is None:
                raise ValueError("local-worker pose requires a pinned weight SHA-256")
        return self


class PerceptionWorkerConfig(ContractModel):
    """Bounded local process controls; the executable is resolved without a shell."""

    protocol_version: Literal["1.0"] = "1.0"
    python_executable_env: str = "LABCOURT_PERCEPTION_PYTHON"
    module: Literal["labcourt.perception_worker"] = "labcourt.perception_worker"
    startup_timeout_seconds: StrictFloat = Field(gt=0, le=3_600)
    frame_timeout_seconds: StrictFloat = Field(gt=0, le=3_600)
    max_request_bytes: int = Field(gt=0, le=64 * 1024 * 1024, strict=True)
    max_response_bytes: int = Field(gt=0, le=16 * 1024 * 1024, strict=True)
    device: str = Field(pattern=r"^(?:cpu|cuda(?::[0-9]+)?)$")
    local_files_only: Literal[True] = True
    cache_enabled: Literal[True] = True
    required_software_versions: dict[ReferenceToken, str] = Field(min_length=1)

    @field_validator("python_executable_env")
    @classmethod
    def validate_python_executable_environment(cls, value: str) -> str:
        if not _ENV_NAME.fullmatch(value):
            raise ValueError("worker Python executable must use an uppercase environment name")
        return value

    @model_validator(mode="after")
    def validate_required_versions(self) -> PerceptionWorkerConfig:
        required = {
            "huggingface-hub",
            "numpy",
            "opencv-python",
            "pillow",
            "pydantic",
            "pyyaml",
            "safetensors",
            "scipy",
            "socksio",
            "supervision",
            "tokenizers",
            "torch",
            "trackers",
            "transformers",
        }
        if set(self.required_software_versions) != required:
            raise ValueError(f"worker software versions must define exactly {sorted(required)}")
        if any(
            not version or len(version) > 128
            for version in self.required_software_versions.values()
        ):
            raise ValueError("worker software versions must be bounded non-empty text")
        return self


class PilotConfig(ContractModel):
    selected_rules: tuple[ViolationType, ...] = Field(min_length=1)
    max_cases: int = Field(gt=0, le=1_000, strict=True)
    write_debug_preview: StrictBool = True
    stop_after_stage: PilotStage | None = None

    @model_validator(mode="after")
    def validate_initial_rule_scope(self) -> PilotConfig:
        if len(self.selected_rules) != len(set(self.selected_rules)):
            raise ValueError("pilot selected_rules must be unique")
        unsupported = set(self.selected_rules) - {ViolationType.PPE_GOGGLES_MISSING}
        if unsupported:
            raise ValueError("v0.2 alpha1 supports only PPE_GOGGLES_MISSING")
        return self


class AbsenceConfig(ContractModel):
    dwell_seconds_by_risk: dict[RiskLevel, StrictFloat]
    confirmation_policy: ConfirmationPolicy
    context_lookahead_seconds: StrictFloat = Field(ge=0)
    track_grace_seconds: StrictFloat = Field(ge=0)
    temporal_crop_count: int = Field(gt=0, strict=True)
    minimum_consistent_clear_frames: int = Field(gt=0, strict=True)
    source_compat_enabled_for_offline_experiments: StrictBool = False

    @model_validator(mode="after")
    def validate_absence_settings(self) -> AbsenceConfig:
        if set(self.dwell_seconds_by_risk) != set(RiskLevel):
            raise ValueError("dwell_seconds_by_risk must define LOW, MEDIUM, and HIGH")
        if any(value <= 0 for value in self.dwell_seconds_by_risk.values()):
            raise ValueError("absence dwell seconds must be positive")
        if self.minimum_consistent_clear_frames > self.temporal_crop_count:
            raise ValueError("minimum_consistent_clear_frames cannot exceed temporal_crop_count")
        return self


class PresenceConfig(ContractModel):
    default_dwell_seconds: StrictFloat = Field(gt=0)
    default_cooldown_seconds: StrictFloat = Field(ge=0)


class EvidenceConfig(ContractModel):
    pre_seconds: StrictFloat = Field(ge=0)
    post_seconds: StrictFloat = Field(ge=0)
    panorama_long_edge: int = Field(gt=0, strict=True)
    subject_expand_ratio: StrictFloat = Field(ge=0)
    persist_raw_full_frames: StrictBool = False
    privacy_policy: PrivacyPolicy
    privacy_transform_version: str = Field(min_length=1)
    encoding_version: str = Field(min_length=1)


class VlmProviderProfile(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"execution_location": {"const": "EXTERNAL"}},
                        "required": ["execution_location"],
                    },
                    "then": {
                        "properties": {
                            "allow_full_frame": {"const": False},
                            "transport": {"const": "HTTP"},
                            "endpoint_env": {
                                "type": "string",
                                "pattern": _ENV_NAME.pattern,
                            },
                            "api_key_env": {
                                "type": "string",
                                "pattern": _ENV_NAME.pattern,
                            },
                        },
                        "required": [
                            "endpoint_env",
                            "api_key_env",
                            "transport",
                            "pricing_currency",
                            "input_cost_per_million_tokens",
                            "output_cost_per_million_tokens",
                        ],
                    },
                },
                {
                    "if": {
                        "properties": {"transport": {"const": "IN_PROCESS"}},
                        "required": ["transport"],
                    },
                    "then": {
                        "properties": {
                            "endpoint_env": {"type": "null"},
                            "api_key_env": {"type": "null"},
                        }
                    },
                    "else": {
                        "properties": {
                            "endpoint_env": {
                                "type": "string",
                                "pattern": _ENV_NAME.pattern,
                            }
                        },
                        "required": [
                            "endpoint_env",
                            "pricing_currency",
                            "input_cost_per_million_tokens",
                            "output_cost_per_million_tokens",
                        ],
                    },
                },
            ]
        }
    )

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    quantization: str | None = None
    execution_location: ExecutionLocation
    transport: ProviderTransport
    allow_full_frame: StrictBool = False
    endpoint_env: str | None = None
    api_key_env: str | None = None
    timeout_seconds: StrictFloat = Field(gt=0, le=3_600)
    cache_enabled: Literal[True] = True
    pricing_currency: Literal["USD", "CNY"] = "USD"
    input_cost_per_million_tokens: StrictFloat = Field(
        default=0.0,
        ge=0,
        le=1_000_000,
    )
    output_cost_per_million_tokens: StrictFloat = Field(
        default=0.0,
        ge=0,
        le=1_000_000,
    )

    @field_validator("endpoint_env", "api_key_env")
    @classmethod
    def validate_environment_variable_name(cls, value: str | None) -> str | None:
        if value is not None and not _ENV_NAME.fullmatch(value):
            raise ValueError("secret/deployment fields must name uppercase environment variables")
        return value

    @model_validator(mode="after")
    def validate_cloud_privacy(self) -> VlmProviderProfile:
        external = self.execution_location == ExecutionLocation.EXTERNAL
        http = self.transport == ProviderTransport.HTTP
        if external and self.allow_full_frame:
            raise ValueError("external profiles cannot upload full frames")
        if external and (not http or not self.endpoint_env or not self.api_key_env):
            raise ValueError(
                "external profiles require HTTP endpoint and API key environment names"
            )
        if http and not self.endpoint_env:
            raise ValueError("HTTP profiles require an endpoint environment name")
        pricing_fields = {
            "pricing_currency",
            "input_cost_per_million_tokens",
            "output_cost_per_million_tokens",
        }
        if http and not pricing_fields.issubset(self.model_fields_set):
            raise ValueError("HTTP profiles require explicit token pricing and currency")
        if not http and (self.endpoint_env or self.api_key_env):
            raise ValueError("in-process profiles cannot declare endpoint or API key variables")
        if self.provider == "fake" and (external or self.transport != ProviderTransport.IN_PROCESS):
            raise ValueError("the deterministic fake provider must run locally in-process")
        if not self.cache_enabled:
            raise ValueError("external model responses must use the deterministic cache")
        return self


class ScreeningConfig(ContractModel):
    provider_profile: str = Field(min_length=1)
    low_probability: StrictFloat = Field(ge=0, le=1)
    high_probability: StrictFloat = Field(ge=0, le=1)
    strong_signal_threshold: StrictFloat = Field(default=0.5, ge=0, le=1)
    router_version: ReferenceToken = "screening-router-v1"
    conflict_policy_version: ReferenceToken = "strong-signal-v1"
    backlog_max_attempts: int = Field(default=3, gt=0, le=100, strict=True)
    timeout_seconds: StrictFloat = Field(gt=0, le=3_600)
    max_images: int = Field(gt=0, le=64, strict=True)
    max_input_pixels: int = Field(
        default=16_777_216,
        gt=0,
        le=1_000_000_000,
        strict=True,
    )
    max_prompt_bytes: int = Field(
        default=524_288,
        gt=0,
        le=1_048_576,
        strict=True,
    )
    max_input_tokens: int = Field(
        default=32_768,
        gt=0,
        le=262_144,
        strict=True,
    )
    max_output_tokens: int = Field(default=2_048, gt=0, le=1_000_000, strict=True)
    max_estimated_cost: StrictFloat = Field(
        default=1.0,
        ge=0,
        le=1_000_000,
    )
    max_response_bytes: int = Field(
        default=262_144,
        gt=0,
        le=262_144,
        strict=True,
    )
    max_json_depth: int = Field(default=16, gt=0, le=64, strict=True)
    max_json_fields: int = Field(default=512, gt=0, le=10_000, strict=True)
    max_string_chars: int = Field(default=8_192, gt=0, le=1_000_000, strict=True)

    @model_validator(mode="after")
    def validate_probability_band(self) -> ScreeningConfig:
        if self.low_probability >= self.high_probability:
            raise ValueError("low_probability must be lower than high_probability")
        return self


class HearingConfig(ContractModel):
    prosecutor_profile: str = Field(min_length=1)
    defender_profile: str = Field(min_length=1)
    judge_profile: str = Field(min_length=1)
    precedent_top_k: int = Field(gt=0, strict=True)
    max_acquisition_rounds: int = Field(ge=0, le=2, strict=True)
    max_rework_rounds: int = Field(ge=0, le=2, strict=True)
    max_total_images: int = Field(gt=0, strict=True)
    max_total_output_tokens: int = Field(gt=0, strict=True)


class NumericToleranceConfig(ContractModel):
    duration_frames: int = Field(ge=0, strict=True)
    person_count: int = Field(ge=0, strict=True)
    frame_interval_frames: int = Field(default=1, ge=0, strict=True)
    track_presence_interval_frames: int = Field(default=1, ge=0, strict=True)
    detection_score: StrictFloat = Field(default=0.01, ge=0, le=1)
    observability: StrictFloat = Field(default=0.01, ge=0, le=1)


class ProceduralGateConfig(ContractModel):
    gate_version: ReferenceToken = "procedural-gate-v1"
    objective_numeric_tolerance: NumericToleranceConfig
    precedent_similarity_min: StrictFloat = Field(ge=-1, le=1)
    absence_clear_frame_threshold: StrictFloat = Field(ge=0, le=1)
    minimum_absence_clear_frames: int = Field(gt=0, strict=True)


class PrecedentConfig(ContractModel):
    text_weight: StrictFloat = Field(ge=0)
    visual_weight: StrictFloat = Field(ge=0)
    source_weights: dict[PrecedentSource, StrictFloat]
    conflict_similarity: StrictFloat = Field(ge=-1, le=1)
    automatic_activation_delay_days: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def validate_weights(self) -> PrecedentConfig:
        if abs(self.text_weight + self.visual_weight - 1.0) > 1e-6:
            raise ValueError("text_weight and visual_weight must sum to one")
        if set(self.source_weights) != set(PrecedentSource):
            raise ValueError("source_weights must define every precedent source")
        if any(value <= 0 for value in self.source_weights.values()):
            raise ValueError("precedent source weights must be positive")
        return self


class AlertConfig(ContractModel):
    cooldown_seconds: StrictFloat = Field(ge=0)
    repeat_window_days: int = Field(ge=0, strict=True)
    confirmed_min_confidence: StrictFloat = Field(ge=0, le=1)
    insufficient_evidence_max_level: AlertLevel

    @model_validator(mode="after")
    def validate_insufficient_evidence_ceiling(self) -> AlertConfig:
        if self.insufficient_evidence_max_level != AlertLevel.ADVISORY:
            raise ValueError("insufficient evidence can be at most ADVISORY")
        return self


class RegressionConfig(ContractModel):
    maximum_machine_flip_rate: StrictFloat = Field(ge=0, le=1)
    gold_set_max_accuracy_drop: StrictFloat = Field(ge=0, le=1)


class TrainingConfig(ContractModel):
    export_minimum_quality: TrainingLabelQuality
    include_weak_labels: StrictBool = False


class RetentionConfig(ContractModel):
    raw_frame_cache_minutes: int = Field(ge=0, strict=True)
    redacted_crop_days: int = Field(ge=0, strict=True)
    case_metadata_days: int = Field(ge=0, strict=True)
    preserve_appeals_and_gold_sets: Literal[True] = True


class SafetyConfig(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"hard_alerts_enabled": {"const": True}},
                        "required": ["hard_alerts_enabled"],
                    },
                    "then": {
                        "required": [
                            "provider",
                            "allowed_signal_types",
                            "certification_ids",
                        ],
                        "properties": {
                            "provider": {"type": "string", "minLength": 1},
                            "allowed_signal_types": {"minItems": 1},
                            "certification_ids": {"minItems": 1},
                        },
                    },
                }
            ]
        }
    )

    hard_alerts_enabled: StrictBool = False
    provider: str | None = None
    allowed_signal_types: tuple[SafetySignalType, ...] = ()
    certification_ids: tuple[str, ...] = ()
    allowed_direct_sources: tuple[DirectSafetySourceClass, ...] = (
        DirectSafetySourceClass.PHYSICAL_SENSOR,
        DirectSafetySourceClass.VALIDATED_DETERMINISTIC,
        DirectSafetySourceClass.MANUAL,
    )

    @model_validator(mode="after")
    def validate_provider_and_sources(self) -> SafetyConfig:
        if self.hard_alerts_enabled and not self.provider:
            raise ValueError("hard alerts require a configured SafetySignal provider")
        if self.hard_alerts_enabled and (
            not self.allowed_signal_types
            or not self.certification_ids
            or not self.allowed_direct_sources
        ):
            raise ValueError(
                "hard alerts require signal types, certification IDs, and direct sources"
            )
        if any(
            not certification_id.strip() or len(certification_id) > 128
            for certification_id in self.certification_ids
        ):
            raise ValueError("certification IDs must be bounded non-empty text")
        if len(self.certification_ids) != len(set(self.certification_ids)):
            raise ValueError("certification IDs must be unique")
        if len(self.allowed_signal_types) != len(set(self.allowed_signal_types)):
            raise ValueError("allowed signal types must be unique")
        if len(self.allowed_direct_sources) != len(set(self.allowed_direct_sources)):
            raise ValueError("allowed direct sources must be unique")
        return self


class AppConfig(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "absence": {
                                "properties": {"confirmation_policy": {"const": "SOURCE_COMPAT"}},
                                "required": ["confirmation_policy"],
                            }
                        },
                        "required": ["absence"],
                    },
                    "then": {
                        "properties": {
                            "run": {
                                "properties": {"mode": {"const": "OFFLINE_EXPERIMENT"}},
                                "required": ["mode"],
                            },
                            "absence": {
                                "properties": {
                                    "source_compat_enabled_for_offline_experiments": {"const": True}
                                },
                                "required": ["source_compat_enabled_for_offline_experiments"],
                            },
                        }
                    },
                }
            ]
        }
    )

    schema_version: Literal["2.0.0"]
    rule_version: Literal["laboratory-v1"]
    run: RunConfig
    storage: StorageConfig
    zones: tuple[ZoneConfig, ...] = Field(min_length=1)
    l0: L0Config
    perception: PerceptionConfig
    pilot: PilotConfig | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    absence: AbsenceConfig
    presence: PresenceConfig
    evidence: EvidenceConfig
    providers: dict[str, VlmProviderProfile]
    screening: ScreeningConfig
    hearing: HearingConfig
    procedural_gate: ProceduralGateConfig
    precedents: PrecedentConfig
    alerts: AlertConfig
    regression: RegressionConfig
    training: TrainingConfig
    retention: RetentionConfig
    safety: SafetyConfig

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_config_hash(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "config_sha256" in payload
        claimed = payload.pop("config_sha256", None)
        config = handler(payload)
        if claimed_present and not isinstance(claimed, str):
            raise ValueError("serialized config_sha256 must be a string")
        if claimed_present and claimed != config.config_sha256:
            raise ValueError("serialized config_sha256 does not match configuration")
        return config

    @computed_field  # type: ignore[prop-decorator]
    @property
    def config_sha256(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"config_sha256"})
        return _config_digest(payload)

    @model_validator(mode="after")
    def validate_cross_references(self) -> AppConfig:
        zone_ids = [zone.zone_id for zone in self.zones]
        if len(zone_ids) != len(set(zone_ids)):
            raise ValueError("zone_id values must be unique")
        profile_ids = set(self.providers)
        required_profiles = {
            self.screening.provider_profile,
            self.hearing.prosecutor_profile,
            self.hearing.defender_profile,
            self.hearing.judge_profile,
        }
        unknown_profiles = required_profiles - profile_ids
        if unknown_profiles:
            raise ValueError(f"unknown VLM profiles: {sorted(unknown_profiles)}")
        screening_profile = self.providers[self.screening.provider_profile]
        if self.screening.timeout_seconds > screening_profile.timeout_seconds:
            raise ValueError("screening timeout cannot exceed its provider profile timeout")
        source_compat = self.absence.confirmation_policy == ConfirmationPolicy.SOURCE_COMPAT
        if source_compat and self.run.mode != RunMode.OFFLINE_EXPERIMENT:
            raise ValueError("SOURCE_COMPAT is allowed only in OFFLINE_EXPERIMENT mode")
        if source_compat and not self.absence.source_compat_enabled_for_offline_experiments:
            raise ValueError("SOURCE_COMPAT requires the explicit experimental opt-in")
        if self.absence.confirmation_policy == ConfirmationPolicy.NONE:
            raise ValueError("absence confirmation policy cannot be NONE")
        if self.l0.persist_events:
            raise ValueError("L0 persistence is forbidden")
        return self
