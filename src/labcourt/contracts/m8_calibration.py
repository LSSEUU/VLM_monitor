"""Additive M8 contracts for non-LLM shadow probability calibration."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, StrictBool, StrictFloat, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_evaluation import M8EvaluationPpeState
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import (
    ReferenceToken,
    require_portable_run_id,
    require_reference_token,
)

M8_CALIBRATION_MINIMUM_SAMPLES_PER_LABEL = 100
M8_CALIBRATION_BOOTSTRAP_ITERATIONS = 200
M8_CALIBRATION_RELIABILITY_BIN_COUNT = 10

M8_EVIDENCE_QUALITY_FEATURE_NAMES = (
    "person_score",
    "keypoint_visibility",
    "frontality",
    "sharpness",
    "exposure",
    "inverse_occlusion",
)
M8_EVENT_RISK_FEATURE_NAMES = (
    "clear_frame_ratio",
    "temporal_coverage_ratio",
    "track_continuity_ratio",
    "goggles_detection_ratio",
    "max_goggles_score",
    "mean_goggles_score",
    "recovery_detected",
    "longest_absence_ratio",
)


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{name} must use timezone-aware UTC")
    return value


class M8CalibrationPartition(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    CALIBRATION = "CALIBRATION"
    SEALED_TEST = "SEALED_TEST"


class M8CalibrationFitStatus(StrEnum):
    SHADOW_READY = "SHADOW_READY"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class M8CalibrationAssessmentMode(StrEnum):
    SHADOW = "SHADOW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class M8EvidenceFeatureStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class M8EvidenceFeatureReason(StrEnum):
    PERSON_DETECTION_MISSING = "PERSON_DETECTION_MISSING"
    PERSON_AMBIGUOUS = "PERSON_AMBIGUOUS"
    TRACK_UNAVAILABLE = "TRACK_UNAVAILABLE"


class M8CalibrationTrainingStage(StrEnum):
    EVIDENCE_QUALITY = "EVIDENCE_QUALITY"
    EVENT_RISK = "EVENT_RISK"


class M8CalibrationTrainingExclusionReason(StrEnum):
    OBSERVATION_MISSING = "OBSERVATION_MISSING"
    EVIDENCE_FEATURE_NOT_APPLICABLE = "EVIDENCE_FEATURE_NOT_APPLICABLE"
    TRACK_SCOPE_INSUFFICIENT = "TRACK_SCOPE_INSUFFICIENT"
    HUMAN_LABEL_UNCLEAR = "HUMAN_LABEL_UNCLEAR"


class M8CalibrationReasonCode(StrEnum):
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    ARTIFACT_UNAVAILABLE = "ARTIFACT_UNAVAILABLE"
    CONFIG_MISMATCH = "CONFIG_MISMATCH"
    MODEL_PROFILE_MISMATCH = "MODEL_PROFILE_MISMATCH"
    DETECTOR_MODEL_MISMATCH = "DETECTOR_MODEL_MISMATCH"
    FEATURE_SCHEMA_MISMATCH = "FEATURE_SCHEMA_MISMATCH"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"


class M8CalibrationMetricName(StrEnum):
    ACCURACY = "ACCURACY"
    RECALL = "RECALL"
    FALSE_POSITIVE_RATE = "FALSE_POSITIVE_RATE"
    BRIER_SCORE = "BRIER_SCORE"
    LOG_LOSS = "LOG_LOSS"
    ECE = "ECE"


class M8CalibrationDatasetEntryV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-dataset-entry-v1"] = "m8-calibration-dataset-entry-v1"
    sample_id: Sha256Hex
    asset_id: Sha256Hex
    ground_truth_id: Sha256Hex
    ground_truth_revision: int = Field(gt=0, strict=True)
    interval_index: int = Field(ge=0, strict=True)
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    ppe_state: M8EvaluationPpeState
    group_id: Sha256Hex
    partition: M8CalibrationPartition
    human_confirmed: Literal[True] = True
    machine_output_is_ground_truth: Literal[False] = False

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("M8 calibration sample interval must be non-empty")
        expected = sha256_hex(
            [
                "m8-calibration-sample",
                1,
                self.asset_id,
                self.ground_truth_id,
                self.ground_truth_revision,
                self.interval_index,
                self.start_frame,
                self.end_frame_exclusive,
                self.ppe_state,
            ]
        )
        if self.sample_id != expected:
            raise ValueError("M8 calibration sample identity does not match its human label")
        return self


class M8CalibrationDatasetManifestV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-dataset-manifest-v1"] = (
        "m8-calibration-dataset-manifest-v1"
    )
    dataset_manifest_id: Sha256Hex
    entries: tuple[M8CalibrationDatasetEntryV1, ...]
    split_policy: Literal["SHA256_GROUP_60_20_20_V1"] = "SHA256_GROUP_60_20_20_V1"
    created_at: datetime
    machine_output_is_ground_truth: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M8 calibration dataset created_at")

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        sample_ids = tuple(item.sample_id for item in self.entries)
        if sample_ids != tuple(sorted(set(sample_ids))):
            raise ValueError("M8 calibration samples must be unique and stably ordered")
        partitions_by_group: dict[str, M8CalibrationPartition] = {}
        for entry in self.entries:
            bucket = int(entry.group_id[:16], 16) % 100
            expected_partition = (
                M8CalibrationPartition.DEVELOPMENT
                if bucket < 60
                else (
                    M8CalibrationPartition.CALIBRATION
                    if bucket < 80
                    else M8CalibrationPartition.SEALED_TEST
                )
            )
            if entry.partition != expected_partition:
                raise ValueError("M8 calibration group partition violates the 60/20/20 policy")
            prior = partitions_by_group.setdefault(entry.group_id, entry.partition)
            if prior != entry.partition:
                raise ValueError("M8 calibration source group leaked across dataset partitions")
        expected = sha256_hex(
            [
                "m8-calibration-dataset-manifest",
                1,
                self.split_policy,
                tuple(entry.model_dump(mode="json") for entry in self.entries),
            ]
        )
        if self.dataset_manifest_id != expected:
            raise ValueError("M8 calibration dataset identity does not match its entries")
        return self


class M8EvidenceQualityFeaturesV1(FrozenContractModel):
    schema_version: Literal["m8-evidence-quality-features-v1"] = "m8-evidence-quality-features-v1"
    person_score: StrictFloat = Field(ge=0, le=1)
    keypoint_visibility: StrictFloat = Field(ge=0, le=1)
    frontality: StrictFloat = Field(ge=0, le=1)
    sharpness: StrictFloat = Field(ge=0, le=1)
    exposure: StrictFloat = Field(ge=0, le=1)
    inverse_occlusion: StrictFloat = Field(ge=0, le=1)

    def vector(self) -> tuple[float, ...]:
        return tuple(float(getattr(self, name)) for name in M8_EVIDENCE_QUALITY_FEATURE_NAMES)


class M8EventRiskFeaturesV1(FrozenContractModel):
    schema_version: Literal["m8-event-risk-features-v1"] = "m8-event-risk-features-v1"
    clear_frame_ratio: StrictFloat = Field(ge=0, le=1)
    temporal_coverage_ratio: StrictFloat = Field(ge=0, le=1)
    track_continuity_ratio: StrictFloat = Field(ge=0, le=1)
    goggles_detection_ratio: StrictFloat = Field(ge=0, le=1)
    max_goggles_score: StrictFloat = Field(ge=0, le=1)
    mean_goggles_score: StrictFloat = Field(ge=0, le=1)
    recovery_detected: StrictBool
    longest_absence_ratio: StrictFloat = Field(ge=0, le=1)

    def vector(self) -> tuple[float, ...]:
        return tuple(float(getattr(self, name)) for name in M8_EVENT_RISK_FEATURE_NAMES)


def detector_score_observation_id(
    *,
    run_id: str,
    dataset_manifest_id: str,
    asset_id: str,
    frame_index: int,
    frame_content_sha256: str,
    worker_request_id: str,
    raw_response_ref: str,
    raw_response_sha256: str,
    track_ref: str | None,
    detector_model_manifest_id: str,
    source_manifest_id: str,
    collection_manifest_id: str,
    authority_config_sha256: str,
    collection_config_sha256: str,
    collection_floor: float,
    authoritative_score_threshold: float,
    evidence_clear_threshold: float,
    goggles_detected: bool,
    postprocessed_goggles_score: float | None,
    evidence_feature_status: M8EvidenceFeatureStatus,
    evidence_feature_reason: M8EvidenceFeatureReason | None,
    evidence_features: M8EvidenceQualityFeaturesV1 | None,
    observability_score: float | None,
) -> str:
    """Return the complete content identity for one local detector observation."""

    return sha256_hex(
        [
            "m8-detector-score-observation",
            1,
            run_id,
            dataset_manifest_id,
            asset_id,
            frame_index,
            frame_content_sha256,
            worker_request_id,
            raw_response_ref,
            raw_response_sha256,
            track_ref,
            detector_model_manifest_id,
            source_manifest_id,
            collection_manifest_id,
            authority_config_sha256,
            collection_config_sha256,
            collection_floor,
            authoritative_score_threshold,
            evidence_clear_threshold,
            goggles_detected,
            postprocessed_goggles_score,
            evidence_feature_status,
            evidence_feature_reason,
            evidence_features.model_dump(mode="json") if evidence_features is not None else None,
            observability_score,
            "GROUNDING_DINO_POSTPROCESSED_SCORE_V1",
        ]
    )


class M8DetectorScoreObservationV1(FrozenContractModel):
    schema_version: Literal["m8-detector-score-observation-v1"] = "m8-detector-score-observation-v1"
    observation_id: Sha256Hex
    run_id: ReferenceToken
    dataset_manifest_id: Sha256Hex
    asset_id: Sha256Hex
    frame_index: int = Field(ge=0, strict=True)
    frame_content_sha256: Sha256Hex
    worker_request_id: ReferenceToken
    raw_response_ref: str
    raw_response_sha256: Sha256Hex
    track_ref: str | None = Field(default=None, min_length=1, max_length=194)
    detector_model_manifest_id: Sha256Hex
    source_manifest_id: Sha256Hex
    collection_manifest_id: Sha256Hex
    authority_config_sha256: Sha256Hex
    collection_config_sha256: Sha256Hex
    collection_floor: StrictFloat = Field(ge=0, le=1)
    authoritative_score_threshold: StrictFloat = Field(ge=0, le=1)
    evidence_clear_threshold: StrictFloat = Field(ge=0, le=1)
    goggles_detected: StrictBool
    postprocessed_goggles_score: StrictFloat | None = Field(default=None, ge=0, le=1)
    evidence_feature_status: M8EvidenceFeatureStatus
    evidence_feature_reason: M8EvidenceFeatureReason | None = None
    evidence_features: M8EvidenceQualityFeaturesV1 | None = None
    observability_score: StrictFloat | None = Field(default=None, ge=0, le=1)
    score_semantics: Literal["GROUNDING_DINO_POSTPROCESSED_SCORE_V1"] = (
        "GROUNDING_DINO_POSTPROCESSED_SCORE_V1"
    )
    llm_output_used: Literal[False] = False

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M8 detector-score run")

    @field_validator("worker_request_id")
    @classmethod
    def validate_worker_request_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 detector-score worker request")

    @field_validator("raw_response_ref")
    @classmethod
    def validate_raw_response_ref(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        if self.collection_floor >= self.authoritative_score_threshold:
            raise ValueError("M8 detector score collection floor must be below authority threshold")
        if self.authority_config_sha256 == self.collection_config_sha256:
            raise ValueError("M8 detector score collection must use an additive shadow config")
        if not (
            self.raw_response_ref.startswith("runs/")
            and self.raw_response_ref.endswith(f"/{self.worker_request_id}.json")
        ):
            raise ValueError("M8 detector score raw response must bind its worker request")
        if self.goggles_detected != (self.postprocessed_goggles_score is not None):
            raise ValueError("M8 detector score presence must match its optional score")
        if (
            self.postprocessed_goggles_score is not None
            and self.postprocessed_goggles_score < self.collection_floor
        ):
            raise ValueError("M8 detector score is below the declared collection floor")
        available = self.evidence_feature_status == M8EvidenceFeatureStatus.AVAILABLE
        if available:
            if (
                self.track_ref is None
                or self.evidence_feature_reason is not None
                or self.evidence_features is None
                or self.observability_score is None
            ):
                raise ValueError(
                    "available M8 evidence features require track, score, and features"
                )
        elif (
            self.track_ref is not None
            or self.evidence_feature_reason is None
            or self.evidence_features is not None
            or self.observability_score is not None
        ):
            raise ValueError("not-applicable M8 evidence features require one typed reason only")
        expected = detector_score_observation_id(
            run_id=self.run_id,
            dataset_manifest_id=self.dataset_manifest_id,
            asset_id=self.asset_id,
            frame_index=self.frame_index,
            frame_content_sha256=self.frame_content_sha256,
            worker_request_id=self.worker_request_id,
            raw_response_ref=self.raw_response_ref,
            raw_response_sha256=self.raw_response_sha256,
            track_ref=self.track_ref,
            detector_model_manifest_id=self.detector_model_manifest_id,
            source_manifest_id=self.source_manifest_id,
            collection_manifest_id=self.collection_manifest_id,
            authority_config_sha256=self.authority_config_sha256,
            collection_config_sha256=self.collection_config_sha256,
            collection_floor=float(self.collection_floor),
            authoritative_score_threshold=float(self.authoritative_score_threshold),
            evidence_clear_threshold=float(self.evidence_clear_threshold),
            goggles_detected=bool(self.goggles_detected),
            postprocessed_goggles_score=(
                float(self.postprocessed_goggles_score)
                if self.postprocessed_goggles_score is not None
                else None
            ),
            evidence_feature_status=self.evidence_feature_status,
            evidence_feature_reason=self.evidence_feature_reason,
            evidence_features=self.evidence_features,
            observability_score=(
                float(self.observability_score) if self.observability_score is not None else None
            ),
        )
        if self.observation_id != expected:
            raise ValueError("M8 detector score identity does not match its local observation")
        return self


class M8EvidenceQualityTrainingExampleV1(FrozenContractModel):
    sample_id: Sha256Hex
    group_id: Sha256Hex
    features: M8EvidenceQualityFeaturesV1
    human_clear: StrictBool
    label_source: Literal["HUMAN_CONFIRMED"] = "HUMAN_CONFIRMED"
    llm_output_used: Literal[False] = False


class M8EventRiskTrainingExampleV1(FrozenContractModel):
    sample_id: Sha256Hex
    group_id: Sha256Hex
    features: M8EventRiskFeaturesV1
    violation: StrictBool
    label_source: Literal["HUMAN_CONFIRMED"] = "HUMAN_CONFIRMED"
    llm_output_used: Literal[False] = False


class M8CalibrationTrainingExclusionV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-training-exclusion-v1"] = (
        "m8-calibration-training-exclusion-v1"
    )
    sample_id: Sha256Hex
    stage: M8CalibrationTrainingStage
    reason: M8CalibrationTrainingExclusionReason
    frame_indexes: tuple[int, ...] = Field(min_length=1)
    llm_output_used: Literal[False] = False

    @model_validator(mode="after")
    def validate_frame_indexes(self) -> Self:
        if self.frame_indexes != tuple(sorted(set(self.frame_indexes))):
            raise ValueError("M8 calibration exclusion frames must be unique and ordered")
        if any(index < 0 for index in self.frame_indexes):
            raise ValueError("M8 calibration exclusion frames cannot be negative")
        return self


class M8CalibrationTrainingAggregationV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-training-aggregation-v1"] = (
        "m8-calibration-training-aggregation-v1"
    )
    dataset_manifest_id: Sha256Hex
    evidence_examples: tuple[M8EvidenceQualityTrainingExampleV1, ...] = ()
    event_examples: tuple[M8EventRiskTrainingExampleV1, ...] = ()
    exclusions: tuple[M8CalibrationTrainingExclusionV1, ...] = ()
    llm_output_used: Literal[False] = False

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        evidence_ids = tuple(item.sample_id for item in self.evidence_examples)
        event_ids = tuple(item.sample_id for item in self.event_examples)
        exclusion_keys = tuple((item.sample_id, item.stage.value) for item in self.exclusions)
        if evidence_ids != tuple(sorted(set(evidence_ids))):
            raise ValueError("M8 evidence examples must be unique and ordered")
        if event_ids != tuple(sorted(set(event_ids))):
            raise ValueError("M8 event examples must be unique and ordered")
        stage_order = {
            M8CalibrationTrainingStage.EVIDENCE_QUALITY.value: 0,
            M8CalibrationTrainingStage.EVENT_RISK.value: 1,
        }
        expected_exclusion_keys = tuple(
            sorted(
                set(exclusion_keys),
                key=lambda item: (item[0], stage_order[item[1]]),
            )
        )
        if exclusion_keys != expected_exclusion_keys:
            raise ValueError("M8 calibration exclusions must be unique and ordered")
        return self


class M8RegularizedLogisticModelV1(FrozenContractModel):
    schema_version: Literal["m8-regularized-logistic-model-v1"] = "m8-regularized-logistic-model-v1"
    feature_names: tuple[str, ...]
    coefficients: tuple[StrictFloat, ...]
    intercept: StrictFloat
    l2_strength: StrictFloat = Field(gt=0)
    iterations: int = Field(gt=0, strict=True)
    learning_rate: StrictFloat = Field(gt=0, le=1)

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if not self.feature_names or len(self.feature_names) != len(self.coefficients):
            raise ValueError("M8 logistic model feature and coefficient shapes differ")
        if len(self.feature_names) != len(set(self.feature_names)):
            raise ValueError("M8 logistic model feature names must be unique")
        return self


class M8PlattScalerV1(FrozenContractModel):
    schema_version: Literal["m8-platt-scaler-v1"] = "m8-platt-scaler-v1"
    slope: StrictFloat = Field(ge=0, le=100)
    intercept: StrictFloat
    iterations: int = Field(gt=0, strict=True)
    learning_rate: StrictFloat = Field(gt=0, le=1)


class M8CalibrationArtifactV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-artifact-v1"] = "m8-calibration-artifact-v1"
    artifact_id: Sha256Hex
    dataset_manifest_id: Sha256Hex
    detector_model_manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    model_profile_sha256: Sha256Hex
    feature_schema_version: Literal["M8_NON_LLM_CALIBRATION_FEATURES_V1"] = (
        "M8_NON_LLM_CALIBRATION_FEATURES_V1"
    )
    evidence_quality_model: M8RegularizedLogisticModelV1
    evidence_quality_platt: M8PlattScalerV1
    event_risk_model: M8RegularizedLogisticModelV1
    event_risk_platt: M8PlattScalerV1
    evidence_quality_threshold: StrictFloat = Field(gt=0, lt=1)
    created_at: datetime
    mode: Literal["SHADOW"] = "SHADOW"
    parameter_encoding: Literal["CANONICAL_JSON_NO_PICKLE"] = "CANONICAL_JSON_NO_PICKLE"
    llm_features_permitted: Literal[False] = False
    routing_authority: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M8 calibration artifact created_at")

    @model_validator(mode="after")
    def validate_artifact(self) -> Self:
        if self.evidence_quality_model.feature_names != M8_EVIDENCE_QUALITY_FEATURE_NAMES:
            raise ValueError("M8 evidence quality model uses an unauthorized feature schema")
        if self.event_risk_model.feature_names != M8_EVENT_RISK_FEATURE_NAMES:
            raise ValueError("M8 event risk model uses an unauthorized feature schema")
        expected = sha256_hex(
            [
                "m8-calibration-artifact",
                1,
                self.dataset_manifest_id,
                self.detector_model_manifest_id,
                self.config_sha256,
                self.model_profile_sha256,
                self.feature_schema_version,
                self.evidence_quality_model.model_dump(mode="json"),
                self.evidence_quality_platt.model_dump(mode="json"),
                self.event_risk_model.model_dump(mode="json"),
                self.event_risk_platt.model_dump(mode="json"),
                self.evidence_quality_threshold,
                self.mode,
                self.parameter_encoding,
                self.llm_features_permitted,
                self.routing_authority,
            ]
        )
        if self.artifact_id != expected:
            raise ValueError("M8 calibration artifact identity does not match its parameters")
        return self


class M8ReliabilityBinV1(FrozenContractModel):
    bin_index: int = Field(ge=0, lt=M8_CALIBRATION_RELIABILITY_BIN_COUNT, strict=True)
    lower_bound: StrictFloat = Field(ge=0, lt=1)
    upper_bound: StrictFloat = Field(gt=0, le=1)
    sample_count: int = Field(ge=0, strict=True)
    mean_probability: StrictFloat | None = Field(default=None, ge=0, le=1)
    positive_rate: StrictFloat | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def validate_bin(self) -> Self:
        if self.lower_bound >= self.upper_bound:
            raise ValueError("M8 reliability bin must be non-empty")
        populated = self.sample_count > 0
        if populated != (self.mean_probability is not None):
            raise ValueError("M8 reliability mean requires a populated bin")
        if populated != (self.positive_rate is not None):
            raise ValueError("M8 reliability rate requires a populated bin")
        return self


class M8MetricConfidenceIntervalV1(FrozenContractModel):
    metric: M8CalibrationMetricName
    estimate: StrictFloat = Field(ge=0)
    lower_95: StrictFloat = Field(ge=0)
    upper_95: StrictFloat = Field(ge=0)
    valid_bootstrap_samples: int = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if not self.lower_95 <= self.estimate <= self.upper_95:
            raise ValueError("M8 metric estimate lies outside its bootstrap interval")
        return self


class M8BinaryCalibrationMetricsV1(FrozenContractModel):
    sample_count: int = Field(gt=0, strict=True)
    positive_count: int = Field(gt=0, strict=True)
    negative_count: int = Field(gt=0, strict=True)
    true_positive: int = Field(ge=0, strict=True)
    true_negative: int = Field(ge=0, strict=True)
    false_positive: int = Field(ge=0, strict=True)
    false_negative: int = Field(ge=0, strict=True)
    decision_threshold: StrictFloat = Field(gt=0, lt=1)
    accuracy: StrictFloat = Field(ge=0, le=1)
    recall: StrictFloat = Field(ge=0, le=1)
    false_positive_rate: StrictFloat = Field(ge=0, le=1)
    brier_score: StrictFloat = Field(ge=0, le=1)
    log_loss: StrictFloat = Field(ge=0)
    expected_calibration_error: StrictFloat = Field(ge=0, le=1)
    reliability_bins: tuple[M8ReliabilityBinV1, ...]
    confidence_intervals: tuple[M8MetricConfidenceIntervalV1, ...]
    bootstrap_iterations: int = Field(gt=0, strict=True)

    @model_validator(mode="after")
    def validate_metrics(self) -> Self:
        if self.positive_count + self.negative_count != self.sample_count:
            raise ValueError("M8 calibration class counts do not cover the sample")
        if self.true_positive + self.false_negative != self.positive_count:
            raise ValueError("M8 calibration positive confusion counts are inconsistent")
        if self.true_negative + self.false_positive != self.negative_count:
            raise ValueError("M8 calibration negative confusion counts are inconsistent")
        indexes = tuple(item.bin_index for item in self.reliability_bins)
        if indexes != tuple(range(M8_CALIBRATION_RELIABILITY_BIN_COUNT)):
            raise ValueError("M8 calibration report requires ten ordered reliability bins")
        if sum(item.sample_count for item in self.reliability_bins) != self.sample_count:
            raise ValueError("M8 calibration reliability bins do not cover the sample")
        metric_names = tuple(item.metric for item in self.confidence_intervals)
        if metric_names != tuple(M8CalibrationMetricName):
            raise ValueError("M8 calibration report confidence intervals are incomplete")
        return self


class M8CalibrationReportV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-report-v1"] = "m8-calibration-report-v1"
    report_id: Sha256Hex
    artifact_id: Sha256Hex
    dataset_manifest_id: Sha256Hex
    partition: Literal[M8CalibrationPartition.SEALED_TEST] = M8CalibrationPartition.SEALED_TEST
    evidence_quality_metrics: M8BinaryCalibrationMetricsV1
    event_risk_metrics: M8BinaryCalibrationMetricsV1
    generated_at: datetime
    sealed_test_used_for_fitting: Literal[False] = False
    probability_claim_permitted: Literal[False] = False

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        return _require_utc(value, "M8 calibration report generated_at")

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        expected = sha256_hex(
            [
                "m8-calibration-report",
                1,
                self.artifact_id,
                self.dataset_manifest_id,
                self.partition,
                self.evidence_quality_metrics.model_dump(mode="json"),
                self.event_risk_metrics.model_dump(mode="json"),
                self.sealed_test_used_for_fitting,
                self.probability_claim_permitted,
            ]
        )
        if self.report_id != expected:
            raise ValueError("M8 calibration report identity does not match its metrics")
        return self


class M8EvidenceQualityAssessmentV1(FrozenContractModel):
    schema_version: Literal["m8-evidence-quality-assessment-v1"] = (
        "m8-evidence-quality-assessment-v1"
    )
    assessment_id: Sha256Hex
    run_id: ReferenceToken
    asset_id: Sha256Hex
    artifact_id: Sha256Hex | None = None
    mode: M8CalibrationAssessmentMode
    quality_probability: StrictFloat | None = Field(default=None, ge=0, le=1)
    sufficiency_threshold: StrictFloat | None = Field(default=None, gt=0, lt=1)
    sufficient: StrictBool | None = None
    reason_code: M8CalibrationReasonCode | None = None
    llm_output_used: Literal[False] = False
    routing_authority: Literal[False] = False

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M8 evidence-quality run")

    @model_validator(mode="after")
    def validate_assessment(self) -> Self:
        values = (
            self.artifact_id,
            self.quality_probability,
            self.sufficiency_threshold,
            self.sufficient,
        )
        if self.mode == M8CalibrationAssessmentMode.SHADOW:
            if any(value is None for value in values) or self.reason_code is not None:
                raise ValueError("shadow evidence assessment requires scores and no reason")
        elif any(value is not None for value in values) or self.reason_code is None:
            raise ValueError("inapplicable evidence assessment requires only a reason")
        expected = sha256_hex(
            [
                "m8-evidence-quality-assessment",
                1,
                self.run_id,
                self.asset_id,
                self.artifact_id,
                self.mode,
                self.quality_probability,
                self.sufficiency_threshold,
                self.sufficient,
                self.reason_code,
                self.llm_output_used,
                self.routing_authority,
            ]
        )
        if self.assessment_id != expected:
            raise ValueError("M8 evidence-quality identity does not match its score")
        return self


class M8EventRiskAssessmentV1(FrozenContractModel):
    schema_version: Literal["m8-event-risk-assessment-v1"] = "m8-event-risk-assessment-v1"
    assessment_id: Sha256Hex
    run_id: ReferenceToken
    asset_id: Sha256Hex
    evidence_quality_assessment_id: Sha256Hex
    artifact_id: Sha256Hex | None = None
    mode: M8CalibrationAssessmentMode
    raw_event_score: StrictFloat | None = None
    calibrated_probability: StrictFloat | None = Field(default=None, ge=0, le=1)
    reason_code: M8CalibrationReasonCode | None = None
    llm_output_used: Literal[False] = False
    routing_authority: Literal[False] = False

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M8 event-risk run")

    @model_validator(mode="after")
    def validate_assessment(self) -> Self:
        values = (self.artifact_id, self.raw_event_score, self.calibrated_probability)
        if self.mode == M8CalibrationAssessmentMode.SHADOW:
            if any(value is None for value in values) or self.reason_code is not None:
                raise ValueError("shadow event assessment requires scores and no reason")
        elif any(value is not None for value in values) or self.reason_code is None:
            raise ValueError("inapplicable event assessment requires only a reason")
        expected = sha256_hex(
            [
                "m8-event-risk-assessment",
                1,
                self.run_id,
                self.asset_id,
                self.evidence_quality_assessment_id,
                self.artifact_id,
                self.mode,
                self.raw_event_score,
                self.calibrated_probability,
                self.reason_code,
                self.llm_output_used,
                self.routing_authority,
            ]
        )
        if self.assessment_id != expected:
            raise ValueError("M8 event-risk identity does not match its score")
        return self


class M8CalibrationFitResultV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-fit-result-v1"] = "m8-calibration-fit-result-v1"
    status: M8CalibrationFitStatus
    dataset_manifest: M8CalibrationDatasetManifestV1
    artifact: M8CalibrationArtifactV1 | None = None
    report: M8CalibrationReportV1 | None = None
    reason_code: M8CalibrationReasonCode | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        ready = self.status == M8CalibrationFitStatus.SHADOW_READY
        if ready != (self.artifact is not None and self.report is not None):
            raise ValueError("M8 calibration ready state must bind artifact and report")
        if ready != (self.reason_code is None):
            raise ValueError("M8 calibration insufficient result requires one reason")
        if (
            self.artifact
            and self.artifact.dataset_manifest_id != self.dataset_manifest.dataset_manifest_id
        ):
            raise ValueError("M8 calibration artifact belongs to another dataset")
        if self.report and self.artifact and self.report.artifact_id != self.artifact.artifact_id:
            raise ValueError("M8 calibration report belongs to another artifact")
        return self


__all__ = [
    "M8_CALIBRATION_BOOTSTRAP_ITERATIONS",
    "M8_CALIBRATION_MINIMUM_SAMPLES_PER_LABEL",
    "M8_CALIBRATION_RELIABILITY_BIN_COUNT",
    "M8_EVENT_RISK_FEATURE_NAMES",
    "M8_EVIDENCE_QUALITY_FEATURE_NAMES",
    "M8BinaryCalibrationMetricsV1",
    "M8CalibrationArtifactV1",
    "M8CalibrationAssessmentMode",
    "M8CalibrationDatasetEntryV1",
    "M8CalibrationDatasetManifestV1",
    "M8CalibrationFitResultV1",
    "M8CalibrationFitStatus",
    "M8CalibrationMetricName",
    "M8CalibrationPartition",
    "M8CalibrationReasonCode",
    "M8CalibrationReportV1",
    "M8CalibrationTrainingAggregationV1",
    "M8CalibrationTrainingExclusionReason",
    "M8CalibrationTrainingExclusionV1",
    "M8CalibrationTrainingStage",
    "M8DetectorScoreObservationV1",
    "M8EventRiskAssessmentV1",
    "M8EventRiskFeaturesV1",
    "M8EventRiskTrainingExampleV1",
    "M8EvidenceFeatureReason",
    "M8EvidenceFeatureStatus",
    "M8EvidenceQualityAssessmentV1",
    "M8EvidenceQualityFeaturesV1",
    "M8EvidenceQualityTrainingExampleV1",
    "M8MetricConfidenceIntervalV1",
    "M8PlattScalerV1",
    "M8RegularizedLogisticModelV1",
    "M8ReliabilityBinV1",
    "detector_score_observation_id",
]
