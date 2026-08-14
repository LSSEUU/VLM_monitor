"""Pure deterministic statistics for additive M8 shadow calibration."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Sequence
from datetime import datetime

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m8_calibration import (
    M8_CALIBRATION_BOOTSTRAP_ITERATIONS,
    M8_CALIBRATION_RELIABILITY_BIN_COUNT,
    M8BinaryCalibrationMetricsV1,
    M8CalibrationArtifactV1,
    M8CalibrationAssessmentMode,
    M8CalibrationDatasetEntryV1,
    M8CalibrationDatasetManifestV1,
    M8CalibrationMetricName,
    M8CalibrationPartition,
    M8CalibrationReasonCode,
    M8CalibrationReportV1,
    M8EventRiskAssessmentV1,
    M8EvidenceQualityAssessmentV1,
    M8MetricConfidenceIntervalV1,
    M8PlattScalerV1,
    M8RegularizedLogisticModelV1,
    M8ReliabilityBinV1,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationGroundTruthV1,
    M8EvaluationReviewState,
)

_EPSILON = 1e-15
_DEFAULT_L2 = 0.01
_DEFAULT_LOGISTIC_ITERATIONS = 800
_DEFAULT_LOGISTIC_LEARNING_RATE = 0.15
_DEFAULT_PLATT_ITERATIONS = 600
_DEFAULT_PLATT_LEARNING_RATE = 0.05


def calibration_partition(group_id: str) -> M8CalibrationPartition:
    """Assign one immutable source group to a deterministic 60/20/20 split."""

    try:
        digest = bytes.fromhex(group_id)
    except ValueError:
        digest = hashlib.sha256(group_id.encode("utf-8")).digest()
    if len(digest) != 32:
        digest = hashlib.sha256(group_id.encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:8], "big") % 100
    if bucket < 60:
        return M8CalibrationPartition.DEVELOPMENT
    if bucket < 80:
        return M8CalibrationPartition.CALIBRATION
    return M8CalibrationPartition.SEALED_TEST


def build_human_confirmed_dataset(
    truths: Sequence[M8EvaluationGroundTruthV1],
    *,
    created_at: datetime,
) -> M8CalibrationDatasetManifestV1:
    """Build interval samples only from human-confirmed ground-truth revisions."""

    entries: list[M8CalibrationDatasetEntryV1] = []
    seen_truth_ids: set[str] = set()
    for truth in sorted(truths, key=lambda item: (item.asset_id, item.revision)):
        if truth.review_state != M8EvaluationReviewState.HUMAN_CONFIRMED:
            continue
        if truth.ground_truth_id in seen_truth_ids:
            raise ValueError("duplicate human-confirmed ground truth supplied for calibration")
        seen_truth_ids.add(truth.ground_truth_id)
        group_id = truth.asset_id
        partition = calibration_partition(group_id)
        for interval_index, interval in enumerate(truth.intervals):
            sample_id = sha256_hex(
                [
                    "m8-calibration-sample",
                    1,
                    truth.asset_id,
                    truth.ground_truth_id,
                    truth.revision,
                    interval_index,
                    interval.start_frame,
                    interval.end_frame_exclusive,
                    interval.ppe_state,
                ]
            )
            entries.append(
                M8CalibrationDatasetEntryV1(
                    sample_id=sample_id,
                    asset_id=truth.asset_id,
                    ground_truth_id=truth.ground_truth_id,
                    ground_truth_revision=truth.revision,
                    interval_index=interval_index,
                    start_frame=interval.start_frame,
                    end_frame_exclusive=interval.end_frame_exclusive,
                    ppe_state=interval.ppe_state,
                    group_id=group_id,
                    partition=partition,
                )
            )
    ordered = tuple(sorted(entries, key=lambda item: item.sample_id))
    dataset_id = sha256_hex(
        [
            "m8-calibration-dataset-manifest",
            1,
            "SHA256_GROUP_60_20_20_V1",
            tuple(entry.model_dump(mode="json") for entry in ordered),
        ]
    )
    return M8CalibrationDatasetManifestV1(
        dataset_manifest_id=dataset_id,
        entries=ordered,
        created_at=created_at,
    )


def dataset_label_counts(
    manifest: M8CalibrationDatasetManifestV1,
) -> Counter[str]:
    return Counter(entry.ppe_state.value for entry in manifest.entries)


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponential = math.exp(-min(value, 709.0))
        return 1.0 / (1.0 + exponential)
    exponential = math.exp(max(value, -709.0))
    return exponential / (1.0 + exponential)


def linear_score(model: M8RegularizedLogisticModelV1, features: Sequence[float]) -> float:
    if len(features) != len(model.coefficients):
        raise ValueError("calibration feature vector does not match its logistic model")
    if any(not math.isfinite(value) for value in features):
        raise ValueError("calibration feature vector contains a non-finite value")
    return float(model.intercept) + sum(
        float(coefficient) * value
        for coefficient, value in zip(model.coefficients, features, strict=True)
    )


def logistic_probability(
    model: M8RegularizedLogisticModelV1,
    features: Sequence[float],
) -> float:
    return _sigmoid(linear_score(model, features))


def platt_probability(scaler: M8PlattScalerV1, score: float) -> float:
    if not math.isfinite(score):
        raise ValueError("Platt calibration requires a finite base score")
    return _sigmoid(float(scaler.slope) * score + float(scaler.intercept))


def fit_regularized_logistic(
    feature_names: tuple[str, ...],
    rows: Sequence[Sequence[float]],
    labels: Sequence[bool],
    *,
    l2_strength: float = _DEFAULT_L2,
    iterations: int = _DEFAULT_LOGISTIC_ITERATIONS,
    learning_rate: float = _DEFAULT_LOGISTIC_LEARNING_RATE,
) -> M8RegularizedLogisticModelV1:
    """Fit a small class-balanced L2 logistic model with fixed gradient descent."""

    if len(rows) != len(labels) or not rows:
        raise ValueError("logistic training rows and labels must be non-empty and aligned")
    width = len(feature_names)
    if width == 0 or any(len(row) != width for row in rows):
        raise ValueError("logistic training rows do not match their feature schema")
    if any(not math.isfinite(value) for row in rows for value in row):
        raise ValueError("logistic training rows contain non-finite values")
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("logistic training requires both human-confirmed classes")
    if l2_strength <= 0 or iterations <= 0 or not 0 < learning_rate <= 1:
        raise ValueError("logistic hyperparameters are outside their bounded domain")

    coefficients = [0.0] * width
    intercept = math.log(positives / negatives)
    positive_weight = 0.5 / positives
    negative_weight = 0.5 / negatives
    for _ in range(iterations):
        gradient = [l2_strength * value for value in coefficients]
        intercept_gradient = 0.0
        for row, label in zip(rows, labels, strict=True):
            score = intercept + sum(
                coefficient * value for coefficient, value in zip(coefficients, row, strict=True)
            )
            error = _sigmoid(score) - float(label)
            weight = positive_weight if label else negative_weight
            intercept_gradient += weight * error
            for index, value in enumerate(row):
                gradient[index] += weight * error * value
        intercept -= learning_rate * intercept_gradient
        for index in range(width):
            coefficients[index] -= learning_rate * gradient[index]

    return M8RegularizedLogisticModelV1(
        feature_names=feature_names,
        coefficients=tuple(float(value) for value in coefficients),
        intercept=float(intercept),
        l2_strength=float(l2_strength),
        iterations=iterations,
        learning_rate=float(learning_rate),
    )


def fit_platt_scaler(
    scores: Sequence[float],
    labels: Sequence[bool],
    *,
    iterations: int = _DEFAULT_PLATT_ITERATIONS,
    learning_rate: float = _DEFAULT_PLATT_LEARNING_RATE,
) -> M8PlattScalerV1:
    """Fit a monotone held-out Platt map over finite base decision scores."""

    if len(scores) != len(labels) or not scores:
        raise ValueError("Platt scores and labels must be non-empty and aligned")
    if any(not math.isfinite(value) for value in scores):
        raise ValueError("Platt scores must be finite")
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("Platt calibration requires both human-confirmed classes")
    slope = 1.0
    intercept = math.log((positives + 1.0) / (negatives + 1.0))
    positive_weight = 0.5 / positives
    negative_weight = 0.5 / negatives
    for _ in range(iterations):
        slope_gradient = 0.0
        intercept_gradient = 0.0
        for score, label in zip(scores, labels, strict=True):
            error = _sigmoid(slope * score + intercept) - float(label)
            weight = positive_weight if label else negative_weight
            slope_gradient += weight * error * score
            intercept_gradient += weight * error
        slope = min(100.0, max(0.0, slope - learning_rate * slope_gradient))
        intercept -= learning_rate * intercept_gradient
    return M8PlattScalerV1(
        slope=float(slope),
        intercept=float(intercept),
        iterations=iterations,
        learning_rate=float(learning_rate),
    )


def calibration_artifact_id(
    *,
    dataset_manifest_id: str,
    detector_model_manifest_id: str,
    config_sha256: str,
    model_profile_sha256: str,
    evidence_model: M8RegularizedLogisticModelV1,
    evidence_platt: M8PlattScalerV1,
    event_model: M8RegularizedLogisticModelV1,
    event_platt: M8PlattScalerV1,
    evidence_quality_threshold: float,
) -> str:
    return sha256_hex(
        [
            "m8-calibration-artifact",
            1,
            dataset_manifest_id,
            detector_model_manifest_id,
            config_sha256,
            model_profile_sha256,
            "M8_NON_LLM_CALIBRATION_FEATURES_V1",
            evidence_model.model_dump(mode="json"),
            evidence_platt.model_dump(mode="json"),
            event_model.model_dump(mode="json"),
            event_platt.model_dump(mode="json"),
            evidence_quality_threshold,
            "SHADOW",
            "CANONICAL_JSON_NO_PICKLE",
            False,
            False,
        ]
    )


def _reliability_bins(
    probabilities: Sequence[float], labels: Sequence[bool]
) -> tuple[M8ReliabilityBinV1, ...]:
    bin_probabilities: list[list[float]] = [[] for _ in range(M8_CALIBRATION_RELIABILITY_BIN_COUNT)]
    bin_labels: list[list[bool]] = [[] for _ in range(M8_CALIBRATION_RELIABILITY_BIN_COUNT)]
    for probability, label in zip(probabilities, labels, strict=True):
        index = min(
            M8_CALIBRATION_RELIABILITY_BIN_COUNT - 1,
            int(probability * M8_CALIBRATION_RELIABILITY_BIN_COUNT),
        )
        bin_probabilities[index].append(probability)
        bin_labels[index].append(label)
    bins: list[M8ReliabilityBinV1] = []
    for index, values in enumerate(bin_probabilities):
        labels_in_bin = bin_labels[index]
        bins.append(
            M8ReliabilityBinV1(
                bin_index=index,
                lower_bound=float(index / M8_CALIBRATION_RELIABILITY_BIN_COUNT),
                upper_bound=float((index + 1) / M8_CALIBRATION_RELIABILITY_BIN_COUNT),
                sample_count=len(values),
                mean_probability=(float(sum(values) / len(values)) if values else None),
                positive_rate=(
                    float(sum(labels_in_bin) / len(labels_in_bin)) if labels_in_bin else None
                ),
            )
        )
    return tuple(bins)


def _metric_values(
    probabilities: Sequence[float],
    labels: Sequence[bool],
    *,
    threshold: float,
) -> dict[M8CalibrationMetricName, float | None]:
    predicted = tuple(value >= threshold for value in probabilities)
    positive_count = sum(labels)
    negative_count = len(labels) - positive_count
    true_positive = sum(
        1 for actual, proposal in zip(labels, predicted, strict=True) if actual and proposal
    )
    true_negative = sum(
        not actual and not proposal for actual, proposal in zip(labels, predicted, strict=True)
    )
    false_positive = sum(
        not actual and proposal for actual, proposal in zip(labels, predicted, strict=True)
    )
    accuracy = (true_positive + true_negative) / len(labels)
    recall = true_positive / positive_count if positive_count else None
    false_positive_rate = false_positive / negative_count if negative_count else None
    brier = sum(
        (probability - float(label)) ** 2
        for probability, label in zip(probabilities, labels, strict=True)
    ) / len(labels)
    log_loss = -sum(
        float(label) * math.log(min(1.0 - _EPSILON, max(_EPSILON, probability)))
        + (1.0 - float(label)) * math.log(min(1.0 - _EPSILON, max(_EPSILON, 1.0 - probability)))
        for probability, label in zip(probabilities, labels, strict=True)
    ) / len(labels)
    bins = _reliability_bins(probabilities, labels)
    ece = 0.0
    for item in bins:
        if item.sample_count == 0:
            continue
        assert item.mean_probability is not None
        assert item.positive_rate is not None
        ece += (
            item.sample_count
            / len(labels)
            * abs(float(item.mean_probability) - float(item.positive_rate))
        )
    return {
        M8CalibrationMetricName.ACCURACY: float(accuracy),
        M8CalibrationMetricName.RECALL: float(recall) if recall is not None else None,
        M8CalibrationMetricName.FALSE_POSITIVE_RATE: (
            float(false_positive_rate) if false_positive_rate is not None else None
        ),
        M8CalibrationMetricName.BRIER_SCORE: float(brier),
        M8CalibrationMetricName.LOG_LOSS: float(log_loss),
        M8CalibrationMetricName.ECE: float(ece),
    }


def _bootstrap_index(seed: str, iteration: int, draw: int, size: int) -> int:
    digest = hashlib.sha256(f"{seed}:{iteration}:{draw}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big") % size


def _quantile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = quantile * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    fraction = position - lower
    return float(ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction)


def binary_calibration_metrics(
    probabilities: Sequence[float],
    labels: Sequence[bool],
    group_ids: Sequence[str],
    *,
    decision_threshold: float = 0.5,
    bootstrap_iterations: int = M8_CALIBRATION_BOOTSTRAP_ITERATIONS,
    bootstrap_seed: str = "m8-calibration-bootstrap-v1",
) -> M8BinaryCalibrationMetricsV1:
    """Compute reproducible binary metrics and deterministic group bootstrap CIs."""

    if not probabilities or len(probabilities) != len(labels) or len(labels) != len(group_ids):
        raise ValueError("calibration metrics require aligned non-empty inputs")
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in probabilities):
        raise ValueError("calibration probabilities must be finite values in [0,1]")
    positive_count = sum(labels)
    negative_count = len(labels) - positive_count
    if positive_count == 0 or negative_count == 0:
        raise ValueError("calibration metrics require both human-confirmed classes")
    if not 0 < decision_threshold < 1 or bootstrap_iterations <= 0:
        raise ValueError("calibration metric parameters are outside their bounded domain")
    grouped: dict[str, list[int]] = {}
    for index, group_id in enumerate(group_ids):
        grouped.setdefault(group_id, []).append(index)
    groups = tuple(sorted(grouped))
    if not groups:
        raise ValueError("calibration metrics require at least one source group")

    estimates = _metric_values(probabilities, labels, threshold=decision_threshold)
    bootstrap: dict[M8CalibrationMetricName, list[float]] = {
        metric: [] for metric in M8CalibrationMetricName
    }
    for iteration in range(bootstrap_iterations):
        selected_indexes: list[int] = []
        for draw in range(len(groups)):
            group = groups[_bootstrap_index(bootstrap_seed, iteration, draw, len(groups))]
            selected_indexes.extend(grouped[group])
        selected_probabilities = tuple(probabilities[index] for index in selected_indexes)
        selected_labels = tuple(labels[index] for index in selected_indexes)
        resampled_metrics = _metric_values(
            selected_probabilities,
            selected_labels,
            threshold=decision_threshold,
        )
        for metric, value in resampled_metrics.items():
            if value is not None:
                bootstrap[metric].append(value)

    intervals: list[M8MetricConfidenceIntervalV1] = []
    for metric in M8CalibrationMetricName:
        estimate = estimates[metric]
        bootstrap_values = bootstrap[metric]
        if estimate is None or not bootstrap_values:
            raise ValueError("calibration bootstrap could not estimate every metric")
        lower = min(estimate, _quantile(bootstrap_values, 0.025))
        upper = max(estimate, _quantile(bootstrap_values, 0.975))
        intervals.append(
            M8MetricConfidenceIntervalV1(
                metric=metric,
                estimate=float(estimate),
                lower_95=float(lower),
                upper_95=float(upper),
                valid_bootstrap_samples=len(bootstrap_values),
            )
        )

    predicted = tuple(value >= decision_threshold for value in probabilities)
    true_positive = sum(
        1 for actual, proposal in zip(labels, predicted, strict=True) if actual and proposal
    )
    true_negative = sum(
        not actual and not proposal for actual, proposal in zip(labels, predicted, strict=True)
    )
    false_positive = sum(
        not actual and proposal for actual, proposal in zip(labels, predicted, strict=True)
    )
    false_negative = sum(
        actual and not proposal for actual, proposal in zip(labels, predicted, strict=True)
    )
    required_estimates: dict[M8CalibrationMetricName, float] = {}
    for metric, estimate in estimates.items():
        if estimate is None:
            raise ValueError("calibration metric is undefined")
        required_estimates[metric] = estimate
    return M8BinaryCalibrationMetricsV1(
        sample_count=len(labels),
        positive_count=positive_count,
        negative_count=negative_count,
        true_positive=true_positive,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        decision_threshold=float(decision_threshold),
        accuracy=float(required_estimates[M8CalibrationMetricName.ACCURACY]),
        recall=float(required_estimates[M8CalibrationMetricName.RECALL]),
        false_positive_rate=float(required_estimates[M8CalibrationMetricName.FALSE_POSITIVE_RATE]),
        brier_score=float(required_estimates[M8CalibrationMetricName.BRIER_SCORE]),
        log_loss=float(required_estimates[M8CalibrationMetricName.LOG_LOSS]),
        expected_calibration_error=float(required_estimates[M8CalibrationMetricName.ECE]),
        reliability_bins=_reliability_bins(probabilities, labels),
        confidence_intervals=tuple(intervals),
        bootstrap_iterations=bootstrap_iterations,
    )


def calibration_report_id(
    artifact: M8CalibrationArtifactV1,
    evidence_metrics: M8BinaryCalibrationMetricsV1,
    event_metrics: M8BinaryCalibrationMetricsV1,
) -> str:
    return sha256_hex(
        [
            "m8-calibration-report",
            1,
            artifact.artifact_id,
            artifact.dataset_manifest_id,
            M8CalibrationPartition.SEALED_TEST,
            evidence_metrics.model_dump(mode="json"),
            event_metrics.model_dump(mode="json"),
            False,
            False,
        ]
    )


def build_calibration_report(
    artifact: M8CalibrationArtifactV1,
    evidence_metrics: M8BinaryCalibrationMetricsV1,
    event_metrics: M8BinaryCalibrationMetricsV1,
    *,
    generated_at: datetime,
) -> M8CalibrationReportV1:
    return M8CalibrationReportV1(
        report_id=calibration_report_id(artifact, evidence_metrics, event_metrics),
        artifact_id=artifact.artifact_id,
        dataset_manifest_id=artifact.dataset_manifest_id,
        evidence_quality_metrics=evidence_metrics,
        event_risk_metrics=event_metrics,
        generated_at=generated_at,
    )


def evidence_assessment_id(
    *,
    run_id: str,
    asset_id: str,
    artifact_id: str | None,
    mode: M8CalibrationAssessmentMode,
    quality_probability: float | None,
    sufficiency_threshold: float | None,
    sufficient: bool | None,
    reason_code: M8CalibrationReasonCode | None,
) -> str:
    return sha256_hex(
        [
            "m8-evidence-quality-assessment",
            1,
            run_id,
            asset_id,
            artifact_id,
            mode,
            quality_probability,
            sufficiency_threshold,
            sufficient,
            reason_code,
            False,
            False,
        ]
    )


def event_assessment_id(
    *,
    run_id: str,
    asset_id: str,
    evidence_quality_assessment_id: str,
    artifact_id: str | None,
    mode: M8CalibrationAssessmentMode,
    raw_event_score: float | None,
    calibrated_probability: float | None,
    reason_code: M8CalibrationReasonCode | None,
) -> str:
    return sha256_hex(
        [
            "m8-event-risk-assessment",
            1,
            run_id,
            asset_id,
            evidence_quality_assessment_id,
            artifact_id,
            mode,
            raw_event_score,
            calibrated_probability,
            reason_code,
            False,
            False,
        ]
    )


def inapplicable_evidence_assessment(
    *,
    run_id: str,
    asset_id: str,
    reason_code: M8CalibrationReasonCode,
) -> M8EvidenceQualityAssessmentV1:
    mode = M8CalibrationAssessmentMode.NOT_APPLICABLE
    return M8EvidenceQualityAssessmentV1(
        assessment_id=evidence_assessment_id(
            run_id=run_id,
            asset_id=asset_id,
            artifact_id=None,
            mode=mode,
            quality_probability=None,
            sufficiency_threshold=None,
            sufficient=None,
            reason_code=reason_code,
        ),
        run_id=run_id,
        asset_id=asset_id,
        mode=mode,
        reason_code=reason_code,
    )


def inapplicable_event_assessment(
    *,
    run_id: str,
    asset_id: str,
    evidence_quality_assessment_id: str,
    reason_code: M8CalibrationReasonCode,
) -> M8EventRiskAssessmentV1:
    mode = M8CalibrationAssessmentMode.NOT_APPLICABLE
    return M8EventRiskAssessmentV1(
        assessment_id=event_assessment_id(
            run_id=run_id,
            asset_id=asset_id,
            evidence_quality_assessment_id=evidence_quality_assessment_id,
            artifact_id=None,
            mode=mode,
            raw_event_score=None,
            calibrated_probability=None,
            reason_code=reason_code,
        ),
        run_id=run_id,
        asset_id=asset_id,
        evidence_quality_assessment_id=evidence_quality_assessment_id,
        mode=mode,
        reason_code=reason_code,
    )


__all__ = [
    "binary_calibration_metrics",
    "build_calibration_report",
    "build_human_confirmed_dataset",
    "calibration_artifact_id",
    "calibration_partition",
    "calibration_report_id",
    "dataset_label_counts",
    "event_assessment_id",
    "evidence_assessment_id",
    "fit_platt_scaler",
    "fit_regularized_logistic",
    "inapplicable_event_assessment",
    "inapplicable_evidence_assessment",
    "linear_score",
    "logistic_probability",
    "platt_probability",
]
