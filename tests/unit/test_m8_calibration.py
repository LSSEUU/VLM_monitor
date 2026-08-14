from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import EvidenceClass, ViolationType
from labcourt.contracts.m8_calibration import (
    M8CalibrationAssessmentMode,
    M8CalibrationFitStatus,
    M8CalibrationReasonCode,
    M8EventRiskFeaturesV1,
    M8EventRiskTrainingExampleV1,
    M8EvidenceQualityFeaturesV1,
    M8EvidenceQualityTrainingExampleV1,
    M8PlattScalerV1,
    M8RegularizedLogisticModelV1,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationExpectedRoute,
    M8EvaluationGroundTruthV1,
    M8EvaluationLabelIntervalV1,
    M8EvaluationPpeState,
    M8EvaluationReviewState,
)
from labcourt.domain.m8_calibration import (
    binary_calibration_metrics,
    build_human_confirmed_dataset,
    calibration_artifact_id,
    calibration_partition,
    fit_platt_scaler,
    fit_regularized_logistic,
)
from labcourt.services.m8_calibration import M8CalibrationService

NOW = datetime(2026, 8, 14, 5, tzinfo=UTC)
CONFIG = "c" * 64
MODEL = "d" * 64
DETECTOR = "e" * 64


def _truth(
    asset_id: str,
    state: M8EvaluationPpeState,
    *,
    revision: int = 1,
    review_state: M8EvaluationReviewState = M8EvaluationReviewState.HUMAN_CONFIRMED,
) -> M8EvaluationGroundTruthV1:
    return M8EvaluationGroundTruthV1(
        asset_id=asset_id,
        revision=revision,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        intervals=(
            M8EvaluationLabelIntervalV1(
                start_frame=0,
                end_frame_exclusive=25,
                ppe_state=state,
            ),
        ),
        expected_route=M8EvaluationExpectedRoute.FAST_VERDICT,
        review_state=review_state,
        reviewer_actor_id="safety-officer-demo",
        reviewed_at=NOW if review_state == M8EvaluationReviewState.HUMAN_CONFIRMED else None,
        label_manifest_id="a" * 64,
    )


def _evidence_features(clear: bool) -> M8EvidenceQualityFeaturesV1:
    value = 0.9 if clear else 0.1
    return M8EvidenceQualityFeaturesV1(
        person_score=value,
        keypoint_visibility=value,
        frontality=value,
        sharpness=value,
        exposure=value,
        inverse_occlusion=value,
    )


def _event_features(violation: bool) -> M8EventRiskFeaturesV1:
    return M8EventRiskFeaturesV1(
        clear_frame_ratio=0.9,
        temporal_coverage_ratio=0.9,
        track_continuity_ratio=0.9,
        goggles_detection_ratio=0.05 if violation else 0.9,
        max_goggles_score=0.05 if violation else 0.95,
        mean_goggles_score=0.03 if violation else 0.8,
        recovery_detected=not violation,
        longest_absence_ratio=0.95 if violation else 0.05,
    )


def test_human_manifest_excludes_draft_and_never_leaks_one_asset_group() -> None:
    asset = sha256_hex(["asset", 1])
    confirmed = _truth(asset, M8EvaluationPpeState.WORN)
    draft = _truth(
        sha256_hex(["draft", 1]),
        M8EvaluationPpeState.UNCLEAR,
        review_state=M8EvaluationReviewState.DRAFT,
    )
    manifest = build_human_confirmed_dataset((draft, confirmed), created_at=NOW)
    assert len(manifest.entries) == 1
    entry = manifest.entries[0]
    assert entry.ground_truth_id == confirmed.ground_truth_id
    assert entry.group_id == asset
    assert entry.partition == calibration_partition(asset)
    assert entry.human_confirmed is True
    assert entry.machine_output_is_ground_truth is False


def test_binary_metrics_have_known_values_and_deterministic_group_bootstrap() -> None:
    probabilities = (0.1, 0.4, 0.6, 0.9)
    labels = (False, False, True, True)
    groups = ("group-a", "group-b", "group-c", "group-d")
    first = binary_calibration_metrics(
        probabilities,
        labels,
        groups,
        bootstrap_iterations=40,
        bootstrap_seed="golden",
    )
    second = binary_calibration_metrics(
        probabilities,
        labels,
        groups,
        bootstrap_iterations=40,
        bootstrap_seed="golden",
    )
    assert first == second
    assert first.accuracy == 1.0
    assert first.recall == 1.0
    assert first.false_positive_rate == 0.0
    assert first.brier_score == pytest.approx(0.085)
    assert first.log_loss == pytest.approx(0.3080930697)
    assert first.expected_calibration_error == pytest.approx(0.25)
    assert len(first.reliability_bins) == 10


def test_logistic_and_platt_fit_are_finite_deterministic_json_parameters() -> None:
    rows = ((0.0,), (0.1,), (0.9,), (1.0,))
    labels = (False, False, True, True)
    first = fit_regularized_logistic(("feature",), rows, labels)
    second = fit_regularized_logistic(("feature",), rows, labels)
    assert first == second
    assert first.coefficients[0] > 0
    scores = tuple(first.intercept + first.coefficients[0] * row[0] for row in rows)
    platt = fit_platt_scaler(scores, labels)
    assert platt.slope >= 0
    assert math.isfinite(platt.intercept)
    assert "pickle" not in first.model_dump_json().casefold()


def test_current_small_dataset_returns_insufficient_data() -> None:
    truth = _truth(sha256_hex(["only-real-sample"]), M8EvaluationPpeState.NOT_WORN)
    service = M8CalibrationService(clock=lambda: NOW)
    manifest = service.build_dataset((truth,))
    result = service.fit_shadow(
        manifest,
        evidence_examples=(),
        event_examples=(),
        detector_model_manifest_id=DETECTOR,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
    )
    assert result.status == M8CalibrationFitStatus.INSUFFICIENT_DATA
    assert result.reason_code == M8CalibrationReasonCode.INSUFFICIENT_DATA
    assert result.artifact is None
    assert result.report is None


def test_full_shadow_fit_is_deterministic_and_excludes_llm_features() -> None:
    truths = []
    for state in M8EvaluationPpeState:
        for index in range(100):
            truths.append(_truth(sha256_hex(["asset", state.value, index]), state))
    service = M8CalibrationService(clock=lambda: NOW)
    manifest = service.build_dataset(tuple(truths))
    evidence_examples = tuple(
        M8EvidenceQualityTrainingExampleV1(
            sample_id=entry.sample_id,
            group_id=entry.group_id,
            features=_evidence_features(entry.ppe_state != M8EvaluationPpeState.UNCLEAR),
            human_clear=entry.ppe_state != M8EvaluationPpeState.UNCLEAR,
        )
        for entry in manifest.entries
    )
    event_examples = tuple(
        M8EventRiskTrainingExampleV1(
            sample_id=entry.sample_id,
            group_id=entry.group_id,
            features=_event_features(entry.ppe_state == M8EvaluationPpeState.NOT_WORN),
            violation=entry.ppe_state == M8EvaluationPpeState.NOT_WORN,
        )
        for entry in manifest.entries
        if entry.ppe_state != M8EvaluationPpeState.UNCLEAR
    )
    first = service.fit_shadow(
        manifest,
        evidence_examples=evidence_examples,
        event_examples=event_examples,
        detector_model_manifest_id=DETECTOR,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
    )
    second = service.fit_shadow(
        manifest,
        evidence_examples=evidence_examples,
        event_examples=event_examples,
        detector_model_manifest_id=DETECTOR,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
    )
    assert first == second
    assert first.status == M8CalibrationFitStatus.SHADOW_READY
    assert first.artifact is not None
    assert first.report is not None
    artifact_json = first.artifact.model_dump_json()
    assert "violation_probability" not in artifact_json
    assert "confidence" not in artifact_json
    assert first.artifact.llm_features_permitted is False
    assert first.artifact.routing_authority is False
    assert first.report.probability_claim_permitted is False


def test_binding_mismatch_and_insufficient_evidence_are_not_applicable() -> None:
    feature_names = (
        "person_score",
        "keypoint_visibility",
        "frontality",
        "sharpness",
        "exposure",
        "inverse_occlusion",
    )
    event_names = (
        "clear_frame_ratio",
        "temporal_coverage_ratio",
        "track_continuity_ratio",
        "goggles_detection_ratio",
        "max_goggles_score",
        "mean_goggles_score",
        "recovery_detected",
        "longest_absence_ratio",
    )
    evidence_model = M8RegularizedLogisticModelV1(
        feature_names=feature_names,
        coefficients=(0.0,) * 6,
        intercept=0.0,
        l2_strength=0.01,
        iterations=1,
        learning_rate=0.1,
    )
    event_model = M8RegularizedLogisticModelV1(
        feature_names=event_names,
        coefficients=(0.0,) * 8,
        intercept=0.0,
        l2_strength=0.01,
        iterations=1,
        learning_rate=0.1,
    )
    platt = M8PlattScalerV1(slope=1.0, intercept=0.0, iterations=1, learning_rate=0.1)
    dataset_id = "a" * 64
    from labcourt.contracts.m8_calibration import M8CalibrationArtifactV1

    artifact = M8CalibrationArtifactV1(
        artifact_id=calibration_artifact_id(
            dataset_manifest_id=dataset_id,
            detector_model_manifest_id=DETECTOR,
            config_sha256=CONFIG,
            model_profile_sha256=MODEL,
            evidence_model=evidence_model,
            evidence_platt=platt,
            event_model=event_model,
            event_platt=platt,
            evidence_quality_threshold=0.5,
        ),
        dataset_manifest_id=dataset_id,
        detector_model_manifest_id=DETECTOR,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
        evidence_quality_model=evidence_model,
        evidence_quality_platt=platt,
        event_risk_model=event_model,
        event_risk_platt=platt,
        evidence_quality_threshold=0.5,
        created_at=NOW,
    )
    service = M8CalibrationService(clock=lambda: NOW)
    mismatch = service.assess_evidence(
        run_id="evaluation-calibration-01",
        asset_id="b" * 64,
        features=_evidence_features(True),
        artifact=artifact,
        detector_model_manifest_id="f" * 64,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
    )
    assert mismatch.mode == M8CalibrationAssessmentMode.NOT_APPLICABLE
    assert mismatch.reason_code == M8CalibrationReasonCode.DETECTOR_MODEL_MISMATCH
    assert mismatch.quality_probability is None
    event = service.assess_event(
        run_id=mismatch.run_id,
        asset_id=mismatch.asset_id,
        features=_event_features(True),
        evidence=mismatch,
        artifact=artifact,
        detector_model_manifest_id=DETECTOR,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
    )
    assert event.mode == M8CalibrationAssessmentMode.NOT_APPLICABLE
    assert event.reason_code == M8CalibrationReasonCode.EVIDENCE_INSUFFICIENT
    assert event.calibrated_probability is None
    assert event.routing_authority is False
