from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from labcourt.adapters.storage.sqlite_m8_calibration_repository import (
    SQLiteM8CalibrationRepository,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.m8_calibration import (
    M8CalibrationArtifactV1,
    M8DetectorScoreObservationV1,
    M8EventRiskFeaturesV1,
    M8EvidenceFeatureStatus,
    M8EvidenceQualityFeaturesV1,
    M8PlattScalerV1,
    M8RegularizedLogisticModelV1,
    detector_score_observation_id,
)
from labcourt.domain.m8_calibration import (
    binary_calibration_metrics,
    build_calibration_report,
    calibration_artifact_id,
)
from labcourt.services.m8_calibration import M8CalibrationService

NOW = datetime(2026, 8, 14, 6, tzinfo=UTC)
REPOSITORY = "9" * 64
DETECTOR = "8" * 64
CONFIG = "7" * 64
MODEL = "6" * 64
ASSET = "5" * 64


def test_calibration_repository_requires_migration_0018_identity(tmp_path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    SQLiteM8CalibrationRepository.initialize(database, 5_000, REPOSITORY)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET name = 'm8_calibration_wrong' WHERE version = 18"
        )

    with pytest.raises(RepositoryIntegrityError, match="migration 0018"):
        SQLiteM8CalibrationRepository(database, 5_000, REPOSITORY)


def _quality(value: float = 0.9) -> M8EvidenceQualityFeaturesV1:
    return M8EvidenceQualityFeaturesV1(
        person_score=value,
        keypoint_visibility=value,
        frontality=value,
        sharpness=value,
        exposure=value,
        inverse_occlusion=value,
    )


def _artifact(dataset_id: str) -> M8CalibrationArtifactV1:
    evidence = M8RegularizedLogisticModelV1(
        feature_names=(
            "person_score",
            "keypoint_visibility",
            "frontality",
            "sharpness",
            "exposure",
            "inverse_occlusion",
        ),
        coefficients=(0.1,) * 6,
        intercept=0.0,
        l2_strength=0.01,
        iterations=10,
        learning_rate=0.1,
    )
    event = M8RegularizedLogisticModelV1(
        feature_names=(
            "clear_frame_ratio",
            "temporal_coverage_ratio",
            "track_continuity_ratio",
            "goggles_detection_ratio",
            "max_goggles_score",
            "mean_goggles_score",
            "recovery_detected",
            "longest_absence_ratio",
        ),
        coefficients=(0.1,) * 8,
        intercept=0.0,
        l2_strength=0.01,
        iterations=10,
        learning_rate=0.1,
    )
    platt = M8PlattScalerV1(slope=1.0, intercept=0.0, iterations=10, learning_rate=0.1)
    identity = calibration_artifact_id(
        dataset_manifest_id=dataset_id,
        detector_model_manifest_id=DETECTOR,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
        evidence_model=evidence,
        evidence_platt=platt,
        event_model=event,
        event_platt=platt,
        evidence_quality_threshold=0.5,
    )
    return M8CalibrationArtifactV1(
        artifact_id=identity,
        dataset_manifest_id=dataset_id,
        detector_model_manifest_id=DETECTOR,
        config_sha256=CONFIG,
        model_profile_sha256=MODEL,
        evidence_quality_model=evidence,
        evidence_quality_platt=platt,
        event_risk_model=event,
        event_risk_platt=platt,
        evidence_quality_threshold=0.5,
        created_at=NOW,
    )


def test_calibration_authorities_are_append_only_and_restart_readable(tmp_path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository = SQLiteM8CalibrationRepository.initialize(database, 5_000, REPOSITORY)
    service = M8CalibrationService(clock=lambda: NOW)
    dataset = repository.put_dataset(service.build_dataset(()))
    artifact = repository.put_artifact(_artifact(dataset.dataset_manifest_id))
    metrics = binary_calibration_metrics(
        (0.1, 0.4, 0.6, 0.9),
        (False, False, True, True),
        ("a", "b", "c", "d"),
        bootstrap_iterations=20,
    )
    report = repository.put_report(
        build_calibration_report(artifact, metrics, metrics, generated_at=NOW)
    )

    quality = _quality()
    request_id = "p" + "0" * 63
    observation_values = {
        "run_id": "evaluation-calibration-storage",
        "dataset_manifest_id": dataset.dataset_manifest_id,
        "asset_id": ASSET,
        "frame_index": 4,
        "frame_content_sha256": "3" * 64,
        "worker_request_id": request_id,
        "raw_response_ref": (
            f"runs/evaluation-calibration-storage/raw/perception/{request_id}.json"
        ),
        "raw_response_sha256": "0" * 64,
        "track_ref": "camera-01:epoch-01:track-01",
        "detector_model_manifest_id": DETECTOR,
        "source_manifest_id": "4" * 64,
        "collection_manifest_id": "2" * 64,
        "authority_config_sha256": CONFIG,
        "collection_config_sha256": "1" * 64,
        "collection_floor": 0.05,
        "authoritative_score_threshold": 0.35,
        "evidence_clear_threshold": 0.6,
        "goggles_detected": True,
        "postprocessed_goggles_score": 0.4,
        "evidence_feature_status": M8EvidenceFeatureStatus.AVAILABLE,
        "evidence_feature_reason": None,
        "evidence_features": quality,
        "observability_score": 0.9,
    }
    observation_id = detector_score_observation_id(**observation_values)
    observation = repository.put_detector_observation(
        M8DetectorScoreObservationV1(observation_id=observation_id, **observation_values)
    )
    evidence = repository.put_evidence_assessment(
        service.assess_evidence(
            run_id=observation.run_id,
            asset_id=observation.asset_id,
            features=quality,
            artifact=artifact,
            detector_model_manifest_id=DETECTOR,
            config_sha256=CONFIG,
            model_profile_sha256=MODEL,
        )
    )
    event = repository.put_event_assessment(
        service.assess_event(
            run_id=observation.run_id,
            asset_id=observation.asset_id,
            features=M8EventRiskFeaturesV1(
                clear_frame_ratio=0.8,
                temporal_coverage_ratio=0.9,
                track_continuity_ratio=0.9,
                goggles_detection_ratio=0.1,
                max_goggles_score=0.2,
                mean_goggles_score=0.1,
                recovery_detected=False,
                longest_absence_ratio=0.8,
            ),
            evidence=evidence,
            artifact=artifact,
            detector_model_manifest_id=DETECTOR,
            config_sha256=CONFIG,
            model_profile_sha256=MODEL,
        )
    )

    restarted = SQLiteM8CalibrationRepository(database, 5_000, REPOSITORY)
    assert restarted.get_dataset(dataset.dataset_manifest_id) == dataset
    assert restarted.list_datasets() == (dataset,)
    assert restarted.get_latest_dataset() == dataset
    assert restarted.get_artifact(artifact.artifact_id) == artifact
    assert restarted.list_artifacts(dataset.dataset_manifest_id) == (artifact,)
    assert restarted.get_latest_artifact(dataset.dataset_manifest_id) == artifact
    assert restarted.get_report(report.report_id) == report
    assert restarted.list_reports(artifact.artifact_id) == (report,)
    assert restarted.get_latest_report(artifact.artifact_id) == report
    assert restarted.get_detector_observation(observation.observation_id) == observation
    assert restarted.list_detector_observations(observation.run_id) == (observation,)
    assert restarted.get_evidence_assessment(evidence.assessment_id) == evidence
    assert restarted.get_latest_evidence_assessment(evidence.run_id) == evidence
    assert restarted.get_event_assessment(event.assessment_id) == event
    assert restarted.get_latest_event_assessment(event.run_id) == event
    assert event.routing_authority is False
