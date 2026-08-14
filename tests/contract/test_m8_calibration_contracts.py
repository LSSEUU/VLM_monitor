from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_calibration import (
    M8DetectorScoreObservationV1,
    M8EventRiskFeaturesV1,
    M8EvidenceFeatureReason,
    M8EvidenceFeatureStatus,
    M8EvidenceQualityFeaturesV1,
    detector_score_observation_id,
)


def _quality() -> M8EvidenceQualityFeaturesV1:
    return M8EvidenceQualityFeaturesV1(
        person_score=0.9,
        keypoint_visibility=0.8,
        frontality=0.7,
        sharpness=0.6,
        exposure=0.8,
        inverse_occlusion=0.9,
    )


def test_detector_score_contract_is_local_postprocessed_authority() -> None:
    quality = _quality()
    request_id = "p" + "6" * 63
    values = {
        "run_id": "evaluation-calibration-contract",
        "dataset_manifest_id": "1" * 64,
        "asset_id": "a" * 64,
        "frame_index": 12,
        "frame_content_sha256": "2" * 64,
        "worker_request_id": request_id,
        "raw_response_ref": (
            f"runs/evaluation-calibration-contract/raw/perception/{request_id}.json"
        ),
        "raw_response_sha256": "6" * 64,
        "track_ref": "camera-01:epoch-01:track-01",
        "detector_model_manifest_id": "b" * 64,
        "source_manifest_id": "c" * 64,
        "collection_manifest_id": "3" * 64,
        "authority_config_sha256": "4" * 64,
        "collection_config_sha256": "5" * 64,
        "collection_floor": 0.05,
        "authoritative_score_threshold": 0.35,
        "evidence_clear_threshold": 0.6,
        "goggles_detected": True,
        "postprocessed_goggles_score": 0.42,
        "evidence_feature_status": M8EvidenceFeatureStatus.AVAILABLE,
        "evidence_feature_reason": None,
        "evidence_features": quality,
        "observability_score": 0.8,
    }
    observation_id = detector_score_observation_id(**values)
    observation = M8DetectorScoreObservationV1(
        observation_id=observation_id,
        **values,
    )
    assert observation.llm_output_used is False
    assert observation.postprocessed_goggles_score == 0.42
    with pytest.raises(ValidationError, match="raw response must bind"):
        M8DetectorScoreObservationV1.model_validate(
            {
                **observation.model_dump(mode="json"),
                "raw_response_ref": "runs/another/request.json",
            }
        )


def test_detector_score_rejects_invented_score_for_nondetection() -> None:
    request_id = "p" + "6" * 63
    payload = {
        "observation_id": "d" * 64,
        "run_id": "evaluation-calibration-contract",
        "dataset_manifest_id": "1" * 64,
        "asset_id": "a" * 64,
        "frame_index": 12,
        "frame_content_sha256": "2" * 64,
        "worker_request_id": request_id,
        "raw_response_ref": (
            f"runs/evaluation-calibration-contract/raw/perception/{request_id}.json"
        ),
        "raw_response_sha256": "6" * 64,
        "detector_model_manifest_id": "b" * 64,
        "source_manifest_id": "c" * 64,
        "collection_manifest_id": "3" * 64,
        "authority_config_sha256": "4" * 64,
        "collection_config_sha256": "5" * 64,
        "collection_floor": 0.05,
        "authoritative_score_threshold": 0.35,
        "evidence_clear_threshold": 0.6,
        "goggles_detected": False,
        "postprocessed_goggles_score": 0.1,
        "track_ref": "camera-01:epoch-01:track-01",
        "evidence_feature_status": M8EvidenceFeatureStatus.AVAILABLE,
        "evidence_features": _quality(),
        "observability_score": 0.8,
    }
    with pytest.raises(ValidationError, match="presence must match"):
        M8DetectorScoreObservationV1.model_validate(payload)


def test_detector_score_requires_typed_not_applicable_features() -> None:
    request_id = "p" + "6" * 63
    values = {
        "run_id": "evaluation-calibration-not-applicable",
        "dataset_manifest_id": "1" * 64,
        "asset_id": "a" * 64,
        "frame_index": 0,
        "frame_content_sha256": "2" * 64,
        "worker_request_id": request_id,
        "raw_response_ref": (
            f"runs/evaluation-calibration-not-applicable/raw/perception/{request_id}.json"
        ),
        "raw_response_sha256": "6" * 64,
        "track_ref": None,
        "detector_model_manifest_id": "b" * 64,
        "source_manifest_id": "c" * 64,
        "collection_manifest_id": "3" * 64,
        "authority_config_sha256": "4" * 64,
        "collection_config_sha256": "5" * 64,
        "collection_floor": 0.05,
        "authoritative_score_threshold": 0.35,
        "evidence_clear_threshold": 0.6,
        "goggles_detected": False,
        "postprocessed_goggles_score": None,
        "evidence_feature_status": M8EvidenceFeatureStatus.NOT_APPLICABLE,
        "evidence_feature_reason": M8EvidenceFeatureReason.PERSON_DETECTION_MISSING,
        "evidence_features": None,
        "observability_score": None,
    }
    observation = M8DetectorScoreObservationV1(
        observation_id=detector_score_observation_id(**values),
        **values,
    )
    assert observation.evidence_features is None
    assert observation.evidence_feature_reason == M8EvidenceFeatureReason.PERSON_DETECTION_MISSING


def test_fixed_event_features_forbid_llm_self_reported_fields() -> None:
    payload = {
        "clear_frame_ratio": 0.8,
        "temporal_coverage_ratio": 0.9,
        "track_continuity_ratio": 0.9,
        "goggles_detection_ratio": 0.1,
        "max_goggles_score": 0.2,
        "mean_goggles_score": 0.1,
        "recovery_detected": False,
        "longest_absence_ratio": 0.8,
        "violation_probability": 0.92,
        "role_confidence": 0.95,
    }
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        M8EventRiskFeaturesV1.model_validate(payload)
