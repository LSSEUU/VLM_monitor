from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from labcourt.adapters.storage.sqlite_m8_calibration_repository import (
    SQLiteM8CalibrationRepository,
)
from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import EvidenceClass, ViolationType
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_calibration import (
    M8CalibrationDatasetManifestV1,
    M8CalibrationFitStatus,
    M8CalibrationReasonCode,
    M8CalibrationTrainingAggregationV1,
    M8EventRiskFeaturesV1,
    M8EventRiskTrainingExampleV1,
    M8EvidenceQualityFeaturesV1,
    M8EvidenceQualityTrainingExampleV1,
)
from labcourt.contracts.m8_calibration_api import (
    M8CalibrationDatasetCreateRequestV1,
    M8CalibrationFitRequestV1,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationExpectedRoute,
    M8EvaluationGroundTruthV1,
    M8EvaluationLabelIntervalV1,
    M8EvaluationPpeState,
    M8EvaluationReviewState,
)
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_calibration import M8CalibrationService
from labcourt.services.m8_calibration_api import M8CalibrationApiService
from labcourt.services.m8_calibration_observation import (
    M8CalibrationCollectionError,
    M8CalibrationCollectionFailureCode,
    M8CalibrationObservationService,
)
from labcourt.services.m8_evaluation import M8EvaluationService

NOW = datetime(2026, 8, 14, 9, tzinfo=UTC)
REPOSITORY = "9" * 64
DETECTOR = "8" * 64
CONFIG = "7" * 64
MODEL_PROFILE = "6" * 64


def _principal(role: M8ActorRole) -> M8ApiPrincipalV1:
    return M8ApiPrincipalV1(
        actor_id=f"{role.value.casefold()}-calibration-test",
        credential_id=f"credential-{role.value.casefold()}",
        credential_authority_id="1" * 64,
        credential_catalog_id="2" * 64,
        authentication_manifest_id="3" * 64,
    )


def _truth(asset_id: str, state: M8EvaluationPpeState) -> M8EvaluationGroundTruthV1:
    return M8EvaluationGroundTruthV1(
        asset_id=asset_id,
        revision=1,
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
        review_state=M8EvaluationReviewState.HUMAN_CONFIRMED,
        reviewer_actor_id="safety-officer-calibration-test",
        reviewed_at=NOW,
        label_manifest_id="4" * 64,
    )


def _full_truths() -> tuple[M8EvaluationGroundTruthV1, ...]:
    return tuple(
        _truth(sha256_hex(["calibration-asset", state.value, index]), state)
        for state in M8EvaluationPpeState
        for index in range(100)
    )


class _Operations:
    def get_current_actor_authority(self, actor_id: str) -> object:
        role_name = actor_id.removesuffix("-calibration-test").upper()
        return SimpleNamespace(
            authority=SimpleNamespace(
                actor_id=actor_id,
                role=M8ActorRole(role_name),
                active=True,
            )
        )


class _Evaluation:
    model_profile_sha256 = MODEL_PROFILE

    def __init__(self, truths: tuple[M8EvaluationGroundTruthV1, ...] = ()) -> None:
        self._truths = truths

    def dashboard(self, _principal: M8ApiPrincipalV1) -> object:
        return SimpleNamespace(ground_truth=self._truths)


class _Observations:
    authority_manifest = SimpleNamespace(detector=SimpleNamespace(model_manifest_id=DETECTOR))
    authority_config = SimpleNamespace(config_sha256=CONFIG)

    def __init__(
        self,
        aggregation: M8CalibrationTrainingAggregationV1 | None = None,
        failure: M8CalibrationCollectionError | None = None,
    ) -> None:
        self.aggregation = aggregation
        self.failure = failure
        self.collect_calls = 0
        self.aggregate_calls = 0

    def collect(self, *, run_id: str, dataset: object) -> tuple[object, ...]:
        assert run_id.startswith("calibration-")
        assert dataset is not None
        self.collect_calls += 1
        if self.failure is not None:
            raise self.failure
        return ()

    def aggregate(
        self,
        *,
        run_id: str,
        dataset: object,
    ) -> M8CalibrationTrainingAggregationV1:
        assert run_id.startswith("calibration-")
        assert dataset is not None
        self.aggregate_calls += 1
        assert self.aggregation is not None
        return self.aggregation


def _repository(tmp_path: Path) -> SQLiteM8CalibrationRepository:
    return SQLiteM8CalibrationRepository.initialize(
        tmp_path / PLATFORM_DATABASE_NAME,
        5_000,
        REPOSITORY,
    )


def _api(
    repository: SQLiteM8CalibrationRepository,
    calibration: M8CalibrationService,
    observations: _Observations,
    *,
    truths: tuple[M8EvaluationGroundTruthV1, ...] = (),
) -> M8CalibrationApiService:
    return M8CalibrationApiService(
        operations_repository=cast(M8OperationsRepository, _Operations()),
        evaluation_service=cast(M8EvaluationService, _Evaluation(truths)),
        repository=repository,
        calibration_service=calibration,
        observation_service=cast(M8CalibrationObservationService, observations),
    )


def _aggregation(
    calibration: M8CalibrationService,
    truths: tuple[M8EvaluationGroundTruthV1, ...],
) -> tuple[M8CalibrationDatasetManifestV1, M8CalibrationTrainingAggregationV1]:
    manifest = calibration.build_dataset(truths)
    evidence = tuple(
        M8EvidenceQualityTrainingExampleV1(
            sample_id=entry.sample_id,
            group_id=entry.group_id,
            features=M8EvidenceQualityFeaturesV1(
                person_score=0.9 if entry.ppe_state != M8EvaluationPpeState.UNCLEAR else 0.1,
                keypoint_visibility=(
                    0.9 if entry.ppe_state != M8EvaluationPpeState.UNCLEAR else 0.1
                ),
                frontality=0.9 if entry.ppe_state != M8EvaluationPpeState.UNCLEAR else 0.1,
                sharpness=0.9 if entry.ppe_state != M8EvaluationPpeState.UNCLEAR else 0.1,
                exposure=0.9 if entry.ppe_state != M8EvaluationPpeState.UNCLEAR else 0.1,
                inverse_occlusion=(0.9 if entry.ppe_state != M8EvaluationPpeState.UNCLEAR else 0.1),
            ),
            human_clear=entry.ppe_state != M8EvaluationPpeState.UNCLEAR,
        )
        for entry in manifest.entries
    )
    event = tuple(
        M8EventRiskTrainingExampleV1(
            sample_id=entry.sample_id,
            group_id=entry.group_id,
            features=M8EventRiskFeaturesV1(
                clear_frame_ratio=0.9,
                temporal_coverage_ratio=0.9,
                track_continuity_ratio=0.9,
                goggles_detection_ratio=(
                    0.05 if entry.ppe_state == M8EvaluationPpeState.NOT_WORN else 0.9
                ),
                max_goggles_score=(
                    0.05 if entry.ppe_state == M8EvaluationPpeState.NOT_WORN else 0.95
                ),
                mean_goggles_score=(
                    0.03 if entry.ppe_state == M8EvaluationPpeState.NOT_WORN else 0.8
                ),
                recovery_detected=entry.ppe_state == M8EvaluationPpeState.WORN,
                longest_absence_ratio=(
                    0.95 if entry.ppe_state == M8EvaluationPpeState.NOT_WORN else 0.05
                ),
            ),
            violation=entry.ppe_state == M8EvaluationPpeState.NOT_WORN,
        )
        for entry in manifest.entries
        if entry.ppe_state != M8EvaluationPpeState.UNCLEAR
    )
    return manifest, M8CalibrationTrainingAggregationV1(
        dataset_manifest_id=manifest.dataset_manifest_id,
        evidence_examples=evidence,
        event_examples=event,
    )


def test_insufficient_dataset_does_not_start_low_floor_collection(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    calibration = M8CalibrationService(clock=lambda: NOW)
    manifest = calibration.build_dataset(
        (_truth(sha256_hex(["one"]), M8EvaluationPpeState.NOT_WORN),)
    )
    repository.put_dataset(manifest)
    observations = _Observations()
    result = _api(repository, calibration, observations).fit(
        _principal(M8ActorRole.OPERATIONS),
        M8CalibrationFitRequestV1(
            dataset_manifest_id=manifest.dataset_manifest_id,
            explicit_human_confirmation=True,
        ),
    )
    assert result.status == M8CalibrationFitStatus.INSUFFICIENT_DATA
    assert result.reason_code == M8CalibrationReasonCode.INSUFFICIENT_DATA
    assert observations.collect_calls == 0
    assert observations.aggregate_calls == 0


def test_complete_collection_fits_persists_and_retries_idempotently(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    calibration = M8CalibrationService(clock=lambda: NOW)
    manifest, aggregation = _aggregation(calibration, _full_truths())
    repository.put_dataset(manifest)
    observations = _Observations(aggregation)
    service = _api(repository, calibration, observations)
    request = M8CalibrationFitRequestV1(
        dataset_manifest_id=manifest.dataset_manifest_id,
        explicit_human_confirmation=True,
    )

    first = service.fit(_principal(M8ActorRole.OPERATIONS), request)
    second = service.fit(_principal(M8ActorRole.OPERATIONS), request)

    assert first == second
    assert first.status == M8CalibrationFitStatus.SHADOW_READY
    assert first.artifact is not None
    assert first.report is not None
    assert first.artifact.detector_model_manifest_id == DETECTOR
    assert first.artifact.config_sha256 == CONFIG
    assert first.artifact.model_profile_sha256 == MODEL_PROFILE
    assert repository.get_artifact(first.artifact.artifact_id) == first.artifact
    assert repository.get_report(first.report.report_id) == first.report
    assert observations.collect_calls == 1
    assert observations.aggregate_calls == 1


def test_collection_failure_is_typed_non_ready_without_artifact(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    calibration = M8CalibrationService(clock=lambda: NOW)
    manifest = calibration.build_dataset(_full_truths())
    repository.put_dataset(manifest)
    observations = _Observations(
        failure=M8CalibrationCollectionError(
            M8CalibrationCollectionFailureCode.WORKER_MANIFEST_MISMATCH
        )
    )

    result = _api(repository, calibration, observations).fit(
        _principal(M8ActorRole.OPERATIONS),
        M8CalibrationFitRequestV1(
            dataset_manifest_id=manifest.dataset_manifest_id,
            explicit_human_confirmation=True,
        ),
    )

    assert result.status == M8CalibrationFitStatus.INSUFFICIENT_DATA
    assert result.reason_code == M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE
    assert repository.list_artifacts() == ()
    assert repository.list_reports() == ()
    assert observations.collect_calls == 1
    assert observations.aggregate_calls == 0


def test_identical_human_snapshot_reuses_first_persisted_dataset(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    times = iter((NOW, NOW + timedelta(seconds=1)))
    calibration = M8CalibrationService(clock=lambda: next(times))
    truths = (_truth(sha256_hex(["stable-snapshot"]), M8EvaluationPpeState.WORN),)
    service = _api(repository, calibration, _Observations(), truths=truths)
    request = M8CalibrationDatasetCreateRequestV1(explicit_human_confirmation=True)

    first = service.create_dataset(_principal(M8ActorRole.SAFETY_OFFICER), request)
    second = service.create_dataset(_principal(M8ActorRole.SAFETY_OFFICER), request)

    assert second == first
    assert second.created_at == NOW
    assert repository.list_datasets() == (first,)
