"""Authenticated same-origin facade for M8 non-LLM shadow calibration."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from labcourt.adapters.storage.sqlite_m8_calibration_repository import (
    SQLiteM8CalibrationRepository,
)
from labcourt.contracts.m8_access_cases import M8ActorAuthorityV1, M8ActorRole
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_calibration import (
    M8_CALIBRATION_MINIMUM_SAMPLES_PER_LABEL,
    M8CalibrationArtifactV1,
    M8CalibrationDatasetManifestV1,
    M8CalibrationFitResultV1,
    M8CalibrationFitStatus,
    M8CalibrationReasonCode,
    M8CalibrationReportV1,
    M8CalibrationTrainingAggregationV1,
    M8CalibrationTrainingExclusionReason,
    M8CalibrationTrainingStage,
)
from labcourt.contracts.m8_calibration_api import (
    M8CalibrationDashboardV1,
    M8CalibrationDatasetCreateRequestV1,
    M8CalibrationFitRequestV1,
    M8RunRiskAssessmentViewV1,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationPpeState,
    M8EvaluationReviewState,
)
from labcourt.domain.m8_calibration import (
    dataset_label_counts,
    inapplicable_event_assessment,
    inapplicable_evidence_assessment,
)
from labcourt.exceptions import ConcurrentModification, EvidenceMissing, LabCourtError
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_calibration import M8CalibrationService
from labcourt.services.m8_calibration_observation import (
    M8CalibrationObservationService,
)
from labcourt.services.m8_evaluation import M8EvaluationService
from labcourt.services.m8_operations_api import (
    M8ApiServiceError,
    M8ApiServiceFailureCode,
)

_T = TypeVar("_T")
_READ_ROLES = frozenset({M8ActorRole.OPERATIONS, M8ActorRole.SAFETY_OFFICER, M8ActorRole.LEADER})


class M8CalibrationApiService:
    """Expose immutable calibration authorities without adding routing power."""

    def __init__(
        self,
        *,
        operations_repository: M8OperationsRepository,
        evaluation_service: M8EvaluationService,
        repository: SQLiteM8CalibrationRepository,
        calibration_service: M8CalibrationService,
        observation_service: M8CalibrationObservationService,
    ) -> None:
        self._operations = operations_repository
        self._evaluation = evaluation_service
        self._repository = repository
        self._calibration = calibration_service
        self._observations = observation_service
        self._detector_model_manifest_id = (
            observation_service.authority_manifest.detector.model_manifest_id
        )
        self._config_sha256 = observation_service.authority_config.config_sha256
        self._model_profile_sha256 = evaluation_service.model_profile_sha256

    def dashboard(self, principal: M8ApiPrincipalV1) -> M8CalibrationDashboardV1:
        self._require_read(principal)
        truths = self._evaluation.dashboard(principal).ground_truth
        counts = {state: 0 for state in M8EvaluationPpeState}
        for truth in truths:
            if truth.review_state != M8EvaluationReviewState.HUMAN_CONFIRMED:
                continue
            for interval in truth.intervals:
                counts[interval.ppe_state] += 1
        try:
            dataset = self._repository.get_latest_dataset()
        except EvidenceMissing:
            dataset = None
        artifact = report = None
        if dataset is not None:
            try:
                artifact = self._repository.get_latest_artifact(dataset.dataset_manifest_id)
                report = self._repository.get_latest_report(artifact.artifact_id)
            except EvidenceMissing:
                artifact = report = None
        status = (
            M8CalibrationFitStatus.SHADOW_READY
            if artifact is not None and report is not None
            else M8CalibrationFitStatus.INSUFFICIENT_DATA
        )
        return M8CalibrationDashboardV1(
            status=status,
            minimum_samples_per_label=M8_CALIBRATION_MINIMUM_SAMPLES_PER_LABEL,
            confirmed_interval_counts=counts,
            dataset_manifest=dataset,
            artifact=artifact,
            report=report,
        )

    def create_dataset(
        self,
        principal: M8ApiPrincipalV1,
        request: M8CalibrationDatasetCreateRequestV1,
    ) -> M8CalibrationDatasetManifestV1:
        self._require_role(principal, M8ActorRole.SAFETY_OFFICER)
        if not isinstance(request, M8CalibrationDatasetCreateRequestV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        truths = self._evaluation.dashboard(principal).ground_truth
        manifest = self._call(lambda: self._calibration.build_dataset(truths))
        try:
            return self._repository.get_dataset(manifest.dataset_manifest_id)
        except EvidenceMissing:
            try:
                return self._repository.put_dataset(manifest)
            except ConcurrentModification:
                # A concurrent request may have published the same immutable
                # HUMAN_CONFIRMED snapshot with another non-identity timestamp.
                return self._call(
                    lambda: self._repository.get_dataset(manifest.dataset_manifest_id)
                )

    def fit(
        self,
        principal: M8ApiPrincipalV1,
        request: M8CalibrationFitRequestV1,
    ) -> M8CalibrationFitResultV1:
        self._require_role(principal, M8ActorRole.OPERATIONS)
        if not isinstance(request, M8CalibrationFitRequestV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        manifest = self._call(lambda: self._repository.get_dataset(request.dataset_manifest_id))
        counts = dataset_label_counts(manifest)
        if any(
            counts[state.value] < M8_CALIBRATION_MINIMUM_SAMPLES_PER_LABEL
            for state in M8EvaluationPpeState
        ):
            return M8CalibrationFitResultV1(
                status=M8CalibrationFitStatus.INSUFFICIENT_DATA,
                dataset_manifest=manifest,
                reason_code=M8CalibrationReasonCode.INSUFFICIENT_DATA,
            )

        ready = self._existing_ready_result(manifest)
        if ready is not None:
            return ready

        collection_run_id = f"calibration-{manifest.dataset_manifest_id[:16]}"
        try:
            self._observations.collect(run_id=collection_run_id, dataset=manifest)
            aggregation = self._observations.aggregate(
                run_id=collection_run_id,
                dataset=manifest,
            )
        except (LabCourtError, OSError, TypeError, ValueError):
            # Local worker, immutable-media, and formal-config failures are
            # explicitly non-ready. They never fall back to Qwen or fixtures.
            return self._non_ready(
                manifest,
                M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE,
            )
        if not self._aggregation_is_complete(manifest, aggregation):
            return self._non_ready(
                manifest,
                M8CalibrationReasonCode.INSUFFICIENT_DATA,
            )
        try:
            result = self._calibration.fit_shadow(
                manifest,
                evidence_examples=aggregation.evidence_examples,
                event_examples=aggregation.event_examples,
                detector_model_manifest_id=self._detector_model_manifest_id,
                config_sha256=self._config_sha256,
                model_profile_sha256=self._model_profile_sha256,
            )
        except (LabCourtError, OSError, TypeError, ValueError):
            return self._non_ready(
                manifest,
                M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE,
            )
        if result.status != M8CalibrationFitStatus.SHADOW_READY:
            return result
        if result.artifact is None or result.report is None:
            return self._non_ready(
                manifest,
                M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE,
            )
        artifact = self._put_or_get_artifact(result.artifact)
        report = self._put_or_get_report(result.report)
        return M8CalibrationFitResultV1(
            status=M8CalibrationFitStatus.SHADOW_READY,
            dataset_manifest=manifest,
            artifact=artifact,
            report=report,
        )

    def report(self, principal: M8ApiPrincipalV1, report_id: str) -> M8CalibrationReportV1:
        self._require_read(principal)
        return self._call(lambda: self._repository.get_report(report_id))

    def risk_assessment(
        self,
        principal: M8ApiPrincipalV1,
        run_id: str,
    ) -> M8RunRiskAssessmentViewV1:
        self._require_read(principal)
        run = self._evaluation.run(principal, run_id)
        try:
            evidence = self._repository.get_latest_evidence_assessment(run_id)
            event = self._repository.get_latest_event_assessment(run_id)
        except EvidenceMissing:
            evidence = inapplicable_evidence_assessment(
                run_id=run_id,
                asset_id=run.source.asset_id,
                reason_code=M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE,
            )
            event = inapplicable_event_assessment(
                run_id=run_id,
                asset_id=run.source.asset_id,
                evidence_quality_assessment_id=evidence.assessment_id,
                reason_code=M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE,
            )
        return M8RunRiskAssessmentViewV1(
            run_id=run_id,
            asset_id=run.source.asset_id,
            evidence_quality=evidence,
            event_risk=event,
        )

    def _require_read(self, principal: M8ApiPrincipalV1) -> None:
        actor = self._actor(principal)
        if actor.role not in _READ_ROLES:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)

    def _require_role(self, principal: M8ApiPrincipalV1, role: M8ActorRole) -> None:
        if self._actor(principal).role != role:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)

    def _actor(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        actor = receipt.authority
        if not actor.active or actor.actor_id != principal.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return actor

    def _existing_ready_result(
        self,
        manifest: M8CalibrationDatasetManifestV1,
    ) -> M8CalibrationFitResultV1 | None:
        for artifact in reversed(self._repository.list_artifacts(manifest.dataset_manifest_id)):
            if (
                artifact.detector_model_manifest_id != self._detector_model_manifest_id
                or artifact.config_sha256 != self._config_sha256
                or artifact.model_profile_sha256 != self._model_profile_sha256
            ):
                continue
            try:
                report = self._repository.get_latest_report(artifact.artifact_id)
            except EvidenceMissing:
                continue
            return M8CalibrationFitResultV1(
                status=M8CalibrationFitStatus.SHADOW_READY,
                dataset_manifest=manifest,
                artifact=artifact,
                report=report,
            )
        return None

    @staticmethod
    def _aggregation_is_complete(
        manifest: M8CalibrationDatasetManifestV1,
        aggregation: M8CalibrationTrainingAggregationV1,
    ) -> bool:
        if aggregation.dataset_manifest_id != manifest.dataset_manifest_id:
            return False
        evidence_ids = {item.sample_id for item in aggregation.evidence_examples}
        event_ids = {item.sample_id for item in aggregation.event_examples}
        expected_evidence_ids = {item.sample_id for item in manifest.entries}
        expected_event_ids = {
            item.sample_id
            for item in manifest.entries
            if item.ppe_state != M8EvaluationPpeState.UNCLEAR
        }
        if evidence_ids != expected_evidence_ids or event_ids != expected_event_ids:
            return False
        state_by_id = {item.sample_id: item.ppe_state for item in manifest.entries}
        return all(
            exclusion.stage == M8CalibrationTrainingStage.EVENT_RISK
            and exclusion.reason == M8CalibrationTrainingExclusionReason.HUMAN_LABEL_UNCLEAR
            and state_by_id.get(exclusion.sample_id) == M8EvaluationPpeState.UNCLEAR
            for exclusion in aggregation.exclusions
        )

    def _put_or_get_artifact(
        self,
        artifact: M8CalibrationArtifactV1,
    ) -> M8CalibrationArtifactV1:
        try:
            return self._repository.get_artifact(artifact.artifact_id)
        except EvidenceMissing:
            try:
                return self._repository.put_artifact(artifact)
            except ConcurrentModification:
                return self._repository.get_artifact(artifact.artifact_id)

    def _put_or_get_report(
        self,
        report: M8CalibrationReportV1,
    ) -> M8CalibrationReportV1:
        try:
            return self._repository.get_report(report.report_id)
        except EvidenceMissing:
            try:
                return self._repository.put_report(report)
            except ConcurrentModification:
                return self._repository.get_report(report.report_id)

    @staticmethod
    def _non_ready(
        manifest: M8CalibrationDatasetManifestV1,
        reason_code: M8CalibrationReasonCode,
    ) -> M8CalibrationFitResultV1:
        return M8CalibrationFitResultV1(
            status=M8CalibrationFitStatus.INSUFFICIENT_DATA,
            dataset_manifest=manifest,
            reason_code=reason_code,
        )

    @staticmethod
    def _call(function: Callable[[], _T]) -> _T:
        try:
            return function()
        except M8ApiServiceError:
            raise
        except EvidenceMissing as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error
        except ConcurrentModification as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION) from error
        except (OSError, TypeError, ValueError) as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error


__all__ = ["M8CalibrationApiService"]
