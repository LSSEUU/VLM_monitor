"""Application service for non-LLM M8 shadow calibration."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import TypeVar

from labcourt.contracts.m8_calibration import (
    M8_CALIBRATION_MINIMUM_SAMPLES_PER_LABEL,
    M8_EVENT_RISK_FEATURE_NAMES,
    M8_EVIDENCE_QUALITY_FEATURE_NAMES,
    M8CalibrationArtifactV1,
    M8CalibrationAssessmentMode,
    M8CalibrationDatasetEntryV1,
    M8CalibrationDatasetManifestV1,
    M8CalibrationFitResultV1,
    M8CalibrationFitStatus,
    M8CalibrationPartition,
    M8CalibrationReasonCode,
    M8EventRiskAssessmentV1,
    M8EventRiskFeaturesV1,
    M8EventRiskTrainingExampleV1,
    M8EvidenceQualityAssessmentV1,
    M8EvidenceQualityFeaturesV1,
    M8EvidenceQualityTrainingExampleV1,
)
from labcourt.contracts.m8_evaluation import (
    M8EvaluationGroundTruthV1,
    M8EvaluationPpeState,
)
from labcourt.domain.m8_calibration import (
    binary_calibration_metrics,
    build_calibration_report,
    build_human_confirmed_dataset,
    calibration_artifact_id,
    dataset_label_counts,
    event_assessment_id,
    evidence_assessment_id,
    fit_platt_scaler,
    fit_regularized_logistic,
    inapplicable_event_assessment,
    inapplicable_evidence_assessment,
    linear_score,
    platt_probability,
)

_ExampleT = TypeVar(
    "_ExampleT",
    M8EvidenceQualityTrainingExampleV1,
    M8EventRiskTrainingExampleV1,
)


class M8CalibrationService:
    """Fit and evaluate immutable shadow artifacts without model-provider input."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def build_dataset(
        self,
        truths: Sequence[M8EvaluationGroundTruthV1],
    ) -> M8CalibrationDatasetManifestV1:
        return build_human_confirmed_dataset(truths, created_at=self._utc_now())

    def fit_shadow(
        self,
        manifest: M8CalibrationDatasetManifestV1,
        *,
        evidence_examples: Sequence[M8EvidenceQualityTrainingExampleV1],
        event_examples: Sequence[M8EventRiskTrainingExampleV1],
        detector_model_manifest_id: str,
        config_sha256: str,
        model_profile_sha256: str,
    ) -> M8CalibrationFitResultV1:
        """Fit development models, calibrate held-out scores, and report sealed metrics."""

        entry_by_id = {entry.sample_id: entry for entry in manifest.entries}
        counts = dataset_label_counts(manifest)
        if any(
            counts[state.value] < M8_CALIBRATION_MINIMUM_SAMPLES_PER_LABEL
            for state in M8EvaluationPpeState
        ):
            return self._insufficient(manifest)
        self._validate_examples(entry_by_id, evidence_examples, event_examples)

        evidence_by_partition = self._partition_examples(
            manifest,
            evidence_examples,
        )
        event_by_partition = self._partition_examples(manifest, event_examples)
        if not self._partition_inventory_ready(evidence_by_partition, event_by_partition):
            return self._insufficient(manifest)

        evidence_development = evidence_by_partition[M8CalibrationPartition.DEVELOPMENT]
        evidence_model = fit_regularized_logistic(
            M8_EVIDENCE_QUALITY_FEATURE_NAMES,
            tuple(item.features.vector() for item in evidence_development),
            tuple(item.human_clear for item in evidence_development),
        )
        evidence_calibration = evidence_by_partition[M8CalibrationPartition.CALIBRATION]
        evidence_platt = fit_platt_scaler(
            tuple(
                linear_score(evidence_model, item.features.vector())
                for item in evidence_calibration
            ),
            tuple(item.human_clear for item in evidence_calibration),
        )

        event_development = event_by_partition[M8CalibrationPartition.DEVELOPMENT]
        event_model = fit_regularized_logistic(
            M8_EVENT_RISK_FEATURE_NAMES,
            tuple(item.features.vector() for item in event_development),
            tuple(item.violation for item in event_development),
        )
        event_calibration = event_by_partition[M8CalibrationPartition.CALIBRATION]
        event_platt = fit_platt_scaler(
            tuple(linear_score(event_model, item.features.vector()) for item in event_calibration),
            tuple(item.violation for item in event_calibration),
        )

        threshold = 0.5
        artifact_id = calibration_artifact_id(
            dataset_manifest_id=manifest.dataset_manifest_id,
            detector_model_manifest_id=detector_model_manifest_id,
            config_sha256=config_sha256,
            model_profile_sha256=model_profile_sha256,
            evidence_model=evidence_model,
            evidence_platt=evidence_platt,
            event_model=event_model,
            event_platt=event_platt,
            evidence_quality_threshold=threshold,
        )
        artifact = M8CalibrationArtifactV1(
            artifact_id=artifact_id,
            dataset_manifest_id=manifest.dataset_manifest_id,
            detector_model_manifest_id=detector_model_manifest_id,
            config_sha256=config_sha256,
            model_profile_sha256=model_profile_sha256,
            evidence_quality_model=evidence_model,
            evidence_quality_platt=evidence_platt,
            event_risk_model=event_model,
            event_risk_platt=event_platt,
            evidence_quality_threshold=threshold,
            created_at=self._utc_now(),
        )

        evidence_sealed = evidence_by_partition[M8CalibrationPartition.SEALED_TEST]
        evidence_probabilities = tuple(
            platt_probability(
                artifact.evidence_quality_platt,
                linear_score(artifact.evidence_quality_model, item.features.vector()),
            )
            for item in evidence_sealed
        )
        evidence_metrics = binary_calibration_metrics(
            evidence_probabilities,
            tuple(item.human_clear for item in evidence_sealed),
            tuple(item.group_id for item in evidence_sealed),
            decision_threshold=threshold,
            bootstrap_seed=f"{artifact.artifact_id}:evidence",
        )
        event_sealed = event_by_partition[M8CalibrationPartition.SEALED_TEST]
        event_probabilities = tuple(
            platt_probability(
                artifact.event_risk_platt,
                linear_score(artifact.event_risk_model, item.features.vector()),
            )
            for item in event_sealed
        )
        event_metrics = binary_calibration_metrics(
            event_probabilities,
            tuple(item.violation for item in event_sealed),
            tuple(item.group_id for item in event_sealed),
            bootstrap_seed=f"{artifact.artifact_id}:event",
        )
        report = build_calibration_report(
            artifact,
            evidence_metrics,
            event_metrics,
            generated_at=self._utc_now(),
        )
        return M8CalibrationFitResultV1(
            status=M8CalibrationFitStatus.SHADOW_READY,
            dataset_manifest=manifest,
            artifact=artifact,
            report=report,
        )

    def assess_evidence(
        self,
        *,
        run_id: str,
        asset_id: str,
        features: M8EvidenceQualityFeaturesV1,
        artifact: M8CalibrationArtifactV1 | None,
        detector_model_manifest_id: str,
        config_sha256: str,
        model_profile_sha256: str,
    ) -> M8EvidenceQualityAssessmentV1:
        reason = self._binding_failure(
            artifact,
            detector_model_manifest_id=detector_model_manifest_id,
            config_sha256=config_sha256,
            model_profile_sha256=model_profile_sha256,
        )
        if reason is not None or artifact is None:
            return inapplicable_evidence_assessment(
                run_id=run_id,
                asset_id=asset_id,
                reason_code=reason or M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE,
            )
        probability = platt_probability(
            artifact.evidence_quality_platt,
            linear_score(artifact.evidence_quality_model, features.vector()),
        )
        mode = M8CalibrationAssessmentMode.SHADOW
        sufficient = probability >= artifact.evidence_quality_threshold
        return M8EvidenceQualityAssessmentV1(
            assessment_id=evidence_assessment_id(
                run_id=run_id,
                asset_id=asset_id,
                artifact_id=artifact.artifact_id,
                mode=mode,
                quality_probability=probability,
                sufficiency_threshold=artifact.evidence_quality_threshold,
                sufficient=sufficient,
                reason_code=None,
            ),
            run_id=run_id,
            asset_id=asset_id,
            artifact_id=artifact.artifact_id,
            mode=mode,
            quality_probability=probability,
            sufficiency_threshold=artifact.evidence_quality_threshold,
            sufficient=sufficient,
        )

    def assess_event(
        self,
        *,
        run_id: str,
        asset_id: str,
        features: M8EventRiskFeaturesV1,
        evidence: M8EvidenceQualityAssessmentV1,
        artifact: M8CalibrationArtifactV1 | None,
        detector_model_manifest_id: str,
        config_sha256: str,
        model_profile_sha256: str,
    ) -> M8EventRiskAssessmentV1:
        if evidence.run_id != run_id or evidence.asset_id != asset_id:
            raise ValueError("event risk evidence-quality assessment belongs to another run")
        reason = self._binding_failure(
            artifact,
            detector_model_manifest_id=detector_model_manifest_id,
            config_sha256=config_sha256,
            model_profile_sha256=model_profile_sha256,
        )
        if reason is None and (
            evidence.mode != M8CalibrationAssessmentMode.SHADOW or not evidence.sufficient
        ):
            reason = M8CalibrationReasonCode.EVIDENCE_INSUFFICIENT
        if reason is not None or artifact is None:
            return inapplicable_event_assessment(
                run_id=run_id,
                asset_id=asset_id,
                evidence_quality_assessment_id=evidence.assessment_id,
                reason_code=reason or M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE,
            )
        raw_score = linear_score(artifact.event_risk_model, features.vector())
        probability = platt_probability(artifact.event_risk_platt, raw_score)
        mode = M8CalibrationAssessmentMode.SHADOW
        return M8EventRiskAssessmentV1(
            assessment_id=event_assessment_id(
                run_id=run_id,
                asset_id=asset_id,
                evidence_quality_assessment_id=evidence.assessment_id,
                artifact_id=artifact.artifact_id,
                mode=mode,
                raw_event_score=raw_score,
                calibrated_probability=probability,
                reason_code=None,
            ),
            run_id=run_id,
            asset_id=asset_id,
            evidence_quality_assessment_id=evidence.assessment_id,
            artifact_id=artifact.artifact_id,
            mode=mode,
            raw_event_score=raw_score,
            calibrated_probability=probability,
        )

    @staticmethod
    def _validate_examples(
        entry_by_id: Mapping[str, M8CalibrationDatasetEntryV1],
        evidence_examples: Sequence[M8EvidenceQualityTrainingExampleV1],
        event_examples: Sequence[M8EventRiskTrainingExampleV1],
    ) -> None:
        evidence_ids = tuple(item.sample_id for item in evidence_examples)
        event_ids = tuple(item.sample_id for item in event_examples)
        if len(evidence_ids) != len(set(evidence_ids)) or len(event_ids) != len(set(event_ids)):
            raise ValueError("calibration training examples must use each sample once")
        if set(evidence_ids) != set(entry_by_id):
            raise ValueError("evidence-quality examples must cover the exact sealed dataset")
        expected_event_ids = {
            entry.sample_id
            for entry in entry_by_id.values()
            if entry.ppe_state != M8EvaluationPpeState.UNCLEAR
        }
        if set(event_ids) != expected_event_ids:
            raise ValueError("event-risk examples must cover every clear human label exactly")
        for example in evidence_examples:
            entry = entry_by_id.get(example.sample_id)
            if not isinstance(entry, M8CalibrationDatasetEntryV1):
                raise ValueError("evidence-quality example is absent from the sealed dataset")
            if entry.group_id != example.group_id:
                raise ValueError("evidence-quality example changed its source group")
            expected_clear = entry.ppe_state != M8EvaluationPpeState.UNCLEAR
            if example.human_clear != expected_clear:
                raise ValueError("evidence-quality label is not human-ground-truth derived")
        for event_example in event_examples:
            entry = entry_by_id.get(event_example.sample_id)
            if not isinstance(entry, M8CalibrationDatasetEntryV1):
                raise ValueError("event-risk example is absent from the sealed dataset")
            if entry.group_id != event_example.group_id:
                raise ValueError("event-risk example changed its source group")
            if entry.ppe_state == M8EvaluationPpeState.UNCLEAR:
                raise ValueError("unclear evidence cannot train substantive event probability")
            expected_violation = entry.ppe_state == M8EvaluationPpeState.NOT_WORN
            if event_example.violation != expected_violation:
                raise ValueError("event-risk label is not human-ground-truth derived")

    @staticmethod
    def _partition_examples(
        manifest: M8CalibrationDatasetManifestV1,
        examples: Sequence[_ExampleT],
    ) -> dict[M8CalibrationPartition, tuple[_ExampleT, ...]]:
        partition_by_id = {entry.sample_id: entry.partition for entry in manifest.entries}
        buckets: dict[M8CalibrationPartition, list[_ExampleT]] = {
            partition: [] for partition in M8CalibrationPartition
        }
        for example in examples:
            buckets[partition_by_id[example.sample_id]].append(example)
        return {
            partition: tuple(sorted(items, key=lambda item: item.sample_id))
            for partition, items in buckets.items()
        }

    @staticmethod
    def _partition_inventory_ready(
        evidence: dict[
            M8CalibrationPartition,
            tuple[M8EvidenceQualityTrainingExampleV1, ...],
        ],
        event: dict[M8CalibrationPartition, tuple[M8EventRiskTrainingExampleV1, ...]],
    ) -> bool:
        for partition in M8CalibrationPartition:
            evidence_items = evidence[partition]
            event_items = event[partition]
            if not evidence_items or not event_items:
                return False
            evidence_labels = {item.human_clear for item in evidence_items}
            event_labels = {item.violation for item in event_items}
            if evidence_labels != {False, True} or event_labels != {False, True}:
                return False
        return True

    @staticmethod
    def _insufficient(
        manifest: M8CalibrationDatasetManifestV1,
    ) -> M8CalibrationFitResultV1:
        return M8CalibrationFitResultV1(
            status=M8CalibrationFitStatus.INSUFFICIENT_DATA,
            dataset_manifest=manifest,
            reason_code=M8CalibrationReasonCode.INSUFFICIENT_DATA,
        )

    @staticmethod
    def _binding_failure(
        artifact: M8CalibrationArtifactV1 | None,
        *,
        detector_model_manifest_id: str,
        config_sha256: str,
        model_profile_sha256: str,
    ) -> M8CalibrationReasonCode | None:
        if artifact is None:
            return M8CalibrationReasonCode.ARTIFACT_UNAVAILABLE
        if artifact.feature_schema_version != "M8_NON_LLM_CALIBRATION_FEATURES_V1":
            return M8CalibrationReasonCode.FEATURE_SCHEMA_MISMATCH
        if artifact.detector_model_manifest_id != detector_model_manifest_id:
            return M8CalibrationReasonCode.DETECTOR_MODEL_MISMATCH
        if artifact.config_sha256 != config_sha256:
            return M8CalibrationReasonCode.CONFIG_MISMATCH
        if artifact.model_profile_sha256 != model_profile_sha256:
            return M8CalibrationReasonCode.MODEL_PROFILE_MISMATCH
        return None

    def _utc_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise ValueError("M8 calibration clock must return timezone-aware UTC")
        return now


__all__ = ["M8CalibrationService"]
