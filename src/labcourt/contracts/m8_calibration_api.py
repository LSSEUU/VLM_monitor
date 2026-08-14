"""Same-origin API contracts for additive M8 shadow calibration."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_calibration import (
    M8CalibrationArtifactV1,
    M8CalibrationDatasetManifestV1,
    M8CalibrationFitStatus,
    M8CalibrationReportV1,
    M8EventRiskAssessmentV1,
    M8EvidenceQualityAssessmentV1,
)
from labcourt.contracts.m8_evaluation import M8EvaluationPpeState
from labcourt.contracts.references import ReferenceToken, require_portable_run_id


class M8CalibrationDatasetCreateRequestV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-dataset-create-request-v1"] = (
        "m8-calibration-dataset-create-request-v1"
    )
    explicit_human_confirmation: Literal[True]


class M8CalibrationFitRequestV1(FrozenContractModel):
    schema_version: Literal["m8-calibration-fit-request-v1"] = "m8-calibration-fit-request-v1"
    dataset_manifest_id: Sha256Hex
    explicit_human_confirmation: Literal[True]


class M8CalibrationDashboardV1(FrozenContractModel):
    """Read-only readiness projection; never an activation authority."""

    schema_version: Literal["m8-calibration-dashboard-v1"] = "m8-calibration-dashboard-v1"
    status: M8CalibrationFitStatus
    minimum_samples_per_label: int = Field(gt=0, strict=True)
    confirmed_interval_counts: dict[M8EvaluationPpeState, int]
    dataset_manifest: M8CalibrationDatasetManifestV1 | None = None
    artifact: M8CalibrationArtifactV1 | None = None
    report: M8CalibrationReportV1 | None = None
    qwen_probability_is_authority: Literal[False] = False
    routing_authority: Literal[False] = False
    activation_available: Literal[False] = False

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if set(self.confirmed_interval_counts) != set(M8EvaluationPpeState):
            raise ValueError("calibration dashboard label counts are incomplete")
        if self.status == M8CalibrationFitStatus.SHADOW_READY:
            if self.dataset_manifest is None or self.artifact is None or self.report is None:
                raise ValueError("shadow-ready dashboard requires its immutable authorities")
            if (
                self.artifact.dataset_manifest_id != self.dataset_manifest.dataset_manifest_id
                or self.report.artifact_id != self.artifact.artifact_id
            ):
                raise ValueError("calibration dashboard authorities do not form one chain")
        elif self.artifact is not None or self.report is not None:
            raise ValueError("insufficient calibration dashboard cannot expose an artifact")
        return self


class M8RunRiskAssessmentViewV1(FrozenContractModel):
    schema_version: Literal["m8-run-risk-assessment-view-v1"] = "m8-run-risk-assessment-view-v1"
    run_id: ReferenceToken
    asset_id: Sha256Hex
    evidence_quality: M8EvidenceQualityAssessmentV1
    event_risk: M8EventRiskAssessmentV1
    qwen_probability_is_authority: Literal[False] = False
    routing_changed: Literal[False] = False

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        require_portable_run_id(self.run_id, "M8 risk-assessment run")
        if (
            self.evidence_quality.run_id != self.run_id
            or self.event_risk.run_id != self.run_id
            or self.evidence_quality.asset_id != self.asset_id
            or self.event_risk.asset_id != self.asset_id
            or self.event_risk.evidence_quality_assessment_id != self.evidence_quality.assessment_id
        ):
            raise ValueError("M8 risk-assessment view crosses run or asset authority")
        return self


__all__ = [
    "M8CalibrationDashboardV1",
    "M8CalibrationDatasetCreateRequestV1",
    "M8CalibrationFitRequestV1",
    "M8RunRiskAssessmentViewV1",
]
