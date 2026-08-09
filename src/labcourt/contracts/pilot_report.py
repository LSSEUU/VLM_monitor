"""Typed A4 operator-report and local-alert publication contracts."""

from __future__ import annotations

from typing import Literal, Self, TypeVar

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.base import ContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    AlertLevel,
    AppealStatus,
    CaseStatus,
    ScreeningDecision,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_appeal_operations import M5AppealResolutionCommandReport
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_operations import M5DispatchCommandReport
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.pilot import PilotA4CloseReport
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    TrackRef,
    require_portable_run_id,
    require_reference_token,
)

PILOT_OPERATOR_DISCLAIMER: Literal[
    "用于安全辅助与记录，不直接作为处罚依据"  # noqa: RUF001
] = "用于安全辅助与记录，不直接作为处罚依据"  # noqa: RUF001

_PilotContractT = TypeVar("_PilotContractT", bound=ContractModel)


def _validate_claimed_id(
    value: object,
    handler: ModelWrapValidatorHandler[_PilotContractT],
    *,
    field_name: str,
) -> _PilotContractT:
    if not isinstance(value, dict):
        return handler(value)
    payload = dict(value)
    claimed_present = field_name in payload
    claimed = payload.pop(field_name, None)
    model = handler(payload)
    if claimed_present and claimed != getattr(model, field_name):
        raise ValueError(f"serialized {field_name} does not match pilot report content")
    return model


class PilotA4ModelVersion(ContractModel):
    component: ReferenceToken
    provider: str = Field(min_length=1, max_length=256)
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=256)
    model_manifest_id: Sha256Hex

    @field_validator("component")
    @classmethod
    def validate_component(cls, value: str) -> str:
        return require_reference_token(value, "pilot report model component")


class PilotA4MediaView(ContractModel):
    crop_id: Sha256Hex
    role: Literal["PANORAMA", "SUBJECT", "FOCUS", "TEMPORAL"]
    frame_id: FrameId
    integrity: Literal["VERIFIED", "MISSING", "HASH_MISMATCH", "NOT_AVAILABLE"]
    run_relative_path: str | None = None
    media_sha256: Sha256Hex
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)

    @field_validator("run_relative_path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        return require_safe_relative_posix_path(value) if value is not None else None

    @model_validator(mode="after")
    def validate_integrity_path(self) -> PilotA4MediaView:
        if (self.integrity == "VERIFIED") != (self.run_relative_path is not None):
            raise ValueError("only verified pilot media may expose a report path")
        return self


class PilotA4CaseView(ContractModel):
    run_id: ReferenceToken
    case_id: ReferenceToken
    revision: int = Field(gt=0, strict=True)
    status: CaseStatus
    violation_type: ViolationType
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    anonymous_track_ref: TrackRef | None = None
    association_start_frame: int | None = Field(default=None, ge=0, strict=True)
    association_end_frame_exclusive: int | None = Field(default=None, gt=0, strict=True)
    observed_frame_count: int | None = Field(default=None, ge=0, strict=True)
    key_crops: tuple[PilotA4MediaView, ...] = Field(max_length=12)
    screening_decision: ScreeningDecision | None = None
    screening_probability: float | None = Field(default=None, ge=0, le=1)
    screening_router_version: ReferenceToken | None = None
    verdict_decision: VerdictDecision | None = None
    verdict_confidence: float | None = Field(default=None, ge=0, le=1)
    procedural_review_passed: bool | None = Field(default=None, strict=True)
    procedural_gate_version: ReferenceToken | None = None
    final_decision: VerdictDecision | None = None
    alert_level: AlertLevel | None = None
    alert_rescinded: bool = Field(default=False, strict=True)
    human_review_required: bool = Field(strict=True)
    appeal_status: AppealStatus | None = None
    detector: PilotA4ModelVersion
    screening_model: PilotA4ModelVersion
    prompt_bundle_sha256: Sha256Hex
    rule_version: ReferenceToken
    manifest_id: Sha256Hex
    disclaimer: Literal[
        "用于安全辅助与记录，不直接作为处罚依据"  # noqa: RUF001
    ] = PILOT_OPERATOR_DISCLAIMER

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot report run_id")

    @field_validator(
        "case_id",
        "screening_router_version",
        "procedural_gate_version",
        "rule_version",
    )
    @classmethod
    def validate_references(cls, value: str | None) -> str | None:
        return (
            require_reference_token(value, "pilot report case reference")
            if value is not None
            else None
        )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_case_view_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_id(value, handler, field_name="case_view_id")

    @model_validator(mode="after")
    def validate_case_view(self) -> PilotA4CaseView:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("pilot report frame interval must be non-empty")
        association_fields = (
            self.association_start_frame,
            self.association_end_frame_exclusive,
            self.observed_frame_count,
        )
        if any(item is None for item in association_fields) and any(
            item is not None for item in association_fields
        ):
            raise ValueError("pilot association projection must be complete when present")
        if self.association_start_frame is not None:
            assert self.association_end_frame_exclusive is not None
            assert self.observed_frame_count is not None
            if self.association_start_frame >= self.association_end_frame_exclusive:
                raise ValueError("pilot association interval must be non-empty")
            if self.observed_frame_count > (
                self.association_end_frame_exclusive - self.association_start_frame
            ):
                raise ValueError("pilot observed frame count exceeds its association interval")
        crop_ids = tuple(crop.crop_id for crop in self.key_crops)
        if len(crop_ids) != len(set(crop_ids)):
            raise ValueError("pilot report key crops must be unique")
        screening_fields = (
            self.screening_decision,
            self.screening_probability,
            self.screening_router_version,
        )
        if any(item is None for item in screening_fields) and any(
            item is not None for item in screening_fields
        ):
            raise ValueError("pilot screening projection must be complete when present")
        verdict_fields = (self.verdict_decision, self.verdict_confidence)
        if any(item is None for item in verdict_fields) and any(
            item is not None for item in verdict_fields
        ):
            raise ValueError("pilot verdict projection must be complete when present")
        review_fields = (self.procedural_review_passed, self.procedural_gate_version)
        if any(item is None for item in review_fields) and any(
            item is not None for item in review_fields
        ):
            raise ValueError("pilot procedural-review projection must be complete when present")
        if (
            self.status in {CaseStatus.CLOSED, CaseStatus.APPEALED, CaseStatus.APPEAL_RESOLVED}
            and self.final_decision is None
        ):
            raise ValueError("a terminal pilot case view requires a final decision")
        if self.alert_level is not None and self.status not in {
            CaseStatus.CLOSED,
            CaseStatus.APPEALED,
            CaseStatus.APPEAL_RESOLVED,
        }:
            raise ValueError("only a terminal pilot case may expose an alert level")
        if self.alert_rescinded and self.alert_level is None:
            raise ValueError("a rescinded pilot alert requires its historical level")
        expected_human = (
            self.status == CaseStatus.HUMAN_REVIEW
            or self.appeal_status in {AppealStatus.SUBMITTED, AppealStatus.UNDER_REVIEW}
            or (
                self.final_decision == VerdictDecision.INSUFFICIENT_EVIDENCE
                and self.appeal_status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
            )
        )
        if self.human_review_required != expected_human:
            raise ValueError("pilot human-review flag conflicts with case and appeal state")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_view_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"case_view_id"})
        return sha256_hex(["pilot-a4-case-view", 1, payload])


class PilotA4Metrics(ContractModel):
    schema_version: Literal["pilot-a4-metrics-v1"] = "pilot-a4-metrics-v1"
    run_id: ReferenceToken
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    case_count: int = Field(ge=0, strict=True)
    closed_count: int = Field(ge=0, strict=True)
    human_review_count: int = Field(ge=0, strict=True)
    established_count: int = Field(ge=0, strict=True)
    not_established_count: int = Field(ge=0, strict=True)
    insufficient_evidence_count: int = Field(ge=0, strict=True)
    unresolved_count: int = Field(ge=0, strict=True)
    verified_local_alert_count: int = Field(ge=0, strict=True)
    production_delivery_count: Literal[0] = 0
    cases: tuple[PilotA4CaseView, ...]

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot metrics run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_metrics_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_id(value, handler, field_name="metrics_id")

    @model_validator(mode="after")
    def validate_counts(self) -> PilotA4Metrics:
        case_ids = tuple(item.case_id for item in self.cases)
        if case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("pilot metrics cases must be unique and stably ordered")
        if any(
            item.run_id != self.run_id or item.manifest_id != self.manifest_id
            for item in self.cases
        ):
            raise ValueError("pilot metrics case is outside the run authority")
        decisions = tuple(item.final_decision for item in self.cases)
        expected = (
            len(self.cases),
            sum(
                item.status in {CaseStatus.CLOSED, CaseStatus.APPEALED, CaseStatus.APPEAL_RESOLVED}
                for item in self.cases
            ),
            sum(item.human_review_required for item in self.cases),
            decisions.count(VerdictDecision.ESTABLISHED),
            decisions.count(VerdictDecision.NOT_ESTABLISHED),
            decisions.count(VerdictDecision.INSUFFICIENT_EVIDENCE),
            decisions.count(None),
        )
        actual = (
            self.case_count,
            self.closed_count,
            self.human_review_count,
            self.established_count,
            self.not_established_count,
            self.insufficient_evidence_count,
            self.unresolved_count,
        )
        if actual != expected:
            raise ValueError("pilot metrics counts conflict with case views")
        if self.verified_local_alert_count > self.closed_count:
            raise ValueError("pilot local alerts cannot exceed terminal cases")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def metrics_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"metrics_id"})
        return sha256_hex(["pilot-a4-metrics", 1, payload])


class PilotLocalAlertDocument(ContractModel):
    schema_version: Literal["pilot-local-json-alert-v1"] = "pilot-local-json-alert-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    case_status: Literal[CaseStatus.CLOSED]
    final_decision: VerdictDecision
    alert: AlertDecision
    idempotency_key: Sha256Hex
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    production_action_prohibited: Literal[True] = True
    disclaimer: Literal[
        "用于安全辅助与记录，不直接作为处罚依据"  # noqa: RUF001
    ] = PILOT_OPERATOR_DISCLAIMER

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot local alert run_id")

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "pilot local alert case_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_document_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_id(value, handler, field_name="document_id")

    @model_validator(mode="after")
    def validate_alert_scope(self) -> PilotLocalAlertDocument:
        if (
            self.alert.case_id != self.case_id
            or self.alert.alert_id != self.idempotency_key
            or self.alert.suppressed_by_cooldown
            or self.alert.merged_into_alert_id is not None
            or self.alert.rescinded
        ):
            raise ValueError("pilot local alert is not an exact deliverable decision")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def document_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"document_id"})
        return sha256_hex(["pilot-local-json-alert", 1, payload])


class PilotA4PublicationReport(ContractModel):
    schema_version: Literal["pilot-a4-publication-report-v1"] = "pilot-a4-publication-report-v1"
    closure: PilotA4CloseReport
    dispatch: M5DispatchCommandReport
    metrics: PilotA4Metrics
    index_path: str
    metrics_path: str
    case_paths: tuple[str, ...]
    local_alert_paths: tuple[str, ...]
    projection_paths: tuple[str, str]

    @field_validator("index_path", "metrics_path")
    @classmethod
    def validate_index_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @field_validator("case_paths", "local_alert_paths", "projection_paths")
    @classmethod
    def validate_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(require_safe_relative_posix_path(value) for value in values)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_publication_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_id(value, handler, field_name="publication_id")

    @model_validator(mode="after")
    def validate_publication_scope(self) -> PilotA4PublicationReport:
        run_id = self.metrics.run_id
        if self.closure.run_id != run_id or self.dispatch.run_id != run_id:
            raise ValueError("pilot A4 publication components belong to different runs")
        if (
            self.closure.manifest_id != self.metrics.manifest_id
            or self.closure.config_sha256 != self.metrics.config_sha256
        ):
            raise ValueError("pilot A4 publication identity differs from closure authority")
        expected_index = f"runs/{run_id}/report/index.html"
        expected_metrics = f"runs/{run_id}/metrics.json"
        expected_cases = tuple(
            f"runs/{run_id}/report/cases/{item.case_id}.html" for item in self.metrics.cases
        )
        expected_projections = (
            f"runs/{run_id}/projections/current.json",
            f"runs/{run_id}/m5-projections/current.json",
        )
        if (
            self.index_path != expected_index
            or self.metrics_path != expected_metrics
            or self.case_paths != expected_cases
            or self.projection_paths != expected_projections
        ):
            raise ValueError("pilot A4 publication paths do not match its case inventory")
        if self.case_paths != tuple(sorted(set(self.case_paths))):
            raise ValueError("pilot A4 case paths must be unique and stably ordered")
        if self.local_alert_paths != tuple(sorted(set(self.local_alert_paths))):
            raise ValueError("pilot local alert paths must be unique and stably ordered")
        if len(self.local_alert_paths) != self.metrics.verified_local_alert_count:
            raise ValueError("pilot local alert paths conflict with verified alert metrics")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def publication_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"publication_id"})
        return sha256_hex(["pilot-a4-publication-report", 1, payload])


class PilotA4ReviewReport(ContractModel):
    """Audit-safe projection of one thin pilot review onto the M5 appeal authority."""

    schema_version: Literal["pilot-a4-review-report-v1"] = "pilot-a4-review-report-v1"
    run_id: str
    case_id: str
    source_decision: VerdictDecision
    requested_decision: VerdictDecision
    reason_sha256: Sha256Hex
    manifest_id: Sha256Hex
    resolution: M5AppealResolutionCommandReport
    review_label: M5AppealTrainingLabelInput | None = None
    publication_id: Sha256Hex
    metrics_id: Sha256Hex
    index_path: str
    production_delivery_count: Literal[0] = 0
    disclaimer: Literal[
        "用于安全辅助与记录，不直接作为处罚依据"  # noqa: RUF001
    ] = PILOT_OPERATOR_DISCLAIMER

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "pilot A4 review run_id")

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return require_reference_token(value, "pilot A4 review case_id")

    @field_validator("index_path")
    @classmethod
    def validate_index_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_review_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        return _validate_claimed_id(value, handler, field_name="review_id")

    @model_validator(mode="after")
    def validate_review_scope(self) -> PilotA4ReviewReport:
        resolution = self.resolution
        if resolution.run_id != self.run_id or resolution.case_id != self.case_id:
            raise ValueError("pilot A4 review differs from its M5 appeal authority")
        if self.index_path != f"runs/{self.run_id}/report/index.html":
            raise ValueError("pilot A4 review index path differs from its run")
        if (
            resolution.source_decision != self.source_decision
            or resolution.final_decision != self.requested_decision
        ):
            raise ValueError("pilot A4 review decision differs from its resolution")
        changed = self.requested_decision != self.source_decision
        if changed:
            if (
                resolution.status != AppealStatus.OVERTURNED
                or self.review_label is None
                or len(resolution.training_label_ids) != 1
            ):
                raise ValueError("pilot A4 changed decision requires one appeal label")
        elif resolution.status != AppealStatus.UPHELD or self.review_label is not None:
            raise ValueError("pilot A4 upheld decision cannot carry an overturn label")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def review_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"review_id"})
        return sha256_hex(["pilot-a4-review-report", 1, payload])


__all__ = [
    "PILOT_OPERATOR_DISCLAIMER",
    "PilotA4CaseView",
    "PilotA4MediaView",
    "PilotA4Metrics",
    "PilotA4ModelVersion",
    "PilotA4PublicationReport",
    "PilotA4ReviewReport",
    "PilotLocalAlertDocument",
]
