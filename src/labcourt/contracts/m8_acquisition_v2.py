"""Additive M8 contracts for real recorded-run acquisition execution.

M4's acquisition contracts are frozen.  This module records facts that M4 v1
cannot represent honestly: an empty successful redetection and the typed
per-frame series behind the aggregate TRACK_CONFIDENCE_CURVE ObjectiveFact.
"""

from __future__ import annotations

import base64
import hashlib
import math
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import AcquisitionAction
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import Crop, CropRequest, ToolResult
from labcourt.contracts.frames import FrameRef, Sha256Hex
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing import AcquisitionRequest, ToolExecutionManifest
from labcourt.contracts.hearing_common import MAX_ACQUISITION_RETURNED_FRAMES
from labcourt.contracts.m8_evaluation import (
    M8EvaluationRunSourceKind,
    M8RunSourceRefV1,
)
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    TrackRef,
    parse_frame_id,
    parse_track_ref,
    require_reference_token,
)


class M8AcquisitionOutcomeStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    SUCCEEDED_EMPTY = "SUCCEEDED_EMPTY"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


class M8AcquisitionM4Representability(StrEnum):
    M4_V1_REPRESENTABLE = "M4_V1_REPRESENTABLE"
    V1_UNREPRESENTABLE = "V1_UNREPRESENTABLE"


class M8AcquisitionFailureCode(StrEnum):
    SOURCE_BINDING_MISSING = "SOURCE_BINDING_MISSING"
    SOURCE_AUTHORITY_MISMATCH = "SOURCE_AUTHORITY_MISMATCH"
    SOURCE_MEDIA_UNAVAILABLE = "SOURCE_MEDIA_UNAVAILABLE"
    RECROP_AUTHORITY_MISSING = "RECROP_AUTHORITY_MISSING"
    DETECTOR_UNAVAILABLE = "DETECTOR_UNAVAILABLE"
    DETECTOR_FAILED = "DETECTOR_FAILED"
    DETECTOR_OUTPUT_INVALID = "DETECTOR_OUTPUT_INVALID"
    TRACK_DATA_MISSING = "TRACK_DATA_MISSING"
    TRACK_DATA_AMBIGUOUS = "TRACK_DATA_AMBIGUOUS"
    OTHER_CAMERA_UNAVAILABLE = "OTHER_CAMERA_UNAVAILABLE"
    V1_EMPTY_OUTPUT_UNREPRESENTABLE = "V1_EMPTY_OUTPUT_UNREPRESENTABLE"


class M8ResolvedRecordedRunSourceV1(FrozenContractModel):
    """One persisted source sidecar closed against one single-stream RunManifest."""

    schema_version: Literal["m8-resolved-recorded-run-source-v1"] = (
        "m8-resolved-recorded-run-source-v1"
    )
    source: M8RunSourceRefV1
    run_manifest_id: Sha256Hex
    camera_id: ReferenceToken
    stream_id: ReferenceToken
    input_file_sha256: Sha256Hex
    frame_count: int = Field(gt=0, strict=True)

    @field_validator("camera_id", "stream_id")
    @classmethod
    def validate_stream_token(cls, value: str) -> str:
        return require_reference_token(value, "resolved run source stream")

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.source.source_kind != M8EvaluationRunSourceKind.RECORDED_ASSET:
            raise ValueError("recorded acquisition requires a recorded-asset source")
        if (
            self.source.media_sha256 != self.input_file_sha256
            or self.source.frame_count != self.frame_count
        ):
            raise ValueError("persisted run source conflicts with stream authority")
        return self


class M8RedetectionDetectorRequestV1(FrozenContractModel):
    """Strict local-detector request over one already privacy-transformed crop."""

    schema_version: Literal["m8-redetection-detector-request-v1"] = (
        "m8-redetection-detector-request-v1"
    )
    request_id: Sha256Hex
    run_id: ReferenceToken
    crop_id: Sha256Hex
    crop_media_sha256: Sha256Hex
    frame_id: FrameId
    crop_bbox: BBoxXYXY
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)
    prompts: tuple[str, ...] = Field(min_length=1, max_length=32)
    image_encoding: Literal["PNG_RGB8_V1"] = "PNG_RGB8_V1"
    image_base64: str = Field(min_length=1, max_length=32 * 1024 * 1024)
    image_sha256: Sha256Hex
    expected_model_manifest_id: Sha256Hex

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "redetection run_id")

    @field_validator("prompts")
    @classmethod
    def validate_prompts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 128 for item in value):
            raise ValueError("redetection prompts must contain bounded non-empty text")
        if len(value) != len(set(value)):
            raise ValueError("redetection prompts must be unique")
        return value

    @model_validator(mode="after")
    def validate_image_identity(self) -> Self:
        try:
            raw = base64.b64decode(self.image_base64, validate=True)
        except (ValueError, TypeError):
            raise ValueError("redetection image is not strict base64") from None
        if (
            hashlib.sha256(raw).hexdigest() != self.image_sha256
            or self.image_sha256 != self.crop_media_sha256
        ):
            raise ValueError("redetection image bytes conflict with their SHA-256")
        return self


class M8RedetectionCandidateV1(FrozenContractModel):
    label: str = Field(min_length=1, max_length=128)
    bbox: BBoxXYXY
    score: StrictFloat = Field(ge=0, le=1)


class M8RedetectionOutcomeV1(FrozenContractModel):
    """Strict raw detector result.  Empty success is intentionally legal here."""

    schema_version: Literal["m8-redetection-outcome-v1"] = "m8-redetection-outcome-v1"
    request_id: Sha256Hex
    crop_id: Sha256Hex
    crop_media_sha256: Sha256Hex
    model_manifest_id: Sha256Hex
    status: Literal["SUCCEEDED", "FAILED"]
    detections: tuple[M8RedetectionCandidateV1, ...] = Field(
        default=(), max_length=MAX_ACQUISITION_RETURNED_FRAMES
    )
    error_code: (
        Literal[
            "IMAGE_INVALID",
            "INFERENCE_FAILED",
            "REQUEST_INVALID",
            "MODEL_UNAVAILABLE",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.status == "SUCCEEDED" and self.error_code is not None:
            raise ValueError("successful redetection cannot carry an error code")
        if self.status == "FAILED" and (self.error_code is None or self.detections):
            raise ValueError("failed redetection requires only a typed error code")
        return self


class M8AcquisitionRawReceiptV1(FrozenContractModel):
    schema_version: Literal["m8-acquisition-raw-receipt-v1"] = "m8-acquisition-raw-receipt-v1"
    request_id: Sha256Hex
    raw_response_ref: str = Field(min_length=1)
    raw_response_sha256: Sha256Hex
    cache_hit: StrictBool

    @field_validator("raw_response_ref")
    @classmethod
    def validate_raw_ref(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)


class M8TrackConfidencePointStatus(StrEnum):
    OBSERVED = "OBSERVED"
    MISSING = "MISSING"


class M8TrackConfidencePointV1(FrozenContractModel):
    frame_index: int = Field(ge=0, strict=True)
    frame_id: FrameId | None = None
    status: M8TrackConfidencePointStatus
    score: StrictFloat | None = Field(default=None, ge=0, le=1)
    detection_id: ReferenceToken | None = None

    @field_validator("detection_id")
    @classmethod
    def validate_detection_id(cls, value: str | None) -> str | None:
        return (
            require_reference_token(value, "track confidence detection")
            if value is not None
            else None
        )

    @model_validator(mode="after")
    def validate_point(self) -> Self:
        observed = self.status == M8TrackConfidencePointStatus.OBSERVED
        if observed != all(
            value is not None for value in (self.frame_id, self.score, self.detection_id)
        ):
            raise ValueError("observed track points require exact detection authority")
        if not observed and any(
            value is not None for value in (self.frame_id, self.score, self.detection_id)
        ):
            raise ValueError("missing track points cannot carry invented detection values")
        if self.frame_id is not None and parse_frame_id(self.frame_id)[2] != self.frame_index:
            raise ValueError("track point frame ID conflicts with its frame index")
        return self


class M8TrackConfidenceSeriesV1(FrozenContractModel):
    schema_version: Literal["m8-track-confidence-series-v1"] = "m8-track-confidence-series-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    acquisition_request_id: Sha256Hex
    track_ref: TrackRef
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    points: tuple[M8TrackConfidencePointV1, ...] = Field(
        min_length=1, max_length=MAX_ACQUISITION_RETURNED_FRAMES
    )
    observed_count: int = Field(gt=0, strict=True)
    mean_score: StrictFloat = Field(ge=0, le=1)
    minimum_score: StrictFloat = Field(ge=0, le=1)
    maximum_score: StrictFloat = Field(ge=0, le=1)

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        return require_reference_token(value, "track confidence scope")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def series_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-track-confidence-series",
                1,
                self.run_id,
                self.case_id,
                self.acquisition_request_id,
                self.track_ref,
                self.start_frame,
                self.end_frame_exclusive,
                [item.model_dump(mode="json") for item in self.points],
            ]
        )

    @property
    def curve_id(self) -> Sha256Hex:
        """Compatibility accessor; public serialization uses series_id."""

        return self.series_id

    @model_validator(mode="after")
    def validate_curve(self) -> Self:
        if self.start_frame >= self.end_frame_exclusive:
            raise ValueError("track confidence interval must be non-empty")
        expected = tuple(range(self.start_frame, self.end_frame_exclusive))
        if tuple(item.frame_index for item in self.points) != expected:
            raise ValueError("track confidence points must close every requested frame")
        camera_id, _, _ = parse_track_ref(self.track_ref)
        observed = tuple(
            item for item in self.points if item.status == M8TrackConfidencePointStatus.OBSERVED
        )
        if len(observed) != self.observed_count:
            raise ValueError("track confidence observed count conflicts with its points")
        observed_frame_ids = tuple(item.frame_id for item in observed)
        if any(item is None for item in observed_frame_ids):
            raise ValueError("observed track point lost its frame authority")
        if any(
            parse_frame_id(item)[0] != camera_id for item in observed_frame_ids if item is not None
        ):
            raise ValueError("track confidence point belongs to another camera")
        scores = tuple(float(item.score) for item in observed if item.score is not None)
        expected_mean = math.fsum(scores) / len(scores)
        if not (
            math.isclose(self.mean_score, expected_mean, rel_tol=0.0, abs_tol=1e-15)
            and self.minimum_score == min(scores)
            and self.maximum_score == max(scores)
        ):
            raise ValueError("track confidence aggregates conflict with their points")
        return self


class M8AcquisitionM4ExecutionV1(FrozenContractModel):
    """Exact M4 execution snapshot used for external-tool crash recovery."""

    schema_version: Literal["m8-acquisition-m4-execution-v1"] = "m8-acquisition-m4-execution-v1"
    request: AcquisitionRequest
    execution_manifest: ToolExecutionManifest
    tool_result: ToolResult
    frames: tuple[FrameRef, ...] = ()
    crops: tuple[Crop, ...] = ()
    objective_facts: tuple[ObjectiveFact, ...] = ()
    detections: tuple[Detection, ...] = ()
    crop_request: CropRequest | None = None

    @model_validator(mode="after")
    def validate_execution_scope(self) -> Self:
        if (
            self.execution_manifest.acquisition_request_id != self.request.request_id
            or self.execution_manifest.execution_manifest_id
            != self.tool_result.execution_manifest_id
            or self.request.action != self.tool_result.action
            or self.request.validated_parameters != self.tool_result.validated_parameters
        ):
            raise ValueError("M8 execution snapshot conflicts with its M4 authority")
        return self


class M8HearingAcquisitionResultV2(FrozenContractModel):
    """Durable additive result and honest M4-v1 representability boundary."""

    schema_version: Literal["m8-hearing-acquisition-result-v2"] = "m8-hearing-acquisition-result-v2"
    run_id: ReferenceToken
    case_id: ReferenceToken
    acquisition_request_id: Sha256Hex
    action: AcquisitionAction
    status: M8AcquisitionOutcomeStatus
    m4_representability: M8AcquisitionM4Representability
    failure_code: M8AcquisitionFailureCode | None = None
    raw_receipt: M8AcquisitionRawReceiptV1 | None = None
    redetection_outcome: M8RedetectionOutcomeV1 | None = None
    track_confidence_series: M8TrackConfidenceSeriesV1 | None = None
    m4_execution: M8AcquisitionM4ExecutionV1 | None = None

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        return require_reference_token(value, "M8 acquisition outcome scope")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_id(self) -> Sha256Hex:
        payload = self.model_dump(mode="json", exclude={"result_id"})
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @property
    def outcome_id(self) -> Sha256Hex:
        """Compatibility accessor; public serialization uses result_id."""

        return self.result_id

    @property
    def redetection(self) -> M8RedetectionOutcomeV1 | None:
        return self.redetection_outcome

    @property
    def track_curve(self) -> M8TrackConfidenceSeriesV1 | None:
        return self.track_confidence_series

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        is_redetection = self.action == AcquisitionAction.REDETECT_HIGH_RES
        if not is_redetection and (
            self.raw_receipt is not None or self.redetection_outcome is not None
        ):
            raise ValueError("only redetection results may carry detector authority")
        represented = self.m4_representability == (
            M8AcquisitionM4Representability.M4_V1_REPRESENTABLE
        )
        if represented != (self.m4_execution is not None):
            raise ValueError("M8 representability conflicts with its M4 execution")
        if self.m4_execution is not None:
            request = self.m4_execution.request
            if (
                request.run_id != self.run_id
                or request.case_id != self.case_id
                or request.request_id != self.acquisition_request_id
                or request.action != self.action
            ):
                raise ValueError("M8 outcome conflicts with its M4 request")
        if self.status == M8AcquisitionOutcomeStatus.SUCCEEDED:
            if not represented or self.failure_code is not None:
                raise ValueError("successful represented outcome has invalid closure")
            if is_redetection and (
                self.raw_receipt is None
                or self.redetection_outcome is None
                or self.redetection_outcome.status != "SUCCEEDED"
                or not self.redetection_outcome.detections
            ):
                raise ValueError("successful redetection requires non-empty detector authority")
        elif self.status == M8AcquisitionOutcomeStatus.SUCCEEDED_EMPTY:
            if (
                represented
                or self.action != AcquisitionAction.REDETECT_HIGH_RES
                or self.failure_code != M8AcquisitionFailureCode.V1_EMPTY_OUTPUT_UNREPRESENTABLE
                or self.redetection_outcome is None
                or self.redetection_outcome.status != "SUCCEEDED"
                or self.redetection_outcome.detections
            ):
                raise ValueError("empty redetection outcome has invalid closure")
        elif self.failure_code is None or represented:
            raise ValueError("failed or unavailable outcomes require a typed failure")
        if self.redetection_outcome is not None and self.raw_receipt is None:
            raise ValueError("parsed redetection requires its raw receipt")
        if self.raw_receipt is not None and self.raw_receipt.request_id != (
            self.acquisition_request_id
        ):
            raise ValueError("redetection receipt conflicts with acquisition request")
        if self.redetection_outcome is not None and self.redetection_outcome.request_id != (
            self.acquisition_request_id
        ):
            raise ValueError("redetection result conflicts with acquisition request")
        if (self.track_confidence_series is not None) != (
            self.action == AcquisitionAction.TRACK_CONFIDENCE_CURVE
            and self.status == M8AcquisitionOutcomeStatus.SUCCEEDED
        ):
            raise ValueError("only successful track acquisition may carry a curve")
        return self


class M8TrackConfidenceSeriesViewV1(FrozenContractModel):
    """Platform-safe projection of a typed series without the internal M4 case ID."""

    schema_version: Literal["m8-track-confidence-series-view-v1"] = (
        "m8-track-confidence-series-view-v1"
    )
    source_series_id: Sha256Hex
    acquisition_request_id: Sha256Hex
    track_ref: TrackRef
    start_frame: int = Field(ge=0, strict=True)
    end_frame_exclusive: int = Field(gt=0, strict=True)
    points: tuple[M8TrackConfidencePointV1, ...]
    observed_count: int = Field(gt=0, strict=True)
    mean_score: StrictFloat = Field(ge=0, le=1)
    minimum_score: StrictFloat = Field(ge=0, le=1)
    maximum_score: StrictFloat = Field(ge=0, le=1)


class M8HearingAcquisitionResultViewV2(FrozenContractModel):
    """Same-origin view keyed by the formal platform Case identity."""

    schema_version: Literal["m8-hearing-acquisition-result-view-v2"] = (
        "m8-hearing-acquisition-result-view-v2"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    result_id: Sha256Hex
    acquisition_request_id: Sha256Hex
    action: AcquisitionAction
    status: M8AcquisitionOutcomeStatus
    m4_representability: M8AcquisitionM4Representability
    failure_code: M8AcquisitionFailureCode | None = None
    raw_receipt: M8AcquisitionRawReceiptV1 | None = None
    redetection_outcome: M8RedetectionOutcomeV1 | None = None
    track_confidence_series: M8TrackConfidenceSeriesViewV1 | None = None

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_view_scope(cls, value: str) -> str:
        return require_reference_token(value, "M8 acquisition result view scope")

    @classmethod
    def project(
        cls,
        result: M8HearingAcquisitionResultV2,
        *,
        platform_case_id: str,
    ) -> M8HearingAcquisitionResultViewV2:
        series = result.track_confidence_series
        series_view = (
            M8TrackConfidenceSeriesViewV1(
                source_series_id=series.series_id,
                acquisition_request_id=series.acquisition_request_id,
                track_ref=series.track_ref,
                start_frame=series.start_frame,
                end_frame_exclusive=series.end_frame_exclusive,
                points=series.points,
                observed_count=series.observed_count,
                mean_score=series.mean_score,
                minimum_score=series.minimum_score,
                maximum_score=series.maximum_score,
            )
            if series is not None
            else None
        )
        return cls(
            run_id=result.run_id,
            case_id=platform_case_id,
            result_id=result.result_id,
            acquisition_request_id=result.acquisition_request_id,
            action=result.action,
            status=result.status,
            m4_representability=result.m4_representability,
            failure_code=result.failure_code,
            raw_receipt=result.raw_receipt,
            redetection_outcome=result.redetection_outcome,
            track_confidence_series=series_view,
        )


# Compatibility aliases for earlier internal names used during integration.
M8RedetectionDetectorResponseV1 = M8RedetectionOutcomeV1
M8TrackConfidenceCurveV1 = M8TrackConfidenceSeriesV1
M8AcquisitionOutcomeV2 = M8HearingAcquisitionResultV2


__all__ = [
    "M8AcquisitionFailureCode",
    "M8AcquisitionM4ExecutionV1",
    "M8AcquisitionM4Representability",
    "M8AcquisitionOutcomeStatus",
    "M8AcquisitionOutcomeV2",
    "M8AcquisitionRawReceiptV1",
    "M8HearingAcquisitionResultV2",
    "M8HearingAcquisitionResultViewV2",
    "M8RedetectionCandidateV1",
    "M8RedetectionDetectorRequestV1",
    "M8RedetectionDetectorResponseV1",
    "M8RedetectionOutcomeV1",
    "M8ResolvedRecordedRunSourceV1",
    "M8TrackConfidenceCurveV1",
    "M8TrackConfidencePointStatus",
    "M8TrackConfidencePointV1",
    "M8TrackConfidenceSeriesV1",
    "M8TrackConfidenceSeriesViewV1",
]
