"""M4 role calls, bounded acquisition tools, and auditable hearing records.

Model-authored payloads stay separate from the run/case authority that wraps
them.  The contracts deliberately validate only syntax and structural binding;
existence of cited evidence, precedents, and tool artifacts remains an L5 gate.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionClaimState,
    AcquisitionExecutionMode,
    ArtifactKind,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import (
    AcquisitionParameters,
    Crop,
    CropRequest,
    RecropParameters,
    ToolResult,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.frames import FrameRef, Sha256Hex
from labcourt.contracts.hearing_common import (
    MAX_HEARING_ACQUISITION_ROUNDS,
    MAX_HEARING_JUDGE_CYCLES,
    MAX_HEARING_REWORK_ROUNDS,
    AcquisitionRequestPayload,
    derive_m4_tool_result_id,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

_CANONICAL_UTC_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"


class AcquisitionRequest(FrozenContractModel):
    """Scoped executable request derived exactly from one Judge proposal."""

    schema_version: Literal["m4-acquisition-request-v1"] = "m4-acquisition-request-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(ge=0, lt=MAX_HEARING_ACQUISITION_ROUNDS, strict=True)
    prior_rework_rounds: int = Field(ge=0, le=MAX_HEARING_REWORK_ROUNDS, strict=True)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    source_judge_output_id: Sha256Hex
    source_model_request_ref: ArtifactRef
    source_model_response_ref: ArtifactRef
    request_payload: AcquisitionRequestPayload
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "acquisition request reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_request_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "request_id" in payload
        claimed = payload.pop("request_id", None)
        request = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != request.request_id):
            raise ValueError("serialized acquisition request ID does not match its content")
        return request

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "acquisition-request",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.round_index,
                self.prior_acquisition_rounds,
                self.prior_rework_rounds,
                self.current_evidence_pack_id,
                self.current_evidence_pack_version,
                self.source_judge_output_id,
                self.source_model_request_ref.model_dump(mode="json"),
                self.source_model_response_ref.model_dump(mode="json"),
                self.request_payload.request_payload_id,
                self.manifest_id,
            ]
        )

    @property
    def action(self) -> AcquisitionAction:
        return self.request_payload.action

    @property
    def validated_parameters(self) -> AcquisitionParameters:
        return self.request_payload.validated_parameters

    @model_validator(mode="after")
    def validate_scope(self) -> AcquisitionRequest:
        if self.round_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("acquisition request round conflicts with its prior counters")
        if self.source_model_request_ref.kind != ArtifactKind.MODEL_REQUEST:
            raise ValueError("acquisition source request must identify a model request")
        if self.source_model_response_ref.kind != ArtifactKind.MODEL_RESPONSE:
            raise ValueError("acquisition source response must identify a model response")
        return self


class ToolExecutionManifest(FrozenContractModel):
    """Immutable implementation authority for one whitelisted acquisition action."""

    schema_version: Literal["m4-tool-execution-manifest-v1"] = "m4-tool-execution-manifest-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    acquisition_request_id: Sha256Hex
    action: AcquisitionAction
    tool_id: ReferenceToken
    tool_revision: ReferenceToken
    parameters_schema_sha256: Sha256Hex
    component_manifest_id: Sha256Hex
    model_manifest_id: Sha256Hex | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "tool_id", "tool_revision")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "tool execution manifest reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_manifest_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "execution_manifest_id" in payload
        claimed = payload.pop("execution_manifest_id", None)
        manifest = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != manifest.execution_manifest_id
        ):
            raise ValueError("serialized execution manifest ID does not match its content")
        return manifest

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_manifest_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "tool-execution-manifest",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.acquisition_request_id,
                self.action.value,
                self.tool_id,
                self.tool_revision,
                self.parameters_schema_sha256,
                self.component_manifest_id,
                self.model_manifest_id,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_model_manifest_matrix(self) -> ToolExecutionManifest:
        is_redetection = self.action == AcquisitionAction.REDETECT_HIGH_RES
        if is_redetection != (self.model_manifest_id is not None):
            raise ValueError("only high-resolution redetection requires a model manifest")
        return self


class AcquisitionExecutionClaimAuthority(FrozenContractModel):
    """Complete secret-free projection of one mutable execution fence."""

    schema_version: Literal["m4-acquisition-execution-claim-v1"] = (
        "m4-acquisition-execution-claim-v1"
    )
    request: AcquisitionRequest
    execution_mode: AcquisitionExecutionMode
    idempotency_key: Sha256Hex
    status: AcquisitionExecutionClaimState
    owner_token_sha256: Sha256Hex
    owner_fence: int = Field(gt=0, strict=True)
    lease_expires_at: str | None = Field(default=None, pattern=_CANONICAL_UTC_PATTERN)
    execution_publication_id: Sha256Hex | None = None
    created_at: str = Field(pattern=_CANONICAL_UTC_PATTERN)
    updated_at: str = Field(pattern=_CANONICAL_UTC_PATTERN)

    @model_validator(mode="after")
    def validate_fence_closure(self) -> AcquisitionExecutionClaimAuthority:
        if self.idempotency_key != self.request.request_id:
            raise ValueError("acquisition claim idempotency key must equal request ID")
        if self.updated_at < self.created_at:
            raise ValueError("acquisition claim update precedes creation")
        if self.status == AcquisitionExecutionClaimState.ACTIVE:
            if (
                self.lease_expires_at is None
                or self.lease_expires_at <= self.updated_at
                or self.execution_publication_id is not None
            ):
                raise ValueError("active acquisition claim has invalid closure fields")
        elif self.status == AcquisitionExecutionClaimState.COMPLETED:
            if self.lease_expires_at is not None or self.execution_publication_id is None:
                raise ValueError("completed acquisition claim has invalid closure fields")
        elif self.lease_expires_at is not None or self.execution_publication_id is not None:
            raise ValueError("automation-abandoned acquisition claim must retain no delivery root")
        return self


class AcquisitionExecutionPublication(FrozenContractModel):
    """Durable result authority published before EvidencePack mutation.

    The publication closes one fenced executor owner and makes the exact tool
    result recoverable without crossing the external tool boundary again.
    """

    schema_version: Literal["m4-acquisition-execution-publication-v1"] = (
        "m4-acquisition-execution-publication-v1"
    )
    request: AcquisitionRequest
    execution_manifest: ToolExecutionManifest
    tool_result: ToolResult
    frames: tuple[FrameRef, ...] = ()
    crops: tuple[Crop, ...] = ()
    objective_facts: tuple[ObjectiveFact, ...] = ()
    detections: tuple[Detection, ...] = ()
    crop_request: CropRequest | None = None
    execution_mode: AcquisitionExecutionMode
    idempotency_key: Sha256Hex
    claim_owner_sha256: Sha256Hex
    claim_fence: int = Field(gt=0, strict=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_publication_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "publication_id" in payload
        claimed = payload.pop("publication_id", None)
        publication = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != publication.publication_id
        ):
            raise ValueError("serialized acquisition publication ID conflicts with content")
        return publication

    @computed_field  # type: ignore[prop-decorator]
    @property
    def publication_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "acquisition-execution-publication",
                1,
                self.request.request_id,
                self.execution_manifest.execution_manifest_id,
                self.tool_result.model_dump(mode="json"),
                [item.model_dump(mode="json") for item in self.frames],
                [item.model_dump(mode="json") for item in self.crops],
                [item.model_dump(mode="json") for item in self.objective_facts],
                [item.model_dump(mode="json") for item in self.detections],
                (
                    self.crop_request.model_dump(mode="json")
                    if self.crop_request is not None
                    else None
                ),
                self.execution_mode.value,
                self.idempotency_key,
                self.claim_owner_sha256,
                self.claim_fence,
            ]
        )

    @model_validator(mode="after")
    def validate_execution_closure(self) -> AcquisitionExecutionPublication:
        request = self.request
        manifest = self.execution_manifest
        result = self.tool_result
        if self.idempotency_key != request.request_id:
            raise ValueError("acquisition idempotency key must equal its request ID")
        if (
            manifest.run_id != request.run_id
            or manifest.case_id != request.case_id
            or manifest.hearing_session_id != request.hearing_session_id
            or manifest.acquisition_request_id != request.request_id
            or manifest.action != request.action
            or manifest.manifest_id != request.manifest_id
        ):
            raise ValueError("acquisition publication manifest conflicts with its request")
        if (
            result.action != request.action
            or result.validated_parameters != request.validated_parameters
            or result.execution_manifest_id != manifest.execution_manifest_id
            or result.tool_result_id
            != derive_m4_tool_result_id(
                result.action,
                result.input_refs,
                result.output_refs,
                result.validated_parameters,
                result.execution_manifest_id,
            )
        ):
            raise ValueError("acquisition publication result conflicts with its authority")
        output_refs = tuple(
            sorted(
                (
                    *(
                        ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=item.frame_id)
                        for item in self.frames
                    ),
                    *(
                        ArtifactRef(kind=ArtifactKind.CROP, artifact_id=item.crop_id)
                        for item in self.crops
                    ),
                    *(
                        ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id=item.fact_id)
                        for item in self.objective_facts
                    ),
                    *(
                        ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id=item.detection_id)
                        for item in self.detections
                    ),
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        if len(output_refs) != len(set(output_refs)) or result.output_refs != output_refs:
            raise ValueError("acquisition publication outputs conflict with ToolResult refs")
        recrop = isinstance(request.validated_parameters, RecropParameters)
        if recrop != isinstance(self.crop_request, CropRequest):
            raise ValueError("only RECROP publication may carry a CropRequest")
        return self


class ToolExecutionReceipt(FrozenContractModel):
    """Exact request/result/manifest closure that advances EvidencePack by one version."""

    schema_version: Literal["m4-tool-execution-receipt-v1"] = "m4-tool-execution-receipt-v1"
    request: AcquisitionRequest
    execution_manifest: ToolExecutionManifest
    tool_result: ToolResult
    resulting_evidence_pack_id: Sha256Hex
    resulting_evidence_pack_version: int = Field(gt=0, strict=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "receipt_id" in payload
        claimed = payload.pop("receipt_id", None)
        receipt = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != receipt.receipt_id):
            raise ValueError("serialized tool receipt ID does not match its content")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "tool-execution-receipt",
                1,
                self.request.request_id,
                self.execution_manifest.execution_manifest_id,
                self.tool_result.model_dump(mode="json"),
                self.resulting_evidence_pack_id,
                self.resulting_evidence_pack_version,
            ]
        )

    @model_validator(mode="after")
    def validate_execution_closure(self) -> ToolExecutionReceipt:
        request = self.request
        manifest = self.execution_manifest
        result = self.tool_result
        if (
            manifest.run_id != request.run_id
            or manifest.case_id != request.case_id
            or manifest.hearing_session_id != request.hearing_session_id
            or manifest.acquisition_request_id != request.request_id
            or manifest.action != request.action
            or manifest.manifest_id != request.manifest_id
        ):
            raise ValueError("tool execution manifest conflicts with its acquisition request")
        if (
            result.action != request.action
            or result.validated_parameters != request.validated_parameters
            or result.execution_manifest_id != manifest.execution_manifest_id
        ):
            raise ValueError("tool result conflicts with its request or execution manifest")
        expected_tool_result_id = derive_m4_tool_result_id(
            result.action,
            result.input_refs,
            result.output_refs,
            result.validated_parameters,
            result.execution_manifest_id,
        )
        if result.tool_result_id != expected_tool_result_id:
            raise ValueError("M4 tool result ID must be its deterministic content address")
        current_pack_ref = ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=request.current_evidence_pack_id,
        )
        if current_pack_ref not in result.input_refs:
            raise ValueError("tool result inputs must include the current evidence pack")
        if not result.output_refs:
            raise ValueError("successful tool execution requires typed output refs")
        if isinstance(request.validated_parameters, TrackConfidenceCurveParameters) and any(
            ref.kind != ArtifactKind.OBJECTIVE_FACT for ref in result.output_refs
        ):
            raise ValueError("track-confidence outputs must be objective facts")
        if self.resulting_evidence_pack_version != request.current_evidence_pack_version + 1:
            raise ValueError("tool execution must advance the evidence pack by exactly one version")
        if self.resulting_evidence_pack_id == request.current_evidence_pack_id:
            raise ValueError("tool execution must produce a new evidence pack identity")
        return self
