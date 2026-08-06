"""M4 role calls, bounded acquisition tools, and auditable hearing records.

Model-authored payloads stay separate from the run/case authority that wraps
them.  The contracts deliberately validate only syntax and structural binding;
existence of cited evidence, precedents, and tool artifacts remains an L5 gate.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.backlog import BacklogLeaseIdentity, BacklogRetryContext
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    ModelParseStatus,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.hearing_common import (
    _ROLE_EVIDENCE_KINDS,
    MAX_HEARING_ACQUISITION_ROUNDS,
    MAX_HEARING_JUDGE_CYCLES,
    MAX_HEARING_REWORK_ROUNDS,
    DefenderModelPayload,
    HearingRole,
    HearingUnknownReferenceAttempt,
    JudgeModelPayload,
    ProsecutorModelPayload,
    _hearing_cycle_scope_id,
    _hearing_cycle_scope_projection,
    _hearing_cycle_scope_sha256,
    _stable_defect_codes,
    _stable_refs,
)
from labcourt.contracts.m3_models import (
    PromptManifest,
    VlmCallBudget,
    require_bounded_public_text,
)
from labcourt.contracts.model_call_failures import (
    ModelCallFailureClosureKind,
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.paths import (
    SAFE_RELATIVE_PATH_PATTERN,
    require_safe_relative_posix_path,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import (
    ProceduralDefect,
)

HearingModelPayload: TypeAlias = Annotated[
    ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
    Field(discriminator="role"),
]


class HearingModelRequest(FrozenContractModel):
    """One role-specific M4 call, including its repair generation when present."""

    schema_version: Literal["m4-hearing-model-request-v1"] = "m4-hearing-model-request-v1"
    purpose: Literal["HEARING_ROLE"] = "HEARING_ROLE"
    attempt_index: Literal[0, 1] = 0
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(
        ge=0,
        le=MAX_HEARING_ACQUISITION_ROUNDS,
        strict=True,
    )
    prior_rework_rounds: int = Field(ge=0, le=MAX_HEARING_REWORK_ROUNDS, strict=True)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    screening_ref: ArtifactRef
    violation_type: ViolationType
    evidence_class: EvidenceClass
    role: HearingRole
    provider_profile: ReferenceToken
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=128)
    model_manifest_id: Sha256Hex
    execution_location: ExecutionLocation
    prompt_manifest: PromptManifest
    hearing_prompt_bundle_sha256: Sha256Hex
    rendered_prompt_sha256: Sha256Hex
    hearing_context_sha256: Sha256Hex
    media: tuple[VLMMediaRef, ...] = Field(default=(), max_length=64)
    allowed_evidence_refs: tuple[ArtifactRef, ...] = Field(min_length=1, max_length=512)
    allowed_precedent_refs: tuple[ArtifactRef, ...] = Field(default=(), max_length=64)
    prosecutor_output_ref: ArtifactRef | None = None
    defender_output_ref: ArtifactRef | None = None
    precedent_retrieval_degraded: StrictBool
    precedent_retrieval_receipt_id: Sha256Hex
    precedent_retrieval_receipt_sha256: Sha256Hex
    initial_trigger_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    rework_review_ref: ArtifactRef | None = None
    rework_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    original_request_id: Sha256Hex | None = None
    original_response_id: Sha256Hex | None = None
    original_response_content_sha256: Sha256Hex | None = None
    repair_context_sha256: Sha256Hex | None = None
    temperature: StrictFloat = Field(ge=0)
    seed: int | None = Field(default=None, strict=True)
    budget: VlmCallBudget
    backlog_retry_context: BacklogRetryContext | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "provider_profile")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing model request reference")

    @field_validator("provider", "model", "revision")
    @classmethod
    def validate_provider_text(cls, value: str) -> str:
        return require_bounded_public_text(value, "hearing provider identity", max_length=256)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        names = (
            "cycle_scope_id",
            "cycle_scope_sha256",
            "request_sha256",
            "request_id",
            "cache_key",
        )
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        request = handler(payload)
        for name in names:
            if present[name] and (
                not isinstance(claimed[name], str) or claimed[name] != getattr(request, name)
            ):
                raise ValueError(f"serialized {name} does not match hearing request content")
        return request

    def cycle_scope_projection(self) -> dict[str, object]:
        return _hearing_cycle_scope_projection(
            run_id=self.run_id,
            case_id=self.case_id,
            hearing_session_id=self.hearing_session_id,
            cycle_index=self.round_index,
            prior_acquisition_rounds=self.prior_acquisition_rounds,
            prior_rework_rounds=self.prior_rework_rounds,
            cycle_evidence_pack_id=self.current_evidence_pack_id,
            cycle_evidence_pack_version=self.current_evidence_pack_version,
            initial_trigger_review_ref=self.initial_trigger_review_ref,
            initial_defect_codes=self.initial_defect_codes,
            rework_review_ref=self.rework_review_ref,
            rework_defect_codes=self.rework_defect_codes,
            manifest_id=self.manifest_id,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cycle_scope_id(self) -> Sha256Hex:
        return _hearing_cycle_scope_id(self.cycle_scope_projection())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cycle_scope_sha256(self) -> Sha256Hex:
        return _hearing_cycle_scope_sha256(self.cycle_scope_projection())

    def request_projection(self) -> dict[str, object]:
        projection: dict[str, object] = {
            "schema_version": self.schema_version,
            "purpose": self.purpose,
            "attempt_index": self.attempt_index,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "hearing_session_id": self.hearing_session_id,
            "cycle_scope_id": self.cycle_scope_id,
            "cycle_scope_sha256": self.cycle_scope_sha256,
            "round_index": self.round_index,
            "prior_acquisition_rounds": self.prior_acquisition_rounds,
            "prior_rework_rounds": self.prior_rework_rounds,
            "current_evidence_pack_id": self.current_evidence_pack_id,
            "current_evidence_pack_version": self.current_evidence_pack_version,
            "screening_ref": self.screening_ref.model_dump(mode="json"),
            "violation_type": self.violation_type.value,
            "evidence_class": self.evidence_class.value,
            "role": self.role.value,
            "provider_profile": self.provider_profile,
            "provider": self.provider,
            "model": self.model,
            "revision": self.revision,
            "model_manifest_id": self.model_manifest_id,
            "execution_location": self.execution_location.value,
            "prompt_manifest_id": self.prompt_manifest.prompt_manifest_id,
            "hearing_prompt_bundle_sha256": self.hearing_prompt_bundle_sha256,
            "prompt_template_sha256": self.prompt_manifest.template_sha256,
            "output_schema_sha256": self.prompt_manifest.output_schema_sha256,
            "rendered_prompt_sha256": self.rendered_prompt_sha256,
            "hearing_context_sha256": self.hearing_context_sha256,
            "media": [item.cache_projection() for item in self.media],
            "allowed_evidence_refs": [
                ref.model_dump(mode="json") for ref in self.allowed_evidence_refs
            ],
            "allowed_precedent_refs": [
                ref.model_dump(mode="json") for ref in self.allowed_precedent_refs
            ],
            "prosecutor_output_ref": (
                self.prosecutor_output_ref.model_dump(mode="json")
                if self.prosecutor_output_ref is not None
                else None
            ),
            "defender_output_ref": (
                self.defender_output_ref.model_dump(mode="json")
                if self.defender_output_ref is not None
                else None
            ),
            "precedent_retrieval_degraded": self.precedent_retrieval_degraded,
            "precedent_retrieval_receipt_id": self.precedent_retrieval_receipt_id,
            "precedent_retrieval_receipt_sha256": self.precedent_retrieval_receipt_sha256,
            "initial_trigger_review_ref": (
                self.initial_trigger_review_ref.model_dump(mode="json")
                if self.initial_trigger_review_ref is not None
                else None
            ),
            "initial_defect_codes": [code.value for code in self.initial_defect_codes],
            "rework_review_ref": (
                self.rework_review_ref.model_dump(mode="json")
                if self.rework_review_ref is not None
                else None
            ),
            "rework_defect_codes": [code.value for code in self.rework_defect_codes],
            "original_request_id": self.original_request_id,
            "original_response_id": self.original_response_id,
            "original_response_content_sha256": self.original_response_content_sha256,
            "repair_context_sha256": self.repair_context_sha256,
            "temperature": self.temperature,
            "seed": self.seed,
            "budget": self.budget.model_dump(mode="json"),
            "manifest_id": self.manifest_id,
        }
        if self.backlog_retry_context is not None:
            projection["backlog_retry_context_id"] = self.backlog_retry_context.context_id
        return projection

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_sha256(self) -> Sha256Hex:
        return sha256_hex(["hearing-model-request-document", 1, self.request_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_id(self) -> Sha256Hex:
        return sha256_hex(["hearing-model-request", 1, self.request_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cache_key(self) -> Sha256Hex:
        return sha256_hex(["hearing-model-cache", 1, self.request_projection()])

    @model_validator(mode="after")
    def validate_scope_role_and_budget(self) -> HearingModelRequest:
        if self.round_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("hearing request round index conflicts with its prior-round counters")
        if self.prompt_manifest.role != self.role:
            raise ValueError("hearing request role conflicts with its prompt manifest")
        if self.prompt_manifest.prompt_bundle_sha256 != self.hearing_prompt_bundle_sha256:
            raise ValueError("hearing request prompt manifest conflicts with the M4 prompt bundle")
        if self.screening_ref.kind != ArtifactKind.SCREENING_RESULT:
            raise ValueError("hearing request screening_ref must identify a screening result")
        _stable_refs(
            self.allowed_evidence_refs,
            "hearing allowed evidence refs",
            allowed_kinds=_ROLE_EVIDENCE_KINDS,
        )
        _stable_refs(
            self.allowed_precedent_refs,
            "hearing allowed precedent refs",
            allowed_kinds=frozenset({ArtifactKind.PRECEDENT}),
        )
        for ref in (self.prosecutor_output_ref, self.defender_output_ref):
            if ref is not None and ref.kind != ArtifactKind.PARSED_MODEL_OUTPUT:
                raise ValueError("hearing upstream output ref has an invalid artifact kind")
        if self.role == VlmRole.PROSECUTOR:
            if self.prosecutor_output_ref is not None or self.defender_output_ref is not None:
                raise ValueError("prosecutor request cannot claim upstream role outputs")
        elif self.role == VlmRole.DEFENDER:
            if self.prosecutor_output_ref is None or self.defender_output_ref is not None:
                raise ValueError("defender request requires only its prosecutor output")
        elif self.prosecutor_output_ref is None or self.defender_output_ref is None:
            raise ValueError("Judge request requires both advocate outputs")
        _stable_defect_codes(self.initial_defect_codes, "initial trigger defect codes")
        if (self.initial_trigger_review_ref is None) != (not self.initial_defect_codes):
            raise ValueError("initial trigger review and defect codes are required together")
        if self.initial_trigger_review_ref is not None and (
            self.round_index != 1
            or self.prior_acquisition_rounds != 0
            or self.prior_rework_rounds != 0
            or self.initial_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        ):
            raise ValueError("initial trigger review is allowed only on the first cycle")
        _stable_defect_codes(self.rework_defect_codes, "hearing rework defect codes")
        if self.prior_rework_rounds == 0:
            if self.rework_review_ref is not None or self.rework_defect_codes:
                raise ValueError("initial hearing work cannot claim a rework review")
        elif (
            self.rework_review_ref is None
            or self.rework_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or not self.rework_defect_codes
        ):
            raise ValueError("reworked hearing requests require a review and defect codes")

        media_keys = tuple(item.sort_key for item in self.media)
        if len(media_keys) != len(set(media_keys)) or media_keys != tuple(sorted(media_keys)):
            raise ValueError("hearing media must be unique and use stable order")
        allowed_crop_ids = {
            ref.artifact_id for ref in self.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
        }
        media_crop_ids = {item.crop_id for item in self.media}
        repair_fields = (
            self.original_request_id,
            self.original_response_id,
            self.original_response_content_sha256,
            self.repair_context_sha256,
        )
        if self.attempt_index == 0:
            if any(value is not None for value in repair_fields):
                raise ValueError("primary hearing request cannot claim repair authority")
            if not self.media or allowed_crop_ids != media_crop_ids:
                raise ValueError("primary hearing request media must match its crop whitelist")
            if len(self.media) > self.budget.max_images:
                raise ValueError("hearing request exceeds its image budget")
            pixels = sum(item.width * item.height for item in self.media)
            if pixels > self.budget.max_input_pixels:
                raise ValueError("hearing request exceeds its pixel budget")
        else:
            if any(value is None for value in repair_fields):
                raise ValueError("repair hearing request requires original request and response")
            if self.media or self.budget.max_images != 0 or self.budget.max_input_pixels != 0:
                raise ValueError("hearing structure repair cannot redisclose media")
        for item in self.media:
            if item.local_path != f"{self.run_id}/frames/{item.media_sha256}.png":
                raise ValueError("hearing media lies outside the canonical run media path")
        if self.execution_location == ExecutionLocation.EXTERNAL:
            if any(item.media_access != MediaAccess.CLOUD_ALLOWED for item in self.media):
                raise ValueError("external hearing requests require cloud-allowed media")
            if any(item.source.value == "PANORAMA" for item in self.media):
                raise ValueError("external hearing requests cannot contain panorama crops")
        return self


def derive_hearing_model_response_id(
    run_id: str,
    request_id: str,
    content_sha256: str,
) -> Sha256Hex:
    return sha256_hex(["hearing-model-response", 1, run_id, request_id, content_sha256])


class HearingModelResponse(FrozenContractModel):
    """Raw M4 provider response receipt; arbitrary bytes remain in private storage."""

    schema_version: Literal["m4-hearing-model-response-v1"] = "m4-hearing-model-response-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(ge=0, le=2, strict=True)
    prior_rework_rounds: int = Field(ge=0, le=2, strict=True)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    role: HearingRole
    attempt_index: Literal[0, 1]
    request_id: Sha256Hex
    request_sha256: Sha256Hex
    cache_key: Sha256Hex
    raw_response_ref: str = Field(
        min_length=1,
        json_schema_extra={"pattern": SAFE_RELATIVE_PATH_PATTERN},
    )
    content_sha256: Sha256Hex
    size_bytes: int = Field(ge=0, le=16_777_216, strict=True)
    input_tokens: int = Field(default=0, ge=0, strict=True)
    output_tokens: int = Field(default=0, ge=0, strict=True)
    latency_ms: int = Field(default=0, ge=0, strict=True)
    model_manifest_id: Sha256Hex
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing response reference")

    @field_validator("raw_response_ref")
    @classmethod
    def validate_raw_response_ref(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_response_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "response_id" in payload
        claimed = payload.pop("response_id", None)
        response = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != response.response_id):
            raise ValueError("serialized hearing response ID does not match its content")
        return response

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_id(self) -> Sha256Hex:
        return derive_hearing_model_response_id(
            self.run_id,
            self.request_id,
            self.content_sha256,
        )

    @model_validator(mode="after")
    def validate_response_scope(self) -> HearingModelResponse:
        if self.round_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("hearing response round conflicts with prior-round counters")
        expected = f"{self.run_id}/model_responses/{self.response_id}.json"
        if self.raw_response_ref != expected:
            raise ValueError("hearing response locator is not its canonical run path")
        return self


class HearingUsageReceipt(FrozenContractModel):
    """Exactly-once provider usage evidence; cache/recovery reads create no receipt."""

    schema_version: Literal["m4-hearing-usage-receipt-v1"] = "m4-hearing-usage-receipt-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    role: HearingRole
    request_ref: ArtifactRef
    response_ref: ArtifactRef
    input_images: int = Field(ge=0, le=64, strict=True)
    input_pixels: int = Field(ge=0, le=1_000_000_000, strict=True)
    input_tokens: int = Field(ge=0, strict=True)
    output_tokens: int = Field(ge=0, strict=True)
    latency_ms: int = Field(ge=0, strict=True)
    retry_count: int = Field(ge=0, le=16, strict=True)
    estimated_cost: StrictFloat = Field(ge=0, le=1_000_000)
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing usage receipt reference")

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
        claimed_present = "usage_receipt_id" in payload
        claimed = payload.pop("usage_receipt_id", None)
        receipt = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != receipt.usage_receipt_id
        ):
            raise ValueError("serialized usage receipt ID does not match its content")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def usage_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-usage-receipt",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.round_index,
                self.role.value,
                self.request_ref.model_dump(mode="json"),
                self.response_ref.model_dump(mode="json"),
                self.input_images,
                self.input_pixels,
                self.input_tokens,
                self.output_tokens,
                self.latency_ms,
                self.retry_count,
                self.estimated_cost,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_usage(self) -> HearingUsageReceipt:
        if self.request_ref.kind != ArtifactKind.MODEL_REQUEST:
            raise ValueError("usage request_ref must identify a model request")
        if self.response_ref.kind != ArtifactKind.MODEL_RESPONSE:
            raise ValueError("usage response_ref must identify a model response")
        if (self.input_images == 0) != (self.input_pixels == 0):
            raise ValueError("zero-image usage must have zero pixels and vice versa")
        return self


class HearingModelParseReceipt(FrozenContractModel):
    """Strict parser outcome for one role payload, preserving unknown references."""

    schema_version: Literal["m4-hearing-parse-receipt-v1"] = "m4-hearing-parse-receipt-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    role: HearingRole
    attempt_index: Literal[0, 1]
    request_id: Sha256Hex
    request_sha256: Sha256Hex
    response_id: Sha256Hex
    response_content_sha256: Sha256Hex
    parser_version: ReferenceToken
    output_schema_sha256: Sha256Hex
    status: ModelParseStatus
    defects: tuple[ProceduralDefect, ...] = Field(default=(), max_length=3)
    unknown_reference_attempts: tuple[HearingUnknownReferenceAttempt, ...] = Field(
        default=(),
        max_length=256,
    )
    parsed_payload_sha256: Sha256Hex | None = None
    repair_request_id: Sha256Hex | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "parser_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing parse receipt reference")

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
        claimed_present = "parse_receipt_id" in payload
        claimed = payload.pop("parse_receipt_id", None)
        receipt = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != receipt.parse_receipt_id
        ):
            raise ValueError("serialized hearing parse receipt ID does not match its content")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def parse_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-model-parse-receipt",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.round_index,
                self.role.value,
                self.attempt_index,
                self.request_id,
                self.request_sha256,
                self.response_id,
                self.response_content_sha256,
                self.parser_version,
                self.output_schema_sha256,
                self.status.value,
                [item.defect_id for item in self.defects],
                [item.model_dump(mode="json") for item in self.unknown_reference_attempts],
                self.parsed_payload_sha256,
                self.repair_request_id,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_outcome(self) -> HearingModelParseReceipt:
        defect_keys = tuple(item.sort_key for item in self.defects)
        if len(defect_keys) != len(set(defect_keys)) or defect_keys != tuple(sorted(defect_keys)):
            raise ValueError("hearing parse defects must be unique and use stable order")
        parser_codes = {
            ProceduralDefectCode.MALFORMED_STRUCTURE,
            ProceduralDefectCode.INVALID_ENUM,
            ProceduralDefectCode.MISSING_REQUIRED_FIELD,
        }
        if any(
            item.origin != ProceduralDefectOrigin.PARSER
            or item.code not in parser_codes
            or item.artifact_ref.artifact_id != self.response_id
            for item in self.defects
        ):
            raise ValueError("hearing parse defects must target this model response")
        attempt_keys = tuple(item.sort_key for item in self.unknown_reference_attempts)
        if len(attempt_keys) != len(set(attempt_keys)) or attempt_keys != tuple(
            sorted(attempt_keys)
        ):
            raise ValueError("unknown reference attempts must be unique and use stable order")
        if self.status == ModelParseStatus.PARSED:
            if (
                self.defects
                or self.parsed_payload_sha256 is None
                or self.repair_request_id is not None
            ):
                raise ValueError("parsed hearing receipt requires only its payload hash")
        elif self.status == ModelParseStatus.REPAIR_REQUIRED:
            if (
                self.attempt_index != 0
                or not self.defects
                or self.parsed_payload_sha256 is not None
                or self.repair_request_id is None
            ):
                raise ValueError("repair-required hearing receipt has an invalid field matrix")
        elif (
            self.attempt_index != 1
            or not self.defects
            or self.parsed_payload_sha256 is not None
            or self.repair_request_id is not None
        ):
            raise ValueError("invalid-final hearing receipt has an invalid field matrix")
        return self


def _validate_hearing_call_closure(
    request: HearingModelRequest,
    response: HearingModelResponse,
    parse_receipt: HearingModelParseReceipt,
) -> None:
    """Validate one exact request/response/strict-parse closure."""

    if (
        response.run_id != request.run_id
        or response.case_id != request.case_id
        or response.hearing_session_id != request.hearing_session_id
        or response.round_index != request.round_index
        or response.prior_acquisition_rounds != request.prior_acquisition_rounds
        or response.prior_rework_rounds != request.prior_rework_rounds
        or response.current_evidence_pack_id != request.current_evidence_pack_id
        or response.current_evidence_pack_version != request.current_evidence_pack_version
        or response.role != request.role
        or response.attempt_index != request.attempt_index
        or response.request_id != request.request_id
        or response.request_sha256 != request.request_sha256
        or response.cache_key != request.cache_key
        or response.model_manifest_id != request.model_manifest_id
        or response.manifest_id != request.manifest_id
    ):
        raise ValueError("hearing response conflicts with its exact request")
    if (
        parse_receipt.run_id != request.run_id
        or parse_receipt.case_id != request.case_id
        or parse_receipt.hearing_session_id != request.hearing_session_id
        or parse_receipt.round_index != request.round_index
        or parse_receipt.role != request.role
        or parse_receipt.attempt_index != request.attempt_index
        or parse_receipt.request_id != request.request_id
        or parse_receipt.request_sha256 != request.request_sha256
        or parse_receipt.response_id != response.response_id
        or parse_receipt.response_content_sha256 != response.content_sha256
        or parse_receipt.output_schema_sha256 != request.prompt_manifest.output_schema_sha256
        or parse_receipt.manifest_id != request.manifest_id
    ):
        raise ValueError("hearing parse receipt conflicts with its exact call")


def _request_matches_lease_generation(
    request: HearingModelRequest,
    lease: BacklogLeaseIdentity,
) -> bool:
    """Generation zero reuses the original request; later generations are explicit."""

    context = request.backlog_retry_context
    if lease.retry_generation == 0:
        return context is None and request.run_id == lease.run_id
    return (
        context is not None
        and request.run_id == lease.run_id
        and context.backlog_item_id == lease.item_id
        and context.retry_generation == lease.retry_generation
    )


class HearingStrictParseFailureAttempt(FrozenContractModel):
    """One fully persisted strict parse failure for a hearing retry."""

    schema_version: Literal["m4-hearing-strict-parse-attempt-v1"] = (
        "m4-hearing-strict-parse-attempt-v1"
    )
    request: HearingModelRequest
    response: HearingModelResponse
    parse_receipt: HearingModelParseReceipt

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_attempt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "attempt_id" in payload
        claimed = payload.pop("attempt_id", None)
        attempt = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != attempt.attempt_id):
            raise ValueError("serialized hearing strict-failure attempt ID conflicts")
        return attempt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def attempt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-strict-parse-failure-attempt",
                1,
                self.request.request_id,
                self.request.request_sha256,
                self.response.response_id,
                self.response.content_sha256,
                self.parse_receipt.parse_receipt_id,
            ]
        )

    @model_validator(mode="after")
    def validate_attempt(self) -> HearingStrictParseFailureAttempt:
        _validate_hearing_call_closure(self.request, self.response, self.parse_receipt)
        expected_status = (
            ModelParseStatus.REPAIR_REQUIRED
            if self.request.attempt_index == 0
            else ModelParseStatus.INVALID_FINAL
        )
        if self.parse_receipt.status != expected_status:
            raise ValueError("hearing strict-failure attempt has the wrong parse status")
        return self


def _validate_hearing_strict_failure_pair(
    attempts: tuple[HearingStrictParseFailureAttempt, ...],
    role: HearingRole,
) -> None:
    """Require one exact primary/repair pair without assigning retry authority."""

    primary, repair = attempts
    if (
        primary.request.attempt_index != 0
        or repair.request.attempt_index != 1
        or primary.request.role != role
        or repair.request.role != role
    ):
        raise ValueError("hearing strict-failure proof requires primary then same-role repair")
    primary_request = primary.request
    repair_request = repair.request
    same_scope = (
        "run_id",
        "case_id",
        "hearing_session_id",
        "round_index",
        "prior_acquisition_rounds",
        "prior_rework_rounds",
        "current_evidence_pack_id",
        "current_evidence_pack_version",
        "screening_ref",
        "violation_type",
        "evidence_class",
        "role",
        "model_manifest_id",
        "hearing_prompt_bundle_sha256",
        "allowed_evidence_refs",
        "allowed_precedent_refs",
        "prosecutor_output_ref",
        "defender_output_ref",
        "precedent_retrieval_receipt_id",
        "precedent_retrieval_receipt_sha256",
        "manifest_id",
    )
    if any(getattr(primary_request, name) != getattr(repair_request, name) for name in same_scope):
        raise ValueError("hearing repair request changed the primary call scope")
    if (
        primary.parse_receipt.repair_request_id != repair_request.request_id
        or repair_request.original_request_id != primary_request.request_id
        or repair_request.original_response_id != primary.response.response_id
        or repair_request.original_response_content_sha256 != primary.response.content_sha256
    ):
        raise ValueError("hearing repair request lacks exact primary failure authority")


class HearingInitialStrictParseFailureProof(FrozenContractModel):
    """Two initial strict failures authorizing generation one backlog work.

    This proof deliberately has no lease: it closes the original role call in
    the same transaction that creates its immutable HEARING backlog item.  A
    later strict failure while processing a lease uses
    :class:`HearingStrictParseFailureProof` instead.
    """

    schema_version: Literal["m4-hearing-initial-strict-parse-failure-proof-v1"] = (
        "m4-hearing-initial-strict-parse-failure-proof-v1"
    )
    backlog_item_id: Sha256Hex
    source_checkpoint_id: Sha256Hex
    source_checkpoint_sha256: Sha256Hex
    source_checkpoint_version: int = Field(gt=0, strict=True)
    role: HearingRole
    attempts: tuple[HearingStrictParseFailureAttempt, ...] = Field(
        min_length=2,
        max_length=2,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_proof_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "proof_id" in payload
        claimed = payload.pop("proof_id", None)
        proof = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != proof.proof_id):
            raise ValueError("serialized initial hearing strict-failure proof ID conflicts")
        return proof

    @computed_field  # type: ignore[prop-decorator]
    @property
    def proof_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-initial-strict-parse-failure-proof",
                1,
                self.backlog_item_id,
                self.source_checkpoint_id,
                self.source_checkpoint_sha256,
                self.source_checkpoint_version,
                self.role.value,
                [attempt.attempt_id for attempt in self.attempts],
            ]
        )

    @model_validator(mode="after")
    def validate_complete_failure(self) -> HearingInitialStrictParseFailureProof:
        _validate_hearing_strict_failure_pair(self.attempts, self.role)
        if any(attempt.request.backlog_retry_context is not None for attempt in self.attempts):
            raise ValueError("initial hearing strict-failure proof cannot use retry requests")
        return self


class HearingStrictParseFailureProof(FrozenContractModel):
    """Exactly two failed parses authorizing one M4 retry generation advance."""

    schema_version: Literal["m4-hearing-strict-parse-failure-proof-v1"] = (
        "m4-hearing-strict-parse-failure-proof-v1"
    )
    lease: BacklogLeaseIdentity
    source_checkpoint_id: Sha256Hex
    source_checkpoint_sha256: Sha256Hex
    source_checkpoint_version: int = Field(gt=0, strict=True)
    role: HearingRole
    attempts: tuple[HearingStrictParseFailureAttempt, ...] = Field(
        min_length=2,
        max_length=2,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_proof_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "proof_id" in payload
        claimed = payload.pop("proof_id", None)
        proof = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != proof.proof_id):
            raise ValueError("serialized hearing strict-failure proof ID conflicts")
        return proof

    @computed_field  # type: ignore[prop-decorator]
    @property
    def proof_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-strict-parse-failure-proof",
                1,
                self.lease.lease_identity_sha256,
                self.source_checkpoint_id,
                self.source_checkpoint_sha256,
                self.source_checkpoint_version,
                self.role.value,
                [attempt.attempt_id for attempt in self.attempts],
            ]
        )

    @model_validator(mode="after")
    def validate_complete_failure(self) -> HearingStrictParseFailureProof:
        _validate_hearing_strict_failure_pair(self.attempts, self.role)
        if any(
            not _request_matches_lease_generation(attempt.request, self.lease)
            for attempt in self.attempts
        ):
            raise ValueError("hearing strict-failure proof belongs to another lease generation")
        return self


class HearingModelCallFailureAuthority(FrozenContractModel):
    """Durable retry authority for a known M4 provider-boundary outcome."""

    schema_version: Literal["m4-hearing-model-call-failure-authority-v1"] = (
        "m4-hearing-model-call-failure-authority-v1"
    )
    authority_version: Literal[1] = 1
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    role: HearingRole
    request: HearingModelRequest
    source_checkpoint_id: Sha256Hex
    source_checkpoint_sha256: Sha256Hex
    source_checkpoint_version: int = Field(gt=0, strict=True)
    lease: BacklogLeaseIdentity | None = None
    claim_owner_sha256: Sha256Hex
    claim_lease_expires_at: datetime
    claim_takeover_count: int = Field(ge=0, strict=True)
    failure_code: VLMProviderFailureCode
    delivery_certainty: Literal[
        VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        VLMDeliveryCertainty.COMPLETED,
    ]
    provider_response_content_sha256: Sha256Hex | None = None
    reserved_images: int = Field(ge=0, le=64, strict=True)
    reserved_pixels: int = Field(ge=0, le=1_000_000_000, strict=True)
    disclosed_images: int = Field(ge=0, le=64, strict=True)
    disclosed_pixels: int = Field(ge=0, le=1_000_000_000, strict=True)
    input_tokens: int = Field(ge=0, strict=True)
    output_tokens: int = Field(ge=0, strict=True)
    latency_ms: int = Field(ge=0, strict=True)
    estimated_cost: StrictFloat = Field(ge=0, le=1_000_000)
    backlog_reason_code: BacklogReasonCode
    backlog_item_id: Sha256Hex
    backlog_version: int = Field(gt=0, strict=True)
    backlog_status: Literal[BacklogStatus.PENDING, BacklogStatus.EXHAUSTED]
    backlog_attempt_count: int = Field(ge=0, strict=True)
    retry_generation: int = Field(ge=0, strict=True)
    closure_kind: ModelCallFailureClosureKind
    completion_receipt_id: Sha256Hex | None = None
    closure_case_revision: int = Field(gt=0, strict=True)
    closure_audit_sequence: int = Field(ge=0, strict=True)
    closure_audit_entry_hash: Sha256Hex
    manifest_id: Sha256Hex
    recorded_at: datetime

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing failure authority reference")

    @field_validator("claim_lease_expires_at", "recorded_at")
    @classmethod
    def validate_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("hearing failure authority timestamps must be timezone-aware UTC")
        if value.utcoffset() != timedelta(0):
            raise ValueError("hearing failure authority timestamps must use UTC")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        names = ("request_document_sha256", "authority_id")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        authority = handler(payload)
        for name in names:
            if present[name] and (
                not isinstance(claimed[name], str) or claimed[name] != getattr(authority, name)
            ):
                raise ValueError(f"serialized hearing failure {name} conflicts with content")
        return authority

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_document_sha256(self) -> Sha256Hex:
        return sha256_hex(
            ["hearing-failed-call-request-document", 1, self.request.model_dump(mode="json")]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-model-call-failure-authority",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.role.value,
                self.request_document_sha256,
                self.source_checkpoint_id,
                self.source_checkpoint_sha256,
                self.source_checkpoint_version,
                (self.lease.lease_identity_sha256 if self.lease is not None else None),
                self.claim_owner_sha256,
                self.claim_lease_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                self.claim_takeover_count,
                self.failure_code.value,
                self.delivery_certainty.value,
                self.provider_response_content_sha256,
                self.reserved_images,
                self.reserved_pixels,
                self.disclosed_images,
                self.disclosed_pixels,
                self.input_tokens,
                self.output_tokens,
                self.latency_ms,
                self.estimated_cost,
                self.backlog_reason_code.value,
                self.backlog_item_id,
                self.backlog_version,
                self.backlog_status.value,
                self.backlog_attempt_count,
                self.retry_generation,
                self.closure_kind.value,
                self.completion_receipt_id,
                self.closure_case_revision,
                self.closure_audit_sequence,
                self.closure_audit_entry_hash,
                self.manifest_id,
                self.recorded_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ]
        )

    @model_validator(mode="after")
    def validate_failure_authority(self) -> HearingModelCallFailureAuthority:
        context = self.request.backlog_retry_context
        if (
            self.request.run_id != self.run_id
            or self.request.case_id != self.case_id
            or self.request.hearing_session_id != self.hearing_session_id
            or self.request.role != self.role
            or self.request.manifest_id != self.manifest_id
        ):
            raise ValueError("hearing failure authority conflicts with request scope")
        expected_reserved_images = len(self.request.media)
        expected_reserved_pixels = sum(item.width * item.height for item in self.request.media)
        if (
            self.reserved_images != expected_reserved_images
            or self.reserved_pixels != expected_reserved_pixels
        ):
            raise ValueError("hearing failure authority reservation conflicts with request media")
        definitely_not_sent = {
            VLMProviderFailureCode.FIXTURE_MISSING,
            VLMProviderFailureCode.PROVIDER_OUTAGE,
            VLMProviderFailureCode.PROVIDER_TIMEOUT,
            VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH,
            VLMProviderFailureCode.PROMPT_MISSING,
            VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE,
            VLMProviderFailureCode.MEDIA_POLICY_REJECTED,
            VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE,
        }
        completed = {
            VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID,
            VLMProviderFailureCode.RESPONSE_TOO_LARGE,
            VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
            VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
            VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE,
        }
        if (
            self.failure_code in definitely_not_sent
            and self.delivery_certainty != VLMDeliveryCertainty.DEFINITELY_NOT_SENT
        ) or (
            self.failure_code in completed
            and self.delivery_certainty != VLMDeliveryCertainty.COMPLETED
        ):
            raise ValueError("hearing failure code conflicts with delivery certainty")
        if self.failure_code not in definitely_not_sent | completed:
            raise ValueError("unknown delivery cannot grant hearing retry authority")
        metrics = (
            self.disclosed_images,
            self.disclosed_pixels,
            self.input_tokens,
            self.output_tokens,
            self.latency_ms,
            self.estimated_cost,
        )
        if self.delivery_certainty == VLMDeliveryCertainty.DEFINITELY_NOT_SENT:
            if self.provider_response_content_sha256 is not None or any(metrics):
                raise ValueError("definitely-not-sent failure cannot claim disclosure or usage")
        elif (
            self.provider_response_content_sha256 is None
            or self.disclosed_images != len(self.request.media)
            or self.disclosed_pixels != sum(item.width * item.height for item in self.request.media)
        ):
            raise ValueError("completed failed call must account its exact media disclosure")
        expected_reason = (
            BacklogReasonCode.PROVIDER_UNAVAILABLE
            if self.failure_code
            in {
                VLMProviderFailureCode.FIXTURE_MISSING,
                VLMProviderFailureCode.PROVIDER_OUTAGE,
                VLMProviderFailureCode.PROVIDER_TIMEOUT,
            }
            else BacklogReasonCode.BUDGET_EXCEEDED
            if self.failure_code
            in {
                VLMProviderFailureCode.RESPONSE_TOO_LARGE,
                VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
                VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
            }
            else BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
        )
        if self.backlog_reason_code != expected_reason:
            raise ValueError("hearing failure code conflicts with backlog reason")
        if self.closure_kind == ModelCallFailureClosureKind.INITIAL_BACKLOG:
            if (
                context is not None
                or self.lease is not None
                or self.backlog_version != 1
                or self.backlog_status != BacklogStatus.PENDING
                or self.backlog_attempt_count != 0
                or self.retry_generation != 0
                or self.completion_receipt_id is not None
            ):
                raise ValueError("initial hearing failure closure has retry-only fields")
        else:
            lease = self.lease
            if (
                lease is None
                or lease.run_id != self.run_id
                or lease.item_id != self.backlog_item_id
                or lease.attempt_count != self.backlog_attempt_count
                or lease.retry_generation != self.retry_generation
                or not _request_matches_lease_generation(self.request, lease)
                or self.completion_receipt_id is None
            ):
                raise ValueError("retry hearing failure lacks exact lease-generation authority")
        return self


class HearingModelCacheEntry(FrozenContractModel):
    """Run/case/session-scoped immutable cache binding for one hearing call."""

    schema_version: Literal["m4-hearing-cache-entry-v1"] = "m4-hearing-cache-entry-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    role: HearingRole
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    cache_key: Sha256Hex
    request_id: Sha256Hex
    request_sha256: Sha256Hex
    response_id: Sha256Hex
    response_content_sha256: Sha256Hex
    model_manifest_id: Sha256Hex
    prompt_manifest_id: Sha256Hex
    output_schema_sha256: Sha256Hex
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing cache reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_cache_entry_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "cache_entry_id" in payload
        claimed = payload.pop("cache_entry_id", None)
        entry = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != entry.cache_entry_id):
            raise ValueError("serialized hearing cache ID does not match its binding")
        return entry

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cache_entry_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-model-cache-entry",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.round_index,
                self.role.value,
                self.current_evidence_pack_id,
                self.current_evidence_pack_version,
                self.cache_key,
                self.request_id,
                self.request_sha256,
                self.response_id,
                self.response_content_sha256,
                self.model_manifest_id,
                self.prompt_manifest_id,
                self.output_schema_sha256,
                self.manifest_id,
            ]
        )


class HearingRoleOutput(FrozenContractModel):
    """Authoritative scope wrapped around one strictly parsed role payload."""

    schema_version: Literal["m4-hearing-role-output-v1"] = "m4-hearing-role-output-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(ge=0, le=2, strict=True)
    prior_rework_rounds: int = Field(ge=0, le=2, strict=True)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    prompt_manifest: PromptManifest
    model_manifest_id: Sha256Hex
    request_ref: ArtifactRef
    response_ref: ArtifactRef
    parse_receipt_ref: ArtifactRef
    prosecutor_output_id: Sha256Hex | None = None
    defender_output_id: Sha256Hex | None = None
    precedent_retrieval_degraded: StrictBool
    precedent_retrieval_receipt_id: Sha256Hex
    precedent_retrieval_receipt_sha256: Sha256Hex
    initial_trigger_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    rework_review_ref: ArtifactRef | None = None
    rework_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    payload: HearingModelPayload
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing role output reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        output_present = "output_id" in payload
        role_present = "role" in payload
        claimed_output = payload.pop("output_id", None)
        claimed_role = payload.pop("role", None)
        output = handler(payload)
        if output_present and (
            not isinstance(claimed_output, str) or claimed_output != output.output_id
        ):
            raise ValueError("serialized hearing output ID does not match its content")
        claimed_role_value = (
            claimed_role.value if isinstance(claimed_role, VlmRole) else claimed_role
        )
        if role_present and claimed_role_value != output.role.value:
            raise ValueError("serialized hearing output role conflicts with its payload")
        return output

    @computed_field  # type: ignore[prop-decorator]
    @property
    def role(self) -> VlmRole:
        return self.payload.role

    def output_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "hearing_session_id": self.hearing_session_id,
            "round_index": self.round_index,
            "prior_acquisition_rounds": self.prior_acquisition_rounds,
            "prior_rework_rounds": self.prior_rework_rounds,
            "current_evidence_pack_id": self.current_evidence_pack_id,
            "current_evidence_pack_version": self.current_evidence_pack_version,
            "role": self.role.value,
            "prompt_manifest_id": self.prompt_manifest.prompt_manifest_id,
            "model_manifest_id": self.model_manifest_id,
            "request_ref": self.request_ref.model_dump(mode="json"),
            "response_ref": self.response_ref.model_dump(mode="json"),
            "parse_receipt_ref": self.parse_receipt_ref.model_dump(mode="json"),
            "prosecutor_output_id": self.prosecutor_output_id,
            "defender_output_id": self.defender_output_id,
            "precedent_retrieval_degraded": self.precedent_retrieval_degraded,
            "precedent_retrieval_receipt_id": self.precedent_retrieval_receipt_id,
            "precedent_retrieval_receipt_sha256": self.precedent_retrieval_receipt_sha256,
            "initial_trigger_review_ref": (
                self.initial_trigger_review_ref.model_dump(mode="json")
                if self.initial_trigger_review_ref is not None
                else None
            ),
            "initial_defect_codes": [code.value for code in self.initial_defect_codes],
            "rework_review_ref": (
                self.rework_review_ref.model_dump(mode="json")
                if self.rework_review_ref is not None
                else None
            ),
            "rework_defect_codes": [code.value for code in self.rework_defect_codes],
            "payload_sha256": self.payload.payload_sha256,
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def output_id(self) -> Sha256Hex:
        return sha256_hex(["hearing-role-output", 1, self.output_projection()])

    @model_validator(mode="after")
    def validate_role_binding(self) -> HearingRoleOutput:
        if self.round_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("hearing output round conflicts with prior-round counters")
        if self.prompt_manifest.role != self.role:
            raise ValueError("hearing output role conflicts with its prompt manifest")
        _stable_defect_codes(self.initial_defect_codes, "initial output trigger defect codes")
        if (self.initial_trigger_review_ref is None) != (not self.initial_defect_codes):
            raise ValueError("initial output trigger review and defects are required together")
        if self.initial_trigger_review_ref is not None and (
            self.round_index != 1
            or self.prior_acquisition_rounds != 0
            or self.prior_rework_rounds != 0
            or self.initial_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        ):
            raise ValueError("initial output trigger is allowed only on the first cycle")
        _stable_defect_codes(self.rework_defect_codes, "output rework defect codes")
        if self.prior_rework_rounds == 0:
            if self.rework_review_ref is not None or self.rework_defect_codes:
                raise ValueError("non-rework output cannot claim a rework review")
        elif (
            self.rework_review_ref is None
            or self.rework_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or not self.rework_defect_codes
        ):
            raise ValueError("reworked role output requires its review and defect codes")
        expected_kinds = (
            (self.request_ref, ArtifactKind.MODEL_REQUEST),
            (self.response_ref, ArtifactKind.MODEL_RESPONSE),
            (self.parse_receipt_ref, ArtifactKind.MODEL_PARSE_RECEIPT),
        )
        if any(ref.kind != kind for ref, kind in expected_kinds):
            raise ValueError("hearing output request/response/parse reference kind is invalid")
        if self.role == VlmRole.PROSECUTOR:
            if self.prosecutor_output_id is not None or self.defender_output_id is not None:
                raise ValueError("prosecutor output cannot claim upstream role outputs")
        elif self.role == VlmRole.DEFENDER:
            if self.prosecutor_output_id is None or self.defender_output_id is not None:
                raise ValueError("defender output requires only its prosecutor binding")
        elif self.prosecutor_output_id is None or self.defender_output_id is None:
            raise ValueError("judge output requires prosecutor and defender bindings")
        return self
