"""Run-scoped model-call, parse, cache, and deterministic screening contracts."""

from __future__ import annotations

from typing import Annotated, Literal, Self, TypeAlias

from pydantic import (
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.backlog import BacklogRetryContext
from labcourt.contracts.base import FrozenContractModel, Scalar
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    ModelParseStatus,
    PrivacyPolicy,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ScreeningConflictCode,
    ScreeningDecision,
    ViolationType,
    VlmCallPurpose,
    VlmRole,
    WearStatus,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    PromptManifest,
    UnknownReferenceAttempt,
    VlmCallBudget,
    require_bounded_public_text,
)
from labcourt.contracts.metadata import validate_safe_scalar_metadata
from labcourt.contracts.paths import (
    SAFE_RELATIVE_PATH_PATTERN,
    require_safe_relative_posix_path,
)
from labcourt.contracts.references import (
    FrameId,
    ReferenceToken,
    parse_frame_id,
    require_reference_token,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import DEFECT_ORDER, ObjectiveClaim, ProceduralDefect

_PARSER_DEFECT_CODES = frozenset(
    {
        ProceduralDefectCode.MALFORMED_STRUCTURE,
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    }
)
_ALLOWED_MODEL_EVIDENCE_KINDS = frozenset(
    {
        ArtifactKind.CROP,
        ArtifactKind.FRAME,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.TOOL_RESULT,
    }
)
_DEFECT_RANK = {code: rank for rank, code in enumerate(DEFECT_ORDER)}


def _add_retry_generation_identity(
    projection: dict[str, object],
    context: BacklogRetryContext | None,
) -> None:
    """Bind only proven semantic generations, never worker/queue identities.

    Generation zero is deliberately identical to the original invocation.  It
    covers provider interruption and lets the durable claim fence prevent a
    second external call.  A generation advances only after the strict
    two-response parse-failure proof.
    """

    if context is not None and context.retry_generation > 0:
        projection["retry_generation"] = context.retry_generation


def derive_model_response_id(
    run_id: str,
    request_id: str,
    content_sha256: str,
) -> Sha256Hex:
    """Return the stable raw-response identity without using its local locator."""

    return sha256_hex(["model-response", 1, run_id, request_id, content_sha256])


def _require_stable_sha_values(values: tuple[str, ...], name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique")
    if values != tuple(sorted(values)):
        raise ValueError(f"{name} must use stable SHA-256 order")


def _require_stable_frame_values(values: tuple[str, ...], name: str) -> None:
    parsed = tuple(parse_frame_id(value) for value in values)
    if len(parsed) != len(set(parsed)):
        raise ValueError(f"{name} must be unique")
    if parsed != tuple(sorted(parsed)):
        raise ValueError(f"{name} must use stable camera, stream, and frame order")


class FrameObservation(FrozenContractModel):
    """A model-authored label; clarity remains authoritative in EvidencePack."""

    crop_id: Sha256Hex
    wear_status: WearStatus
    reason_summary: str = Field(min_length=1, max_length=512)

    @field_validator("reason_summary")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return require_bounded_public_text(value, "frame observation reason", max_length=512)

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.crop_id, self.wear_status.value


class VLMMediaRef(FrozenContractModel):
    crop_id: Sha256Hex
    media_sha256: Sha256Hex
    local_path: str = Field(
        min_length=1,
        json_schema_extra={"pattern": SAFE_RELATIVE_PATH_PATTERN},
    )
    source: CropSource
    media_access: MediaAccess
    privacy_policy: PrivacyPolicy
    privacy_transform_version: ReferenceToken
    width: int = Field(gt=0, strict=True)
    height: int = Field(gt=0, strict=True)

    @field_validator("local_path")
    @classmethod
    def validate_local_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @field_validator("privacy_transform_version")
    @classmethod
    def validate_transform_version(cls, value: str) -> str:
        return require_reference_token(value, "privacy transform version")

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.crop_id, self.media_sha256

    def cache_projection(self) -> dict[str, object]:
        return {
            "crop_id": self.crop_id,
            "media_sha256": self.media_sha256,
            "source": self.source.value,
            "media_access": self.media_access.value,
            "privacy_policy": self.privacy_policy.value,
            "privacy_transform_version": self.privacy_transform_version,
            "width": self.width,
            "height": self.height,
        }


class VLMRequest(FrozenContractModel):
    """Primary screening call with a derived request identity and cache key."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"execution_location": {"const": "EXTERNAL"}},
                        "required": ["execution_location"],
                    },
                    "then": {
                        "properties": {
                            "media": {
                                "items": {
                                    "properties": {
                                        "media_access": {"const": "CLOUD_ALLOWED"},
                                        "source": {"not": {"const": "PANORAMA"}},
                                    },
                                    "required": ["media_access", "source"],
                                }
                            }
                        }
                    },
                }
            ]
        }
    )

    purpose: Literal[VlmCallPurpose.SCREENING] = VlmCallPurpose.SCREENING
    run_id: ReferenceToken
    case_id: ReferenceToken
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    provider_profile: ReferenceToken
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=128)
    model_manifest_id: Sha256Hex
    execution_location: ExecutionLocation
    role: Literal[VlmRole.SCREENING] = VlmRole.SCREENING
    prompt_manifest: PromptManifest
    rendered_prompt_sha256: Sha256Hex
    violation_type: ViolationType
    evidence_class: EvidenceClass
    rule_summary: str = Field(min_length=1, max_length=2_048)
    media: tuple[VLMMediaRef, ...] = Field(min_length=1)
    allowed_evidence_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    objective_summary: dict[str, Scalar] = Field(default_factory=dict)
    temperature: StrictFloat = Field(ge=0)
    seed: int | None = Field(default=None, strict=True)
    enable_thinking: StrictBool | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    budget: VlmCallBudget
    backlog_retry_context: BacklogRetryContext | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "provider_profile")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "VLM request reference")

    @field_validator("provider", "model", "revision")
    @classmethod
    def validate_provider_text(cls, value: str) -> str:
        return require_bounded_public_text(value, "VLM provider identity", max_length=256)

    @field_validator("rule_summary")
    @classmethod
    def validate_rule_summary(cls, value: str) -> str:
        return require_bounded_public_text(value, "VLM rule summary", max_length=2_048)

    @field_validator("objective_summary")
    @classmethod
    def validate_objective_summary(cls, value: dict[str, Scalar]) -> dict[str, Scalar]:
        validate_safe_scalar_metadata(value)
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
        computed_names = (
            "allowed_crop_ids",
            "request_sha256",
            "request_id",
            "cache_key",
        )
        claims = {name: payload.pop(name, None) for name in computed_names}
        present = {name: name in value for name in computed_names}
        request = handler(payload)
        for name in computed_names:
            if present[name] and (
                not isinstance(claims[name], (str, list, tuple))
                or (
                    tuple(claims[name])
                    if name == "allowed_crop_ids" and isinstance(claims[name], (list, tuple))
                    else claims[name]
                )
                != getattr(request, name)
            ):
                raise ValueError(f"serialized {name} does not match VLM request content")
        return request

    @computed_field  # type: ignore[prop-decorator]
    @property
    def allowed_crop_ids(self) -> tuple[Sha256Hex, ...]:
        return tuple(item.crop_id for item in self.media)

    def request_projection(self) -> dict[str, object]:
        projection: dict[str, object] = {
            "purpose": self.purpose.value,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "evidence_pack_id": self.evidence_pack_id,
            "evidence_pack_version": self.evidence_pack_version,
            "provider_profile": self.provider_profile,
            "provider": self.provider,
            "model": self.model,
            "revision": self.revision,
            "model_manifest_id": self.model_manifest_id,
            "execution_location": self.execution_location.value,
            "role": self.role.value,
            "prompt_manifest_id": self.prompt_manifest.prompt_manifest_id,
            "rendered_prompt_sha256": self.rendered_prompt_sha256,
            "violation_type": self.violation_type.value,
            "evidence_class": self.evidence_class.value,
            "rule_summary": self.rule_summary,
            "media": [item.cache_projection() for item in self.media],
            "allowed_evidence_refs": [
                ref.model_dump(mode="json") for ref in self.allowed_evidence_refs
            ],
            "objective_summary": dict(self.objective_summary),
            "temperature": self.temperature,
            "seed": self.seed,
            "budget": self.budget.model_dump(mode="json"),
            "manifest_id": self.manifest_id,
        }
        if self.enable_thinking is not None:
            projection["enable_thinking"] = self.enable_thinking
        _add_retry_generation_identity(projection, self.backlog_retry_context)
        return projection

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_sha256(self) -> Sha256Hex:
        return sha256_hex(["vlm-request-document", 1, self.request_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_id(self) -> Sha256Hex:
        return sha256_hex(["vlm-request", 1, self.request_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cache_key(self) -> Sha256Hex:
        canonical_text_input = {
            "purpose": self.purpose.value,
            "role": self.role.value,
            "violation_type": self.violation_type.value,
            "evidence_class": self.evidence_class.value,
            "rule_summary": self.rule_summary,
            "objective_summary": dict(self.objective_summary),
            "allowed_evidence_refs": [
                ref.model_dump(mode="json") for ref in self.allowed_evidence_refs
            ],
        }
        cache_projection: dict[str, object] = {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "evidence_pack_id": self.evidence_pack_id,
            "evidence_pack_version": self.evidence_pack_version,
            "manifest_id": self.manifest_id,
            "provider_profile": self.provider_profile,
            "provider": self.provider,
            "model": self.model,
            "revision": self.revision,
            "model_manifest_id": self.model_manifest_id,
            "execution_location": self.execution_location.value,
            "prompt_manifest_id": self.prompt_manifest.prompt_manifest_id,
            "prompt_template_sha256": self.prompt_manifest.template_sha256,
            "rendered_prompt_sha256": self.rendered_prompt_sha256,
            "output_schema_sha256": self.prompt_manifest.output_schema_sha256,
            "ordered_media": [item.cache_projection() for item in self.media],
            "canonical_text_input": canonical_text_input,
            "decoding_parameters": {
                "temperature": self.temperature,
                "seed": self.seed,
            },
            "budget": self.budget.model_dump(mode="json"),
        }
        if self.enable_thinking is not None:
            decoding = cache_projection["decoding_parameters"]
            assert isinstance(decoding, dict)
            decoding["enable_thinking"] = self.enable_thinking
        _add_retry_generation_identity(cache_projection, self.backlog_retry_context)
        return sha256_hex(
            [
                "vlm-cache",
                3,
                cache_projection,
            ]
        )

    @model_validator(mode="after")
    def validate_request_scope_and_budget(self) -> VLMRequest:
        if self.prompt_manifest.role != VlmRole.SCREENING:
            raise ValueError("screening request requires a SCREENING prompt manifest")
        media_keys = tuple(item.sort_key for item in self.media)
        if len(media_keys) != len(set(media_keys)):
            raise ValueError("VLM request media must be unique")
        if media_keys != tuple(sorted(media_keys)):
            raise ValueError("VLM request media must use stable crop order")
        allowed_keys = tuple(ref.sort_key for ref in self.allowed_evidence_refs)
        if len(allowed_keys) != len(set(allowed_keys)):
            raise ValueError("VLM allowed evidence references must be unique")
        if allowed_keys != tuple(sorted(allowed_keys)):
            raise ValueError("VLM allowed evidence references must use stable order")
        if any(ref.kind not in _ALLOWED_MODEL_EVIDENCE_KINDS for ref in self.allowed_evidence_refs):
            raise ValueError("VLM allowed evidence contains a non-citable artifact kind")
        allowed_crop_ids = {
            ref.artifact_id for ref in self.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
        }
        if allowed_crop_ids != set(self.allowed_crop_ids):
            raise ValueError("VLM allowed crop references must exactly match request media")
        if self.budget.max_images <= 0 or len(self.media) > self.budget.max_images:
            raise ValueError("VLM request exceeds its image budget")
        input_pixels = sum(item.width * item.height for item in self.media)
        if self.budget.max_input_pixels <= 0 or input_pixels > self.budget.max_input_pixels:
            raise ValueError("VLM request exceeds its pixel budget")
        for item in self.media:
            expected_path = f"{self.run_id}/frames/{item.media_sha256}.png"
            if item.local_path != expected_path:
                raise ValueError("VLM media locator is outside the canonical run media path")
        if self.execution_location == ExecutionLocation.EXTERNAL:
            if any(item.media_access != MediaAccess.CLOUD_ALLOWED for item in self.media):
                raise ValueError("external VLM requests require cloud-allowed media")
            if any(item.source == CropSource.PANORAMA for item in self.media):
                raise ValueError("external VLM requests cannot contain panorama crops")
        return self


class StructureRepairRequest(FrozenContractModel):
    """The sole media-free structural repair attempt for one failed response."""

    purpose: Literal[VlmCallPurpose.STRUCTURE_REPAIR] = VlmCallPurpose.STRUCTURE_REPAIR
    repair_ordinal: Literal[1] = 1
    run_id: ReferenceToken
    case_id: ReferenceToken
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    provider_profile: ReferenceToken
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=128)
    model_manifest_id: Sha256Hex
    execution_location: ExecutionLocation
    role: Literal[VlmRole.STRUCTURE_REPAIR] = VlmRole.STRUCTURE_REPAIR
    prompt_manifest: PromptManifest
    rendered_prompt_sha256: Sha256Hex
    original_request_id: Sha256Hex
    original_request_sha256: Sha256Hex
    original_backlog_retry_context_id: Sha256Hex | None = None
    original_response_id: Sha256Hex
    original_response_sha256: Sha256Hex
    parse_defect_codes: tuple[ProceduralDefectCode, ...] = Field(min_length=1)
    temperature: StrictFloat = Field(ge=0)
    seed: int | None = Field(default=None, strict=True)
    enable_thinking: StrictBool | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    budget: VlmCallBudget
    backlog_retry_context: BacklogRetryContext | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "provider_profile")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "structure repair reference")

    @field_validator("provider", "model", "revision")
    @classmethod
    def validate_provider_text(cls, value: str) -> str:
        return require_bounded_public_text(value, "VLM provider identity", max_length=256)

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
        computed_names = ("request_sha256", "request_id", "cache_key")
        claims = {name: payload.pop(name, None) for name in computed_names}
        present = {name: name in value for name in computed_names}
        request = handler(payload)
        for name in computed_names:
            if present[name] and (
                not isinstance(claims[name], str) or claims[name] != getattr(request, name)
            ):
                raise ValueError(f"serialized {name} does not match repair request content")
        return request

    def request_projection(self) -> dict[str, object]:
        projection: dict[str, object] = {
            "purpose": self.purpose.value,
            "repair_ordinal": self.repair_ordinal,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "evidence_pack_id": self.evidence_pack_id,
            "evidence_pack_version": self.evidence_pack_version,
            "provider_profile": self.provider_profile,
            "provider": self.provider,
            "model": self.model,
            "revision": self.revision,
            "model_manifest_id": self.model_manifest_id,
            "execution_location": self.execution_location.value,
            "role": self.role.value,
            "prompt_manifest_id": self.prompt_manifest.prompt_manifest_id,
            "rendered_prompt_sha256": self.rendered_prompt_sha256,
            "original_request_id": self.original_request_id,
            "original_request_sha256": self.original_request_sha256,
            "original_response_id": self.original_response_id,
            "original_response_sha256": self.original_response_sha256,
            "parse_defect_codes": [code.value for code in self.parse_defect_codes],
            "temperature": self.temperature,
            "seed": self.seed,
            "budget": self.budget.model_dump(mode="json"),
            "manifest_id": self.manifest_id,
        }
        if self.enable_thinking is not None:
            projection["enable_thinking"] = self.enable_thinking
        _add_retry_generation_identity(projection, self.backlog_retry_context)
        return projection

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_sha256(self) -> Sha256Hex:
        return sha256_hex(["vlm-repair-request-document", 1, self.request_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_id(self) -> Sha256Hex:
        return sha256_hex(["vlm-repair-request", 1, self.request_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cache_key(self) -> Sha256Hex:
        cache_projection: dict[str, object] = {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "evidence_pack_id": self.evidence_pack_id,
            "evidence_pack_version": self.evidence_pack_version,
            "manifest_id": self.manifest_id,
            "purpose": self.purpose.value,
            "provider_profile": self.provider_profile,
            "provider": self.provider,
            "model": self.model,
            "revision": self.revision,
            "model_manifest_id": self.model_manifest_id,
            "execution_location": self.execution_location.value,
            "prompt_manifest_id": self.prompt_manifest.prompt_manifest_id,
            "prompt_template_sha256": self.prompt_manifest.template_sha256,
            "rendered_prompt_sha256": self.rendered_prompt_sha256,
            "output_schema_sha256": self.prompt_manifest.output_schema_sha256,
            "original_request_id": self.original_request_id,
            "original_request_sha256": self.original_request_sha256,
            "original_response_id": self.original_response_id,
            "original_response_sha256": self.original_response_sha256,
            "parse_defect_codes": [code.value for code in self.parse_defect_codes],
            "decoding_parameters": {
                "temperature": self.temperature,
                "seed": self.seed,
            },
            "budget": self.budget.model_dump(mode="json"),
        }
        if self.enable_thinking is not None:
            decoding = cache_projection["decoding_parameters"]
            assert isinstance(decoding, dict)
            decoding["enable_thinking"] = self.enable_thinking
        _add_retry_generation_identity(cache_projection, self.backlog_retry_context)
        return sha256_hex(
            [
                "vlm-cache",
                3,
                cache_projection,
            ]
        )

    @model_validator(mode="after")
    def validate_repair_constraints(self) -> StructureRepairRequest:
        if self.prompt_manifest.role != VlmRole.STRUCTURE_REPAIR:
            raise ValueError("repair request requires a STRUCTURE_REPAIR prompt manifest")
        if self.budget.max_images != 0 or self.budget.max_input_pixels != 0:
            raise ValueError("structure repair cannot carry media or a media budget")
        if len(self.parse_defect_codes) != len(
            set(self.parse_defect_codes)
        ) or self.parse_defect_codes != tuple(
            sorted(self.parse_defect_codes, key=_DEFECT_RANK.__getitem__)
        ):
            raise ValueError("repair parse defects must be unique and use stable order")
        if any(code not in _PARSER_DEFECT_CODES for code in self.parse_defect_codes):
            raise ValueError("structure repair accepts only parser-origin defect codes")
        if self.backlog_retry_context is None:
            if self.original_backlog_retry_context_id is not None:
                raise ValueError(
                    "non-retry structure repair cannot claim an original retry context"
                )
        elif self.original_backlog_retry_context_id != self.backlog_retry_context.context_id:
            raise ValueError(
                "structure repair retry context must match its original request context"
            )
        return self


VLMCallRequest: TypeAlias = Annotated[
    VLMRequest | StructureRepairRequest,
    Field(discriminator="purpose"),
]


class VLMResponse(FrozenContractModel):
    """Persisted raw-response receipt; provider bytes stay in owner-only storage."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    request_id: Sha256Hex
    request_sha256: Sha256Hex
    cache_key: Sha256Hex
    purpose: VlmCallPurpose
    attempt_index: int = Field(ge=0, le=1, strict=True)
    raw_response_ref: str = Field(
        min_length=1,
        json_schema_extra={"pattern": SAFE_RELATIVE_PATH_PATTERN},
    )
    content_sha256: Sha256Hex
    size_bytes: int = Field(ge=0, strict=True)
    input_tokens: int = Field(default=0, ge=0, strict=True)
    output_tokens: int = Field(default=0, ge=0, strict=True)
    latency_ms: int = Field(default=0, ge=0, strict=True)
    model_manifest_id: Sha256Hex
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "VLM response reference")

    @field_validator("raw_response_ref")
    @classmethod
    def validate_raw_response_path(cls, value: str) -> str:
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
            raise ValueError("serialized response_id does not match response content")
        return response

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_id(self) -> Sha256Hex:
        return derive_model_response_id(
            self.run_id,
            self.request_id,
            self.content_sha256,
        )

    @model_validator(mode="after")
    def validate_receipt_scope_and_order(self) -> VLMResponse:
        expected_attempt = 0 if self.purpose == VlmCallPurpose.SCREENING else 1
        if self.attempt_index != expected_attempt:
            raise ValueError("VLM response attempt index conflicts with its call purpose")
        expected_path = f"{self.run_id}/model_responses/{self.response_id}.json"
        if self.raw_response_ref != expected_path:
            raise ValueError("raw response locator is outside its canonical run location")
        return self


class ScreeningModelPayload(FrozenContractModel):
    """Exact provider-authored JSON object, without injected system authority."""

    violation_type: ViolationType
    evidence_class: EvidenceClass
    violation_probability: StrictFloat = Field(ge=0, le=1)
    frame_observations: tuple[FrameObservation, ...] = ()
    evidence_citations: tuple[EvidenceCitation, ...] = ()
    objective_claims: tuple[ObjectiveClaim, ...] = ()
    prosecution_summary: str = Field(min_length=1, max_length=2_048)
    rationale_summary: str = Field(min_length=1, max_length=2_048)

    @field_validator("prosecution_summary", "rationale_summary")
    @classmethod
    def validate_summaries(cls, value: str) -> str:
        return require_bounded_public_text(value, "screening summary", max_length=2_048)

    def semantic_projection(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude_computed_fields=True)

    @property
    def payload_sha256(self) -> Sha256Hex:
        return sha256_hex(["screening-model-payload", 1, self.semantic_projection()])

    @model_validator(mode="after")
    def validate_stable_outputs(self) -> ScreeningModelPayload:
        observation_ids = tuple(item.crop_id for item in self.frame_observations)
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("model frame observations must use each crop at most once")
        if observation_ids != tuple(sorted(observation_ids)):
            raise ValueError("model frame observations must use stable crop order")
        citation_keys = tuple(item.sort_key for item in self.evidence_citations)
        if len(citation_keys) != len(set(citation_keys)):
            raise ValueError("model evidence citations must be unique")
        if citation_keys != tuple(sorted(citation_keys)):
            raise ValueError("model evidence citations must use stable order")
        claim_ids = tuple(claim.claim_id for claim in self.objective_claims)
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("model objective claims must be unique")
        if claim_ids != tuple(sorted(claim_ids)):
            raise ValueError("model objective claims must use stable order")
        return self


class ParsedScreeningOutput(FrozenContractModel):
    """System envelope around one strictly validated model payload."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    request_id: Sha256Hex
    response_id: Sha256Hex
    response_content_sha256: Sha256Hex
    output_schema_sha256: Sha256Hex
    payload: ScreeningModelPayload
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "parsed screening output reference")

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
        computed_names = (
            "model_payload_sha256",
            "parsed_output_id",
            "parsed_output_sha256",
        )
        claimed = {name: payload.pop(name, None) for name in computed_names}
        present = {name: name in value for name in computed_names}
        output = handler(payload)
        for name in computed_names:
            if present[name] and (
                not isinstance(claimed[name], str) or claimed[name] != getattr(output, name)
            ):
                raise ValueError(f"serialized {name} does not match parsed content")
        return output

    @property
    def violation_type(self) -> ViolationType:
        return self.payload.violation_type

    @property
    def evidence_class(self) -> EvidenceClass:
        return self.payload.evidence_class

    @property
    def violation_probability(self) -> float:
        return self.payload.violation_probability

    @property
    def frame_observations(self) -> tuple[FrameObservation, ...]:
        return self.payload.frame_observations

    @property
    def evidence_citations(self) -> tuple[EvidenceCitation, ...]:
        return self.payload.evidence_citations

    @property
    def objective_claims(self) -> tuple[ObjectiveClaim, ...]:
        return self.payload.objective_claims

    @property
    def prosecution_summary(self) -> str:
        return self.payload.prosecution_summary

    @property
    def rationale_summary(self) -> str:
        return self.payload.rationale_summary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def model_payload_sha256(self) -> Sha256Hex:
        return self.payload.payload_sha256

    def output_projection(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "evidence_pack_id": self.evidence_pack_id,
            "evidence_pack_version": self.evidence_pack_version,
            "request_id": self.request_id,
            "response_id": self.response_id,
            "response_content_sha256": self.response_content_sha256,
            "output_schema_sha256": self.output_schema_sha256,
            "payload": self.payload.semantic_projection(),
            "model_payload_sha256": self.model_payload_sha256,
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def parsed_output_sha256(self) -> Sha256Hex:
        return sha256_hex(["parsed-screening-output-document", 1, self.output_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def parsed_output_id(self) -> Sha256Hex:
        return sha256_hex(["parsed-screening-output", 1, self.output_projection()])


class ModelParseReceipt(FrozenContractModel):
    """Bounded parser outcome, separate from raw response and routed screening."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    request_id: Sha256Hex
    request_sha256: Sha256Hex
    response_id: Sha256Hex
    response_content_sha256: Sha256Hex
    attempt_index: int = Field(ge=0, le=1, strict=True)
    parser_version: ReferenceToken
    output_schema_sha256: Sha256Hex
    status: ModelParseStatus
    defects: tuple[ProceduralDefect, ...] = ()
    unknown_reference_attempts: tuple[UnknownReferenceAttempt, ...] = ()
    parsed_output_id: Sha256Hex | None = None
    parsed_output_sha256: Sha256Hex | None = None
    repair_request_id: Sha256Hex | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "parser_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "model parse receipt reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_parse_receipt_id(
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
            raise ValueError("serialized parse_receipt_id does not match parse receipt")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def parse_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "model-parse-receipt",
                1,
                self.run_id,
                self.case_id,
                self.evidence_pack_id,
                self.evidence_pack_version,
                self.request_id,
                self.request_sha256,
                self.response_id,
                self.response_content_sha256,
                self.attempt_index,
                self.parser_version,
                self.output_schema_sha256,
                self.status.value,
                [defect.defect_id for defect in self.defects],
                [attempt.model_dump(mode="json") for attempt in self.unknown_reference_attempts],
                self.parsed_output_id,
                self.parsed_output_sha256,
                self.repair_request_id,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_parse_outcome(self) -> ModelParseReceipt:
        keys = tuple(defect.sort_key for defect in self.defects)
        if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
            raise ValueError("parse defects must be unique and use stable order")
        if any(
            defect.origin != ProceduralDefectOrigin.PARSER
            or defect.code not in _PARSER_DEFECT_CODES
            or defect.artifact_ref.artifact_id != self.response_id
            for defect in self.defects
        ):
            raise ValueError("parse receipt accepts only parser defects for its response")
        attempt_keys = tuple(attempt.sort_key for attempt in self.unknown_reference_attempts)
        if len(attempt_keys) != len(set(attempt_keys)):
            raise ValueError("unknown reference attempts must be unique")
        if attempt_keys != tuple(sorted(attempt_keys)):
            raise ValueError("unknown reference attempts must use stable order")

        parsed_fields = (self.parsed_output_id, self.parsed_output_sha256)
        if self.status == ModelParseStatus.PARSED:
            if self.defects or any(value is None for value in parsed_fields):
                raise ValueError("parsed receipt requires output identity and no parse defects")
            if self.repair_request_id is not None:
                raise ValueError("parsed receipt cannot request structure repair")
        elif self.status == ModelParseStatus.REPAIR_REQUIRED:
            if self.attempt_index != 0 or not self.defects:
                raise ValueError("repair-required receipt needs first-attempt parse defects")
            if any(value is not None for value in parsed_fields) or self.repair_request_id is None:
                raise ValueError("repair-required receipt must bind only its repair request")
        else:
            if self.attempt_index != 1:
                raise ValueError("invalid-final receipt requires the repair attempt")
            if not self.defects or any(value is not None for value in parsed_fields):
                raise ValueError("invalid-final receipt requires defects and no parsed output")
            if self.repair_request_id is not None:
                raise ValueError("invalid-final receipt cannot request another repair")
        return self


class ScreeningResult(FrozenContractModel):
    """Deterministic route over a parsed model output and pack-authoritative clarity."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    version: int = Field(gt=0, strict=True)
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    parsed_output: ParsedScreeningOutput
    low_probability: StrictFloat = Field(ge=0, le=1)
    high_probability: StrictFloat = Field(ge=0, le=1)
    authoritative_evidence_class: EvidenceClass
    authoritative_l1_score: StrictFloat = Field(ge=0, le=1)
    strong_signal_threshold: StrictFloat = Field(ge=0, le=1)
    conflict_policy_version: ReferenceToken
    alleged_interval_crop_ids: tuple[Sha256Hex, ...] = ()
    authoritative_clear_crop_ids: tuple[Sha256Hex, ...] = ()
    correction_frame_ids: tuple[FrameId, ...] = ()
    required_clear_count: int | None = Field(default=None, gt=0, strict=True)
    router_version: ReferenceToken
    manifest_id: Sha256Hex

    @field_validator(
        "run_id",
        "case_id",
        "router_version",
        "conflict_policy_version",
    )
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "screening result reference")

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
        screening_present = "screening_id" in payload
        decision_present = "decision" in payload
        conflicts_present = "conflict_codes" in payload
        claimed_screening_id = payload.pop("screening_id", None)
        claimed_decision = payload.pop("decision", None)
        claimed_conflicts = payload.pop("conflict_codes", None)
        result = handler(payload)
        if screening_present and (
            not isinstance(claimed_screening_id, str) or claimed_screening_id != result.screening_id
        ):
            raise ValueError("serialized screening_id does not match routing content")
        serialized_decision = (
            claimed_decision.value
            if isinstance(claimed_decision, ScreeningDecision)
            else claimed_decision
        )
        if decision_present and serialized_decision != result.decision.value:
            raise ValueError("serialized screening decision conflicts with routing inputs")
        serialized_conflicts = (
            tuple(
                item.value if isinstance(item, ScreeningConflictCode) else item
                for item in claimed_conflicts
            )
            if isinstance(claimed_conflicts, (list, tuple))
            else claimed_conflicts
        )
        if conflicts_present and serialized_conflicts != tuple(
            code.value for code in result.conflict_codes
        ):
            raise ValueError("serialized screening conflicts conflict with routing inputs")
        return result

    def _base_decision(self) -> ScreeningDecision:
        if self.authoritative_evidence_class == EvidenceClass.PRESENCE:
            probability = self.parsed_output.violation_probability
            if probability <= self.low_probability:
                return ScreeningDecision.NOT_ESTABLISHED
            if probability >= self.high_probability:
                return ScreeningDecision.ESTABLISHED
            return ScreeningDecision.ESCALATE

        clear_ids = set(self.authoritative_clear_crop_ids)
        clear_observations = tuple(
            observation
            for observation in self.parsed_output.frame_observations
            if observation.crop_id in clear_ids
        )
        observed_crop_ids = {item.crop_id for item in clear_observations}
        if not clear_observations:
            return ScreeningDecision.ESCALATE
        if any(item.wear_status == WearStatus.WORN for item in clear_observations):
            return ScreeningDecision.NOT_ESTABLISHED
        assert self.required_clear_count is not None
        if (
            observed_crop_ids == clear_ids
            and len(clear_ids) >= self.required_clear_count
            and all(item.wear_status == WearStatus.NOT_WORN for item in clear_observations)
        ):
            return ScreeningDecision.ESTABLISHED
        return ScreeningDecision.ESCALATE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def conflict_codes(self) -> tuple[ScreeningConflictCode, ...]:
        conflicts: list[ScreeningConflictCode] = []
        if self.parsed_output.evidence_class != self.authoritative_evidence_class:
            conflicts.append(ScreeningConflictCode.MODEL_EVIDENCE_CLASS_MISMATCH)
        if (
            self.authoritative_evidence_class == EvidenceClass.PRESENCE
            and self.authoritative_l1_score >= self.strong_signal_threshold
            and self._base_decision() == ScreeningDecision.NOT_ESTABLISHED
        ):
            conflicts.append(ScreeningConflictCode.STRONG_SIGNAL_CONFLICT)
        return tuple(conflicts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def decision(self) -> ScreeningDecision:
        if self.conflict_codes:
            return ScreeningDecision.ESCALATE
        return self._base_decision()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def screening_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "screening-result",
                1,
                self.run_id,
                self.case_id,
                self.version,
                self.evidence_pack_id,
                self.evidence_pack_version,
                self.parsed_output.parsed_output_id,
                self.low_probability,
                self.high_probability,
                self.authoritative_evidence_class.value,
                self.authoritative_l1_score,
                self.strong_signal_threshold,
                self.conflict_policy_version,
                [code.value for code in self.conflict_codes],
                list(self.alleged_interval_crop_ids),
                list(self.authoritative_clear_crop_ids),
                list(self.correction_frame_ids),
                self.required_clear_count,
                self.router_version,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_route_scope_and_inputs(self) -> ScreeningResult:
        if self.low_probability >= self.high_probability:
            raise ValueError("screening low probability must be below high probability")
        if (
            self.parsed_output.run_id != self.run_id
            or self.parsed_output.case_id != self.case_id
            or self.parsed_output.evidence_pack_id != self.evidence_pack_id
            or self.parsed_output.evidence_pack_version != self.evidence_pack_version
            or self.parsed_output.manifest_id != self.manifest_id
        ):
            raise ValueError("screening result and parsed output scope do not match")
        for values, name in (
            (self.alleged_interval_crop_ids, "alleged interval crop IDs"),
            (self.authoritative_clear_crop_ids, "authoritative clear crop IDs"),
        ):
            _require_stable_sha_values(values, name)
        _require_stable_frame_values(self.correction_frame_ids, "correction frame IDs")
        if not set(self.authoritative_clear_crop_ids).issubset(self.alleged_interval_crop_ids):
            raise ValueError("authoritative clear crops must lie in the alleged interval")
        if self.authoritative_evidence_class == EvidenceClass.PRESENCE:
            if (
                self.required_clear_count is not None
                or self.alleged_interval_crop_ids
                or self.authoritative_clear_crop_ids
                or self.correction_frame_ids
            ):
                raise ValueError("presence screening cannot carry absence routing inputs")
        elif self.required_clear_count is None or not self.alleged_interval_crop_ids:
            raise ValueError("absence screening requires interval crops and a clear-count rule")
        return self


class ModelCacheEntry(FrozenContractModel):
    """Run-scoped immutable binding from a request cache key to raw response bytes."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
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
        return require_reference_token(value, "model cache entry reference")

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
            raise ValueError("serialized cache_entry_id does not match cache binding")
        return entry

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cache_entry_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "model-cache-entry",
                1,
                self.run_id,
                self.case_id,
                self.evidence_pack_id,
                self.evidence_pack_version,
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


class CachedModelResponse(FrozenContractModel):
    entry: ModelCacheEntry
    response: VLMResponse

    @model_validator(mode="after")
    def validate_binding(self) -> CachedModelResponse:
        if (
            self.entry.run_id != self.response.run_id
            or self.entry.case_id != self.response.case_id
            or self.entry.evidence_pack_id != self.response.evidence_pack_id
            or self.entry.evidence_pack_version != self.response.evidence_pack_version
            or self.entry.cache_key != self.response.cache_key
            or self.entry.request_id != self.response.request_id
            or self.entry.request_sha256 != self.response.request_sha256
            or self.entry.response_id != self.response.response_id
            or self.entry.response_content_sha256 != self.response.content_sha256
            or self.entry.model_manifest_id != self.response.model_manifest_id
            or self.entry.manifest_id != self.response.manifest_id
        ):
            raise ValueError("cached response conflicts with its cache entry")
        return self


__all__ = [
    "CachedModelResponse",
    "FrameObservation",
    "ModelCacheEntry",
    "ModelParseReceipt",
    "ParsedScreeningOutput",
    "ScreeningModelPayload",
    "ScreeningResult",
    "StructureRepairRequest",
    "VLMCallRequest",
    "VLMMediaRef",
    "VLMRequest",
    "VLMResponse",
    "derive_model_response_id",
]
