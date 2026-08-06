"""Shared M3 prompt, budget, reference-diagnostic, and citation contracts."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    EvidenceClass,
    PrecedentLookupStatus,
    PrecedentStatus,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.precedents import Precedent
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

PROMPT_MANIFEST_VERSION: Literal["m3-prompt-v1"] = "m3-prompt-v1"

_EVIDENCE_REFERENCE_SOURCES = frozenset(
    {
        UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID,
        UnknownReferenceSource.EVIDENCE_CITATION_REF,
        UnknownReferenceSource.ARGUMENT_EVIDENCE_REF,
        UnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF,
        UnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
    }
)
_CITABLE_ARTIFACT_KINDS = frozenset(
    {
        ArtifactKind.CROP,
        ArtifactKind.FRAME,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.TOOL_RESULT,
    }
)


def require_bounded_public_text(value: str, name: str, *, max_length: int) -> str:
    """Require bounded printable text without normalizing model-authored content."""

    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value or len(value) > max_length:
        raise ValueError(f"{name} must contain 1 through {max_length} characters")
    if value != value.strip() or not value.isprintable():
        raise ValueError(f"{name} must be trimmed printable text")
    return value


class PromptManifest(FrozenContractModel):
    """Immutable prompt-template authority bound to the existing run prompt bundle."""

    schema_version: Literal["m3-prompt-v1"] = PROMPT_MANIFEST_VERSION
    prompt_id: ReferenceToken
    role: VlmRole
    template_sha256: Sha256Hex
    output_schema_sha256: Sha256Hex
    prompt_bundle_sha256: Sha256Hex
    renderer: Literal["JINJA2_STRICT"] = "JINJA2_STRICT"
    renderer_version: ReferenceToken

    @field_validator("prompt_id", "renderer_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "prompt manifest reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_prompt_manifest_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "prompt_manifest_id" in payload
        claimed = payload.pop("prompt_manifest_id", None)
        manifest = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != manifest.prompt_manifest_id
        ):
            raise ValueError("serialized prompt_manifest_id does not match prompt manifest content")
        return manifest

    @computed_field  # type: ignore[prop-decorator]
    @property
    def prompt_manifest_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "prompt-manifest",
                1,
                self.model_dump(mode="json", exclude={"prompt_manifest_id"}),
            ]
        )


class VlmCallBudget(FrozenContractModel):
    """Hard per-call limits included in request identity and cache binding."""

    max_images: int = Field(ge=0, le=64, strict=True)
    max_input_pixels: int = Field(ge=0, le=1_000_000_000, strict=True)
    max_prompt_bytes: int = Field(
        default=524_288,
        gt=0,
        le=1_048_576,
        strict=True,
    )
    max_input_tokens: int = Field(
        default=32_768,
        gt=0,
        le=262_144,
        strict=True,
    )
    max_output_tokens: int = Field(gt=0, le=1_000_000, strict=True)
    pricing_currency: Literal["USD"]
    input_cost_per_million_tokens: StrictFloat = Field(
        ge=0,
        le=1_000_000,
    )
    output_cost_per_million_tokens: StrictFloat = Field(
        ge=0,
        le=1_000_000,
    )
    max_estimated_cost: StrictFloat = Field(ge=0, le=1_000_000)
    max_response_bytes: int = Field(gt=0, le=16_777_216, strict=True)
    max_json_depth: int = Field(gt=0, le=64, strict=True)
    max_json_fields: int = Field(gt=0, le=10_000, strict=True)
    max_string_chars: int = Field(gt=0, le=1_000_000, strict=True)
    timeout_seconds: StrictFloat = Field(gt=0, le=3_600)
    claim_completion_grace_seconds: StrictFloat = Field(default=5.0, gt=0, le=300)

    @property
    def claim_lease_seconds(self) -> float:
        """Bound one durable claim beyond provider timeout for local commit work."""

        return float(self.timeout_seconds + self.claim_completion_grace_seconds)

    @staticmethod
    def _require_token_count(value: int, name: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
        return value

    def _estimated_cost_decimal(self, input_tokens: int, output_tokens: int) -> Decimal:
        checked_input = self._require_token_count(input_tokens, "input_tokens")
        checked_output = self._require_token_count(output_tokens, "output_tokens")
        return (
            Decimal(checked_input) * Decimal(str(self.input_cost_per_million_tokens))
            + Decimal(checked_output) * Decimal(str(self.output_cost_per_million_tokens))
        ) / Decimal(1_000_000)

    def estimate_cost(self, *, input_tokens: int, output_tokens: int) -> float:
        """Price exact provider usage using the immutable request-bound USD rates."""

        return float(self._estimated_cost_decimal(input_tokens, output_tokens))

    def allows_cost(self, *, input_tokens: int, output_tokens: int) -> bool:
        """Return whether exact provider usage stays within this call's USD cap."""

        return self._estimated_cost_decimal(input_tokens, output_tokens) <= Decimal(
            str(self.max_estimated_cost)
        )


class UnknownReferenceAttempt(FrozenContractModel):
    """Non-sensitive evidence that a model emitted a non-whitelisted reference."""

    namespace: UnknownReferenceNamespace
    source: UnknownReferenceSource
    value_sha256: Sha256Hex

    @model_validator(mode="after")
    def validate_namespace_source(self) -> UnknownReferenceAttempt:
        if self.namespace == UnknownReferenceNamespace.EVIDENCE:
            if self.source not in _EVIDENCE_REFERENCE_SOURCES:
                raise ValueError("evidence reference diagnostic uses a precedent source")
        elif self.source != UnknownReferenceSource.PRECEDENT_APPLICATION_ID:
            raise ValueError("precedent reference diagnostic uses an evidence source")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.namespace.value, self.source.value, self.value_sha256


class EvidenceCitation(FrozenContractModel):
    """A typed model citation whose relative geometry is checked later by L5."""

    model_config = ConfigDict(
        json_schema_extra={
            "oneOf": [
                {
                    "not": {
                        "anyOf": [
                            {"required": ["bbox"]},
                            {"required": ["coordinate_space"]},
                        ]
                    }
                },
                {
                    "properties": {
                        "bbox": {"type": "null"},
                        "coordinate_space": {"type": "null"},
                    },
                    "required": ["bbox", "coordinate_space"],
                },
                {
                    "properties": {
                        "bbox": {"not": {"type": "null"}},
                        "coordinate_space": {"const": "CITED_ARTIFACT_PIXELS"},
                        "evidence_ref": {
                            "properties": {
                                "kind": {"enum": ["CROP", "FRAME"]},
                            },
                            "required": ["kind"],
                        },
                    },
                    "required": ["bbox", "coordinate_space", "evidence_ref"],
                },
            ]
        }
    )

    evidence_ref: ArtifactRef
    bbox: BBoxXYXY | None = None
    coordinate_space: Literal["CITED_ARTIFACT_PIXELS"] | None = None

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_citation_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "citation_id" in payload
        claimed = payload.pop("citation_id", None)
        citation = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != citation.citation_id):
            raise ValueError("serialized citation_id does not match citation content")
        return citation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def citation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "evidence-citation",
                1,
                self.evidence_ref.model_dump(mode="json"),
                self.bbox.model_dump(mode="json") if self.bbox is not None else None,
                self.coordinate_space,
            ]
        )

    @model_validator(mode="after")
    def validate_citable_shape(self) -> EvidenceCitation:
        if self.evidence_ref.kind not in _CITABLE_ARTIFACT_KINDS:
            raise ValueError("evidence citation uses a non-citable artifact kind")
        if self.bbox is not None and self.evidence_ref.kind not in {
            ArtifactKind.CROP,
            ArtifactKind.FRAME,
        }:
            raise ValueError("citation coordinates require crop or frame evidence")
        if (self.bbox is None) != (self.coordinate_space is None):
            raise ValueError(
                "citation bbox and CITED_ARTIFACT_PIXELS coordinate space are required together"
            )
        return self

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (*self.evidence_ref.sort_key, self.citation_id)


class PrecedentLookupQuery(FrozenContractModel):
    """One case-scoped, exact precedent resolution request for the M3 gate."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    precedent_id: ReferenceToken
    rule_version: ReferenceToken
    evidence_class: EvidenceClass
    violation_type: ViolationType
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "precedent_id", "rule_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "precedent lookup reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_query_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "query_id" in payload
        claimed = payload.pop("query_id", None)
        query = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != query.query_id):
            raise ValueError("serialized precedent query_id does not match query scope")
        return query

    @computed_field  # type: ignore[prop-decorator]
    @property
    def query_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "precedent-lookup-query",
                1,
                self.run_id,
                self.case_id,
                self.precedent_id,
                self.rule_version,
                self.evidence_class.value,
                self.violation_type.value,
                self.manifest_id,
            ]
        )


class PrecedentResolution(FrozenContractModel):
    """Controlled lookup result that distinguishes absence from invisibility."""

    query: PrecedentLookupQuery
    status: PrecedentLookupStatus
    snapshot: Precedent | None = None
    authoritative_similarity: StrictFloat | None = Field(default=None, ge=-1, le=1)
    lookup_version: ReferenceToken

    @field_validator("lookup_version")
    @classmethod
    def validate_lookup_version(cls, value: str) -> str:
        return require_reference_token(value, "precedent lookup version")

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
        resolution = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != resolution.receipt_id):
            raise ValueError("serialized precedent receipt_id does not match resolution")
        return resolution

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "precedent-resolution",
                1,
                self.query.query_id,
                self.status.value,
                (self.snapshot.model_dump(mode="json") if self.snapshot is not None else None),
                self.authoritative_similarity,
                self.lookup_version,
            ]
        )

    @model_validator(mode="after")
    def validate_resolution_matrix(self) -> PrecedentResolution:
        if self.status == PrecedentLookupStatus.FOUND:
            if self.snapshot is None or self.authoritative_similarity is None:
                raise ValueError("FOUND precedent resolution requires a scored snapshot")
            if (
                self.snapshot.precedent_id != self.query.precedent_id
                or self.snapshot.rule_version != self.query.rule_version
                or self.snapshot.evidence_class != self.query.evidence_class
                or self.snapshot.violation_type != self.query.violation_type
            ):
                raise ValueError("precedent snapshot conflicts with lookup scope")
            if self.snapshot.status != PrecedentStatus.ACTIVE:
                raise ValueError("FOUND precedent resolution requires an active snapshot")
        elif self.snapshot is not None or self.authoritative_similarity is not None:
            raise ValueError("unresolved precedent lookup cannot expose a snapshot or score")
        return self


__all__ = [
    "PROMPT_MANIFEST_VERSION",
    "EvidenceCitation",
    "PrecedentLookupQuery",
    "PrecedentResolution",
    "PromptManifest",
    "UnknownReferenceAttempt",
    "VlmCallBudget",
    "require_bounded_public_text",
]
