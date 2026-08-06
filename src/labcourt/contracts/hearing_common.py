"""M4 role calls, bounded acquisition tools, and auditable hearing records.

Model-authored payloads stay separate from the run/case authority that wraps
them.  The contracts deliberately validate only syntax and structural binding;
existence of cited evidence, precedents, and tool artifacts remains an L5 gate.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self, TypeAlias

from pydantic import (
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
    AcquisitionAction,
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    ProceduralDefectCode,
    UnknownReferenceNamespace,
    VerdictDecision,
    VlmRole,
)
from labcourt.contracts.evidence import (
    AcquisitionParameters,
    RedetectHighResolutionParameters,
    RequestMoreFramesParameters,
    TrackConfidenceCurveParameters,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    require_bounded_public_text,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import (
    DEFECT_ORDER,
    Argument,
    JudgeResponse,
    ObjectiveClaim,
    ObservationSufficiency,
    PrecedentApplication,
)

MAX_HEARING_ACQUISITION_ROUNDS = 2
MAX_HEARING_REWORK_ROUNDS = 2
MAX_HEARING_JUDGE_CYCLES = 5
MAX_ACQUISITION_FRAME_SPAN = 10_000
MAX_ACQUISITION_RETURNED_FRAMES = 512
MAX_HEARING_PERSISTED_CALLS = 640

HearingRole: TypeAlias = Literal[
    VlmRole.PROSECUTOR,
    VlmRole.DEFENDER,
    VlmRole.JUDGE,
]
_HEARING_ROLES = frozenset({VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE})
_CITABLE_KINDS = frozenset(
    {
        ArtifactKind.CROP,
        ArtifactKind.FRAME,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.TOOL_RESULT,
    }
)
_ROLE_EVIDENCE_KINDS = frozenset(
    {
        ArtifactKind.CROP,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.TOOL_RESULT,
    }
)
_DEFECT_RANK = {code: rank for rank, code in enumerate(DEFECT_ORDER)}


def _stable_refs(
    refs: tuple[ArtifactRef, ...],
    name: str,
    *,
    allowed_kinds: frozenset[ArtifactKind] | None = None,
) -> None:
    keys = tuple(ref.sort_key for ref in refs)
    if len(keys) != len(set(keys)):
        raise ValueError(f"{name} must be unique")
    if keys != tuple(sorted(keys)):
        raise ValueError(f"{name} must use stable artifact order")
    if allowed_kinds is not None and any(ref.kind not in allowed_kinds for ref in refs):
        raise ValueError(f"{name} contains an unauthorized artifact kind")


def _stable_sha(values: tuple[str, ...], name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique")
    if values != tuple(sorted(values)):
        raise ValueError(f"{name} must use stable SHA-256 order")


def _stable_arguments(
    arguments: tuple[Argument, ...],
    stance: ArgumentStance,
    name: str,
) -> None:
    if any(argument.stance != stance for argument in arguments):
        raise ValueError(f"{name} contains the wrong argument stance")
    ids = tuple(argument.argument_id for argument in arguments)
    if len(ids) != len(set(ids)):
        raise ValueError(f"{name} must be unique")
    if ids != tuple(sorted(ids)):
        raise ValueError(f"{name} must use stable argument-ID order")


def _stable_defect_codes(codes: tuple[ProceduralDefectCode, ...], name: str) -> None:
    if len(codes) != len(set(codes)):
        raise ValueError(f"{name} must be unique")
    if codes != tuple(sorted(codes, key=_DEFECT_RANK.__getitem__)):
        raise ValueError(f"{name} must use procedural taxonomy order")


def derive_m4_tool_result_id(
    action: AcquisitionAction,
    input_refs: tuple[ArtifactRef, ...],
    output_refs: tuple[ArtifactRef, ...],
    validated_parameters: AcquisitionParameters,
    execution_manifest_id: Sha256Hex,
) -> Sha256Hex:
    """Derive the content address required for a ToolResult used by M4."""

    return sha256_hex(
        [
            "m4-tool-result",
            1,
            action.value,
            [ref.model_dump(mode="json") for ref in input_refs],
            [ref.model_dump(mode="json") for ref in output_refs],
            validated_parameters.model_dump(mode="json"),
            execution_manifest_id,
        ]
    )


def derive_hearing_session_id(
    run_id: str,
    case_id: str,
    screening_id: str,
    initial_evidence_pack_id: str,
    initial_evidence_pack_version: int,
    manifest_id: str,
    *,
    entry_status: str = "ESCALATED",
    initial_trigger_review_id: str | None = None,
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = (),
    acquisition_round_limit: int = MAX_HEARING_ACQUISITION_ROUNDS,
    rework_round_limit: int = MAX_HEARING_REWORK_ROUNDS,
    max_total_images: int = 20,
    max_total_output_tokens: int = 6_000,
    hearing_prompt_bundle_sha256: str = "0" * 64,
    prosecutor_model_manifest_id: str = "0" * 64,
    defender_model_manifest_id: str = "0" * 64,
    judge_model_manifest_id: str = "0" * 64,
) -> Sha256Hex:
    """Derive the stable session scope before its first role request exists."""

    return sha256_hex(
        [
            "hearing-session",
            1,
            run_id,
            case_id,
            screening_id,
            initial_evidence_pack_id,
            initial_evidence_pack_version,
            entry_status,
            initial_trigger_review_id,
            [code.value for code in initial_defect_codes],
            acquisition_round_limit,
            rework_round_limit,
            max_total_images,
            max_total_output_tokens,
            hearing_prompt_bundle_sha256,
            prosecutor_model_manifest_id,
            defender_model_manifest_id,
            judge_model_manifest_id,
            manifest_id,
        ]
    )


def _hearing_cycle_scope_projection(
    *,
    run_id: str,
    case_id: str,
    hearing_session_id: str,
    cycle_index: int,
    prior_acquisition_rounds: int,
    prior_rework_rounds: int,
    cycle_evidence_pack_id: str,
    cycle_evidence_pack_version: int,
    initial_trigger_review_ref: ArtifactRef | None,
    initial_defect_codes: tuple[ProceduralDefectCode, ...],
    rework_review_ref: ArtifactRef | None,
    rework_defect_codes: tuple[ProceduralDefectCode, ...],
    manifest_id: str,
) -> dict[str, object]:
    return {
        "schema_version": "m4-hearing-cycle-scope-v1",
        "run_id": run_id,
        "case_id": case_id,
        "hearing_session_id": hearing_session_id,
        "cycle_index": cycle_index,
        "prior_acquisition_rounds": prior_acquisition_rounds,
        "prior_rework_rounds": prior_rework_rounds,
        "cycle_evidence_pack_id": cycle_evidence_pack_id,
        "cycle_evidence_pack_version": cycle_evidence_pack_version,
        "initial_trigger_review_ref": (
            initial_trigger_review_ref.model_dump(mode="json")
            if initial_trigger_review_ref is not None
            else None
        ),
        "initial_defect_codes": [code.value for code in initial_defect_codes],
        "rework_review_ref": (
            rework_review_ref.model_dump(mode="json") if rework_review_ref is not None else None
        ),
        "rework_defect_codes": [code.value for code in rework_defect_codes],
        "manifest_id": manifest_id,
    }


def _hearing_cycle_scope_id(projection: dict[str, object]) -> Sha256Hex:
    return sha256_hex(["hearing-cycle-scope", 1, projection])


def _hearing_cycle_scope_sha256(projection: dict[str, object]) -> Sha256Hex:
    return sha256_hex(
        [
            "hearing-cycle-scope-document",
            1,
            _hearing_cycle_scope_id(projection),
            projection,
        ]
    )


class _RolePayloadBase(FrozenContractModel):
    IDENTITY_TAG: ClassVar[str]
    role: VlmRole

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_payload_sha256(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "payload_sha256" in payload
        claimed = payload.pop("payload_sha256", None)
        result = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != result.payload_sha256):
            raise ValueError("serialized role payload hash does not match its content")
        return result

    def semantic_projection(self) -> dict[str, object]:
        return self.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def payload_sha256(self) -> Sha256Hex:
        return sha256_hex([self.IDENTITY_TAG, 1, self.semantic_projection()])


class ProsecutorModelPayload(_RolePayloadBase):
    """Strict provider payload for the prosecution role."""

    IDENTITY_TAG: ClassVar[str] = "prosecutor-model-payload"
    schema_version: Literal["m4-prosecutor-payload-v1"] = "m4-prosecutor-payload-v1"
    role: Literal[VlmRole.PROSECUTOR] = VlmRole.PROSECUTOR
    arguments: tuple[Argument, ...] = Field(min_length=1, max_length=32)
    case_summary: str = Field(min_length=1, max_length=2_048)

    @field_validator("case_summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return require_bounded_public_text(value, "prosecutor summary", max_length=2_048)

    @model_validator(mode="after")
    def validate_payload(self) -> ProsecutorModelPayload:
        _stable_arguments(self.arguments, ArgumentStance.PROSECUTION, "prosecution arguments")
        if any(not argument.evidence_refs for argument in self.arguments):
            raise ValueError("every prosecution argument must cite typed evidence")
        return self


class DefenderModelPayload(_RolePayloadBase):
    """Strict provider payload for the defense role."""

    IDENTITY_TAG: ClassVar[str] = "defender-model-payload"
    schema_version: Literal["m4-defender-payload-v1"] = "m4-defender-payload-v1"
    role: Literal[VlmRole.DEFENDER] = VlmRole.DEFENDER
    arguments: tuple[Argument, ...] = Field(min_length=1, max_length=32)
    case_summary: str = Field(min_length=1, max_length=2_048)

    @field_validator("case_summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return require_bounded_public_text(value, "defender summary", max_length=2_048)

    @model_validator(mode="after")
    def validate_payload(self) -> DefenderModelPayload:
        _stable_arguments(self.arguments, ArgumentStance.DEFENSE, "defense arguments")
        return self


class AcquisitionRequestPayload(FrozenContractModel):
    """Model-authored, non-authoritative proposal for one whitelisted tool action."""

    action: AcquisitionAction
    validated_parameters: AcquisitionParameters
    reason_summary: str = Field(min_length=1, max_length=1_024)
    supporting_evidence_refs: tuple[ArtifactRef, ...] = Field(default=(), max_length=32)

    @field_validator("reason_summary")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return require_bounded_public_text(value, "acquisition reason", max_length=1_024)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_payload_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "request_payload_id" in payload
        claimed = payload.pop("request_payload_id", None)
        request = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != request.request_payload_id
        ):
            raise ValueError("serialized acquisition payload ID does not match its content")
        return request

    @computed_field  # type: ignore[prop-decorator]
    @property
    def request_payload_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "acquisition-request-payload",
                1,
                self.action.value,
                self.validated_parameters.model_dump(mode="json"),
                self.reason_summary,
                [ref.model_dump(mode="json") for ref in self.supporting_evidence_refs],
            ]
        )

    @model_validator(mode="after")
    def validate_action_and_bounds(self) -> AcquisitionRequestPayload:
        if self.action != self.validated_parameters.action:
            raise ValueError("acquisition action must match its typed parameters")
        _stable_refs(
            self.supporting_evidence_refs,
            "acquisition supporting evidence refs",
            allowed_kinds=_CITABLE_KINDS,
        )
        parameters = self.validated_parameters
        if isinstance(parameters, RequestMoreFramesParameters):
            span = parameters.end_frame_exclusive - parameters.start_frame
            returned = (span + parameters.step - 1) // parameters.step
            if span > MAX_ACQUISITION_FRAME_SPAN or returned > MAX_ACQUISITION_RETURNED_FRAMES:
                raise ValueError("request-more-frames exceeds the bounded frame budget")
        elif isinstance(parameters, TrackConfidenceCurveParameters):
            if parameters.end_frame_exclusive - parameters.start_frame > MAX_ACQUISITION_FRAME_SPAN:
                raise ValueError("track-confidence request exceeds the bounded frame span")
        elif isinstance(parameters, RedetectHighResolutionParameters):
            prompts = parameters.prompts
            if len(prompts) != len(set(prompts)) or prompts != tuple(sorted(prompts)):
                raise ValueError("redetection prompts must be unique and use stable order")
            for prompt in prompts:
                require_bounded_public_text(prompt, "redetection prompt", max_length=128)
        return self


class JudgeFinalDecisionPayload(FrozenContractModel):
    outcome_type: Literal["FINAL"] = "FINAL"
    decision: VerdictDecision
    confidence: StrictFloat = Field(ge=0, le=1)
    recommended_alert_level: AlertLevel
    rationale_summary: str = Field(min_length=1, max_length=2_048)
    evidence_citations: tuple[EvidenceCitation, ...] = Field(default=(), max_length=64)
    objective_claims: tuple[ObjectiveClaim, ...] = Field(default=(), max_length=32)
    observation_sufficiency: ObservationSufficiency | None = None

    @field_validator("rationale_summary")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        return require_bounded_public_text(value, "judge rationale", max_length=2_048)

    @model_validator(mode="after")
    def validate_stable_content(self) -> JudgeFinalDecisionPayload:
        citation_keys = tuple(item.sort_key for item in self.evidence_citations)
        if len(citation_keys) != len(set(citation_keys)) or citation_keys != tuple(
            sorted(citation_keys)
        ):
            raise ValueError("judge evidence citations must be unique and use stable order")
        claim_ids = tuple(item.claim_id for item in self.objective_claims)
        _stable_sha(claim_ids, "judge objective claims")
        return self


class JudgeAcquisitionDecisionPayload(FrozenContractModel):
    outcome_type: Literal["ACQUISITION"] = "ACQUISITION"
    request: AcquisitionRequestPayload


JudgeDecisionPayload: TypeAlias = Annotated[
    JudgeFinalDecisionPayload | JudgeAcquisitionDecisionPayload,
    Field(discriminator="outcome_type"),
]


class JudgeModelPayload(_RolePayloadBase):
    """Strict Judge output: one final decision or exactly one acquisition request."""

    IDENTITY_TAG: ClassVar[str] = "judge-model-payload"
    schema_version: Literal["m4-judge-payload-v1"] = "m4-judge-payload-v1"
    role: Literal[VlmRole.JUDGE] = VlmRole.JUDGE
    judge_responses: tuple[JudgeResponse, ...] = Field(default=(), max_length=32)
    precedent_applications: tuple[PrecedentApplication, ...] = Field(default=(), max_length=16)
    outcome: JudgeDecisionPayload

    @model_validator(mode="after")
    def validate_payload(self) -> JudgeModelPayload:
        response_keys = tuple(item.sort_key for item in self.judge_responses)
        response_ids = tuple(item.response_id for item in self.judge_responses)
        if len(response_ids) != len(set(response_ids)) or response_keys != tuple(
            sorted(response_keys)
        ):
            raise ValueError("judge responses must be unique and use stable order")
        application_keys = tuple(item.sort_key for item in self.precedent_applications)
        if len(application_keys) != len(set(application_keys)) or application_keys != tuple(
            sorted(application_keys)
        ):
            raise ValueError("judge precedent applications must be unique and use stable order")
        return self


class HearingCycleScope(FrozenContractModel):
    """Immutable authority persisted when one logical Judge cycle begins."""

    schema_version: Literal["m4-hearing-cycle-scope-v1"] = "m4-hearing-cycle-scope-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    cycle_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(
        ge=0,
        le=MAX_HEARING_ACQUISITION_ROUNDS,
        strict=True,
    )
    prior_rework_rounds: int = Field(ge=0, le=MAX_HEARING_REWORK_ROUNDS, strict=True)
    cycle_evidence_pack_id: Sha256Hex
    cycle_evidence_pack_version: int = Field(gt=0, strict=True)
    initial_trigger_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    rework_review_ref: ArtifactRef | None = None
    rework_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing cycle reference")

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
        names = ("cycle_id", "cycle_sha256")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        scope = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(scope, name):
                raise ValueError(f"serialized {name} conflicts with hearing cycle scope")
        return scope

    def cycle_scope_projection(self) -> dict[str, object]:
        return _hearing_cycle_scope_projection(
            run_id=self.run_id,
            case_id=self.case_id,
            hearing_session_id=self.hearing_session_id,
            cycle_index=self.cycle_index,
            prior_acquisition_rounds=self.prior_acquisition_rounds,
            prior_rework_rounds=self.prior_rework_rounds,
            cycle_evidence_pack_id=self.cycle_evidence_pack_id,
            cycle_evidence_pack_version=self.cycle_evidence_pack_version,
            initial_trigger_review_ref=self.initial_trigger_review_ref,
            initial_defect_codes=self.initial_defect_codes,
            rework_review_ref=self.rework_review_ref,
            rework_defect_codes=self.rework_defect_codes,
            manifest_id=self.manifest_id,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cycle_id(self) -> Sha256Hex:
        return _hearing_cycle_scope_id(self.cycle_scope_projection())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cycle_sha256(self) -> Sha256Hex:
        return _hearing_cycle_scope_sha256(self.cycle_scope_projection())

    @model_validator(mode="after")
    def validate_cycle_trigger(self) -> HearingCycleScope:
        if self.cycle_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("hearing cycle index conflicts with its prior-round counters")
        _stable_defect_codes(self.initial_defect_codes, "hearing cycle initial defects")
        if (self.initial_trigger_review_ref is None) != (not self.initial_defect_codes):
            raise ValueError("hearing cycle initial review and defects are required together")
        if self.initial_trigger_review_ref is not None and (
            self.cycle_index != 1
            or self.initial_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        ):
            raise ValueError("initial review may trigger only the first hearing cycle")
        _stable_defect_codes(self.rework_defect_codes, "hearing cycle rework defects")
        if self.prior_rework_rounds == 0:
            if self.rework_review_ref is not None or self.rework_defect_codes:
                raise ValueError("non-rework hearing cycle cannot claim a rework trigger")
        elif (
            self.rework_review_ref is None
            or self.rework_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or not self.rework_defect_codes
        ):
            raise ValueError("rework hearing cycle requires its failed review and defects")
        return self


class HearingUnknownReferenceSource(StrEnum):
    ARGUMENT_EVIDENCE_REF = "ARGUMENT_EVIDENCE_REF"
    JUDGE_RESPONSE_EVIDENCE_REF = "JUDGE_RESPONSE_EVIDENCE_REF"
    JUDGE_CITATION_REF = "JUDGE_CITATION_REF"
    OBJECTIVE_CLAIM_EVIDENCE_REF = "OBJECTIVE_CLAIM_EVIDENCE_REF"
    OBSERVATION_CROP_ID = "OBSERVATION_CROP_ID"
    PRECEDENT_APPLICATION_ID = "PRECEDENT_APPLICATION_ID"
    PRECEDENT_FACT_DIFFERENCE_REF = "PRECEDENT_FACT_DIFFERENCE_REF"
    ACQUISITION_SUPPORTING_EVIDENCE_REF = "ACQUISITION_SUPPORTING_EVIDENCE_REF"
    ACQUISITION_PARAMETER_FRAME_ID = "ACQUISITION_PARAMETER_FRAME_ID"
    ACQUISITION_PARAMETER_CROP_ID = "ACQUISITION_PARAMETER_CROP_ID"


_HEARING_PRECEDENT_REFERENCE_SOURCES = frozenset(
    {HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID}
)


class HearingUnknownReferenceAttempt(FrozenContractModel):
    """Non-sensitive proof that one M4 role emitted a non-whitelisted reference."""

    namespace: UnknownReferenceNamespace
    source: HearingUnknownReferenceSource
    value_sha256: Sha256Hex

    @model_validator(mode="after")
    def validate_namespace_source(self) -> HearingUnknownReferenceAttempt:
        is_precedent_source = self.source in _HEARING_PRECEDENT_REFERENCE_SOURCES
        if (self.namespace == UnknownReferenceNamespace.PRECEDENT) != is_precedent_source:
            raise ValueError("hearing unknown-reference namespace conflicts with its source")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.namespace.value, self.source.value, self.value_sha256
