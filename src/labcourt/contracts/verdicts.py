"""Auditable verdict and procedural-review contracts without hidden reasoning."""

from __future__ import annotations

import re
from typing import Self

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
    AcquisitionAction,
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    JudgeDisposition,
    ObjectiveFactKind,
    PrecedentApplicationMode,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    VerdictDecision,
    ViolationType,
    WearStatus,
)
from labcourt.contracts.events import (
    OBJECTIVE_VALUE_SCHEMA,
    ObjectiveValue,
    validate_objective_value,
)
from labcourt.contracts.frames import SHA256_PATTERN, Sha256Hex
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    require_bounded_public_text,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

_SHA256 = re.compile(SHA256_PATTERN)
_CITABLE_KINDS = frozenset(
    {
        ArtifactKind.CROP,
        ArtifactKind.FRAME,
        ArtifactKind.OBJECTIVE_FACT,
        ArtifactKind.TOOL_RESULT,
    }
)
_PARSER_DEFECT_CODES = frozenset(
    {
        ProceduralDefectCode.MALFORMED_STRUCTURE,
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    }
)
DEFECT_ORDER: tuple[ProceduralDefectCode, ...] = (
    ProceduralDefectCode.MALFORMED_STRUCTURE,
    ProceduralDefectCode.INVALID_ENUM,
    ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,
    ProceduralDefectCode.INVALID_COORDINATES,
    ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE,
    ProceduralDefectCode.PRECEDENT_DIRECTION_MISMATCH,
    ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON,
    ProceduralDefectCode.ESTABLISHED_WITHOUT_EVIDENCE,
    ProceduralDefectCode.UNANSWERED_DEFENSE_POINT,
    ProceduralDefectCode.CONFIDENCE_ALERT_LEVEL_MISMATCH,
    ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION,
    ProceduralDefectCode.VIOLATION_TYPE_MISMATCH,
    ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION,
)
_DEFECT_RANK = {code: rank for rank, code in enumerate(DEFECT_ORDER)}
_DEFECT_FIELDS = {
    ProceduralDefectCode.MALFORMED_STRUCTURE: ProceduralField.JSON_ROOT,
    ProceduralDefectCode.INVALID_ENUM: ProceduralField.ENUM_VALUE,
    ProceduralDefectCode.MISSING_REQUIRED_FIELD: ProceduralField.REQUIRED_FIELD,
    ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE: (ProceduralField.EVIDENCE_REFERENCE),
    ProceduralDefectCode.INVALID_COORDINATES: ProceduralField.EVIDENCE_COORDINATES,
    ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE: (ProceduralField.PRECEDENT_REFERENCE),
    ProceduralDefectCode.PRECEDENT_DIRECTION_MISMATCH: ProceduralField.PRECEDENT_MODE,
    ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON: (ProceduralField.DISTINGUISHING_REASON),
    ProceduralDefectCode.ESTABLISHED_WITHOUT_EVIDENCE: ProceduralField.EVIDENCE_REFS,
    ProceduralDefectCode.UNANSWERED_DEFENSE_POINT: ProceduralField.DEFENSE_ARGUMENTS,
    ProceduralDefectCode.CONFIDENCE_ALERT_LEVEL_MISMATCH: (ProceduralField.RECOMMENDED_ALERT_LEVEL),
    ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION: (ProceduralField.OBJECTIVE_CLAIMS),
    ProceduralDefectCode.VIOLATION_TYPE_MISMATCH: ProceduralField.VIOLATION_TYPE,
    ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION: (
        ProceduralField.OBSERVATION_SUFFICIENCY
    ),
}
_DEFECT_REASONS = {
    ProceduralDefectCode.MALFORMED_STRUCTURE: frozenset(
        {
            ProceduralReasonCode.MALFORMED_JSON,
            ProceduralReasonCode.ROOT_NOT_OBJECT,
            ProceduralReasonCode.RESPONSE_LIMIT_EXCEEDED,
        }
    ),
    ProceduralDefectCode.INVALID_ENUM: frozenset({ProceduralReasonCode.UNKNOWN_ENUM_VALUE}),
    ProceduralDefectCode.MISSING_REQUIRED_FIELD: frozenset(
        {ProceduralReasonCode.REQUIRED_FIELD_ABSENT}
    ),
    ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE: frozenset(
        {ProceduralReasonCode.REFERENCE_NOT_ALLOWED}
    ),
    ProceduralDefectCode.INVALID_COORDINATES: frozenset(
        {ProceduralReasonCode.COORDINATE_OUTSIDE_EVIDENCE}
    ),
    ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE: frozenset(
        {ProceduralReasonCode.PRECEDENT_NOT_VISIBLE}
    ),
    ProceduralDefectCode.PRECEDENT_DIRECTION_MISMATCH: frozenset(
        {ProceduralReasonCode.PRECEDENT_DIRECTION_CONFLICT}
    ),
    ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON: frozenset(
        {ProceduralReasonCode.DISTINGUISHING_REASON_ABSENT}
    ),
    ProceduralDefectCode.ESTABLISHED_WITHOUT_EVIDENCE: frozenset(
        {ProceduralReasonCode.ESTABLISHED_REQUIRES_SUPPORT}
    ),
    ProceduralDefectCode.UNANSWERED_DEFENSE_POINT: frozenset(
        {ProceduralReasonCode.DEFENSE_RESPONSE_CARDINALITY}
    ),
    ProceduralDefectCode.CONFIDENCE_ALERT_LEVEL_MISMATCH: frozenset(
        {ProceduralReasonCode.ALERT_POLICY_CONFLICT}
    ),
    ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION: frozenset(
        {ProceduralReasonCode.OBJECTIVE_VALUE_CONFLICT}
    ),
    ProceduralDefectCode.VIOLATION_TYPE_MISMATCH: frozenset(
        {ProceduralReasonCode.CASE_VIOLATION_CONFLICT}
    ),
    ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION: frozenset(
        {ProceduralReasonCode.ABSENCE_OBSERVATION_INSUFFICIENT}
    ),
}
_VALUE_HASH_CODES = frozenset(
    {
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
        ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,
        ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE,
        ProceduralDefectCode.UNANSWERED_DEFENSE_POINT,
    }
)
_RELATED_KIND_RULES = {
    ProceduralDefectCode.INVALID_COORDINATES: frozenset({ArtifactKind.CROP, ArtifactKind.FRAME}),
    ProceduralDefectCode.PRECEDENT_DIRECTION_MISMATCH: frozenset({ArtifactKind.PRECEDENT}),
    ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON: frozenset(
        {ArtifactKind.PRECEDENT, ArtifactKind.OBJECTIVE_FACT}
    ),
    ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION: frozenset(
        {ArtifactKind.OBJECTIVE_FACT}
    ),
    ProceduralDefectCode.VIOLATION_TYPE_MISMATCH: frozenset(
        {ArtifactKind.CASE, ArtifactKind.EVENT}
    ),
    ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION: frozenset({ArtifactKind.CROP}),
}


def _require_stable_refs(
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
        raise ValueError(f"{name} uses an unauthorized artifact kind")


class Argument(FrozenContractModel):
    stance: ArgumentStance
    claim: str = Field(min_length=1, max_length=2_048)
    evidence_refs: tuple[ArtifactRef, ...] = ()
    uncertainty: StrictFloat = Field(ge=0, le=1)

    @field_validator("claim")
    @classmethod
    def validate_claim(cls, value: str) -> str:
        return require_bounded_public_text(value, "argument claim", max_length=2_048)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_argument_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "argument_id" in payload
        claimed = payload.pop("argument_id", None)
        argument = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != argument.argument_id):
            raise ValueError("serialized argument_id does not match argument content")
        return argument

    @computed_field  # type: ignore[prop-decorator]
    @property
    def argument_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "verdict-argument",
                1,
                self.stance.value,
                self.claim,
                [ref.model_dump(mode="json") for ref in self.evidence_refs],
                self.uncertainty,
            ]
        )

    @model_validator(mode="after")
    def validate_references(self) -> Argument:
        _require_stable_refs(
            self.evidence_refs,
            "argument evidence_refs",
            allowed_kinds=_CITABLE_KINDS,
        )
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.stance.value, self.argument_id


class JudgeResponse(FrozenContractModel):
    defense_argument_id: Sha256Hex
    disposition: JudgeDisposition
    response_summary: str = Field(min_length=1, max_length=2_048)
    evidence_refs: tuple[ArtifactRef, ...] = ()

    @field_validator("response_summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return require_bounded_public_text(value, "judge response", max_length=2_048)

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
        return sha256_hex(
            [
                "judge-response",
                1,
                self.defense_argument_id,
                self.disposition.value,
                self.response_summary,
                [ref.model_dump(mode="json") for ref in self.evidence_refs],
            ]
        )

    @model_validator(mode="after")
    def validate_references(self) -> JudgeResponse:
        _require_stable_refs(
            self.evidence_refs,
            "judge response evidence_refs",
            allowed_kinds=_CITABLE_KINDS,
        )
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.defense_argument_id, self.response_id


class PrecedentApplication(FrozenContractModel):
    precedent_ref: ArtifactRef
    mode: PrecedentApplicationMode
    similarity_score: StrictFloat = Field(ge=-1, le=1)
    distinguishing_reason: str | None = Field(default=None, max_length=2_048)
    fact_difference_refs: tuple[ArtifactRef, ...] = ()

    @field_validator("distinguishing_reason")
    @classmethod
    def validate_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_bounded_public_text(value, "distinguishing reason", max_length=2_048)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_application_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "application_id" in payload
        claimed = payload.pop("application_id", None)
        application = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != application.application_id
        ):
            raise ValueError("serialized application_id does not match precedent application")
        return application

    @computed_field  # type: ignore[prop-decorator]
    @property
    def application_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "precedent-application",
                1,
                self.precedent_ref.model_dump(mode="json"),
                self.mode.value,
                self.similarity_score,
                self.distinguishing_reason,
                [ref.model_dump(mode="json") for ref in self.fact_difference_refs],
            ]
        )

    @model_validator(mode="after")
    def validate_references(self) -> PrecedentApplication:
        if self.precedent_ref.kind != ArtifactKind.PRECEDENT:
            raise ValueError("precedent application requires a PRECEDENT reference")
        _require_stable_refs(
            self.fact_difference_refs,
            "precedent fact difference refs",
            allowed_kinds=frozenset({ArtifactKind.OBJECTIVE_FACT}),
        )
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.precedent_ref.artifact_id, self.application_id


class AcquisitionLogEntry(FrozenContractModel):
    round_index: int = Field(gt=0, strict=True)
    action: AcquisitionAction
    request_ref: ArtifactRef
    tool_result_ref: ArtifactRef | None = None
    outcome_summary: str = Field(min_length=1, max_length=1_024)

    @field_validator("outcome_summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return require_bounded_public_text(value, "acquisition outcome", max_length=1_024)

    @model_validator(mode="after")
    def validate_ref_kinds(self) -> AcquisitionLogEntry:
        if self.request_ref.kind != ArtifactKind.MODEL_REQUEST:
            raise ValueError("acquisition request_ref must identify a model request")
        if (
            self.tool_result_ref is not None
            and self.tool_result_ref.kind != ArtifactKind.TOOL_RESULT
        ):
            raise ValueError("acquisition tool_result_ref must identify a tool result")
        return self


class ObjectiveClaim(FrozenContractModel):
    model_config = ConfigDict(json_schema_extra=OBJECTIVE_VALUE_SCHEMA)

    kind: ObjectiveFactKind
    value: ObjectiveValue
    evidence_ref: ArtifactRef

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claim_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "claim_id" in payload
        claimed = payload.pop("claim_id", None)
        claim = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != claim.claim_id):
            raise ValueError("serialized claim_id does not match objective claim content")
        return claim

    @computed_field  # type: ignore[prop-decorator]
    @property
    def claim_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "objective-claim",
                1,
                self.kind.value,
                self.value,
                self.evidence_ref.model_dump(mode="json"),
            ]
        )

    @model_validator(mode="after")
    def validate_value_shape(self) -> ObjectiveClaim:
        validate_objective_value(self.kind, self.value)
        if self.evidence_ref.kind != ArtifactKind.OBJECTIVE_FACT:
            raise ValueError("objective claim must reference an objective fact")
        return self


class ObservationLabel(FrozenContractModel):
    crop_id: Sha256Hex
    wear_status: WearStatus

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.crop_id, self.wear_status.value


class ObservationSufficiency(FrozenContractModel):
    clear_threshold: StrictFloat = Field(ge=0, le=1)
    required_clear_count: int = Field(gt=0, strict=True)
    observations: tuple[ObservationLabel, ...] = ()

    @model_validator(mode="after")
    def validate_observation_order(self) -> ObservationSufficiency:
        crop_ids = tuple(item.crop_id for item in self.observations)
        if len(crop_ids) != len(set(crop_ids)):
            raise ValueError("observation sufficiency crop IDs must be unique")
        if crop_ids != tuple(sorted(crop_ids)):
            raise ValueError("observation sufficiency must use stable crop order")
        return self


class ProceduralDefect(FrozenContractModel):
    """One code-specific, non-sensitive parser or gate defect."""

    code: ProceduralDefectCode
    origin: ProceduralDefectOrigin
    reason_code: ProceduralReasonCode
    artifact_ref: ArtifactRef
    field: ProceduralField
    related_refs: tuple[ArtifactRef, ...] = ()
    value_sha256: Sha256Hex | None = None

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_defect_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "defect_id" in payload
        claimed = payload.pop("defect_id", None)
        defect = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != defect.defect_id):
            raise ValueError("serialized defect_id does not match defect context")
        return defect

    @computed_field  # type: ignore[prop-decorator]
    @property
    def defect_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "procedural-defect",
                1,
                self.code.value,
                self.origin.value,
                self.reason_code.value,
                self.artifact_ref.model_dump(mode="json"),
                self.field.value,
                [ref.model_dump(mode="json") for ref in self.related_refs],
                self.value_sha256,
            ]
        )

    @model_validator(mode="after")
    def validate_code_context_matrix(self) -> ProceduralDefect:
        parser_origin = self.code in _PARSER_DEFECT_CODES
        expected_origin = (
            ProceduralDefectOrigin.PARSER
            if parser_origin
            else ProceduralDefectOrigin.PROCEDURAL_GATE
        )
        expected_target_kind = (
            ArtifactKind.MODEL_RESPONSE if parser_origin else ArtifactKind.VERDICT
        )
        if self.origin != expected_origin:
            raise ValueError("procedural defect origin conflicts with its code")
        if (
            self.artifact_ref.kind != expected_target_kind
            or _SHA256.fullmatch(self.artifact_ref.artifact_id) is None
        ):
            raise ValueError("procedural defect target conflicts with its origin")
        if self.field != _DEFECT_FIELDS[self.code]:
            raise ValueError("procedural defect field conflicts with its code")
        if self.reason_code not in _DEFECT_REASONS[self.code]:
            raise ValueError("procedural defect reason conflicts with its code")
        if (self.value_sha256 is not None) != (self.code in _VALUE_HASH_CODES):
            raise ValueError("procedural defect value hash conflicts with its code")

        _require_stable_refs(self.related_refs, "procedural defect related_refs")
        allowed_related = _RELATED_KIND_RULES.get(self.code)
        if allowed_related is None:
            if self.related_refs:
                raise ValueError("procedural defect code cannot carry related refs")
        else:
            if self.code != ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION and (
                not self.related_refs
            ):
                raise ValueError("procedural defect code requires related refs")
            if any(ref.kind not in allowed_related for ref in self.related_refs):
                raise ValueError("procedural defect related ref kind conflicts with its code")
        return self

    @property
    def sort_key(self) -> tuple[int, str, str, str]:
        return (
            _DEFECT_RANK[self.code],
            self.artifact_ref.artifact_id,
            self.field.value,
            self.defect_id,
        )


class ProceduralReview(FrozenContractModel):
    """Independent deterministic review whose passed state cannot be forged."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    version: int = Field(gt=0, strict=True)
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    reviewed_verdict_id: Sha256Hex
    reviewed_verdict_version: int = Field(gt=0, strict=True)
    reviewed_verdict_sha256: Sha256Hex
    gate_version: ReferenceToken
    defects: tuple[ProceduralDefect, ...] = ()
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "gate_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "procedural review reference")

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
        review_id_present = "review_id" in payload
        passed_present = "passed" in payload
        claimed_review_id = payload.pop("review_id", None)
        claimed_passed = payload.pop("passed", None)
        review = handler(payload)
        if review_id_present and (
            not isinstance(claimed_review_id, str) or claimed_review_id != review.review_id
        ):
            raise ValueError("serialized review_id does not match review content")
        if passed_present and (type(claimed_passed) is not bool or claimed_passed != review.passed):
            raise ValueError("serialized procedural review passed conflicts with defects")
        return review

    @computed_field  # type: ignore[prop-decorator]
    @property
    def review_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "procedural-review",
                1,
                self.run_id,
                self.case_id,
                self.version,
                self.evidence_pack_id,
                self.evidence_pack_version,
                self.reviewed_verdict_id,
                self.reviewed_verdict_version,
                self.reviewed_verdict_sha256,
                self.gate_version,
                [defect.defect_id for defect in self.defects],
                self.manifest_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.defects

    @model_validator(mode="after")
    def validate_defects(self) -> ProceduralReview:
        keys = tuple(defect.sort_key for defect in self.defects)
        if len(keys) != len(set(keys)):
            raise ValueError("procedural review defects must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("procedural review defects must use stable order")
        if any(
            defect.origin != ProceduralDefectOrigin.PROCEDURAL_GATE
            or defect.artifact_ref.artifact_id != self.reviewed_verdict_id
            for defect in self.defects
        ):
            raise ValueError("procedural review defects must target its reviewed verdict")
        return self


class Verdict(FrozenContractModel):
    run_id: ReferenceToken
    case_id: ReferenceToken
    version: int = Field(gt=0, strict=True)
    screening_id: Sha256Hex
    violation_type: ViolationType
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    decision: VerdictDecision
    confidence: StrictFloat = Field(ge=0, le=1)
    recommended_alert_level: AlertLevel
    rationale_summary: str = Field(min_length=1, max_length=2_048)
    evidence_citations: tuple[EvidenceCitation, ...] = ()
    prosecution_arguments: tuple[Argument, ...] = ()
    defense_arguments: tuple[Argument, ...] = ()
    judge_responses: tuple[JudgeResponse, ...] = ()
    precedent_applications: tuple[PrecedentApplication, ...] = ()
    acquisition_log: tuple[AcquisitionLogEntry, ...] = ()
    objective_claims: tuple[ObjectiveClaim, ...] = ()
    observation_sufficiency: ObservationSufficiency | None = None
    model_response_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "verdict run or case reference")

    @field_validator("rationale_summary")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        return require_bounded_public_text(value, "verdict rationale", max_length=2_048)

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
        verdict_id_present = "verdict_id" in payload
        input_hash_present = "verdict_input_sha256" in payload
        verdict_hash_present = "verdict_sha256" in payload
        claimed_verdict_id = payload.pop("verdict_id", None)
        claimed_input_hash = payload.pop("verdict_input_sha256", None)
        claimed_verdict_hash = payload.pop("verdict_sha256", None)
        verdict = handler(payload)
        if verdict_id_present and (
            not isinstance(claimed_verdict_id, str) or claimed_verdict_id != verdict.verdict_id
        ):
            raise ValueError("serialized verdict_id does not match verdict content")
        if input_hash_present and (
            not isinstance(claimed_input_hash, str)
            or claimed_input_hash != verdict.verdict_input_sha256
        ):
            raise ValueError("serialized verdict input hash does not match verdict content")
        if verdict_hash_present and (
            not isinstance(claimed_verdict_hash, str)
            or claimed_verdict_hash != verdict.verdict_sha256
        ):
            raise ValueError("serialized verdict hash does not match verdict content")
        return verdict

    def input_projection(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "screening_id": self.screening_id,
            "violation_type": self.violation_type.value,
            "evidence_pack_id": self.evidence_pack_id,
            "evidence_pack_version": self.evidence_pack_version,
            "decision": self.decision.value,
            "confidence": self.confidence,
            "recommended_alert_level": self.recommended_alert_level.value,
            "rationale_summary": self.rationale_summary,
            "evidence_citations": [
                citation.model_dump(mode="json") for citation in self.evidence_citations
            ],
            "prosecution_arguments": [
                argument.model_dump(mode="json") for argument in self.prosecution_arguments
            ],
            "defense_arguments": [
                argument.model_dump(mode="json") for argument in self.defense_arguments
            ],
            "judge_responses": [
                response.model_dump(mode="json") for response in self.judge_responses
            ],
            "precedent_applications": [
                application.model_dump(mode="json") for application in self.precedent_applications
            ],
            "acquisition_log": [entry.model_dump(mode="json") for entry in self.acquisition_log],
            "objective_claims": [claim.model_dump(mode="json") for claim in self.objective_claims],
            "observation_sufficiency": (
                self.observation_sufficiency.model_dump(mode="json")
                if self.observation_sufficiency is not None
                else None
            ),
            "model_response_refs": [
                ref.model_dump(mode="json") for ref in self.model_response_refs
            ],
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict_input_sha256(self) -> Sha256Hex:
        return sha256_hex(["verdict-input", 1, self.input_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "verdict",
                1,
                self.run_id,
                self.case_id,
                self.version,
                self.verdict_input_sha256,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "verdict-document",
                1,
                self.run_id,
                self.case_id,
                self.version,
                self.verdict_id,
                self.verdict_input_sha256,
            ]
        )

    @model_validator(mode="after")
    def validate_stable_nested_content(self) -> Verdict:
        citation_keys = tuple(item.sort_key for item in self.evidence_citations)
        if len(citation_keys) != len(set(citation_keys)):
            raise ValueError("verdict evidence citations must be unique")
        if citation_keys != tuple(sorted(citation_keys)):
            raise ValueError("verdict evidence citations must use stable order")

        for arguments, expected_stance, name in (
            (self.prosecution_arguments, ArgumentStance.PROSECUTION, "prosecution"),
            (self.defense_arguments, ArgumentStance.DEFENSE, "defense"),
        ):
            if any(argument.stance != expected_stance for argument in arguments):
                raise ValueError(f"{name} argument collection has the wrong stance")
            argument_ids = tuple(argument.argument_id for argument in arguments)
            if len(argument_ids) != len(set(argument_ids)):
                raise ValueError(f"{name} arguments must be unique")
            if argument_ids != tuple(sorted(argument_ids)):
                raise ValueError(f"{name} arguments must use stable order")
        all_argument_ids = tuple(
            argument.argument_id for argument in self.prosecution_arguments + self.defense_arguments
        )
        if len(all_argument_ids) != len(set(all_argument_ids)):
            raise ValueError("argument IDs must be unique across a verdict")

        response_keys = tuple(response.sort_key for response in self.judge_responses)
        response_ids = tuple(response.response_id for response in self.judge_responses)
        if len(response_ids) != len(set(response_ids)):
            raise ValueError("judge responses must be unique")
        if response_keys != tuple(sorted(response_keys)):
            raise ValueError("judge responses must use stable order")

        application_keys = tuple(item.sort_key for item in self.precedent_applications)
        if len(application_keys) != len(set(application_keys)):
            raise ValueError("precedent applications must be unique")
        if application_keys != tuple(sorted(application_keys)):
            raise ValueError("precedent applications must use stable order")

        rounds = tuple(entry.round_index for entry in self.acquisition_log)
        if len(rounds) != len(set(rounds)) or rounds != tuple(sorted(rounds)):
            raise ValueError("acquisition rounds must be unique and use stable order")

        claim_ids = tuple(claim.claim_id for claim in self.objective_claims)
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("objective claims must be unique")
        if claim_ids != tuple(sorted(claim_ids)):
            raise ValueError("objective claims must use stable order")

        _require_stable_refs(
            self.model_response_refs,
            "verdict model_response_refs",
            allowed_kinds=frozenset({ArtifactKind.MODEL_RESPONSE}),
        )
        if any(_SHA256.fullmatch(ref.artifact_id) is None for ref in self.model_response_refs):
            raise ValueError("verdict model response references must use response SHA-256 IDs")
        return self


__all__ = [
    "DEFECT_ORDER",
    "AcquisitionLogEntry",
    "Argument",
    "JudgeResponse",
    "ObjectiveClaim",
    "ObservationLabel",
    "ObservationSufficiency",
    "PrecedentApplication",
    "ProceduralDefect",
    "ProceduralReview",
    "Verdict",
]
