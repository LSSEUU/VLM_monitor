"""Additive M8 authority for deterministic pre-hearing evidence routing."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

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
from labcourt.contracts.enums import CaseStatus, EvidenceClass, EvidenceFailureCode
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M8PreHearingPreparationState(StrEnum):
    """Append-only lifecycle of one objective-evidence gate decision."""

    PENDING = "PENDING"
    COMPLETED = "COMPLETED"


class M8PreHearingOutcomeCode(StrEnum):
    """Typed, non-model outcomes produced before an M4 session exists."""

    NO_NOVEL_CLEAR_FRAME = "NO_NOVEL_CLEAR_FRAME"


class M8PreHearingEvidencePreparationV1(FrozenContractModel):
    """Restart-safe authority for an insufficient-observation M3 escalation.

    This contract intentionally represents only the first, objective absence-
    evidence gate.  It cannot represent an M4 role call or a successful
    hearing, which keeps that frozen state machine outside this authority.
    """

    schema_version: Literal["m8-prehearing-preparation-v1"] = "m8-prehearing-preparation-v1"
    revision: int = Field(ge=1, le=2, strict=True)
    run_id: ReferenceToken
    case_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    source_screening_id: Sha256Hex
    source_screening_version: int = Field(gt=0, strict=True)
    source_evidence_pack_id: Sha256Hex
    source_evidence_pack_version: int = Field(gt=0, strict=True)
    manifest_id: Sha256Hex
    evidence_class: Literal[EvidenceClass.ABSENCE] = EvidenceClass.ABSENCE
    candidate_crop_ids: tuple[Sha256Hex, ...]
    clear_crop_ids: tuple[Sha256Hex, ...] = ()
    clear_threshold: StrictFloat = Field(ge=0, le=1)
    required_clear_count: int = Field(gt=0, strict=True)
    selection_policy_version: ReferenceToken
    state: M8PreHearingPreparationState
    outcome_code: M8PreHearingOutcomeCode | None = None
    resulting_case_revision: int | None = Field(default=None, gt=0, strict=True)
    resulting_case_status: Literal[CaseStatus.HUMAN_REVIEW] | None = None
    evidence_failure_code: Literal[EvidenceFailureCode.EVIDENCE_MISSING] | None = None
    hearing_session_absent_at_start: Literal[True] = True
    hearing_role_call_count: Literal[0] = 0

    @field_validator("run_id", "case_id", "selection_policy_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "pre-hearing preparation reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_preparation_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "preparation_id" in payload
        claimed = payload.pop("preparation_id", None)
        preparation = handler(payload)
        if claimed_present and claimed != preparation.preparation_id:
            raise ValueError(
                "serialized preparation_id does not match its immutable source authority"
            )
        return preparation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def preparation_id(self) -> Sha256Hex:
        """Stable identity shared by both append-only revisions."""

        return sha256_hex(
            [
                "m8-prehearing-preparation",
                1,
                self.run_id,
                self.case_id,
                self.source_case_revision,
                self.source_screening_id,
                self.source_screening_version,
                self.source_evidence_pack_id,
                self.source_evidence_pack_version,
                self.manifest_id,
                list(self.candidate_crop_ids),
                list(self.clear_crop_ids),
                self.clear_threshold,
                self.required_clear_count,
                self.selection_policy_version,
            ]
        )

    @model_validator(mode="after")
    def validate_gate_authority(self) -> M8PreHearingEvidencePreparationV1:
        for values, name in (
            (self.candidate_crop_ids, "candidate crop IDs"),
            (self.clear_crop_ids, "clear crop IDs"),
        ):
            if not values:
                if name == "candidate crop IDs":
                    raise ValueError("pre-hearing preparation requires candidate crops")
                continue
            if len(values) != len(set(values)) or values != tuple(sorted(values)):
                raise ValueError(f"{name} must be unique and use stable order")
        if not set(self.clear_crop_ids).issubset(self.candidate_crop_ids):
            raise ValueError("clear crop IDs must be a subset of candidate crop IDs")
        if len(self.clear_crop_ids) >= self.required_clear_count:
            raise ValueError("pre-hearing preparation accepts only insufficient clear evidence")

        terminal_values = (
            self.outcome_code,
            self.resulting_case_revision,
            self.resulting_case_status,
            self.evidence_failure_code,
        )
        if self.state == M8PreHearingPreparationState.PENDING:
            if self.revision != 1 or any(value is not None for value in terminal_values):
                raise ValueError("pending preparation must be revision one without an outcome")
        elif (
            self.revision != 2
            or self.outcome_code != M8PreHearingOutcomeCode.NO_NOVEL_CLEAR_FRAME
            or self.resulting_case_revision != self.source_case_revision + 1
            or self.resulting_case_status != CaseStatus.HUMAN_REVIEW
            or self.evidence_failure_code != EvidenceFailureCode.EVIDENCE_MISSING
        ):
            raise ValueError(
                "completed preparation must bind NO_NOVEL_CLEAR_FRAME to the next "
                "EVIDENCE_MISSING human-review revision"
            )
        return self

    def complete_no_novel_clear_frame(
        self,
        resulting_case_revision: int,
    ) -> M8PreHearingEvidencePreparationV1:
        """Create the sole terminal revision without mutating the pending record."""

        if self.state != M8PreHearingPreparationState.PENDING or self.revision != 1:
            raise ValueError("only a pending preparation can be completed")
        return self.model_copy(
            update={
                "revision": 2,
                "state": M8PreHearingPreparationState.COMPLETED,
                "outcome_code": M8PreHearingOutcomeCode.NO_NOVEL_CLEAR_FRAME,
                "resulting_case_revision": resulting_case_revision,
                "resulting_case_status": CaseStatus.HUMAN_REVIEW,
                "evidence_failure_code": EvidenceFailureCode.EVIDENCE_MISSING,
            }
        )


# Compatibility name retained for the first internal implementation slice.
M8PreHearingPreparationV1 = M8PreHearingEvidencePreparationV1


class M8PreHearingPreparationViewV1(FrozenContractModel):
    """Platform-case projection that keeps the frozen M4 case ID private."""

    schema_version: Literal["m8-prehearing-preparation-view-v1"] = (
        "m8-prehearing-preparation-view-v1"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    preparation_id: Sha256Hex
    source_evidence_pack_id: Sha256Hex
    source_evidence_pack_version: int = Field(gt=0, strict=True)
    candidate_crop_ids: tuple[Sha256Hex, ...]
    clear_crop_ids: tuple[Sha256Hex, ...]
    clear_threshold: StrictFloat = Field(ge=0, le=1)
    required_clear_count: int = Field(gt=0, strict=True)
    state: M8PreHearingPreparationState
    outcome_code: M8PreHearingOutcomeCode | None = None
    evidence_failure_code: Literal[EvidenceFailureCode.EVIDENCE_MISSING] | None = None
    hearing_role_call_count: Literal[0] = 0

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_view_references(cls, value: str) -> str:
        return require_reference_token(value, "pre-hearing view reference")

    @classmethod
    def project(
        cls,
        preparation: M8PreHearingPreparationV1,
        *,
        platform_case_id: str,
    ) -> M8PreHearingPreparationViewV1:
        return cls(
            run_id=preparation.run_id,
            case_id=platform_case_id,
            preparation_id=preparation.preparation_id,
            source_evidence_pack_id=preparation.source_evidence_pack_id,
            source_evidence_pack_version=preparation.source_evidence_pack_version,
            candidate_crop_ids=preparation.candidate_crop_ids,
            clear_crop_ids=preparation.clear_crop_ids,
            clear_threshold=preparation.clear_threshold,
            required_clear_count=preparation.required_clear_count,
            state=preparation.state,
            outcome_code=preparation.outcome_code,
            evidence_failure_code=preparation.evidence_failure_code,
            hearing_role_call_count=preparation.hearing_role_call_count,
        )


__all__ = [
    "M8PreHearingEvidencePreparationV1",
    "M8PreHearingOutcomeCode",
    "M8PreHearingPreparationState",
    "M8PreHearingPreparationV1",
    "M8PreHearingPreparationViewV1",
]
