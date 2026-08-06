"""M4 role calls, bounded acquisition tools, and auditable hearing records.

Model-authored payloads stay separate from the run/case authority that wraps
them.  The contracts deliberately validate only syntax and structural binding;
existence of cited evidence, precedents, and tool artifacts remains an L5 gate.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self, TypeAlias

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    EvidenceClass,
    PrecedentStatus,
    ProceduralDefectCode,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.hearing_acquisition import (
    AcquisitionRequest,
    ToolExecutionReceipt,
)
from labcourt.contracts.hearing_common import (
    MAX_HEARING_ACQUISITION_ROUNDS,
    MAX_HEARING_JUDGE_CYCLES,
    MAX_HEARING_PERSISTED_CALLS,
    MAX_HEARING_REWORK_ROUNDS,
    HearingCycleScope,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    _hearing_cycle_scope_id,
    _hearing_cycle_scope_projection,
    _hearing_cycle_scope_sha256,
    _stable_defect_codes,
    _stable_refs,
    derive_hearing_session_id,
)
from labcourt.contracts.hearing_model import (
    HearingModelCallFailureAuthority,
    HearingModelRequest,
    HearingRoleOutput,
    HearingUsageReceipt,
)
from labcourt.contracts.precedents import ScoredPrecedent
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef


class HearingPrecedentRetrievalStatus(StrEnum):
    SUCCESS = "SUCCESS"
    DEGRADED = "DEGRADED"


class HearingPrecedentDegradedReason(StrEnum):
    EMBEDDING_PROVIDER_UNAVAILABLE = "EMBEDDING_PROVIDER_UNAVAILABLE"
    EMBEDDING_MODEL_UNAVAILABLE = "EMBEDDING_MODEL_UNAVAILABLE"
    PRECEDENT_INDEX_UNAVAILABLE = "PRECEDENT_INDEX_UNAVAILABLE"


class HearingPrecedentRetrievalReceipt(FrozenContractModel):
    """Auditable visible-set and ranked-result authority for one hearing round."""

    schema_version: Literal["m4-hearing-precedent-retrieval-v1"] = (
        "m4-hearing-precedent-retrieval-v1"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(ge=0, le=2, strict=True)
    prior_rework_rounds: int = Field(ge=0, le=2, strict=True)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    evidence_class: EvidenceClass
    violation_type: ViolationType
    rule_version: ReferenceToken
    top_k: int = Field(ge=0, le=64, strict=True)
    query_sha256: Sha256Hex
    initial_trigger_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    rework_review_ref: ArtifactRef | None = None
    rework_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    candidate_precedent_refs: tuple[ArtifactRef, ...] = Field(default=(), max_length=10_000)
    candidate_snapshot_sha256: Sha256Hex
    visible_precedent_refs: tuple[ArtifactRef, ...] = Field(default=(), max_length=10_000)
    visible_snapshot_sha256: Sha256Hex
    scored_precedents: tuple[ScoredPrecedent, ...] = Field(default=(), max_length=64)
    status: HearingPrecedentRetrievalStatus
    degraded_reason: HearingPrecedentDegradedReason | None = None
    retriever_version: ReferenceToken
    retriever_manifest_id: Sha256Hex
    embedding_model_manifest_id: Sha256Hex | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id", "rule_version", "retriever_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing precedent retrieval reference")

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
            "receipt_id",
            "receipt_sha256",
        )
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        receipt = handler(payload)
        for name in names:
            if present[name] and (
                not isinstance(claimed[name], str) or claimed[name] != getattr(receipt, name)
            ):
                raise ValueError(f"serialized precedent {name} does not match receipt content")
        return receipt

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

    def receipt_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
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
            "evidence_class": self.evidence_class.value,
            "violation_type": self.violation_type.value,
            "rule_version": self.rule_version,
            "top_k": self.top_k,
            "query_sha256": self.query_sha256,
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
            "candidate_precedent_refs": [
                ref.model_dump(mode="json") for ref in self.candidate_precedent_refs
            ],
            "candidate_snapshot_sha256": self.candidate_snapshot_sha256,
            "visible_precedent_refs": [
                ref.model_dump(mode="json") for ref in self.visible_precedent_refs
            ],
            "visible_snapshot_sha256": self.visible_snapshot_sha256,
            "scored_precedents": [item.model_dump(mode="json") for item in self.scored_precedents],
            "status": self.status.value,
            "degraded_reason": (
                self.degraded_reason.value if self.degraded_reason is not None else None
            ),
            "retriever_version": self.retriever_version,
            "retriever_manifest_id": self.retriever_manifest_id,
            "embedding_model_manifest_id": self.embedding_model_manifest_id,
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(["hearing-precedent-retrieval", 1, self.receipt_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_sha256(self) -> Sha256Hex:
        return sha256_hex(
            ["hearing-precedent-retrieval-document", 1, self.receipt_id, self.receipt_projection()]
        )

    @model_validator(mode="after")
    def validate_retrieval(self) -> HearingPrecedentRetrievalReceipt:
        if self.round_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("precedent retrieval round conflicts with prior counters")
        _stable_defect_codes(self.initial_defect_codes, "retrieval initial defect codes")
        _stable_defect_codes(self.rework_defect_codes, "retrieval rework defect codes")
        if (self.initial_trigger_review_ref is None) != (not self.initial_defect_codes):
            raise ValueError("retrieval initial review and defects are required together")
        if self.initial_trigger_review_ref is not None and (
            self.round_index != 1
            or self.initial_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        ):
            raise ValueError("retrieval initial trigger is allowed only on cycle one")
        if self.prior_rework_rounds == 0:
            if self.rework_review_ref is not None or self.rework_defect_codes:
                raise ValueError("non-rework retrieval cannot claim a rework review")
        elif (
            self.rework_review_ref is None
            or self.rework_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or not self.rework_defect_codes
        ):
            raise ValueError("rework retrieval requires its review and defect codes")
        _stable_refs(
            self.candidate_precedent_refs,
            "candidate precedent refs",
            allowed_kinds=frozenset({ArtifactKind.PRECEDENT}),
        )
        _stable_refs(
            self.visible_precedent_refs,
            "visible precedent refs",
            allowed_kinds=frozenset({ArtifactKind.PRECEDENT}),
        )
        candidate_ids = {ref.artifact_id for ref in self.candidate_precedent_refs}
        visible_ids = {ref.artifact_id for ref in self.visible_precedent_refs}
        if not visible_ids.issubset(candidate_ids):
            raise ValueError("visible precedents must be a subset of retrieval candidates")
        result_ids = tuple(item.precedent.precedent_id for item in self.scored_precedents)
        if len(result_ids) != len(set(result_ids)):
            raise ValueError("scored precedents must be unique")
        if len(self.scored_precedents) > self.top_k:
            raise ValueError("scored precedents exceed top_k")
        if any(
            item.precedent.precedent_id not in visible_ids
            or item.precedent.status != PrecedentStatus.ACTIVE
            or item.precedent.rule_version != self.rule_version
            or item.precedent.evidence_class != self.evidence_class
            or item.precedent.violation_type != self.violation_type
            or item.fused_score > 1.25
            for item in self.scored_precedents
        ):
            raise ValueError("scored precedent lies outside the visible active query scope")
        score_keys = tuple(
            (-item.fused_score, item.precedent.precedent_id) for item in self.scored_precedents
        )
        if score_keys != tuple(sorted(score_keys)):
            raise ValueError("scored precedents must use stable (-score, precedent_id) order")
        if self.status == HearingPrecedentRetrievalStatus.SUCCESS:
            if self.degraded_reason is not None or self.embedding_model_manifest_id is None:
                raise ValueError(
                    "successful retrieval requires a model manifest and no degradation"
                )
            if set(result_ids) != visible_ids:
                raise ValueError(
                    "successful retrieval scored precedents must exactly equal its visible set"
                )
        elif self.degraded_reason is None or self.visible_precedent_refs or self.scored_precedents:
            raise ValueError(
                "degraded retrieval requires a reason and no visible or scored results"
            )
        return self


class HearingSessionEntryStatus(StrEnum):
    ESCALATED = "ESCALATED"
    REWORK_REQUIRED = "REWORK_REQUIRED"


class HearingSession(FrozenContractModel):
    """Immutable authority that opens an M4 hearing and fixes all total budgets."""

    schema_version: Literal["m4-hearing-session-v1"] = "m4-hearing-session-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    screening_id: Sha256Hex
    entry_status: HearingSessionEntryStatus
    initial_evidence_pack_id: Sha256Hex
    initial_evidence_pack_version: int = Field(gt=0, strict=True)
    initial_trigger_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    acquisition_round_limit: int = Field(
        default=MAX_HEARING_ACQUISITION_ROUNDS,
        ge=0,
        le=MAX_HEARING_ACQUISITION_ROUNDS,
        strict=True,
    )
    rework_round_limit: int = Field(
        default=MAX_HEARING_REWORK_ROUNDS,
        ge=0,
        le=MAX_HEARING_REWORK_ROUNDS,
        strict=True,
    )
    max_total_images: int = Field(gt=0, le=320, strict=True)
    max_total_output_tokens: int = Field(gt=0, le=1_000_000, strict=True)
    hearing_prompt_bundle_sha256: Sha256Hex
    prosecutor_model_manifest_id: Sha256Hex
    defender_model_manifest_id: Sha256Hex
    judge_model_manifest_id: Sha256Hex
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing session reference")

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
        names = ("max_total_judge_cycles", "session_id", "session_sha256")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        session = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(session, name):
                raise ValueError(f"serialized {name} conflicts with hearing session content")
        return session

    @computed_field  # type: ignore[prop-decorator]
    @property
    def max_total_judge_cycles(self) -> int:
        return 1 + self.acquisition_round_limit + self.rework_round_limit

    @computed_field  # type: ignore[prop-decorator]
    @property
    def session_id(self) -> Sha256Hex:
        return derive_hearing_session_id(
            self.run_id,
            self.case_id,
            self.screening_id,
            self.initial_evidence_pack_id,
            self.initial_evidence_pack_version,
            self.manifest_id,
            entry_status=self.entry_status.value,
            initial_trigger_review_id=(
                self.initial_trigger_review_ref.artifact_id
                if self.initial_trigger_review_ref is not None
                else None
            ),
            initial_defect_codes=self.initial_defect_codes,
            acquisition_round_limit=self.acquisition_round_limit,
            rework_round_limit=self.rework_round_limit,
            max_total_images=self.max_total_images,
            max_total_output_tokens=self.max_total_output_tokens,
            hearing_prompt_bundle_sha256=self.hearing_prompt_bundle_sha256,
            prosecutor_model_manifest_id=self.prosecutor_model_manifest_id,
            defender_model_manifest_id=self.defender_model_manifest_id,
            judge_model_manifest_id=self.judge_model_manifest_id,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def session_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-session-document",
                1,
                self.session_id,
                self.model_dump(mode="json", exclude_computed_fields=True),
            ]
        )

    @model_validator(mode="after")
    def validate_entry(self) -> HearingSession:
        _stable_defect_codes(self.initial_defect_codes, "hearing initial defect codes")
        if self.entry_status == HearingSessionEntryStatus.ESCALATED:
            if self.initial_trigger_review_ref is not None or self.initial_defect_codes:
                raise ValueError("ESCALATED session cannot claim a failed review")
        elif (
            self.initial_trigger_review_ref is None
            or self.initial_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or not self.initial_defect_codes
        ):
            raise ValueError("REWORK_REQUIRED session requires its failed review and defects")
        if self.max_total_judge_cycles > MAX_HEARING_JUDGE_CYCLES:
            raise ValueError("hearing session exceeds the five-cycle hard limit")
        return self


class HearingRound(FrozenContractModel):
    """One complete prosecutor/defender/Judge cycle over a single current pack."""

    schema_version: Literal["m4-hearing-round-v1"] = "m4-hearing-round-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(ge=0, le=2, strict=True)
    prior_rework_rounds: int = Field(ge=0, le=2, strict=True)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    precedent_retrieval_degraded: StrictBool
    precedent_retrieval_receipt: HearingPrecedentRetrievalReceipt
    initial_trigger_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    rework_review_ref: ArtifactRef | None = None
    rework_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    prosecutor_output: HearingRoleOutput
    defender_output: HearingRoleOutput
    judge_output: HearingRoleOutput
    acquisition_request: AcquisitionRequest | None = None
    tool_execution_receipt: ToolExecutionReceipt | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing round reference")

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
            "round_id",
            "resulting_evidence_pack_id",
            "resulting_evidence_pack_version",
        )
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        hearing_round = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(hearing_round, name):
                raise ValueError(f"serialized {name} conflicts with hearing round content")
        return hearing_round

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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resulting_evidence_pack_id(self) -> Sha256Hex:
        if self.tool_execution_receipt is None:
            return self.current_evidence_pack_id
        return self.tool_execution_receipt.resulting_evidence_pack_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resulting_evidence_pack_version(self) -> int:
        if self.tool_execution_receipt is None:
            return self.current_evidence_pack_version
        return self.tool_execution_receipt.resulting_evidence_pack_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def round_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-round",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.cycle_scope_id,
                self.cycle_scope_sha256,
                self.round_index,
                self.prior_acquisition_rounds,
                self.prior_rework_rounds,
                self.current_evidence_pack_id,
                self.current_evidence_pack_version,
                self.precedent_retrieval_degraded,
                self.precedent_retrieval_receipt.receipt_id,
                self.precedent_retrieval_receipt.receipt_sha256,
                (
                    self.initial_trigger_review_ref.model_dump(mode="json")
                    if self.initial_trigger_review_ref is not None
                    else None
                ),
                [code.value for code in self.initial_defect_codes],
                (
                    self.rework_review_ref.model_dump(mode="json")
                    if self.rework_review_ref is not None
                    else None
                ),
                [code.value for code in self.rework_defect_codes],
                self.prosecutor_output.output_id,
                self.defender_output.output_id,
                self.judge_output.output_id,
                (
                    self.acquisition_request.request_id
                    if self.acquisition_request is not None
                    else None
                ),
                (
                    self.tool_execution_receipt.receipt_id
                    if self.tool_execution_receipt is not None
                    else None
                ),
                self.resulting_evidence_pack_id,
                self.resulting_evidence_pack_version,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_cycle(self) -> HearingRound:
        if self.round_index != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("hearing round index conflicts with prior-round counters")
        retrieval = self.precedent_retrieval_receipt
        if (
            retrieval.run_id != self.run_id
            or retrieval.case_id != self.case_id
            or retrieval.hearing_session_id != self.hearing_session_id
            or retrieval.round_index != self.round_index
            or retrieval.prior_acquisition_rounds != self.prior_acquisition_rounds
            or retrieval.prior_rework_rounds != self.prior_rework_rounds
            or retrieval.current_evidence_pack_id != self.current_evidence_pack_id
            or retrieval.current_evidence_pack_version != self.current_evidence_pack_version
            or retrieval.initial_trigger_review_ref != self.initial_trigger_review_ref
            or retrieval.initial_defect_codes != self.initial_defect_codes
            or retrieval.rework_review_ref != self.rework_review_ref
            or retrieval.rework_defect_codes != self.rework_defect_codes
            or (retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED)
            != self.precedent_retrieval_degraded
            or retrieval.manifest_id != self.manifest_id
        ):
            raise ValueError("precedent retrieval receipt conflicts with its hearing round")
        _stable_defect_codes(self.initial_defect_codes, "initial round trigger defect codes")
        if (self.initial_trigger_review_ref is None) != (not self.initial_defect_codes):
            raise ValueError("initial round trigger review and defects are required together")
        if self.initial_trigger_review_ref is not None and (
            self.round_index != 1
            or self.prior_acquisition_rounds != 0
            or self.prior_rework_rounds != 0
            or self.initial_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        ):
            raise ValueError("initial round trigger is allowed only on the first cycle")
        _stable_defect_codes(self.rework_defect_codes, "hearing round rework defect codes")
        if self.prior_rework_rounds == 0:
            if self.rework_review_ref is not None or self.rework_defect_codes:
                raise ValueError("non-rework hearing round cannot carry a review")
        elif (
            self.rework_review_ref is None
            or self.rework_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or not self.rework_defect_codes
        ):
            raise ValueError("rework hearing round requires a review and defect codes")

        outputs = (
            (self.prosecutor_output, VlmRole.PROSECUTOR),
            (self.defender_output, VlmRole.DEFENDER),
            (self.judge_output, VlmRole.JUDGE),
        )
        for output, expected_role in outputs:
            if output.role != expected_role:
                raise ValueError("hearing round contains a role output in the wrong slot")
            if (
                output.run_id != self.run_id
                or output.case_id != self.case_id
                or output.hearing_session_id != self.hearing_session_id
                or output.round_index != self.round_index
                or output.prior_acquisition_rounds != self.prior_acquisition_rounds
                or output.prior_rework_rounds != self.prior_rework_rounds
                or output.current_evidence_pack_id != self.current_evidence_pack_id
                or output.current_evidence_pack_version != self.current_evidence_pack_version
                or output.precedent_retrieval_degraded != self.precedent_retrieval_degraded
                or output.precedent_retrieval_receipt_id != retrieval.receipt_id
                or output.precedent_retrieval_receipt_sha256 != retrieval.receipt_sha256
                or output.initial_trigger_review_ref != self.initial_trigger_review_ref
                or output.initial_defect_codes != self.initial_defect_codes
                or output.rework_review_ref != self.rework_review_ref
                or output.rework_defect_codes != self.rework_defect_codes
                or output.manifest_id != self.manifest_id
            ):
                raise ValueError("hearing role output conflicts with its round scope")
        if self.defender_output.prosecutor_output_id != self.prosecutor_output.output_id:
            raise ValueError("defender output does not bind this round's prosecutor")
        if (
            self.judge_output.prosecutor_output_id != self.prosecutor_output.output_id
            or self.judge_output.defender_output_id != self.defender_output.output_id
        ):
            raise ValueError("judge output does not bind this round's advocate outputs")
        model_refs = tuple(
            ref.artifact_id
            for output, _ in outputs
            for ref in (output.request_ref, output.response_ref, output.parse_receipt_ref)
        )
        if len(model_refs) != len(set(model_refs)):
            raise ValueError("each hearing role call requires distinct request/response/parse refs")

        assert isinstance(self.judge_output.payload, JudgeModelPayload)
        outcome = self.judge_output.payload.outcome
        if isinstance(outcome, JudgeFinalDecisionPayload):
            if self.acquisition_request is not None or self.tool_execution_receipt is not None:
                raise ValueError("final Judge outcome cannot carry an acquisition execution")
        else:
            request = self.acquisition_request
            receipt = self.tool_execution_receipt
            if request is None or receipt is None:
                raise ValueError("Judge acquisition outcome requires one request and one receipt")
            if (
                request.run_id != self.run_id
                or request.case_id != self.case_id
                or request.hearing_session_id != self.hearing_session_id
                or request.round_index != self.round_index
                or request.prior_acquisition_rounds != self.prior_acquisition_rounds
                or request.prior_rework_rounds != self.prior_rework_rounds
                or request.current_evidence_pack_id != self.current_evidence_pack_id
                or request.current_evidence_pack_version != self.current_evidence_pack_version
                or request.source_judge_output_id != self.judge_output.output_id
                or request.source_model_request_ref != self.judge_output.request_ref
                or request.source_model_response_ref != self.judge_output.response_ref
                or request.request_payload != outcome.request
                or request.manifest_id != self.manifest_id
            ):
                raise ValueError("acquisition request conflicts with the Judge proposal or round")
            if receipt.request != request:
                raise ValueError("tool execution receipt does not close this acquisition request")
        return self


class HearingRecord(FrozenContractModel):
    """Append-only hearing aggregate with computed head, limits, and completion state."""

    schema_version: Literal["m4-hearing-record-v1"] = "m4-hearing-record-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    version: int = Field(gt=0, strict=True)
    session: HearingSession
    screening_id: Sha256Hex
    initial_evidence_pack_id: Sha256Hex
    initial_evidence_pack_version: int = Field(gt=0, strict=True)
    acquisition_round_limit: int = Field(
        default=MAX_HEARING_ACQUISITION_ROUNDS,
        ge=0,
        le=MAX_HEARING_ACQUISITION_ROUNDS,
        strict=True,
    )
    rework_round_limit: int = Field(
        default=MAX_HEARING_REWORK_ROUNDS,
        ge=0,
        le=MAX_HEARING_REWORK_ROUNDS,
        strict=True,
    )
    rounds: tuple[HearingRound, ...] = Field(min_length=1, max_length=MAX_HEARING_JUDGE_CYCLES)
    model_request_refs: tuple[ArtifactRef, ...] = Field(
        min_length=3,
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    model_response_refs: tuple[ArtifactRef, ...] = Field(
        min_length=3,
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    parse_receipt_refs: tuple[ArtifactRef, ...] = Field(
        min_length=3,
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    usage_receipts: tuple[HearingUsageReceipt, ...] = Field(
        min_length=3,
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    failure_authorities: tuple[HearingModelCallFailureAuthority, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing record reference")

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
            "hearing_session_id",
            "current_evidence_pack_id",
            "current_evidence_pack_version",
            "acquisition_rounds_used",
            "rework_rounds_used",
            "precedent_retrieval_degraded",
            "total_reserved_images",
            "total_reserved_pixels",
            "total_input_images",
            "total_input_pixels",
            "total_input_tokens",
            "total_output_tokens",
            "total_latency_ms",
            "total_retry_count",
            "total_estimated_cost",
            "complete",
            "record_id",
            "record_sha256",
        )
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        record = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(record, name):
                raise ValueError(f"serialized {name} conflicts with hearing record content")
        return record

    @computed_field  # type: ignore[prop-decorator]
    @property
    def hearing_session_id(self) -> Sha256Hex:
        return self.session.session_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def current_evidence_pack_id(self) -> Sha256Hex:
        return self.rounds[-1].resulting_evidence_pack_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def current_evidence_pack_version(self) -> int:
        return self.rounds[-1].resulting_evidence_pack_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def acquisition_rounds_used(self) -> int:
        return sum(round_.acquisition_request is not None for round_ in self.rounds)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rework_rounds_used(self) -> int:
        return max(round_.prior_rework_rounds for round_ in self.rounds)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def precedent_retrieval_degraded(self) -> bool:
        return any(round_.precedent_retrieval_degraded for round_ in self.rounds)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_reserved_images(self) -> int:
        reservations = {
            item.request_ref.artifact_id: item.input_images for item in self.usage_receipts
        }
        reservations.update(
            {item.request.request_id: item.reserved_images for item in self.failure_authorities}
        )
        return sum(reservations.values())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_reserved_pixels(self) -> int:
        reservations = {
            item.request_ref.artifact_id: item.input_pixels for item in self.usage_receipts
        }
        reservations.update(
            {item.request.request_id: item.reserved_pixels for item in self.failure_authorities}
        )
        return sum(reservations.values())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_input_images(self) -> int:
        return sum(item.input_images for item in self.usage_receipts) + sum(
            item.disclosed_images for item in self.failure_authorities
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_input_pixels(self) -> int:
        return sum(item.input_pixels for item in self.usage_receipts) + sum(
            item.disclosed_pixels for item in self.failure_authorities
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_input_tokens(self) -> int:
        return sum(item.input_tokens for item in self.usage_receipts) + sum(
            item.input_tokens for item in self.failure_authorities
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_output_tokens(self) -> int:
        return sum(item.output_tokens for item in self.usage_receipts) + sum(
            item.output_tokens for item in self.failure_authorities
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_latency_ms(self) -> int:
        return sum(item.latency_ms for item in self.usage_receipts) + sum(
            item.latency_ms for item in self.failure_authorities
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_retry_count(self) -> int:
        return sum(item.retry_count for item in self.usage_receipts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_estimated_cost(self) -> float:
        return sum(item.estimated_cost for item in self.usage_receipts) + sum(
            item.estimated_cost for item in self.failure_authorities
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def complete(self) -> bool:
        payload = self.rounds[-1].judge_output.payload
        assert isinstance(payload, JudgeModelPayload)
        return isinstance(payload.outcome, JudgeFinalDecisionPayload)

    def record_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "version": self.version,
            "session_id": self.session.session_id,
            "session_sha256": self.session.session_sha256,
            "screening_id": self.screening_id,
            "initial_evidence_pack_id": self.initial_evidence_pack_id,
            "initial_evidence_pack_version": self.initial_evidence_pack_version,
            "acquisition_round_limit": self.acquisition_round_limit,
            "rework_round_limit": self.rework_round_limit,
            "round_ids": [round_.round_id for round_ in self.rounds],
            "model_request_refs": [ref.model_dump(mode="json") for ref in self.model_request_refs],
            "model_response_refs": [
                ref.model_dump(mode="json") for ref in self.model_response_refs
            ],
            "parse_receipt_refs": [ref.model_dump(mode="json") for ref in self.parse_receipt_refs],
            "usage_receipt_ids": [item.usage_receipt_id for item in self.usage_receipts],
            "failure_authority_ids": [item.authority_id for item in self.failure_authorities],
            "current_evidence_pack_id": self.current_evidence_pack_id,
            "current_evidence_pack_version": self.current_evidence_pack_version,
            "acquisition_rounds_used": self.acquisition_rounds_used,
            "rework_rounds_used": self.rework_rounds_used,
            "precedent_retrieval_degraded": self.precedent_retrieval_degraded,
            "total_reserved_images": self.total_reserved_images,
            "total_reserved_pixels": self.total_reserved_pixels,
            "total_input_images": self.total_input_images,
            "total_input_pixels": self.total_input_pixels,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_latency_ms": self.total_latency_ms,
            "total_retry_count": self.total_retry_count,
            "total_estimated_cost": self.total_estimated_cost,
            "complete": self.complete,
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def record_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-record",
                1,
                self.run_id,
                self.case_id,
                self.version,
                self.record_projection(),
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def record_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-record-document",
                1,
                self.record_id,
                self.record_projection(),
            ]
        )

    @model_validator(mode="after")
    def validate_history(self) -> HearingRecord:
        if (
            self.session.run_id != self.run_id
            or self.session.case_id != self.case_id
            or self.session.screening_id != self.screening_id
            or self.session.initial_evidence_pack_id != self.initial_evidence_pack_id
            or self.session.initial_evidence_pack_version != self.initial_evidence_pack_version
            or self.session.acquisition_round_limit != self.acquisition_round_limit
            or self.session.rework_round_limit != self.rework_round_limit
            or self.session.manifest_id != self.manifest_id
        ):
            raise ValueError("hearing record conflicts with its session authority")
        if len(self.rounds) > 1 + self.acquisition_round_limit + self.rework_round_limit:
            raise ValueError("hearing record exceeds its derived Judge-cycle limit")
        first = self.rounds[0]
        if (
            first.round_index != 1
            or first.prior_acquisition_rounds != 0
            or first.prior_rework_rounds != 0
            or first.current_evidence_pack_id != self.initial_evidence_pack_id
            or first.current_evidence_pack_version != self.initial_evidence_pack_version
            or first.initial_trigger_review_ref != self.session.initial_trigger_review_ref
            or first.initial_defect_codes != self.session.initial_defect_codes
        ):
            raise ValueError("first hearing round conflicts with the initial pack or counters")
        for index, current in enumerate(self.rounds):
            if (
                current.run_id != self.run_id
                or current.case_id != self.case_id
                or current.hearing_session_id != self.hearing_session_id
                or current.manifest_id != self.manifest_id
                or current.round_index != index + 1
                or current.prior_acquisition_rounds > self.acquisition_round_limit
                or current.prior_rework_rounds > self.rework_round_limit
            ):
                raise ValueError("hearing round conflicts with its record scope or limits")
            if current.acquisition_request is not None and (
                current.prior_acquisition_rounds >= self.acquisition_round_limit
            ):
                raise ValueError("Judge acquisition request exceeds the configured round limit")
            expected_models = {
                VlmRole.PROSECUTOR: self.session.prosecutor_model_manifest_id,
                VlmRole.DEFENDER: self.session.defender_model_manifest_id,
                VlmRole.JUDGE: self.session.judge_model_manifest_id,
            }
            for output in (
                current.prosecutor_output,
                current.defender_output,
                current.judge_output,
            ):
                if (
                    output.model_manifest_id != expected_models[output.role]
                    or output.prompt_manifest.prompt_bundle_sha256
                    != self.session.hearing_prompt_bundle_sha256
                ):
                    raise ValueError("role output conflicts with session model or prompt authority")
            if index == 0:
                continue
            previous = self.rounds[index - 1]
            previous_payload = previous.judge_output.payload
            assert isinstance(previous_payload, JudgeModelPayload)
            followed_acquisition = isinstance(
                previous_payload.outcome,
                JudgeAcquisitionDecisionPayload,
            )
            expected_acquisitions = previous.prior_acquisition_rounds + int(followed_acquisition)
            expected_reworks = previous.prior_rework_rounds + int(not followed_acquisition)
            if (
                current.current_evidence_pack_id != previous.resulting_evidence_pack_id
                or current.current_evidence_pack_version != previous.resulting_evidence_pack_version
                or current.prior_acquisition_rounds != expected_acquisitions
                or current.prior_rework_rounds != expected_reworks
            ):
                raise ValueError("hearing round transition violates acquisition/rework history")

        request_ids = tuple(
            output.request_ref.artifact_id
            for hearing_round in self.rounds
            for output in (
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                hearing_round.judge_output,
            )
        )
        response_ids = tuple(
            output.response_ref.artifact_id
            for hearing_round in self.rounds
            for output in (
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                hearing_round.judge_output,
            )
        )
        if len(request_ids) != len(set(request_ids)) or len(response_ids) != len(set(response_ids)):
            raise ValueError("hearing model requests and responses must be unique across rounds")
        for refs, name, kind in (
            (self.model_request_refs, "record model request refs", ArtifactKind.MODEL_REQUEST),
            (self.model_response_refs, "record model response refs", ArtifactKind.MODEL_RESPONSE),
            (
                self.parse_receipt_refs,
                "record parse receipt refs",
                ArtifactKind.MODEL_PARSE_RECEIPT,
            ),
        ):
            _stable_refs(refs, name, allowed_kinds=frozenset({kind}))
        if not set(request_ids).issubset(
            {ref.artifact_id for ref in self.model_request_refs}
        ) or not set(response_ids).issubset({ref.artifact_id for ref in self.model_response_refs}):
            raise ValueError("record call refs must include every successful role output")
        if not (
            len(self.model_request_refs)
            == len(self.model_response_refs)
            == len(self.parse_receipt_refs)
        ):
            raise ValueError("record must preserve one request/response/parse trace per call")
        usage_keys = tuple(
            (item.round_index, item.role.value, item.request_ref.artifact_id)
            for item in self.usage_receipts
        )
        if len(usage_keys) != len(set(usage_keys)) or usage_keys != tuple(sorted(usage_keys)):
            raise ValueError("hearing usage receipts must be unique and use stable call order")
        usage_requests = {item.request_ref.artifact_id for item in self.usage_receipts}
        usage_responses = {item.response_ref.artifact_id for item in self.usage_receipts}
        if len(usage_requests) != len(self.usage_receipts) or len(usage_responses) != len(
            self.usage_receipts
        ):
            raise ValueError("hearing usage cannot charge one request or response twice")
        if usage_requests != {
            ref.artifact_id for ref in self.model_request_refs
        } or usage_responses != {ref.artifact_id for ref in self.model_response_refs}:
            raise ValueError("record usage must exactly cover every provider call once")
        if any(
            item.run_id != self.run_id
            or item.case_id != self.case_id
            or item.hearing_session_id != self.hearing_session_id
            or item.manifest_id != self.manifest_id
            for item in self.usage_receipts
        ):
            raise ValueError("hearing usage receipt conflicts with record scope")
        failure_keys = tuple(
            (
                item.request.round_index,
                item.role.value,
                item.request.request_id,
                item.authority_id,
            )
            for item in self.failure_authorities
        )
        if len(failure_keys) != len(set(failure_keys)) or failure_keys != tuple(
            sorted(failure_keys)
        ):
            raise ValueError("hearing failure authorities must be unique and use call order")
        if any(
            item.run_id != self.run_id
            or item.case_id != self.case_id
            or item.hearing_session_id != self.hearing_session_id
            or item.manifest_id != self.manifest_id
            for item in self.failure_authorities
        ):
            raise ValueError("hearing failure authority conflicts with record scope")
        reservations: dict[str, tuple[int, int]] = {
            item.request_ref.artifact_id: (item.input_images, item.input_pixels)
            for item in self.usage_receipts
        }
        for authority in self.failure_authorities:
            candidate = (authority.reserved_images, authority.reserved_pixels)
            previous_reservation = reservations.setdefault(
                authority.request.request_id,
                candidate,
            )
            if previous_reservation != candidate:
                raise ValueError("one hearing request has conflicting budget reservations")
        if (
            self.total_reserved_images > self.session.max_total_images
            or self.total_output_tokens > self.session.max_total_output_tokens
        ):
            raise ValueError("hearing usage exceeds its immutable session budget")
        return self


class HearingHumanReviewReason(StrEnum):
    ACQUISITION_LIMIT_EXHAUSTED = "ACQUISITION_LIMIT_EXHAUSTED"
    REWORK_LIMIT_EXHAUSTED = "REWORK_LIMIT_EXHAUSTED"
    HEARING_BUDGET_EXHAUSTED = "HEARING_BUDGET_EXHAUSTED"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    ACQUISITION_UNRECOVERABLE = "ACQUISITION_UNRECOVERABLE"
    HEARING_BACKLOG_EXHAUSTED = "HEARING_BACKLOG_EXHAUSTED"


class HearingCheckpointPhase(StrEnum):
    PRECEDENT_RETRIEVAL_PENDING = "PRECEDENT_RETRIEVAL_PENDING"
    PROSECUTOR_PENDING = "PROSECUTOR_PENDING"
    DEFENDER_PENDING = "DEFENDER_PENDING"
    JUDGE_PENDING = "JUDGE_PENDING"
    ACQUISITION_PENDING = "ACQUISITION_PENDING"
    ROUND_COMPLETE = "ROUND_COMPLETE"
    REWORK_READY = "REWORK_READY"
    COMPLETE = "COMPLETE"
    HUMAN_REVIEW = "HUMAN_REVIEW"


_CHECKPOINT_TRANSITIONS: dict[HearingCheckpointPhase, frozenset[HearingCheckpointPhase]] = {
    HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING: frozenset(
        {
            HearingCheckpointPhase.PROSECUTOR_PENDING,
            HearingCheckpointPhase.HUMAN_REVIEW,
        }
    ),
    HearingCheckpointPhase.PROSECUTOR_PENDING: frozenset(
        {HearingCheckpointPhase.DEFENDER_PENDING, HearingCheckpointPhase.HUMAN_REVIEW}
    ),
    HearingCheckpointPhase.DEFENDER_PENDING: frozenset(
        {HearingCheckpointPhase.JUDGE_PENDING, HearingCheckpointPhase.HUMAN_REVIEW}
    ),
    HearingCheckpointPhase.JUDGE_PENDING: frozenset(
        {
            HearingCheckpointPhase.ACQUISITION_PENDING,
            HearingCheckpointPhase.ROUND_COMPLETE,
            HearingCheckpointPhase.HUMAN_REVIEW,
        }
    ),
    HearingCheckpointPhase.ACQUISITION_PENDING: frozenset(
        {HearingCheckpointPhase.ROUND_COMPLETE, HearingCheckpointPhase.HUMAN_REVIEW}
    ),
    HearingCheckpointPhase.ROUND_COMPLETE: frozenset(
        {
            HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
            HearingCheckpointPhase.REWORK_READY,
            HearingCheckpointPhase.COMPLETE,
            HearingCheckpointPhase.HUMAN_REVIEW,
        }
    ),
    HearingCheckpointPhase.REWORK_READY: frozenset(
        {
            HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
            HearingCheckpointPhase.HUMAN_REVIEW,
        }
    ),
    HearingCheckpointPhase.COMPLETE: frozenset(),
    HearingCheckpointPhase.HUMAN_REVIEW: frozenset(),
}


class HearingCheckpoint(FrozenContractModel):
    """Append-only crash-resume authority for every partial M4 phase."""

    schema_version: Literal["m4-hearing-checkpoint-v1"] = "m4-hearing-checkpoint-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    hearing_session_sha256: Sha256Hex
    version: int = Field(gt=0, strict=True)
    phase: HearingCheckpointPhase
    judge_cycle: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    prior_acquisition_rounds: int = Field(ge=0, le=2, strict=True)
    prior_rework_rounds: int = Field(ge=0, le=2, strict=True)
    cycle_evidence_pack_id: Sha256Hex
    cycle_evidence_pack_version: int = Field(gt=0, strict=True)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    previous_checkpoint_id: Sha256Hex | None = None
    previous_checkpoint_sha256: Sha256Hex | None = None
    previous_phase: HearingCheckpointPhase | None = None
    initial_trigger_review_ref: ArtifactRef | None = None
    initial_defect_codes: tuple[ProceduralDefectCode, ...] = Field(default=(), max_length=14)
    cycle_trigger_review_ref: ArtifactRef | None = None
    cycle_trigger_defect_codes: tuple[ProceduralDefectCode, ...] = Field(
        default=(),
        max_length=14,
    )
    precedent_retrieval_receipt: HearingPrecedentRetrievalReceipt | None = None
    prosecutor_output: HearingRoleOutput | None = None
    defender_output: HearingRoleOutput | None = None
    judge_output: HearingRoleOutput | None = None
    acquisition_request: AcquisitionRequest | None = None
    tool_execution_receipt: ToolExecutionReceipt | None = None
    procedural_review_ref: ArtifactRef | None = None
    human_review_receipt_id: Sha256Hex | None = None
    human_review_receipt_sha256: Sha256Hex | None = None
    human_review_reason: HearingHumanReviewReason | None = None
    model_request_refs: tuple[ArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    model_response_refs: tuple[ArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    parse_receipt_refs: tuple[ArtifactRef, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    usage_receipts: tuple[HearingUsageReceipt, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    failure_authorities: tuple[HearingModelCallFailureAuthority, ...] = Field(
        default=(),
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing checkpoint reference")

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
            "checkpoint_id",
            "checkpoint_sha256",
        )
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        checkpoint = handler(payload)
        for name in names:
            if present[name] and (
                not isinstance(claimed[name], str) or claimed[name] != getattr(checkpoint, name)
            ):
                raise ValueError(f"serialized {name} conflicts with checkpoint content")
        return checkpoint

    def cycle_scope_projection(self) -> dict[str, object]:
        return _hearing_cycle_scope_projection(
            run_id=self.run_id,
            case_id=self.case_id,
            hearing_session_id=self.hearing_session_id,
            cycle_index=self.judge_cycle,
            prior_acquisition_rounds=self.prior_acquisition_rounds,
            prior_rework_rounds=self.prior_rework_rounds,
            cycle_evidence_pack_id=self.cycle_evidence_pack_id,
            cycle_evidence_pack_version=self.cycle_evidence_pack_version,
            initial_trigger_review_ref=self.initial_trigger_review_ref,
            initial_defect_codes=self.initial_defect_codes,
            rework_review_ref=self.cycle_trigger_review_ref,
            rework_defect_codes=self.cycle_trigger_defect_codes,
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

    def checkpoint_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "hearing_session_id": self.hearing_session_id,
            "hearing_session_sha256": self.hearing_session_sha256,
            "cycle_scope_id": self.cycle_scope_id,
            "cycle_scope_sha256": self.cycle_scope_sha256,
            "version": self.version,
            "phase": self.phase.value,
            "judge_cycle": self.judge_cycle,
            "prior_acquisition_rounds": self.prior_acquisition_rounds,
            "prior_rework_rounds": self.prior_rework_rounds,
            "cycle_evidence_pack_id": self.cycle_evidence_pack_id,
            "cycle_evidence_pack_version": self.cycle_evidence_pack_version,
            "current_evidence_pack_id": self.current_evidence_pack_id,
            "current_evidence_pack_version": self.current_evidence_pack_version,
            "previous_checkpoint_id": self.previous_checkpoint_id,
            "previous_checkpoint_sha256": self.previous_checkpoint_sha256,
            "previous_phase": self.previous_phase.value
            if self.previous_phase is not None
            else None,
            "initial_trigger_review_ref": (
                self.initial_trigger_review_ref.model_dump(mode="json")
                if self.initial_trigger_review_ref is not None
                else None
            ),
            "initial_defect_codes": [code.value for code in self.initial_defect_codes],
            "cycle_trigger_review_ref": (
                self.cycle_trigger_review_ref.model_dump(mode="json")
                if self.cycle_trigger_review_ref is not None
                else None
            ),
            "cycle_trigger_defect_codes": [code.value for code in self.cycle_trigger_defect_codes],
            "precedent_retrieval_receipt_id": (
                self.precedent_retrieval_receipt.receipt_id
                if self.precedent_retrieval_receipt is not None
                else None
            ),
            "prosecutor_output_id": (
                self.prosecutor_output.output_id if self.prosecutor_output is not None else None
            ),
            "defender_output_id": (
                self.defender_output.output_id if self.defender_output is not None else None
            ),
            "judge_output_id": (
                self.judge_output.output_id if self.judge_output is not None else None
            ),
            "acquisition_request_id": (
                self.acquisition_request.request_id
                if self.acquisition_request is not None
                else None
            ),
            "tool_execution_receipt_id": (
                self.tool_execution_receipt.receipt_id
                if self.tool_execution_receipt is not None
                else None
            ),
            "procedural_review_ref": (
                self.procedural_review_ref.model_dump(mode="json")
                if self.procedural_review_ref is not None
                else None
            ),
            "human_review_receipt_id": self.human_review_receipt_id,
            "human_review_receipt_sha256": self.human_review_receipt_sha256,
            "human_review_reason": (
                self.human_review_reason.value if self.human_review_reason is not None else None
            ),
            "model_request_refs": [ref.model_dump(mode="json") for ref in self.model_request_refs],
            "model_response_refs": [
                ref.model_dump(mode="json") for ref in self.model_response_refs
            ],
            "parse_receipt_refs": [ref.model_dump(mode="json") for ref in self.parse_receipt_refs],
            "usage_receipt_ids": [item.usage_receipt_id for item in self.usage_receipts],
            "failure_authority_ids": [item.authority_id for item in self.failure_authorities],
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def checkpoint_id(self) -> Sha256Hex:
        return sha256_hex(["hearing-checkpoint", 1, self.checkpoint_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def checkpoint_sha256(self) -> Sha256Hex:
        return sha256_hex(
            ["hearing-checkpoint-document", 1, self.checkpoint_id, self.checkpoint_projection()]
        )

    @model_validator(mode="after")
    def validate_checkpoint(self) -> HearingCheckpoint:
        if self.judge_cycle != 1 + self.prior_acquisition_rounds + self.prior_rework_rounds:
            raise ValueError("checkpoint cycle conflicts with prior-round counters")
        previous = (
            self.previous_checkpoint_id,
            self.previous_checkpoint_sha256,
            self.previous_phase,
        )
        if self.version == 1:
            if any(value is not None for value in previous) or self.phase != (
                HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING
            ):
                raise ValueError("first checkpoint must open at precedent retrieval")
        elif any(value is None for value in previous):
            raise ValueError("later checkpoint versions require the exact previous checkpoint")
        elif self.phase not in _CHECKPOINT_TRANSITIONS[self.previous_phase]:  # type: ignore[index]
            raise ValueError("checkpoint phase transition is not allowed")

        _stable_defect_codes(self.initial_defect_codes, "checkpoint initial defect codes")
        if (self.initial_trigger_review_ref is None) != (not self.initial_defect_codes):
            raise ValueError("checkpoint initial trigger review and defects are required together")
        if self.initial_trigger_review_ref is not None and (
            self.judge_cycle != 1
            or self.prior_acquisition_rounds != 0
            or self.prior_rework_rounds != 0
            or self.initial_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        ):
            raise ValueError("checkpoint initial trigger is allowed only on the first cycle")
        _stable_defect_codes(
            self.cycle_trigger_defect_codes,
            "checkpoint cycle-trigger defect codes",
        )
        if self.prior_rework_rounds == 0:
            if self.cycle_trigger_review_ref is not None or self.cycle_trigger_defect_codes:
                raise ValueError("non-rework checkpoint cannot claim a cycle trigger")
        elif (
            self.cycle_trigger_review_ref is None
            or self.cycle_trigger_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or not self.cycle_trigger_defect_codes
        ):
            raise ValueError("rework checkpoint requires its exact cycle trigger")

        for refs, name, kind in (
            (self.model_request_refs, "checkpoint request refs", ArtifactKind.MODEL_REQUEST),
            (self.model_response_refs, "checkpoint response refs", ArtifactKind.MODEL_RESPONSE),
            (
                self.parse_receipt_refs,
                "checkpoint parse refs",
                ArtifactKind.MODEL_PARSE_RECEIPT,
            ),
        ):
            _stable_refs(refs, name, allowed_kinds=frozenset({kind}))
        if not (
            len(self.model_request_refs)
            == len(self.model_response_refs)
            == len(self.parse_receipt_refs)
            == len(self.usage_receipts)
        ):
            raise ValueError("checkpoint must preserve one complete trace per provider call")
        usage_request_ids = tuple(item.request_ref.artifact_id for item in self.usage_receipts)
        usage_response_ids = tuple(item.response_ref.artifact_id for item in self.usage_receipts)
        if set(usage_request_ids) != {ref.artifact_id for ref in self.model_request_refs} or set(
            usage_response_ids
        ) != {ref.artifact_id for ref in self.model_response_refs}:
            raise ValueError("checkpoint usage must exactly cover its provider calls")
        if any(
            item.run_id != self.run_id
            or item.case_id != self.case_id
            or item.hearing_session_id != self.hearing_session_id
            or item.round_index != self.judge_cycle
            or item.manifest_id != self.manifest_id
            for item in self.usage_receipts
        ):
            raise ValueError("checkpoint usage conflicts with its scope")
        failure_keys = tuple(
            (
                item.request.round_index,
                item.role.value,
                item.request.request_id,
                item.authority_id,
            )
            for item in self.failure_authorities
        )
        if len(failure_keys) != len(set(failure_keys)) or failure_keys != tuple(
            sorted(failure_keys)
        ):
            raise ValueError("checkpoint failure authorities must use stable call order")
        if any(
            item.run_id != self.run_id
            or item.case_id != self.case_id
            or item.hearing_session_id != self.hearing_session_id
            or item.request.round_index != self.judge_cycle
            or item.request.current_evidence_pack_id != self.cycle_evidence_pack_id
            or item.request.current_evidence_pack_version != self.cycle_evidence_pack_version
            or item.manifest_id != self.manifest_id
            for item in self.failure_authorities
        ):
            raise ValueError("checkpoint failure authority conflicts with cycle scope")
        reservations: dict[str, tuple[int, int]] = {
            item.request_ref.artifact_id: (item.input_images, item.input_pixels)
            for item in self.usage_receipts
        }
        for authority in self.failure_authorities:
            candidate = (authority.reserved_images, authority.reserved_pixels)
            previous_reservation = reservations.setdefault(
                authority.request.request_id,
                candidate,
            )
            if previous_reservation != candidate:
                raise ValueError("checkpoint request has conflicting budget reservations")

        retrieval = self.precedent_retrieval_receipt
        if retrieval is not None and (
            retrieval.run_id != self.run_id
            or retrieval.case_id != self.case_id
            or retrieval.hearing_session_id != self.hearing_session_id
            or retrieval.round_index != self.judge_cycle
            or retrieval.current_evidence_pack_id != self.cycle_evidence_pack_id
            or retrieval.current_evidence_pack_version != self.cycle_evidence_pack_version
            or retrieval.initial_trigger_review_ref != self.initial_trigger_review_ref
            or retrieval.initial_defect_codes != self.initial_defect_codes
            or retrieval.rework_review_ref != self.cycle_trigger_review_ref
            or retrieval.rework_defect_codes != self.cycle_trigger_defect_codes
            or retrieval.manifest_id != self.manifest_id
        ):
            raise ValueError("checkpoint retrieval receipt conflicts with cycle scope")
        outputs = (self.prosecutor_output, self.defender_output, self.judge_output)
        expected_roles = (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE)
        for output, role in zip(outputs, expected_roles, strict=True):
            if output is not None and (
                output.role != role
                or output.run_id != self.run_id
                or output.case_id != self.case_id
                or output.hearing_session_id != self.hearing_session_id
                or output.round_index != self.judge_cycle
                or output.current_evidence_pack_id != self.cycle_evidence_pack_id
                or output.current_evidence_pack_version != self.cycle_evidence_pack_version
                or output.initial_trigger_review_ref != self.initial_trigger_review_ref
                or output.initial_defect_codes != self.initial_defect_codes
                or output.rework_review_ref != self.cycle_trigger_review_ref
                or output.rework_defect_codes != self.cycle_trigger_defect_codes
                or output.manifest_id != self.manifest_id
            ):
                raise ValueError("checkpoint role output conflicts with its role or pack scope")
        persisted_outputs = tuple(output for output in outputs if output is not None)
        persisted_request_ids = {output.request_ref.artifact_id for output in persisted_outputs}
        persisted_response_ids = {output.response_ref.artifact_id for output in persisted_outputs}
        persisted_parse_ids = {output.parse_receipt_ref.artifact_id for output in persisted_outputs}
        if (
            not persisted_request_ids.issubset({ref.artifact_id for ref in self.model_request_refs})
            or not persisted_response_ids.issubset(
                {ref.artifact_id for ref in self.model_response_refs}
            )
            or not persisted_parse_ids.issubset(
                {ref.artifact_id for ref in self.parse_receipt_refs}
            )
        ):
            raise ValueError("checkpoint role outputs require their complete provider traces")
        if self.defender_output is not None and self.prosecutor_output is None:
            raise ValueError("checkpoint cannot persist defense before prosecution")
        if self.judge_output is not None and (
            self.prosecutor_output is None or self.defender_output is None
        ):
            raise ValueError("checkpoint cannot persist Judge before both advocates")
        if self.acquisition_request is not None and self.judge_output is None:
            raise ValueError("checkpoint acquisition requires its Judge output")
        if self.acquisition_request is not None:
            assert self.judge_output is not None
            assert isinstance(self.judge_output.payload, JudgeModelPayload)
            outcome = self.judge_output.payload.outcome
            request = self.acquisition_request
            if not isinstance(outcome, JudgeAcquisitionDecisionPayload) or (
                request.run_id != self.run_id
                or request.case_id != self.case_id
                or request.hearing_session_id != self.hearing_session_id
                or request.round_index != self.judge_cycle
                or request.prior_acquisition_rounds != self.prior_acquisition_rounds
                or request.prior_rework_rounds != self.prior_rework_rounds
                or request.current_evidence_pack_id != self.cycle_evidence_pack_id
                or request.current_evidence_pack_version != self.cycle_evidence_pack_version
                or request.source_judge_output_id != self.judge_output.output_id
                or request.source_model_request_ref != self.judge_output.request_ref
                or request.source_model_response_ref != self.judge_output.response_ref
                or request.request_payload != outcome.request
                or request.manifest_id != self.manifest_id
            ):
                raise ValueError("checkpoint acquisition request conflicts with Judge proposal")
        if self.tool_execution_receipt is not None and (
            self.acquisition_request is None
            or self.tool_execution_receipt.request != self.acquisition_request
        ):
            raise ValueError("checkpoint tool receipt requires its exact acquisition request")
        if self.procedural_review_ref is not None:
            if self.procedural_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW:
                raise ValueError("checkpoint review ref must identify a procedural review")
            review_allowed = self.phase in {
                HearingCheckpointPhase.REWORK_READY,
                HearingCheckpointPhase.COMPLETE,
            } or (
                self.phase == HearingCheckpointPhase.HUMAN_REVIEW
                and self.human_review_reason == HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED
            )
            if not review_allowed:
                raise ValueError("checkpoint phase cannot claim a procedural review")

        required_count = {
            HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING: 0,
            HearingCheckpointPhase.PROSECUTOR_PENDING: 0,
            HearingCheckpointPhase.DEFENDER_PENDING: 1,
            HearingCheckpointPhase.JUDGE_PENDING: 2,
            HearingCheckpointPhase.ACQUISITION_PENDING: 3,
            HearingCheckpointPhase.ROUND_COMPLETE: 3,
            HearingCheckpointPhase.REWORK_READY: 3,
            HearingCheckpointPhase.COMPLETE: 3,
        }.get(self.phase)
        actual_count = sum(output is not None for output in outputs)
        if required_count is not None and actual_count != required_count:
            raise ValueError("checkpoint phase conflicts with persisted role cardinality")
        if self.phase == HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING:
            if retrieval is not None:
                raise ValueError("retrieval-pending checkpoint cannot claim a receipt")
        elif self.phase != HearingCheckpointPhase.HUMAN_REVIEW and retrieval is None:
            raise ValueError("post-retrieval checkpoint requires its exact retrieval receipt")
        if self.phase == HearingCheckpointPhase.ACQUISITION_PENDING and (
            self.acquisition_request is None or self.tool_execution_receipt is not None
        ):
            raise ValueError("acquisition-pending checkpoint requires only its request")
        if self.phase == HearingCheckpointPhase.ROUND_COMPLETE:
            assert self.judge_output is not None
            assert isinstance(self.judge_output.payload, JudgeModelPayload)
            judge_requested_tool = isinstance(
                self.judge_output.payload.outcome,
                JudgeAcquisitionDecisionPayload,
            )
            if judge_requested_tool and (
                self.acquisition_request is None or self.tool_execution_receipt is None
            ):
                raise ValueError("round-complete checkpoint conflicts with Judge outcome")
            if not judge_requested_tool and (
                self.acquisition_request is not None or self.tool_execution_receipt is not None
            ):
                raise ValueError("round-complete final Judge outcome cannot carry acquisition")
        if self.phase in {
            HearingCheckpointPhase.REWORK_READY,
            HearingCheckpointPhase.COMPLETE,
        }:
            if self.procedural_review_ref is None:
                raise ValueError("review terminal checkpoint requires its procedural review")
            assert self.judge_output is not None
            assert isinstance(self.judge_output.payload, JudgeModelPayload)
            if (
                not isinstance(self.judge_output.payload.outcome, JudgeFinalDecisionPayload)
                or self.acquisition_request is not None
                or self.tool_execution_receipt is not None
            ):
                raise ValueError("review terminal checkpoint requires a final Judge proposal")
        if self.phase == HearingCheckpointPhase.HUMAN_REVIEW:
            if (
                self.human_review_receipt_id is None
                or self.human_review_receipt_sha256 is None
                or self.human_review_reason is None
            ):
                raise ValueError("human-review checkpoint requires its exact receipt")
            if (self.human_review_reason == HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED) != (
                self.procedural_review_ref is not None
            ):
                raise ValueError("human-review checkpoint review authority conflicts with reason")
            allowed_previous_phases = {
                HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED: frozenset(
                    {HearingCheckpointPhase.JUDGE_PENDING}
                ),
                HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED: frozenset(
                    {HearingCheckpointPhase.REWORK_READY}
                ),
                HearingHumanReviewReason.HEARING_BUDGET_EXHAUSTED: frozenset(
                    {
                        HearingCheckpointPhase.PROSECUTOR_PENDING,
                        HearingCheckpointPhase.DEFENDER_PENDING,
                        HearingCheckpointPhase.JUDGE_PENDING,
                    }
                ),
                HearingHumanReviewReason.EVIDENCE_UNAVAILABLE: frozenset(
                    {
                        HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
                        HearingCheckpointPhase.PROSECUTOR_PENDING,
                        HearingCheckpointPhase.DEFENDER_PENDING,
                        HearingCheckpointPhase.JUDGE_PENDING,
                    }
                ),
                HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE: frozenset(
                    {HearingCheckpointPhase.ACQUISITION_PENDING}
                ),
                HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED: frozenset(
                    {
                        HearingCheckpointPhase.PROSECUTOR_PENDING,
                        HearingCheckpointPhase.DEFENDER_PENDING,
                        HearingCheckpointPhase.JUDGE_PENDING,
                    }
                ),
            }
            assert self.previous_phase is not None
            if self.previous_phase not in allowed_previous_phases[self.human_review_reason]:
                raise ValueError("human-review reason conflicts with its source phase")
        elif (
            self.human_review_receipt_id is not None
            or self.human_review_receipt_sha256 is not None
            or self.human_review_reason is not None
        ):
            raise ValueError("only human-review checkpoint can bind a human-review receipt")
        if self.tool_execution_receipt is None:
            if (
                self.current_evidence_pack_id != self.cycle_evidence_pack_id
                or self.current_evidence_pack_version != self.cycle_evidence_pack_version
            ):
                raise ValueError("checkpoint cannot change pack without a tool receipt")
        elif (
            self.current_evidence_pack_id != self.tool_execution_receipt.resulting_evidence_pack_id
            or self.current_evidence_pack_version
            != self.tool_execution_receipt.resulting_evidence_pack_version
        ):
            raise ValueError("checkpoint current pack conflicts with tool execution")
        return self


HearingCycleBoundArtifact: TypeAlias = (
    HearingPrecedentRetrievalReceipt | HearingModelRequest | HearingCheckpoint | HearingRound
)


def validate_hearing_cycle_scope_binding(
    scope: HearingCycleScope,
    artifact: HearingCycleBoundArtifact,
) -> None:
    """Require exact stored-cycle projection closure for one cycle-bound artifact."""

    if not isinstance(scope, HearingCycleScope):
        raise TypeError("scope must be a HearingCycleScope")
    if not isinstance(
        artifact,
        HearingPrecedentRetrievalReceipt | HearingModelRequest | HearingCheckpoint | HearingRound,
    ):
        raise TypeError("artifact must carry an M4 hearing cycle scope")
    if artifact.cycle_scope_projection() != scope.cycle_scope_projection():
        raise ValueError("hearing artifact fields conflict with its stored cycle scope")
    if (
        artifact.cycle_scope_id != scope.cycle_id
        or artifact.cycle_scope_sha256 != scope.cycle_sha256
    ):
        raise ValueError("hearing artifact identity conflicts with its stored cycle scope")


class HearingVerdictBinding(FrozenContractModel):
    """Bind every Judge FINAL proposal to its immutable Verdict, before L5 outcome."""

    schema_version: Literal["m4-hearing-verdict-binding-v1"] = "m4-hearing-verdict-binding-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    hearing_record_id: Sha256Hex
    hearing_record_version: int = Field(gt=0, strict=True)
    hearing_record_sha256: Sha256Hex
    judge_round_id: Sha256Hex
    judge_round_index: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    evidence_pack_id: Sha256Hex
    evidence_pack_version: int = Field(gt=0, strict=True)
    prosecutor_output_id: Sha256Hex
    defender_output_id: Sha256Hex
    judge_output_id: Sha256Hex
    verdict_id: Sha256Hex
    verdict_version: int = Field(gt=0, strict=True)
    verdict_input_sha256: Sha256Hex
    verdict_sha256: Sha256Hex
    model_request_refs: tuple[ArtifactRef, ...] = Field(
        min_length=3,
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    model_response_refs: tuple[ArtifactRef, ...] = Field(
        min_length=3,
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    parse_receipt_refs: tuple[ArtifactRef, ...] = Field(
        min_length=3,
        max_length=MAX_HEARING_PERSISTED_CALLS,
    )
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing verdict binding reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_binding_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "binding_id" in payload
        claimed = payload.pop("binding_id", None)
        binding = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != binding.binding_id):
            raise ValueError("serialized verdict binding ID does not match its content")
        return binding

    @computed_field  # type: ignore[prop-decorator]
    @property
    def binding_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-verdict-binding",
                1,
                self.run_id,
                self.case_id,
                self.hearing_session_id,
                self.hearing_record_id,
                self.hearing_record_version,
                self.hearing_record_sha256,
                self.judge_round_id,
                self.judge_round_index,
                self.evidence_pack_id,
                self.evidence_pack_version,
                self.prosecutor_output_id,
                self.defender_output_id,
                self.judge_output_id,
                self.verdict_id,
                self.verdict_version,
                self.verdict_input_sha256,
                self.verdict_sha256,
                [ref.model_dump(mode="json") for ref in self.model_request_refs],
                [ref.model_dump(mode="json") for ref in self.model_response_refs],
                [ref.model_dump(mode="json") for ref in self.parse_receipt_refs],
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_reference_sets(self) -> HearingVerdictBinding:
        for refs, name, kind in (
            (self.model_request_refs, "binding model request refs", ArtifactKind.MODEL_REQUEST),
            (
                self.model_response_refs,
                "binding model response refs",
                ArtifactKind.MODEL_RESPONSE,
            ),
            (
                self.parse_receipt_refs,
                "binding parse receipt refs",
                ArtifactKind.MODEL_PARSE_RECEIPT,
            ),
        ):
            _stable_refs(refs, name, allowed_kinds=frozenset({kind}))
        if not (
            len(self.model_request_refs)
            == len(self.model_response_refs)
            == len(self.parse_receipt_refs)
        ):
            raise ValueError("verdict binding requires the complete request/response/parse trace")
        return self


class HearingHumanReviewReceipt(FrozenContractModel):
    """Content-addressed authority for a bounded M4 transfer to human review."""

    schema_version: Literal["m4-hearing-human-review-receipt-v1"] = (
        "m4-hearing-human-review-receipt-v1"
    )
    run_id: ReferenceToken
    case_id: ReferenceToken
    hearing_session_id: Sha256Hex
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    judge_cycle: int = Field(gt=0, le=MAX_HEARING_JUDGE_CYCLES, strict=True)
    reason: HearingHumanReviewReason
    source_checkpoint_id: Sha256Hex
    source_checkpoint_sha256: Sha256Hex
    source_checkpoint_version: int = Field(gt=0, strict=True)
    procedural_review_ref: ArtifactRef | None = None
    backlog_item_ref: ArtifactRef | None = None
    acquisition_request_ref: ArtifactRef | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "hearing human-review receipt reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_identity(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        names = ("receipt_id", "receipt_sha256")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        receipt = handler(payload)
        for name in names:
            if present[name] and (
                not isinstance(claimed[name], str) or claimed[name] != getattr(receipt, name)
            ):
                raise ValueError(f"serialized human-review {name} does not match its content")
        return receipt

    def receipt_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "hearing_session_id": self.hearing_session_id,
            "current_evidence_pack_id": self.current_evidence_pack_id,
            "current_evidence_pack_version": self.current_evidence_pack_version,
            "judge_cycle": self.judge_cycle,
            "reason": self.reason.value,
            "source_checkpoint_id": self.source_checkpoint_id,
            "source_checkpoint_sha256": self.source_checkpoint_sha256,
            "source_checkpoint_version": self.source_checkpoint_version,
            "procedural_review_ref": (
                self.procedural_review_ref.model_dump(mode="json")
                if self.procedural_review_ref is not None
                else None
            ),
            "backlog_item_ref": (
                self.backlog_item_ref.model_dump(mode="json")
                if self.backlog_item_ref is not None
                else None
            ),
            "acquisition_request_ref": (
                self.acquisition_request_ref.model_dump(mode="json")
                if self.acquisition_request_ref is not None
                else None
            ),
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(["hearing-human-review-receipt", 1, self.receipt_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_sha256(self) -> Sha256Hex:
        return sha256_hex(
            ["hearing-human-review-document", 1, self.receipt_id, self.receipt_projection()]
        )

    @model_validator(mode="after")
    def validate_reason_matrix(self) -> HearingHumanReviewReceipt:
        if (
            self.procedural_review_ref is not None
            and self.procedural_review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
        ):
            raise ValueError("human-review procedural ref must identify a review")
        if (
            self.backlog_item_ref is not None
            and self.backlog_item_ref.kind != ArtifactKind.BACKLOG_ITEM
        ):
            raise ValueError("human-review backlog ref must identify a backlog item")
        if (
            self.acquisition_request_ref is not None
            and self.acquisition_request_ref.kind != ArtifactKind.MODEL_REQUEST
        ):
            raise ValueError("human-review acquisition ref must identify a request")
        expected_authorities = {
            HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED: (False, False, True),
            HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED: (True, False, False),
            HearingHumanReviewReason.HEARING_BUDGET_EXHAUSTED: (False, False, False),
            HearingHumanReviewReason.EVIDENCE_UNAVAILABLE: (False, False, False),
            HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE: (False, False, True),
            HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED: (False, True, False),
        }[self.reason]
        actual_authorities = (
            self.procedural_review_ref is not None,
            self.backlog_item_ref is not None,
            self.acquisition_request_ref is not None,
        )
        if actual_authorities != expected_authorities:
            raise ValueError("human-review reason requires an exact authority reference set")
        return self
