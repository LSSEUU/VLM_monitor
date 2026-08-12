"""Additive M8 API contracts exposing the frozen M4 hearing authority."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    ExecutionLocation,
    ProviderTransport,
    ScreeningDecision,
    VlmRole,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    HearingCheckpoint,
    HearingModelCallFailureAuthority,
    HearingModelResponse,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    ToolExecutionReceipt,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ProceduralReview, Verdict

MAX_M8_HEARING_ROLE_OUTPUTS = 15
MAX_M8_HEARING_MODEL_RESPONSES = 30
MAX_M8_HEARING_FAILURES = 30


class M8HearingModelMode(StrEnum):
    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"
    OPENAI_COMPATIBLE_QWEN = "OPENAI_COMPATIBLE_QWEN"


class M8HearingEligibility(StrEnum):
    ELIGIBLE_ESCALATED = "ELIGIBLE_ESCALATED"
    ELIGIBLE_REWORK_REQUIRED = "ELIGIBLE_REWORK_REQUIRED"
    IN_PROGRESS = "IN_PROGRESS"
    BACKLOGGED = "BACKLOGGED"
    COMPLETED = "COMPLETED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"


class M8HearingL5Status(StrEnum):
    NOT_RUN = "NOT_RUN"
    PASSED = "PASSED"
    FAILED = "FAILED"


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 hearing API content")


class M8HearingStartRequestV1(FrozenContractModel):
    """Explicit source fence and model selection for one M4 hearing start."""

    schema_version: Literal["m8-hearing-start-request-v1"] = "m8-hearing-start-request-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    source_status: CaseStatus
    source_screening_id: Sha256Hex
    source_evidence_pack_id: Sha256Hex
    source_evidence_pack_version: int = Field(gt=0, strict=True)
    model_mode: M8HearingModelMode = M8HearingModelMode.OFFLINE_FIXTURE
    explicit_start: Literal[True] = True
    request_manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 hearing start reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "client_actor_authority_permitted",
                "automatic_start_permitted",
                "clear_case_forcing_permitted",
                "start_request_id",
            ),
        )
        request = handler(payload)
        _verify_computed_claims(request, claims)
        return request

    @model_validator(mode="after")
    def validate_eligible_source_status(self) -> Self:
        if self.source_status not in {CaseStatus.ESCALATED, CaseStatus.REWORK_REQUIRED}:
            raise ValueError("M8 hearing start accepts only ESCALATED or REWORK_REQUIRED")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def client_actor_authority_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_start_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clear_case_forcing_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def start_request_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-hearing-start-request",
                1,
                self.run_id,
                self.case_id,
                self.source_status,
                self.source_screening_id,
                self.source_evidence_pack_id,
                self.source_evidence_pack_version,
                self.model_mode,
                self.explicit_start,
                self.request_manifest_id,
                self.client_actor_authority_permitted,
                self.automatic_start_permitted,
                self.clear_case_forcing_permitted,
            ]
        )


class M8HearingProviderSelectionV1(FrozenContractModel):
    """Exact role profile selected by server configuration and the run manifest."""

    schema_version: Literal["m8-hearing-provider-selection-v1"] = "m8-hearing-provider-selection-v1"
    role: VlmRole
    provider_profile: ReferenceToken
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    revision: str = Field(min_length=1, max_length=128)
    model_manifest_id: Sha256Hex
    execution_location: ExecutionLocation
    transport: ProviderTransport

    @field_validator("provider_profile")
    @classmethod
    def validate_provider_profile(cls, value: str) -> str:
        return require_reference_token(value, "M8 hearing provider profile")

    @field_validator("provider", "model", "revision")
    @classmethod
    def validate_public_text(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("M8 hearing provider identity must be trimmed visible text")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("selection_id",))
        selection = handler(payload)
        _verify_computed_claims(selection, claims)
        return selection

    @model_validator(mode="after")
    def validate_hearing_role(self) -> Self:
        if self.role not in {VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE}:
            raise ValueError("M8 hearing selection requires a hearing role")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def selection_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-hearing-provider-selection",
                1,
                self.role,
                self.provider_profile,
                self.provider,
                self.model,
                self.revision,
                self.model_manifest_id,
                self.execution_location,
                self.transport,
            ]
        )


class M8HearingViewV1(FrozenContractModel):
    """Read-only M8 projection over existing M4 persistence and L5 authority."""

    schema_version: Literal["m8-hearing-view-v1"] = "m8-hearing-view-v1"
    run_id: ReferenceToken
    case_id: ReferenceToken
    case_location_id: ReferenceToken
    model_mode: M8HearingModelMode
    provider_selections: tuple[M8HearingProviderSelectionV1, ...] = Field(
        min_length=3,
        max_length=3,
    )
    case_revision: int = Field(gt=0, strict=True)
    case_status: CaseStatus
    eligibility: M8HearingEligibility
    screening_id: Sha256Hex
    screening_decision: ScreeningDecision
    screening_conflict_flags: tuple[str, ...] = Field(default=(), max_length=64)
    current_evidence_pack_id: Sha256Hex
    current_evidence_pack_version: int = Field(gt=0, strict=True)
    hearing_session: HearingSession | None = None
    checkpoint: HearingCheckpoint | None = None
    rounds: tuple[HearingRound, ...] = Field(default=(), max_length=5)
    role_outputs: tuple[HearingRoleOutput, ...] = Field(
        default=(),
        max_length=MAX_M8_HEARING_ROLE_OUTPUTS,
    )
    model_responses: tuple[HearingModelResponse, ...] = Field(
        default=(),
        max_length=MAX_M8_HEARING_MODEL_RESPONSES,
    )
    typed_failures: tuple[HearingModelCallFailureAuthority, ...] = Field(
        default=(),
        max_length=MAX_M8_HEARING_FAILURES,
    )
    cited_evidence_refs: tuple[ArtifactRef, ...] = Field(default=(), max_length=512)
    cited_precedent_refs: tuple[ArtifactRef, ...] = Field(default=(), max_length=64)
    acquisition_requests: tuple[AcquisitionRequest, ...] = Field(default=(), max_length=2)
    tool_execution_receipts: tuple[ToolExecutionReceipt, ...] = Field(
        default=(),
        max_length=2,
    )
    final_verdict: Verdict | None = None
    procedural_reviews: tuple[ProceduralReview, ...] = Field(default=(), max_length=8)
    l5_status: M8HearingL5Status
    current_backlog_item_id: ReferenceToken | None = None
    start_request_id: Sha256Hex | None = None
    raw_model_response_content_exposed: Literal[False] = False
    case_transition_permitted: Literal[False] = False

    @field_validator("run_id", "case_id", "case_location_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 hearing view reference")

    @field_validator("current_backlog_item_id")
    @classmethod
    def validate_backlog_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 hearing backlog reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("hearing_session_id", "view_id"))
        view = handler(payload)
        _verify_computed_claims(view, claims)
        return view

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        roles = tuple(item.role for item in self.provider_selections)
        expected_roles = (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE)
        if roles != expected_roles:
            raise ValueError(
                "M8 hearing provider selections must use prosecutor/defender/judge order"
            )
        profiles = tuple(item.provider_profile for item in self.provider_selections)
        if len(profiles) != len(set(profiles)):
            raise ValueError("M8 hearing provider selections must use independent profiles")
        if self.model_mode == M8HearingModelMode.OFFLINE_FIXTURE:
            if any(
                item.provider != "fake"
                or item.transport != ProviderTransport.IN_PROCESS
                or item.execution_location != ExecutionLocation.LOCAL
                for item in self.provider_selections
            ):
                raise ValueError("offline M8 hearing view requires exact in-process fake roles")
        elif any(
            item.provider != "openai-compatible"
            or item.transport != ProviderTransport.HTTP
            or "qwen" not in item.model.lower()
            for item in self.provider_selections
        ):
            raise ValueError("real M8 hearing view requires exact OpenAI-compatible Qwen roles")

        if self.eligibility == M8HearingEligibility.ELIGIBLE_ESCALATED:
            if (
                self.case_status != CaseStatus.ESCALATED
                or self.screening_decision != ScreeningDecision.ESCALATE
                or self.hearing_session is not None
            ):
                raise ValueError("eligible escalated view conflicts with its source Case")
        elif self.eligibility == M8HearingEligibility.ELIGIBLE_REWORK_REQUIRED:
            if self.case_status != CaseStatus.REWORK_REQUIRED or self.hearing_session is not None:
                raise ValueError("eligible rework view conflicts with its source Case")
        elif self.eligibility == M8HearingEligibility.BACKLOGGED:
            if self.case_status != CaseStatus.BACKLOGGED or self.current_backlog_item_id is None:
                raise ValueError("backlogged hearing view lacks its exact backlog reference")
        elif self.eligibility == M8HearingEligibility.COMPLETED:
            if self.case_status != CaseStatus.READY_FOR_ALERT_POLICY:
                raise ValueError("completed hearing view conflicts with the M4 Case status")
        elif self.eligibility == M8HearingEligibility.HUMAN_REVIEW:
            if self.case_status != CaseStatus.HUMAN_REVIEW:
                raise ValueError("human-review hearing view conflicts with the M4 Case status")
        elif self.eligibility == M8HearingEligibility.IN_PROGRESS and self.case_status not in {
            CaseStatus.DELIBERATING,
            CaseStatus.REWORK_REQUIRED,
        }:
            raise ValueError("in-progress hearing view conflicts with the M4 Case status")

        if self.hearing_session is None:
            hearing_values = (
                self.checkpoint,
                self.rounds,
                self.role_outputs,
                self.model_responses,
                self.typed_failures,
                self.acquisition_requests,
                self.tool_execution_receipts,
            )
            if any(hearing_values):
                raise ValueError("M8 hearing details require a persisted M4 session")
        else:
            session_id = self.hearing_session.session_id
            if (
                self.hearing_session.run_id != self.run_id
                or self.hearing_session.case_id != self.case_id
                or any(item.hearing_session_id != session_id for item in self.rounds)
                or any(item.hearing_session_id != session_id for item in self.role_outputs)
                or any(item.hearing_session_id != session_id for item in self.model_responses)
                or any(item.hearing_session_id != session_id for item in self.typed_failures)
            ):
                raise ValueError("M8 hearing details do not share one frozen M4 session")
            if self.checkpoint is None or self.checkpoint.hearing_session_id != session_id:
                raise ValueError("M8 hearing session requires its current checkpoint")

        self._validate_stable_refs(self.cited_evidence_refs, precedent=False)
        self._validate_stable_refs(self.cited_precedent_refs, precedent=True)
        role_rank = {
            VlmRole.PROSECUTOR.value: 0,
            VlmRole.DEFENDER.value: 1,
            VlmRole.JUDGE.value: 2,
        }
        response_keys = tuple(
            (item.round_index, role_rank[item.role.value], item.attempt_index)
            for item in self.model_responses
        )
        if response_keys != tuple(sorted(response_keys)):
            raise ValueError("M8 hearing model responses must use stable role-call order")
        output_keys = tuple((item.round_index, item.role.value) for item in self.role_outputs)
        ranked_output_keys = tuple(
            (round_index, role_rank[role]) for round_index, role in output_keys
        )
        if ranked_output_keys != tuple(sorted(ranked_output_keys)):
            raise ValueError("M8 hearing role outputs must use stable round/role order")
        round_indexes = tuple(item.round_index for item in self.rounds)
        if round_indexes != tuple(sorted(set(round_indexes))):
            raise ValueError("M8 hearing rounds must be unique and use stable order")
        failure_keys = tuple(
            (
                item.request.round_index,
                role_rank[item.role.value],
                item.retry_generation,
                item.authority_id,
            )
            for item in self.typed_failures
        )
        if failure_keys != tuple(sorted(set(failure_keys))):
            raise ValueError("M8 hearing typed failures must be unique and use call order")
        if self.acquisition_requests != tuple(
            item.acquisition_request for item in self.rounds if item.acquisition_request is not None
        ):
            raise ValueError("M8 hearing acquisition projection conflicts with its rounds")
        if self.tool_execution_receipts != tuple(
            item.tool_execution_receipt
            for item in self.rounds
            if item.tool_execution_receipt is not None
        ):
            raise ValueError("M8 hearing tool projection conflicts with its rounds")

        review_versions = tuple(item.version for item in self.procedural_reviews)
        if review_versions != tuple(sorted(set(review_versions))) or any(
            item.run_id != self.run_id or item.case_id != self.case_id
            for item in self.procedural_reviews
        ):
            raise ValueError("M8 hearing L5 reviews must be one stable Case history")
        if self.final_verdict is not None and (
            self.hearing_session is None
            or self.final_verdict.run_id != self.run_id
            or self.final_verdict.case_id != self.case_id
            or not self.procedural_reviews
            or self.procedural_reviews[-1].reviewed_verdict_id != self.final_verdict.verdict_id
        ):
            raise ValueError("M8 final verdict lacks its M4 session and latest L5 binding")

        if self.l5_status == M8HearingL5Status.NOT_RUN:
            if self.procedural_reviews:
                raise ValueError("L5 NOT_RUN cannot carry procedural reviews")
        elif not self.procedural_reviews:
            raise ValueError("completed L5 status requires procedural review authority")
        elif self.l5_status == M8HearingL5Status.PASSED:
            if not self.procedural_reviews[-1].passed:
                raise ValueError("L5 PASSED conflicts with the latest review")
        elif self.procedural_reviews[-1].passed:
            raise ValueError("L5 FAILED conflicts with the latest review")
        return self

    @staticmethod
    def _validate_stable_refs(refs: tuple[ArtifactRef, ...], *, precedent: bool) -> None:
        expected_kind = ArtifactKind.PRECEDENT if precedent else None
        keys = tuple(item.sort_key for item in refs)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M8 hearing cited references must be unique and stable")
        if expected_kind is not None and any(item.kind != expected_kind for item in refs):
            raise ValueError("M8 hearing precedent citations require PRECEDENT refs")
        if expected_kind is None and any(item.kind == ArtifactKind.PRECEDENT for item in refs):
            raise ValueError("M8 hearing evidence citations cannot contain precedents")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def hearing_session_id(self) -> Sha256Hex | None:
        return self.hearing_session.session_id if self.hearing_session is not None else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def view_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-hearing-view",
                1,
                self.model_dump(mode="json", exclude={"hearing_session_id", "view_id"}),
            ]
        )


__all__ = [
    "M8HearingEligibility",
    "M8HearingL5Status",
    "M8HearingModelMode",
    "M8HearingProviderSelectionV1",
    "M8HearingStartRequestV1",
    "M8HearingViewV1",
]
