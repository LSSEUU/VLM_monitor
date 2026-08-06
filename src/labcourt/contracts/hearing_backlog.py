"""M4 role calls, bounded acquisition tools, and auditable hearing records.

Model-authored payloads stay separate from the run/case authority that wraps
them.  The contracts deliberately validate only syntax and structural binding;
existence of cited evidence, precedents, and tool artifacts remains an L5 gate.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self, TypeAlias

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    model_validator,
)

from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    ModelParseStatus,
    VlmRole,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.hearing_common import (
    HearingRole,
    JudgeAcquisitionDecisionPayload,
    JudgeModelPayload,
    _stable_refs,
)
from labcourt.contracts.hearing_model import (
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingStrictParseFailureProof,
    _request_matches_lease_generation,
    _validate_hearing_call_closure,
)
from labcourt.contracts.hearing_state import (
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingHumanReviewReason,
    HearingHumanReviewReceipt,
    HearingSession,
)
from labcourt.contracts.storage import ArtifactRef


class HearingBacklogRetrySuccess(FrozenContractModel):
    """A parsed M4 role output and the exact checkpoint it advances."""

    schema_version: Literal["m4-hearing-backlog-retry-success-v1"] = (
        "m4-hearing-backlog-retry-success-v1"
    )
    outcome_kind: Literal["SUCCESS"] = "SUCCESS"
    lease: BacklogLeaseIdentity
    session: HearingSession
    source_checkpoint_id: Sha256Hex
    source_checkpoint_sha256: Sha256Hex
    source_checkpoint_version: int = Field(gt=0, strict=True)
    request: HearingModelRequest
    response: HearingModelResponse
    parse_receipt: HearingModelParseReceipt
    parsed_role_output: HearingRoleOutput
    next_checkpoint: HearingCheckpoint
    human_review_receipt: HearingHumanReviewReceipt | None = None
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_outcome_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "outcome_id" in payload
        claimed = payload.pop("outcome_id", None)
        outcome = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != outcome.outcome_id):
            raise ValueError("serialized hearing backlog success ID conflicts")
        return outcome

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outcome_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-backlog-retry-success",
                1,
                self.lease.lease_identity_sha256,
                self.session.session_id,
                self.session.session_sha256,
                self.source_checkpoint_id,
                self.source_checkpoint_sha256,
                self.source_checkpoint_version,
                self.request.request_id,
                self.request.request_sha256,
                self.response.response_id,
                self.response.content_sha256,
                self.parse_receipt.parse_receipt_id,
                self.parsed_role_output.output_id,
                self.next_checkpoint.checkpoint_id,
                self.next_checkpoint.checkpoint_sha256,
                (
                    self.human_review_receipt.receipt_id
                    if self.human_review_receipt is not None
                    else None
                ),
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_success(self) -> HearingBacklogRetrySuccess:
        _validate_hearing_call_closure(self.request, self.response, self.parse_receipt)
        output = self.parsed_role_output
        checkpoint = self.next_checkpoint
        expected_model_manifest_id = {
            VlmRole.PROSECUTOR: self.session.prosecutor_model_manifest_id,
            VlmRole.DEFENDER: self.session.defender_model_manifest_id,
            VlmRole.JUDGE: self.session.judge_model_manifest_id,
        }[self.request.role]
        expected_prosecutor_output_id = (
            self.request.prosecutor_output_ref.artifact_id
            if self.request.prosecutor_output_ref is not None
            else None
        )
        expected_defender_output_id = (
            self.request.defender_output_ref.artifact_id
            if self.request.defender_output_ref is not None
            else None
        )
        if (
            not _request_matches_lease_generation(self.request, self.lease)
            or self.session.run_id != self.request.run_id
            or self.session.case_id != self.request.case_id
            or self.session.session_id != self.request.hearing_session_id
            or self.session.manifest_id != self.manifest_id
            or self.request.model_manifest_id != expected_model_manifest_id
            or self.request.hearing_prompt_bundle_sha256
            != self.session.hearing_prompt_bundle_sha256
            or self.parse_receipt.status != ModelParseStatus.PARSED
            or self.parse_receipt.parsed_payload_sha256 != output.payload.payload_sha256
            or output.role != self.request.role
            or output.prompt_manifest != self.request.prompt_manifest
            or output.model_manifest_id != self.request.model_manifest_id
            or output.request_ref
            != ArtifactRef(kind=ArtifactKind.MODEL_REQUEST, artifact_id=self.request.request_id)
            or output.response_ref
            != ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=self.response.response_id)
            or output.parse_receipt_ref
            != ArtifactRef(
                kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                artifact_id=self.parse_receipt.parse_receipt_id,
            )
            or output.run_id != self.request.run_id
            or output.case_id != self.request.case_id
            or output.hearing_session_id != self.request.hearing_session_id
            or output.round_index != self.request.round_index
            or output.prior_acquisition_rounds != self.request.prior_acquisition_rounds
            or output.prior_rework_rounds != self.request.prior_rework_rounds
            or output.current_evidence_pack_id != self.request.current_evidence_pack_id
            or output.current_evidence_pack_version != self.request.current_evidence_pack_version
            or output.prosecutor_output_id != expected_prosecutor_output_id
            or output.defender_output_id != expected_defender_output_id
            or output.precedent_retrieval_degraded != self.request.precedent_retrieval_degraded
            or output.precedent_retrieval_receipt_id != self.request.precedent_retrieval_receipt_id
            or output.precedent_retrieval_receipt_sha256
            != self.request.precedent_retrieval_receipt_sha256
            or output.initial_trigger_review_ref != self.request.initial_trigger_review_ref
            or output.initial_defect_codes != self.request.initial_defect_codes
            or output.rework_review_ref != self.request.rework_review_ref
            or output.rework_defect_codes != self.request.rework_defect_codes
            or output.manifest_id != self.manifest_id
            or self.request.manifest_id != self.manifest_id
        ):
            raise ValueError("hearing backlog success conflicts with its exact parsed call")
        expected_previous_phase = {
            VlmRole.PROSECUTOR: HearingCheckpointPhase.PROSECUTOR_PENDING,
            VlmRole.DEFENDER: HearingCheckpointPhase.DEFENDER_PENDING,
            VlmRole.JUDGE: HearingCheckpointPhase.JUDGE_PENDING,
        }[self.request.role]
        if self.request.role == VlmRole.PROSECUTOR:
            expected_next_phase = HearingCheckpointPhase.DEFENDER_PENDING
            persisted_output = checkpoint.prosecutor_output
            if self.human_review_receipt is not None:
                raise ValueError("prosecutor success cannot claim human-review authority")
        elif self.request.role == VlmRole.DEFENDER:
            expected_next_phase = HearingCheckpointPhase.JUDGE_PENDING
            persisted_output = checkpoint.defender_output
            if self.human_review_receipt is not None:
                raise ValueError("defender success cannot claim human-review authority")
        else:
            assert isinstance(output.payload, JudgeModelPayload)
            persisted_output = checkpoint.judge_output
            if isinstance(output.payload.outcome, JudgeAcquisitionDecisionPayload):
                acquisition_exhausted = (
                    self.request.prior_acquisition_rounds >= self.session.acquisition_round_limit
                )
                expected_next_phase = (
                    HearingCheckpointPhase.HUMAN_REVIEW
                    if acquisition_exhausted
                    else HearingCheckpointPhase.ACQUISITION_PENDING
                )
                if acquisition_exhausted:
                    human = self.human_review_receipt
                    expected_request_ref = ArtifactRef(
                        kind=ArtifactKind.MODEL_REQUEST,
                        artifact_id=self.request.request_id,
                    )
                    if (
                        checkpoint.acquisition_request is not None
                        or checkpoint.tool_execution_receipt is not None
                        or human is None
                        or human.reason != HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED
                        or human.acquisition_request_ref != expected_request_ref
                        or human.run_id != self.request.run_id
                        or human.case_id != self.request.case_id
                        or human.hearing_session_id != self.request.hearing_session_id
                        or human.current_evidence_pack_id != self.request.current_evidence_pack_id
                        or human.current_evidence_pack_version
                        != self.request.current_evidence_pack_version
                        or human.judge_cycle != self.request.round_index
                        or human.source_checkpoint_id != self.source_checkpoint_id
                        or human.source_checkpoint_sha256 != self.source_checkpoint_sha256
                        or human.source_checkpoint_version != self.source_checkpoint_version
                        or checkpoint.human_review_receipt_id != human.receipt_id
                        or checkpoint.human_review_receipt_sha256 != human.receipt_sha256
                        or checkpoint.human_review_reason != human.reason
                    ):
                        raise ValueError(
                            "exhausted Judge acquisition requires exact human-review authority"
                        )
                elif self.human_review_receipt is not None:
                    raise ValueError("executable Judge acquisition cannot claim human review")
            else:
                expected_next_phase = HearingCheckpointPhase.ROUND_COMPLETE
                if self.human_review_receipt is not None:
                    raise ValueError("final Judge success cannot claim human-review authority")
        if (
            checkpoint.run_id != self.request.run_id
            or checkpoint.case_id != self.request.case_id
            or checkpoint.hearing_session_id != self.request.hearing_session_id
            or checkpoint.version != self.source_checkpoint_version + 1
            or checkpoint.previous_checkpoint_id != self.source_checkpoint_id
            or checkpoint.previous_checkpoint_sha256 != self.source_checkpoint_sha256
            or checkpoint.previous_phase != expected_previous_phase
            or checkpoint.phase != expected_next_phase
            or persisted_output != output
            or checkpoint.manifest_id != self.manifest_id
        ):
            raise ValueError("hearing backlog success does not advance the exact next checkpoint")
        matching_usage = tuple(
            item
            for item in checkpoint.usage_receipts
            if item.request_ref.artifact_id == self.request.request_id
        )
        if len(matching_usage) != 1:
            raise ValueError("hearing backlog success requires exactly one usage receipt")
        usage = matching_usage[0]
        if (
            usage.response_ref.artifact_id != self.response.response_id
            or usage.input_images != len(self.request.media)
            or usage.input_pixels != sum(item.width * item.height for item in self.request.media)
            or usage.input_tokens != self.response.input_tokens
            or usage.output_tokens != self.response.output_tokens
            or usage.latency_ms != self.response.latency_ms
        ):
            raise ValueError("hearing backlog success usage conflicts with its exact call")
        return self


class HearingBacklogRetryFailure(FrozenContractModel):
    """A failed M4 retry that preserves checkpoint state and controls generation."""

    schema_version: Literal["m4-hearing-backlog-retry-failure-v1"] = (
        "m4-hearing-backlog-retry-failure-v1"
    )
    outcome_kind: Literal["FAILURE"] = "FAILURE"
    lease: BacklogLeaseIdentity
    source_checkpoint_id: Sha256Hex
    source_checkpoint_sha256: Sha256Hex
    source_checkpoint_version: int = Field(gt=0, strict=True)
    request: HearingModelRequest
    request_binding: Literal[
        "LEASE_GENERATION_CALL",
        "BACKLOG_STAGE_INPUT",
    ] = "LEASE_GENERATION_CALL"
    lease_expiry_resume_request_ref: ArtifactRef | None = None
    role: HearingRole
    reason_code: BacklogReasonCode
    next_status: Literal[BacklogStatus.PENDING, BacklogStatus.EXHAUSTED]
    response_refs: tuple[ArtifactRef, ...] = Field(
        default=(),
        max_length=2,
    )
    strict_parse_failure: HearingStrictParseFailureProof | None = None
    human_review_receipt: HearingHumanReviewReceipt | None = None
    manifest_id: Sha256Hex

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
        names = ("next_retry_generation", "outcome_id")
        present = {name: name in payload for name in names}
        claimed = {name: payload.pop(name, None) for name in names}
        outcome = handler(payload)
        for name in names:
            if present[name] and claimed[name] != getattr(outcome, name):
                raise ValueError(f"serialized hearing backlog failure {name} conflicts")
        return outcome

    @computed_field  # type: ignore[prop-decorator]
    @property
    def next_retry_generation(self) -> int:
        if self.next_status == BacklogStatus.PENDING and self.strict_parse_failure is not None:
            return self.lease.retry_generation + 1
        return self.lease.retry_generation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outcome_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "hearing-backlog-retry-failure",
                1,
                self.lease.lease_identity_sha256,
                self.source_checkpoint_id,
                self.source_checkpoint_sha256,
                self.source_checkpoint_version,
                self.request.request_id,
                self.request.request_sha256,
                self.request_binding,
                (
                    self.lease_expiry_resume_request_ref.model_dump(mode="json")
                    if self.lease_expiry_resume_request_ref is not None
                    else None
                ),
                self.role.value,
                self.reason_code.value,
                self.next_status.value,
                [ref.model_dump(mode="json") for ref in self.response_refs],
                (
                    self.strict_parse_failure.proof_id
                    if self.strict_parse_failure is not None
                    else None
                ),
                (
                    self.human_review_receipt.receipt_id
                    if self.human_review_receipt is not None
                    else None
                ),
                self.next_retry_generation,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_failure(self) -> HearingBacklogRetryFailure:
        _stable_refs(
            self.response_refs,
            "hearing backlog failure response refs",
            allowed_kinds=frozenset({ArtifactKind.MODEL_RESPONSE}),
        )
        if (
            self.request.run_id != self.lease.run_id
            or self.request.role != self.role
            or self.request.manifest_id != self.manifest_id
        ):
            raise ValueError("hearing backlog failure conflicts with request or lease scope")
        if self.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED:
            resume_ref = self.lease_expiry_resume_request_ref
            if self.request_binding != "BACKLOG_STAGE_INPUT":
                raise ValueError("hearing lease expiry must bind the immutable backlog stage input")
            if resume_ref is not None and resume_ref.kind != ArtifactKind.MODEL_REQUEST:
                raise ValueError("hearing lease expiry resume ref must name a model request")
            if self.response_refs or self.strict_parse_failure is not None:
                raise ValueError("hearing lease expiry cannot claim model failure evidence")
        elif (
            self.request_binding != "LEASE_GENERATION_CALL"
            or self.lease_expiry_resume_request_ref is not None
            or not _request_matches_lease_generation(self.request, self.lease)
        ):
            raise ValueError("hearing model-call failure must bind its lease generation request")
        elif self.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID:
            proof = self.strict_parse_failure
            if proof is None:
                raise ValueError("hearing invalid output requires strict parse-failure proof")
            if (
                proof.lease != self.lease
                or proof.source_checkpoint_id != self.source_checkpoint_id
                or proof.source_checkpoint_sha256 != self.source_checkpoint_sha256
                or proof.source_checkpoint_version != self.source_checkpoint_version
                or proof.role != self.role
                or proof.attempts[0].request != self.request
            ):
                raise ValueError("hearing strict proof belongs to another retry authority")
            proof_responses = tuple(
                sorted(
                    (
                        ArtifactRef(
                            kind=ArtifactKind.MODEL_RESPONSE,
                            artifact_id=attempt.response.response_id,
                        )
                        for attempt in proof.attempts
                    ),
                    key=lambda ref: ref.sort_key,
                )
            )
            if self.response_refs != proof_responses:
                raise ValueError("hearing invalid-output refs must exactly match strict proof")
        elif self.strict_parse_failure is not None or self.response_refs:
            raise ValueError("only hearing MODEL_OUTPUT_INVALID can claim response refs or proof")
        if self.next_status == BacklogStatus.PENDING:
            if self.human_review_receipt is not None:
                raise ValueError("pending hearing retry cannot claim human-review authority")
        else:
            human = self.human_review_receipt
            expected_backlog_ref = ArtifactRef(
                kind=ArtifactKind.BACKLOG_ITEM,
                artifact_id=self.lease.item_id,
            )
            if (
                human is None
                or human.reason != HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED
                or human.backlog_item_ref != expected_backlog_ref
                or human.run_id != self.request.run_id
                or human.case_id != self.request.case_id
                or human.hearing_session_id != self.request.hearing_session_id
                or human.current_evidence_pack_id != self.request.current_evidence_pack_id
                or human.current_evidence_pack_version != self.request.current_evidence_pack_version
                or human.judge_cycle != self.request.round_index
                or human.source_checkpoint_id != self.source_checkpoint_id
                or human.source_checkpoint_sha256 != self.source_checkpoint_sha256
                or human.source_checkpoint_version != self.source_checkpoint_version
                or human.manifest_id != self.manifest_id
            ):
                raise ValueError("exhausted hearing retry requires its exact human-review receipt")
        return self


HearingBacklogRetryOutcome: TypeAlias = Annotated[
    HearingBacklogRetrySuccess | HearingBacklogRetryFailure,
    Field(discriminator="outcome_kind"),
]


class HearingBacklogCompletionReceipt(FrozenContractModel):
    """Idempotent closure for one leased hearing retry attempt."""

    schema_version: Literal["m4-hearing-backlog-completion-receipt-v1"] = (
        "m4-hearing-backlog-completion-receipt-v1"
    )
    outcome: HearingBacklogRetryOutcome
    backlog_status: Literal[
        BacklogStatus.PENDING,
        BacklogStatus.COMPLETED,
        BacklogStatus.EXHAUSTED,
    ]
    source_checkpoint_id: Sha256Hex
    source_checkpoint_sha256: Sha256Hex
    source_checkpoint_version: int = Field(gt=0, strict=True)
    resulting_checkpoint_id: Sha256Hex
    resulting_checkpoint_sha256: Sha256Hex
    resulting_checkpoint_version: int = Field(gt=0, strict=True)
    completion_case_status: Literal[
        CaseStatus.DELIBERATING,
        CaseStatus.BACKLOGGED,
        CaseStatus.HUMAN_REVIEW,
    ]
    completion_case_revision: int = Field(gt=0, strict=True)
    completion_audit_sequence: int = Field(ge=0, strict=True)
    completion_audit_entry_hash: Sha256Hex
    manifest_id: Sha256Hex

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
                raise ValueError(f"serialized hearing backlog {name} conflicts with content")
        return receipt

    def receipt_projection(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "outcome_id": self.outcome.outcome_id,
            "backlog_status": self.backlog_status.value,
            "source_checkpoint_id": self.source_checkpoint_id,
            "source_checkpoint_sha256": self.source_checkpoint_sha256,
            "source_checkpoint_version": self.source_checkpoint_version,
            "resulting_checkpoint_id": self.resulting_checkpoint_id,
            "resulting_checkpoint_sha256": self.resulting_checkpoint_sha256,
            "resulting_checkpoint_version": self.resulting_checkpoint_version,
            "completion_case_status": self.completion_case_status.value,
            "completion_case_revision": self.completion_case_revision,
            "completion_audit_sequence": self.completion_audit_sequence,
            "completion_audit_entry_hash": self.completion_audit_entry_hash,
            "manifest_id": self.manifest_id,
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(["hearing-backlog-completion-receipt", 1, self.receipt_projection()])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_sha256(self) -> Sha256Hex:
        return sha256_hex(
            ["hearing-backlog-completion-document", 1, self.receipt_id, self.receipt_projection()]
        )

    @model_validator(mode="after")
    def validate_completion(self) -> HearingBacklogCompletionReceipt:
        outcome = self.outcome
        if (
            outcome.source_checkpoint_id != self.source_checkpoint_id
            or outcome.source_checkpoint_sha256 != self.source_checkpoint_sha256
            or outcome.source_checkpoint_version != self.source_checkpoint_version
            or outcome.manifest_id != self.manifest_id
        ):
            raise ValueError("hearing backlog receipt conflicts with its source or manifest")
        if isinstance(outcome, HearingBacklogRetrySuccess):
            next_checkpoint = outcome.next_checkpoint
            expected_case_status = (
                CaseStatus.HUMAN_REVIEW
                if next_checkpoint.phase == HearingCheckpointPhase.HUMAN_REVIEW
                else CaseStatus.DELIBERATING
            )
            if (
                self.backlog_status != BacklogStatus.COMPLETED
                or self.completion_case_status != expected_case_status
                or self.resulting_checkpoint_id != next_checkpoint.checkpoint_id
                or self.resulting_checkpoint_sha256 != next_checkpoint.checkpoint_sha256
                or self.resulting_checkpoint_version != next_checkpoint.version
            ):
                raise ValueError("successful hearing retry must bind its exact next checkpoint")
        else:
            expected_case_status = (
                CaseStatus.BACKLOGGED
                if outcome.next_status == BacklogStatus.PENDING
                else CaseStatus.HUMAN_REVIEW
            )
            if (
                self.backlog_status != outcome.next_status
                or self.completion_case_status != expected_case_status
                or self.resulting_checkpoint_id != self.source_checkpoint_id
                or self.resulting_checkpoint_sha256 != self.source_checkpoint_sha256
                or self.resulting_checkpoint_version != self.source_checkpoint_version
            ):
                raise ValueError("failed hearing retry must preserve its source checkpoint")
        return self
