"""Pure, append-only M4 hearing checkpoint transitions.

This module owns orchestration order only.  It performs no database, clock,
provider, tool, or procedural-gate work.  Every function consumes immutable
typed authority and returns the exact next :class:`HearingCheckpoint`; the
application layer is responsible for committing it atomically with the related
case and artifact records.

The two hearing counters are cumulative and never reset.  Consequently every
checkpoint obeys ``judge_cycle == 1 + acquisitions + reworks`` and the frozen
``1 + A + R <= 5`` rule makes a sixth logical Judge cycle unrepresentable.
"""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogStage,
    BacklogStatus,
    ModelParseStatus,
    ProceduralDefectCode,
    VlmRole,
)
from labcourt.contracts.hearing import (
    MAX_HEARING_JUDGE_CYCLES,
    AcquisitionRequest,
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingHumanReviewReason,
    HearingHumanReviewReceipt,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRoleOutput,
    HearingSession,
    HearingUsageReceipt,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ToolExecutionReceipt,
)
from labcourt.contracts.storage import ArtifactRef

from .hearing_verdict_builder import (
    HearingReviewClosure,
    HearingVerdictBuildError,
    validate_hearing_review_closure,
)


class HearingTransitionError(ValueError):
    """The supplied authority cannot make the requested pure transition."""


@dataclass(frozen=True, slots=True)
class HearingCallClosure:
    """One exact request/response/strict-parse/usage provider call."""

    request: HearingModelRequest
    response: HearingModelResponse
    parse_receipt: HearingModelParseReceipt
    usage: HearingUsageReceipt

    def __post_init__(self) -> None:
        if not isinstance(self.request, HearingModelRequest):
            raise TypeError("call closure request must be a HearingModelRequest")
        if not isinstance(self.response, HearingModelResponse):
            raise TypeError("call closure response must be a HearingModelResponse")
        if not isinstance(self.parse_receipt, HearingModelParseReceipt):
            raise TypeError("call closure parse receipt must be a HearingModelParseReceipt")
        if not isinstance(self.usage, HearingUsageReceipt):
            raise TypeError("call closure usage must be a HearingUsageReceipt")

        request = self.request
        response = self.response
        parse = self.parse_receipt
        usage = self.usage
        request_ref = ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        )
        response_ref = ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        )
        request_scope = (
            request.run_id,
            request.case_id,
            request.hearing_session_id,
            request.round_index,
            request.prior_acquisition_rounds,
            request.prior_rework_rounds,
            request.current_evidence_pack_id,
            request.current_evidence_pack_version,
            request.role,
            request.attempt_index,
            request.manifest_id,
        )
        response_scope = (
            response.run_id,
            response.case_id,
            response.hearing_session_id,
            response.round_index,
            response.prior_acquisition_rounds,
            response.prior_rework_rounds,
            response.current_evidence_pack_id,
            response.current_evidence_pack_version,
            response.role,
            response.attempt_index,
            response.manifest_id,
        )
        parse_scope = (
            parse.run_id,
            parse.case_id,
            parse.hearing_session_id,
            parse.round_index,
            parse.role,
            parse.attempt_index,
            parse.manifest_id,
        )
        if request_scope != response_scope or parse_scope != (
            request.run_id,
            request.case_id,
            request.hearing_session_id,
            request.round_index,
            request.role,
            request.attempt_index,
            request.manifest_id,
        ):
            raise ValueError("hearing call entities do not share one exact scope")
        if (
            response.request_id != request.request_id
            or response.request_sha256 != request.request_sha256
            or response.cache_key != request.cache_key
            or response.model_manifest_id != request.model_manifest_id
            or parse.request_id != request.request_id
            or parse.request_sha256 != request.request_sha256
            or parse.response_id != response.response_id
            or parse.response_content_sha256 != response.content_sha256
            or parse.output_schema_sha256 != request.prompt_manifest.output_schema_sha256
        ):
            raise ValueError("hearing response or parse receipt conflicts with its exact request")
        expected_images = len(request.media)
        expected_pixels = sum(item.width * item.height for item in request.media)
        if (
            usage.run_id != request.run_id
            or usage.case_id != request.case_id
            or usage.hearing_session_id != request.hearing_session_id
            or usage.round_index != request.round_index
            or usage.role != request.role
            or usage.request_ref != request_ref
            or usage.response_ref != response_ref
            or usage.input_images != expected_images
            or usage.input_pixels != expected_pixels
            or usage.input_tokens != response.input_tokens
            or usage.output_tokens != response.output_tokens
            or usage.latency_ms != response.latency_ms
            or usage.estimated_cost
            != request.budget.estimate_cost(
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            )
            or usage.manifest_id != request.manifest_id
        ):
            raise ValueError("hearing usage does not exactly account its request and response")
        if request.attempt_index == 1 and (expected_images != 0 or expected_pixels != 0):
            raise ValueError("hearing structure repair must disclose zero media")
        if (
            response.input_tokens > request.budget.max_input_tokens
            or response.output_tokens > request.budget.max_output_tokens
            or response.size_bytes > request.budget.max_response_bytes
            or not request.budget.allows_cost(
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            )
        ):
            raise ValueError("hearing response exceeds its request-bound budget")

    @property
    def request_ref(self) -> ArtifactRef:
        return ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=self.request.request_id,
        )

    @property
    def response_ref(self) -> ArtifactRef:
        return ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=self.response.response_id,
        )

    @property
    def parse_receipt_ref(self) -> ArtifactRef:
        return ArtifactRef(
            kind=ArtifactKind.MODEL_PARSE_RECEIPT,
            artifact_id=self.parse_receipt.parse_receipt_id,
        )


@dataclass(frozen=True, slots=True)
class HearingCallTrace:
    """One role's typed primary/optional-repair provider-call closure."""

    calls: tuple[HearingCallClosure, ...]

    def __post_init__(self) -> None:
        if len(self.calls) not in {1, 2} or any(
            not isinstance(call, HearingCallClosure) for call in self.calls
        ):
            raise ValueError("a hearing role trace requires one primary and at most one repair")
        if tuple(call.request.attempt_index for call in self.calls) != tuple(
            range(len(self.calls))
        ):
            raise ValueError("hearing role trace must contain primary then optional repair")
        primary = self.calls[0]
        terminal = self.calls[-1]
        if terminal.parse_receipt.status != ModelParseStatus.PARSED:
            raise ValueError("hearing role trace must end in a strict parsed result")
        if len(self.calls) == 1:
            return
        repair = self.calls[1]
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
            "provider_profile",
            "provider",
            "model",
            "revision",
            "model_manifest_id",
            "execution_location",
            "hearing_prompt_bundle_sha256",
            "allowed_evidence_refs",
            "allowed_precedent_refs",
            "prosecutor_output_ref",
            "defender_output_ref",
            "precedent_retrieval_degraded",
            "precedent_retrieval_receipt_id",
            "precedent_retrieval_receipt_sha256",
            "initial_trigger_review_ref",
            "initial_defect_codes",
            "rework_review_ref",
            "rework_defect_codes",
            "temperature",
            "seed",
            "backlog_retry_context",
            "manifest_id",
        )
        if any(
            getattr(primary.request, name) != getattr(repair.request, name) for name in same_scope
        ):
            raise ValueError("hearing repair changed primary call authority")
        if (
            primary.parse_receipt.status != ModelParseStatus.REPAIR_REQUIRED
            or primary.parse_receipt.repair_request_id != repair.request.request_id
            or repair.request.original_request_id != primary.request.request_id
            or repair.request.original_response_id != primary.response.response_id
            or repair.request.original_response_content_sha256 != primary.response.content_sha256
            or repair.request.budget.model_dump(exclude={"max_images", "max_input_pixels"})
            != primary.request.budget.model_dump(exclude={"max_images", "max_input_pixels"})
        ):
            raise ValueError("hearing repair lacks exact primary failure authority")

    @property
    def successful_call(self) -> HearingCallClosure:
        return self.calls[-1]

    @property
    def model_request_refs(self) -> tuple[ArtifactRef, ...]:
        return tuple(
            sorted((call.request_ref for call in self.calls), key=lambda ref: ref.sort_key)
        )

    @property
    def model_response_refs(self) -> tuple[ArtifactRef, ...]:
        return tuple(
            sorted((call.response_ref for call in self.calls), key=lambda ref: ref.sort_key)
        )

    @property
    def parse_receipt_refs(self) -> tuple[ArtifactRef, ...]:
        return tuple(
            sorted((call.parse_receipt_ref for call in self.calls), key=lambda ref: ref.sort_key)
        )

    @property
    def usage_receipts(self) -> tuple[HearingUsageReceipt, ...]:
        return tuple(
            sorted(
                (call.usage for call in self.calls),
                key=lambda item: item.request_ref.artifact_id,
            )
        )


@dataclass(frozen=True, slots=True)
class HearingTransition:
    """Next checkpoint plus the human receipt that must accompany it, if any."""

    checkpoint: HearingCheckpoint
    human_review_receipt: HearingHumanReviewReceipt | None = None

    def __post_init__(self) -> None:
        human = self.checkpoint.phase == HearingCheckpointPhase.HUMAN_REVIEW
        if human != (self.human_review_receipt is not None):
            raise ValueError("human-review checkpoint and receipt must be returned together")
        if self.human_review_receipt is not None and (
            self.checkpoint.human_review_receipt_id != self.human_review_receipt.receipt_id
            or self.checkpoint.human_review_receipt_sha256
            != self.human_review_receipt.receipt_sha256
            or self.checkpoint.human_review_reason != self.human_review_receipt.reason
            or self.checkpoint.previous_checkpoint_id
            != self.human_review_receipt.source_checkpoint_id
            or self.checkpoint.previous_checkpoint_sha256
            != self.human_review_receipt.source_checkpoint_sha256
            or self.checkpoint.version != self.human_review_receipt.source_checkpoint_version + 1
        ):
            raise ValueError("human-review checkpoint conflicts with its returned receipt")


def _validate_session(session: HearingSession, checkpoint: HearingCheckpoint) -> None:
    if not isinstance(session, HearingSession):
        raise TypeError("session must be a HearingSession")
    if not isinstance(checkpoint, HearingCheckpoint):
        raise TypeError("checkpoint must be a HearingCheckpoint")
    if (
        checkpoint.run_id != session.run_id
        or checkpoint.case_id != session.case_id
        or checkpoint.hearing_session_id != session.session_id
        or checkpoint.hearing_session_sha256 != session.session_sha256
        or checkpoint.manifest_id != session.manifest_id
    ):
        raise HearingTransitionError("checkpoint is outside the supplied hearing session")
    if checkpoint.judge_cycle > session.max_total_judge_cycles:
        raise HearingTransitionError("checkpoint already exceeds its immutable session budget")
    if (
        checkpoint.prior_acquisition_rounds > session.acquisition_round_limit
        or checkpoint.prior_rework_rounds > session.rework_round_limit
    ):
        raise HearingTransitionError("checkpoint counters exceed immutable session limits")


def _require_phase(checkpoint: HearingCheckpoint, phase: HearingCheckpointPhase) -> None:
    if checkpoint.phase != phase:
        raise HearingTransitionError(f"expected {phase.value}, found {checkpoint.phase.value}")


def _next_checkpoint(
    checkpoint: HearingCheckpoint,
    phase: HearingCheckpointPhase,
    **updates: object,
) -> HearingCheckpoint:
    payload = checkpoint.model_dump(mode="python", exclude_computed_fields=True)
    payload.update(
        {
            "version": checkpoint.version + 1,
            "phase": phase,
            "previous_checkpoint_id": checkpoint.checkpoint_id,
            "previous_checkpoint_sha256": checkpoint.checkpoint_sha256,
            "previous_phase": checkpoint.phase,
            **updates,
        }
    )
    return HearingCheckpoint.model_validate(payload)


def _validate_trace_scope(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    trace: HearingCallTrace,
    role: VlmRole,
    output: HearingRoleOutput,
) -> None:
    if not isinstance(trace, HearingCallTrace):
        raise TypeError("trace must be a HearingCallTrace")
    if not isinstance(output, HearingRoleOutput):
        raise TypeError("output must be a HearingRoleOutput")
    if output.role != role:
        raise HearingTransitionError("role output conflicts with the transition role")
    expected_model_manifest = {
        VlmRole.PROSECUTOR: session.prosecutor_model_manifest_id,
        VlmRole.DEFENDER: session.defender_model_manifest_id,
        VlmRole.JUDGE: session.judge_model_manifest_id,
    }[role]
    successful = trace.successful_call
    request = successful.request
    parse = successful.parse_receipt
    expected_prosecutor_ref = (
        ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=output.prosecutor_output_id,
        )
        if output.prosecutor_output_id is not None
        else None
    )
    expected_defender_ref = (
        ArtifactRef(
            kind=ArtifactKind.PARSED_MODEL_OUTPUT,
            artifact_id=output.defender_output_id,
        )
        if output.defender_output_id is not None
        else None
    )
    expected_precedent_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.PRECEDENT,
                    artifact_id=item.precedent.precedent_id,
                )
                for item in checkpoint.precedent_retrieval_receipt.scored_precedents
            ),
            key=lambda ref: ref.sort_key,
        )
        if checkpoint.precedent_retrieval_receipt is not None
        else ()
    )
    if (
        output.model_manifest_id != expected_model_manifest
        or output.prompt_manifest.prompt_bundle_sha256 != session.hearing_prompt_bundle_sha256
        or request.model_manifest_id != expected_model_manifest
        or request.hearing_prompt_bundle_sha256 != session.hearing_prompt_bundle_sha256
    ):
        raise HearingTransitionError("role output conflicts with session model or prompt authority")
    retrieval = checkpoint.precedent_retrieval_receipt
    if retrieval is None or (
        output.precedent_retrieval_receipt_id != retrieval.receipt_id
        or output.precedent_retrieval_receipt_sha256 != retrieval.receipt_sha256
        or output.precedent_retrieval_degraded
        != (retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED)
        or output.initial_trigger_review_ref != retrieval.initial_trigger_review_ref
        or output.initial_defect_codes != retrieval.initial_defect_codes
        or output.rework_review_ref != retrieval.rework_review_ref
        or output.rework_defect_codes != retrieval.rework_defect_codes
    ):
        raise HearingTransitionError("role output conflicts with precedent retrieval authority")
    if (
        request.run_id != checkpoint.run_id
        or request.case_id != checkpoint.case_id
        or request.hearing_session_id != checkpoint.hearing_session_id
        or request.round_index != checkpoint.judge_cycle
        or request.prior_acquisition_rounds != checkpoint.prior_acquisition_rounds
        or request.prior_rework_rounds != checkpoint.prior_rework_rounds
        or request.current_evidence_pack_id != checkpoint.cycle_evidence_pack_id
        or request.current_evidence_pack_version != checkpoint.cycle_evidence_pack_version
        or request.screening_ref
        != ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=session.screening_id,
        )
        or request.role != role
        or request.prompt_manifest != output.prompt_manifest
        or request.prosecutor_output_ref != expected_prosecutor_ref
        or request.defender_output_ref != expected_defender_ref
        or request.allowed_precedent_refs != expected_precedent_refs
        or request.evidence_class != retrieval.evidence_class
        or request.violation_type != retrieval.violation_type
        or request.precedent_retrieval_degraded != output.precedent_retrieval_degraded
        or request.precedent_retrieval_receipt_id != output.precedent_retrieval_receipt_id
        or request.precedent_retrieval_receipt_sha256 != output.precedent_retrieval_receipt_sha256
        or request.initial_trigger_review_ref != output.initial_trigger_review_ref
        or request.initial_defect_codes != output.initial_defect_codes
        or request.rework_review_ref != output.rework_review_ref
        or request.rework_defect_codes != output.rework_defect_codes
        or request.manifest_id != checkpoint.manifest_id
    ):
        raise HearingTransitionError("successful model request conflicts with checkpoint authority")
    if (
        output.request_ref != successful.request_ref
        or output.response_ref != successful.response_ref
        or output.parse_receipt_ref != successful.parse_receipt_ref
        or parse.parsed_payload_sha256 != output.payload.payload_sha256
    ):
        raise HearingTransitionError("role output is not closed by its complete call trace")
    for usage in trace.usage_receipts:
        if (
            usage.run_id != checkpoint.run_id
            or usage.case_id != checkpoint.case_id
            or usage.hearing_session_id != checkpoint.hearing_session_id
            or usage.round_index != checkpoint.judge_cycle
            or usage.role != role
            or usage.manifest_id != checkpoint.manifest_id
        ):
            raise HearingTransitionError("role usage is outside the checkpoint scope")


def _merged_trace(
    checkpoint: HearingCheckpoint,
    trace: HearingCallTrace,
) -> dict[str, object]:
    def merge_refs(
        current: tuple[ArtifactRef, ...],
        new: tuple[ArtifactRef, ...],
    ) -> tuple[ArtifactRef, ...]:
        combined = current + new
        keys = tuple(ref.sort_key for ref in combined)
        if len(keys) != len(set(keys)):
            raise HearingTransitionError("provider call trace reuses an existing artifact ref")
        return tuple(sorted(combined, key=lambda ref: ref.sort_key))

    usage = checkpoint.usage_receipts + trace.usage_receipts
    usage_keys = tuple(
        (item.round_index, item.role.value, item.request_ref.artifact_id) for item in usage
    )
    if len(usage_keys) != len(set(usage_keys)):
        raise HearingTransitionError("provider call trace reuses an existing usage authority")
    return {
        "model_request_refs": merge_refs(
            checkpoint.model_request_refs,
            trace.model_request_refs,
        ),
        "model_response_refs": merge_refs(
            checkpoint.model_response_refs,
            trace.model_response_refs,
        ),
        "parse_receipt_refs": merge_refs(
            checkpoint.parse_receipt_refs,
            trace.parse_receipt_refs,
        ),
        "usage_receipts": tuple(
            sorted(
                usage,
                key=lambda item: (
                    item.round_index,
                    item.role.value,
                    item.request_ref.artifact_id,
                ),
            )
        ),
    }


def begin_hearing(session: HearingSession) -> HearingCheckpoint:
    """Open cycle one at precedent retrieval without consuming any round."""

    if not isinstance(session, HearingSession):
        raise TypeError("session must be a HearingSession")
    return HearingCheckpoint(
        run_id=session.run_id,
        case_id=session.case_id,
        hearing_session_id=session.session_id,
        hearing_session_sha256=session.session_sha256,
        version=1,
        phase=HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        judge_cycle=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=session.initial_evidence_pack_id,
        cycle_evidence_pack_version=session.initial_evidence_pack_version,
        current_evidence_pack_id=session.initial_evidence_pack_id,
        current_evidence_pack_version=session.initial_evidence_pack_version,
        initial_trigger_review_ref=session.initial_trigger_review_ref,
        initial_defect_codes=session.initial_defect_codes,
        manifest_id=session.manifest_id,
    )


def complete_precedent_retrieval(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    receipt: HearingPrecedentRetrievalReceipt,
) -> HearingCheckpoint:
    """Persist retrieval (including typed degradation) before prosecution."""

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING)
    if not isinstance(receipt, HearingPrecedentRetrievalReceipt):
        raise TypeError("receipt must be a HearingPrecedentRetrievalReceipt")
    if (
        receipt.run_id != checkpoint.run_id
        or receipt.case_id != checkpoint.case_id
        or receipt.hearing_session_id != checkpoint.hearing_session_id
        or receipt.round_index != checkpoint.judge_cycle
        or receipt.prior_acquisition_rounds != checkpoint.prior_acquisition_rounds
        or receipt.prior_rework_rounds != checkpoint.prior_rework_rounds
        or receipt.current_evidence_pack_id != checkpoint.cycle_evidence_pack_id
        or receipt.current_evidence_pack_version != checkpoint.cycle_evidence_pack_version
        or receipt.initial_trigger_review_ref != checkpoint.initial_trigger_review_ref
        or receipt.initial_defect_codes != checkpoint.initial_defect_codes
        or receipt.rework_review_ref != checkpoint.cycle_trigger_review_ref
        or receipt.rework_defect_codes != checkpoint.cycle_trigger_defect_codes
        or receipt.manifest_id != checkpoint.manifest_id
    ):
        raise HearingTransitionError("retrieval conflicts with exact hearing cycle authority")
    return _next_checkpoint(
        checkpoint,
        HearingCheckpointPhase.PROSECUTOR_PENDING,
        precedent_retrieval_receipt=receipt,
    )


def complete_prosecutor(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    output: HearingRoleOutput,
    trace: HearingCallTrace,
) -> HearingCheckpoint:
    """Persist the prosecution output and its complete primary/repair trace."""

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.PROSECUTOR_PENDING)
    _validate_trace_scope(session, checkpoint, trace, VlmRole.PROSECUTOR, output)
    return _next_checkpoint(
        checkpoint,
        HearingCheckpointPhase.DEFENDER_PENDING,
        prosecutor_output=output,
        **_merged_trace(checkpoint, trace),
    )


def complete_defender(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    output: HearingRoleOutput,
    trace: HearingCallTrace,
) -> HearingCheckpoint:
    """Persist the defense output and its complete primary/repair trace."""

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.DEFENDER_PENDING)
    _validate_trace_scope(session, checkpoint, trace, VlmRole.DEFENDER, output)
    if (
        checkpoint.prosecutor_output is None
        or output.prosecutor_output_id != checkpoint.prosecutor_output.output_id
    ):
        raise HearingTransitionError("defense does not bind the persisted prosecution")
    return _next_checkpoint(
        checkpoint,
        HearingCheckpointPhase.JUDGE_PENDING,
        defender_output=output,
        **_merged_trace(checkpoint, trace),
    )


def _human_transition(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    reason: HearingHumanReviewReason,
    *,
    procedural_review_ref: ArtifactRef | None = None,
    backlog_item_ref: ArtifactRef | None = None,
    acquisition_request_ref: ArtifactRef | None = None,
    updates: dict[str, object] | None = None,
) -> HearingTransition:
    receipt = HearingHumanReviewReceipt(
        run_id=checkpoint.run_id,
        case_id=checkpoint.case_id,
        hearing_session_id=checkpoint.hearing_session_id,
        current_evidence_pack_id=checkpoint.current_evidence_pack_id,
        current_evidence_pack_version=checkpoint.current_evidence_pack_version,
        judge_cycle=checkpoint.judge_cycle,
        reason=reason,
        source_checkpoint_id=checkpoint.checkpoint_id,
        source_checkpoint_sha256=checkpoint.checkpoint_sha256,
        source_checkpoint_version=checkpoint.version,
        procedural_review_ref=procedural_review_ref,
        backlog_item_ref=backlog_item_ref,
        acquisition_request_ref=acquisition_request_ref,
        manifest_id=session.manifest_id,
    )
    next_updates = dict(updates or {})
    next_updates.update(
        {
            "human_review_receipt_id": receipt.receipt_id,
            "human_review_receipt_sha256": receipt.receipt_sha256,
            "human_review_reason": receipt.reason,
        }
    )
    return HearingTransition(
        checkpoint=_next_checkpoint(
            checkpoint,
            HearingCheckpointPhase.HUMAN_REVIEW,
            **next_updates,
        ),
        human_review_receipt=receipt,
    )


def complete_judge(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    output: HearingRoleOutput,
    trace: HearingCallTrace,
    *,
    acquisition_request: AcquisitionRequest | None = None,
) -> HearingTransition:
    """Persist one Judge outcome without rewriting it or inventing a full round.

    A third acquisition proposal goes directly to typed human review.  It keeps
    the Judge output and all call refs, but intentionally has no executable
    :class:`AcquisitionRequest`, tool receipt, or fabricated ``HearingRound``.
    """

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.JUDGE_PENDING)
    _validate_trace_scope(session, checkpoint, trace, VlmRole.JUDGE, output)
    if (
        checkpoint.prosecutor_output is None
        or checkpoint.defender_output is None
        or output.prosecutor_output_id != checkpoint.prosecutor_output.output_id
        or output.defender_output_id != checkpoint.defender_output.output_id
    ):
        raise HearingTransitionError("Judge does not bind both persisted advocates")
    payload = output.payload
    if not isinstance(payload, JudgeModelPayload):
        raise HearingTransitionError("Judge transition requires a Judge payload")
    trace_updates = _merged_trace(checkpoint, trace)
    output_updates = {"judge_output": output, **trace_updates}
    if isinstance(payload.outcome, JudgeFinalDecisionPayload):
        if acquisition_request is not None:
            raise HearingTransitionError("FINAL Judge outcome cannot carry acquisition authority")
        return HearingTransition(
            checkpoint=_next_checkpoint(
                checkpoint,
                HearingCheckpointPhase.ROUND_COMPLETE,
                **output_updates,
            )
        )

    if checkpoint.prior_acquisition_rounds >= session.acquisition_round_limit:
        if acquisition_request is not None:
            raise HearingTransitionError(
                "exhausted acquisition proposal cannot create executable acquisition authority"
            )
        return _human_transition(
            session,
            checkpoint,
            HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED,
            acquisition_request_ref=output.request_ref,
            updates=output_updates,
        )
    if acquisition_request is None:
        raise HearingTransitionError("Judge acquisition outcome requires its scoped request")
    if (
        acquisition_request.run_id != checkpoint.run_id
        or acquisition_request.case_id != checkpoint.case_id
        or acquisition_request.hearing_session_id != checkpoint.hearing_session_id
        or acquisition_request.source_judge_output_id != output.output_id
        or acquisition_request.source_model_request_ref != output.request_ref
        or acquisition_request.source_model_response_ref != output.response_ref
        or acquisition_request.request_payload != payload.outcome.request
        or acquisition_request.round_index != checkpoint.judge_cycle
        or acquisition_request.prior_acquisition_rounds != checkpoint.prior_acquisition_rounds
        or acquisition_request.prior_rework_rounds != checkpoint.prior_rework_rounds
        or acquisition_request.current_evidence_pack_id != checkpoint.cycle_evidence_pack_id
        or acquisition_request.current_evidence_pack_version
        != checkpoint.cycle_evidence_pack_version
        or acquisition_request.manifest_id != checkpoint.manifest_id
    ):
        raise HearingTransitionError("acquisition request conflicts with the Judge proposal")
    return HearingTransition(
        checkpoint=_next_checkpoint(
            checkpoint,
            HearingCheckpointPhase.ACQUISITION_PENDING,
            acquisition_request=acquisition_request,
            **output_updates,
        )
    )


def complete_acquisition(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    receipt: ToolExecutionReceipt,
) -> HearingCheckpoint:
    """Persist a successful tool closure; counters still remain unchanged here."""

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.ACQUISITION_PENDING)
    if not isinstance(receipt, ToolExecutionReceipt):
        raise TypeError("receipt must be a ToolExecutionReceipt")
    if checkpoint.acquisition_request is None or receipt.request != checkpoint.acquisition_request:
        raise HearingTransitionError("tool receipt does not close the pending acquisition")
    return _next_checkpoint(
        checkpoint,
        HearingCheckpointPhase.ROUND_COMPLETE,
        tool_execution_receipt=receipt,
        current_evidence_pack_id=receipt.resulting_evidence_pack_id,
        current_evidence_pack_version=receipt.resulting_evidence_pack_version,
    )


def _open_cycle(
    checkpoint: HearingCheckpoint,
    *,
    judge_cycle: int,
    acquisitions: int,
    reworks: int,
    cycle_trigger_review_ref: ArtifactRef | None,
    cycle_trigger_defect_codes: tuple[ProceduralDefectCode, ...],
) -> HearingCheckpoint:
    return _next_checkpoint(
        checkpoint,
        HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING,
        judge_cycle=judge_cycle,
        prior_acquisition_rounds=acquisitions,
        prior_rework_rounds=reworks,
        cycle_evidence_pack_id=checkpoint.current_evidence_pack_id,
        cycle_evidence_pack_version=checkpoint.current_evidence_pack_version,
        initial_trigger_review_ref=None,
        initial_defect_codes=(),
        cycle_trigger_review_ref=cycle_trigger_review_ref,
        cycle_trigger_defect_codes=cycle_trigger_defect_codes,
        precedent_retrieval_receipt=None,
        prosecutor_output=None,
        defender_output=None,
        judge_output=None,
        acquisition_request=None,
        tool_execution_receipt=None,
        procedural_review_ref=None,
        human_review_receipt_id=None,
        human_review_receipt_sha256=None,
        human_review_reason=None,
        model_request_refs=(),
        model_response_refs=(),
        parse_receipt_refs=(),
        usage_receipts=(),
        failure_authorities=(),
    )


def start_cycle_after_acquisition(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
) -> HearingTransition:
    """Consume one global acquisition round and open the next full role cycle."""

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.ROUND_COMPLETE)
    if checkpoint.tool_execution_receipt is None:
        raise HearingTransitionError("round did not complete an acquisition")
    acquisitions = checkpoint.prior_acquisition_rounds + 1
    cycle = checkpoint.judge_cycle + 1
    if acquisitions > session.acquisition_round_limit:
        if checkpoint.judge_output is None:
            raise HearingTransitionError("completed acquisition lacks its Judge output")
        return _human_transition(
            session,
            checkpoint,
            HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED,
            acquisition_request_ref=checkpoint.judge_output.request_ref,
        )
    if cycle > session.max_total_judge_cycles or cycle > MAX_HEARING_JUDGE_CYCLES:
        raise HearingTransitionError("acquisition counters cannot authorize another Judge cycle")
    return HearingTransition(
        checkpoint=_open_cycle(
            checkpoint,
            judge_cycle=cycle,
            acquisitions=acquisitions,
            reworks=checkpoint.prior_rework_rounds,
            cycle_trigger_review_ref=checkpoint.cycle_trigger_review_ref,
            cycle_trigger_defect_codes=checkpoint.cycle_trigger_defect_codes,
        )
    )


def record_procedural_review(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    closure: HearingReviewClosure,
) -> HearingCheckpoint:
    """Record review outcome only; this function never calls the L5 gate."""

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.ROUND_COMPLETE)
    if checkpoint.judge_output is None:
        raise HearingTransitionError("review requires a terminal Judge output")
    payload = checkpoint.judge_output.payload
    if not isinstance(payload, JudgeModelPayload) or not isinstance(
        payload.outcome,
        JudgeFinalDecisionPayload,
    ):
        raise HearingTransitionError("acquisition rounds cannot enter procedural review")
    _validate_review_checkpoint(checkpoint, closure)
    review = closure.review
    return _next_checkpoint(
        checkpoint,
        (HearingCheckpointPhase.COMPLETE if review.passed else HearingCheckpointPhase.REWORK_READY),
        procedural_review_ref=ArtifactRef(
            kind=ArtifactKind.PROCEDURAL_REVIEW,
            artifact_id=review.review_id,
        ),
    )


def _validate_review_checkpoint(
    checkpoint: HearingCheckpoint,
    closure: HearingReviewClosure,
) -> None:
    try:
        validate_hearing_review_closure(closure)
    except HearingVerdictBuildError as error:
        raise HearingTransitionError(str(error)) from error
    record = closure.record
    binding = closure.binding
    terminal_round = record.rounds[-1]
    if (
        record.run_id != checkpoint.run_id
        or record.case_id != checkpoint.case_id
        or record.hearing_session_id != checkpoint.hearing_session_id
        or record.session.session_sha256 != checkpoint.hearing_session_sha256
        or record.manifest_id != checkpoint.manifest_id
        or terminal_round.current_evidence_pack_id != checkpoint.current_evidence_pack_id
        or terminal_round.current_evidence_pack_version != checkpoint.current_evidence_pack_version
        or checkpoint.judge_output is None
        or terminal_round.judge_output.output_id != checkpoint.judge_output.output_id
        or binding.hearing_session_id != checkpoint.hearing_session_id
        or binding.judge_round_index != checkpoint.judge_cycle
        or binding.evidence_pack_id != checkpoint.current_evidence_pack_id
        or binding.evidence_pack_version != checkpoint.current_evidence_pack_version
        or binding.judge_output_id != checkpoint.judge_output.output_id
        or binding.manifest_id != checkpoint.manifest_id
        or checkpoint.precedent_retrieval_receipt is None
        or closure.verdict.violation_type != checkpoint.precedent_retrieval_receipt.violation_type
    ):
        raise HearingTransitionError(
            "procedural review closure conflicts with checkpoint authority"
        )
    for checkpoint_refs, record_refs, name in (
        (checkpoint.model_request_refs, record.model_request_refs, "request"),
        (checkpoint.model_response_refs, record.model_response_refs, "response"),
        (checkpoint.parse_receipt_refs, record.parse_receipt_refs, "parse receipt"),
    ):
        if not set(checkpoint_refs).issubset(record_refs):
            raise HearingTransitionError(
                f"procedural review record omits current checkpoint {name} authority"
            )


def start_rework_cycle(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    closure: HearingReviewClosure,
) -> HearingTransition:
    """After durable ``REWORK_READY``, open one rework or transfer to a human."""

    _validate_session(session, checkpoint)
    _require_phase(checkpoint, HearingCheckpointPhase.REWORK_READY)
    if checkpoint.procedural_review_ref is None:
        raise HearingTransitionError("rework-ready checkpoint lacks its failed review")
    _validate_review_checkpoint(checkpoint, closure)
    review_ref = ArtifactRef(
        kind=ArtifactKind.PROCEDURAL_REVIEW,
        artifact_id=closure.review.review_id,
    )
    if closure.review.passed or checkpoint.procedural_review_ref != review_ref:
        raise HearingTransitionError("rework requires the checkpoint's exact failed review")
    if checkpoint.prior_rework_rounds >= session.rework_round_limit:
        return _human_transition(
            session,
            checkpoint,
            HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED,
            procedural_review_ref=review_ref,
        )
    reworks = checkpoint.prior_rework_rounds + 1
    cycle = checkpoint.judge_cycle + 1
    if cycle > session.max_total_judge_cycles or cycle > MAX_HEARING_JUDGE_CYCLES:
        raise HearingTransitionError("rework counters cannot authorize another Judge cycle")
    return HearingTransition(
        checkpoint=_open_cycle(
            checkpoint,
            judge_cycle=cycle,
            acquisitions=checkpoint.prior_acquisition_rounds,
            reworks=reworks,
            cycle_trigger_review_ref=review_ref,
            cycle_trigger_defect_codes=tuple(defect.code for defect in closure.review.defects),
        )
    )


def transfer_to_human_review(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    reason: HearingHumanReviewReason,
    *,
    procedural_review_ref: ArtifactRef | None = None,
    backlog_item: BacklogItem | None = None,
    acquisition_request_ref: ArtifactRef | None = None,
) -> HearingTransition:
    """Dispatch only explicitly allowed source-phase/reason authority matrices."""

    _validate_session(session, checkpoint)
    if not isinstance(reason, HearingHumanReviewReason):
        raise TypeError("reason must be a HearingHumanReviewReason")
    if reason == HearingHumanReviewReason.ACQUISITION_LIMIT_EXHAUSTED:
        raise HearingTransitionError(
            "acquisition-limit transfer is owned by the exact Judge transition"
        )
    if reason == HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED:
        raise HearingTransitionError(
            "rework-limit transfer is owned by the exact failed-review transition"
        )
    allowed_phases = {
        HearingHumanReviewReason.HEARING_BUDGET_EXHAUSTED: frozenset(
            {
                HearingCheckpointPhase.PROSECUTOR_PENDING,
                HearingCheckpointPhase.DEFENDER_PENDING,
                HearingCheckpointPhase.JUDGE_PENDING,
            }
        ),
        HearingHumanReviewReason.EVIDENCE_UNAVAILABLE: frozenset(
            {HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING}
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
    }[reason]
    if checkpoint.phase not in allowed_phases:
        raise HearingTransitionError("human-review reason is not allowed from this phase")

    if procedural_review_ref is not None:
        raise HearingTransitionError("human-review reason has the wrong procedural authority")

    expected_acquisition: ArtifactRef | None = None
    if reason == HearingHumanReviewReason.ACQUISITION_UNRECOVERABLE:
        if checkpoint.acquisition_request is None:
            raise HearingTransitionError("unrecoverable acquisition lacks its exact request")
        expected_acquisition = checkpoint.acquisition_request.source_model_request_ref
    if acquisition_request_ref != expected_acquisition:
        raise HearingTransitionError("human-review reason has the wrong acquisition authority")

    backlog_item_ref: ArtifactRef | None = None
    if reason == HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED:
        if not isinstance(backlog_item, BacklogItem):
            raise HearingTransitionError("backlog exhaustion requires the typed exhausted item")
        expected_role = {
            HearingCheckpointPhase.PROSECUTOR_PENDING: VlmRole.PROSECUTOR,
            HearingCheckpointPhase.DEFENDER_PENDING: VlmRole.DEFENDER,
            HearingCheckpointPhase.JUDGE_PENDING: VlmRole.JUDGE,
        }[checkpoint.phase]
        if (
            backlog_item.run_id != checkpoint.run_id
            or backlog_item.case_id != checkpoint.case_id
            or backlog_item.stage != BacklogStage.HEARING
            or backlog_item.role != expected_role
            or backlog_item.status != BacklogStatus.EXHAUSTED
            or backlog_item.manifest_id != checkpoint.manifest_id
        ):
            raise HearingTransitionError("backlog item conflicts with the exact pending role")
        backlog_item_ref = ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=backlog_item.item_id,
        )
    elif backlog_item is not None:
        raise HearingTransitionError("only backlog exhaustion accepts backlog authority")

    return _human_transition(
        session,
        checkpoint,
        reason,
        procedural_review_ref=procedural_review_ref,
        backlog_item_ref=backlog_item_ref,
        acquisition_request_ref=acquisition_request_ref,
    )


# Short aliases keep application code readable without creating a second state
# model that could drift from the serialized contract.
HearingPhase = HearingCheckpointPhase
HearingState = HearingCheckpoint


__all__ = [
    "HearingCallClosure",
    "HearingCallTrace",
    "HearingPhase",
    "HearingState",
    "HearingTransition",
    "HearingTransitionError",
    "begin_hearing",
    "complete_acquisition",
    "complete_defender",
    "complete_judge",
    "complete_precedent_retrieval",
    "complete_prosecutor",
    "record_procedural_review",
    "start_cycle_after_acquisition",
    "start_rework_cycle",
    "transfer_to_human_review",
]
