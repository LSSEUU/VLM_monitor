"""Prepare the exact persisted authority for one M4 rework cycle."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingCycleScope,
    HearingReworkReceipt,
    HearingSession,
)
from labcourt.domain.hearing_fsm import (
    HearingTransitionError,
    start_rework_cycle,
)
from labcourt.domain.hearing_verdict_builder import HearingReviewClosure
from labcourt.exceptions import ContractViolation


class HearingReworkPreparationFailureCode(StrEnum):
    """Stable reasons a failed review cannot open an exact successor cycle."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    REVIEW_AUTHORITY_MISMATCH = "REVIEW_AUTHORITY_MISMATCH"
    REWORK_LIMIT_EXHAUSTED = "REWORK_LIMIT_EXHAUSTED"
    SUCCESSOR_TRANSITION_MISMATCH = "SUCCESSOR_TRANSITION_MISMATCH"


class HearingReworkPreparationError(ContractViolation):
    """A persisted failed review cannot authorize the requested rework."""

    def __init__(self, reason_code: HearingReworkPreparationFailureCode) -> None:
        if not isinstance(reason_code, HearingReworkPreparationFailureCode):
            raise TypeError("reason_code must be a HearingReworkPreparationFailureCode")
        self.reason_code = reason_code
        super().__init__(f"hearing rework preparation failed: {reason_code.value}")


def _fail(code: HearingReworkPreparationFailureCode) -> NoReturn:
    raise HearingReworkPreparationError(code)


@dataclass(frozen=True, slots=True)
class PreparedHearingRework:
    """One adjacent cycle, its opening checkpoint, and immutable rework receipt."""

    cycle_scope: HearingCycleScope
    checkpoint: HearingCheckpoint
    receipt: HearingReworkReceipt

    def __post_init__(self) -> None:
        if not isinstance(self.cycle_scope, HearingCycleScope):
            raise TypeError("cycle_scope must be a HearingCycleScope")
        if not isinstance(self.checkpoint, HearingCheckpoint):
            raise TypeError("checkpoint must be a HearingCheckpoint")
        if not isinstance(self.receipt, HearingReworkReceipt):
            raise TypeError("receipt must be a HearingReworkReceipt")
        if (
            self.checkpoint.phase != HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING
            or self.checkpoint.cycle_scope_id != self.cycle_scope.cycle_id
            or self.checkpoint.cycle_scope_sha256 != self.cycle_scope.cycle_sha256
            or self.receipt.next_cycle_scope_id != self.cycle_scope.cycle_id
            or self.receipt.next_cycle_scope_sha256 != self.cycle_scope.cycle_sha256
        ):
            raise ValueError("prepared rework roots do not share one successor cycle")


def cycle_scope_from_checkpoint(checkpoint: HearingCheckpoint) -> HearingCycleScope:
    """Rebuild the immutable cycle root carried by any exact checkpoint."""

    if not isinstance(checkpoint, HearingCheckpoint):
        raise TypeError("checkpoint must be a HearingCheckpoint")
    try:
        scope = HearingCycleScope(
            run_id=checkpoint.run_id,
            case_id=checkpoint.case_id,
            hearing_session_id=checkpoint.hearing_session_id,
            cycle_index=checkpoint.judge_cycle,
            prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
            prior_rework_rounds=checkpoint.prior_rework_rounds,
            cycle_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
            cycle_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
            initial_trigger_review_ref=checkpoint.initial_trigger_review_ref,
            initial_defect_codes=checkpoint.initial_defect_codes,
            rework_review_ref=checkpoint.cycle_trigger_review_ref,
            rework_defect_codes=checkpoint.cycle_trigger_defect_codes,
            manifest_id=checkpoint.manifest_id,
        )
    except (TypeError, ValueError):
        _fail(HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH)
    if (
        scope.cycle_id != checkpoint.cycle_scope_id
        or scope.cycle_sha256 != checkpoint.cycle_scope_sha256
    ):
        _fail(HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH)
    return scope


def _prompt_defect_summary_sha256(closure: HearingReviewClosure) -> str:
    review = closure.review
    return sha256_hex(
        [
            "hearing-rework-prompt-defect-summary",
            1,
            review.review_id,
            [
                defect.model_dump(mode="json")
                for defect in sorted(review.defects, key=lambda item: item.defect_id)
            ],
        ]
    )


def prepare_hearing_rework(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    closure: HearingReviewClosure,
) -> PreparedHearingRework:
    """Derive, but do not persist, one exact adjacent failed-review successor."""

    if (
        not isinstance(session, HearingSession)
        or not isinstance(checkpoint, HearingCheckpoint)
        or not isinstance(closure, HearingReviewClosure)
    ):
        _fail(HearingReworkPreparationFailureCode.INVALID_ARGUMENT)
    if checkpoint.phase != HearingCheckpointPhase.REWORK_READY:
        _fail(HearingReworkPreparationFailureCode.REVIEW_AUTHORITY_MISMATCH)
    try:
        transition = start_rework_cycle(session, checkpoint, closure)
    except (TypeError, ValueError, HearingTransitionError):
        _fail(HearingReworkPreparationFailureCode.REVIEW_AUTHORITY_MISMATCH)
    if transition.human_review_receipt is not None:
        _fail(HearingReworkPreparationFailureCode.REWORK_LIMIT_EXHAUSTED)
    successor = transition.checkpoint
    try:
        cycle = cycle_scope_from_checkpoint(successor)
        terminal_round = closure.record.rounds[-1]
        defect_codes = tuple(
            sorted(
                {defect.code for defect in closure.review.defects},
                key=lambda code: code.value,
            )
        )
        receipt = HearingReworkReceipt(
            run_id=successor.run_id,
            case_id=successor.case_id,
            hearing_session_id=successor.hearing_session_id,
            failed_review_id=closure.review.review_id,
            prior_round_id=terminal_round.round_id,
            next_cycle_scope_id=cycle.cycle_id,
            next_cycle_scope_sha256=cycle.cycle_sha256,
            rework_index=successor.prior_rework_rounds,
            defect_codes=defect_codes,
            prompt_defect_summary_sha256=_prompt_defect_summary_sha256(closure),
            manifest_id=successor.manifest_id,
        )
    except (IndexError, TypeError, ValueError):
        _fail(HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH)
    if (
        successor.previous_checkpoint_id != checkpoint.checkpoint_id
        or successor.previous_checkpoint_sha256 != checkpoint.checkpoint_sha256
        or successor.previous_phase != checkpoint.phase
        or terminal_round.round_index != checkpoint.judge_cycle
        or terminal_round.judge_output != checkpoint.judge_output
        or receipt.rework_index != checkpoint.prior_rework_rounds + 1
    ):
        _fail(HearingReworkPreparationFailureCode.SUCCESSOR_TRANSITION_MISMATCH)
    return PreparedHearingRework(
        cycle_scope=cycle,
        checkpoint=successor,
        receipt=receipt,
    )


__all__ = [
    "HearingReworkPreparationError",
    "HearingReworkPreparationFailureCode",
    "PreparedHearingRework",
    "cycle_scope_from_checkpoint",
    "prepare_hearing_rework",
]
