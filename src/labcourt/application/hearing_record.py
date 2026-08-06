"""Build exact M4 round and record projections from completed checkpoints."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingModelCallFailureAuthority,
    HearingPrecedentRetrievalStatus,
    HearingRecord,
    HearingRound,
    HearingSession,
    HearingUsageReceipt,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation


class HearingRecordBuildFailureCode(StrEnum):
    """Stable reasons checkpoint history cannot become record authority."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CHECKPOINT_NOT_ROUND_COMPLETE = "CHECKPOINT_NOT_ROUND_COMPLETE"
    CHECKPOINT_SCOPE_MISMATCH = "CHECKPOINT_SCOPE_MISMATCH"
    CHECKPOINT_SEQUENCE_INVALID = "CHECKPOINT_SEQUENCE_INVALID"
    ROUND_INVALID = "ROUND_INVALID"
    TRACE_CONFLICT = "TRACE_CONFLICT"
    RECORD_INVALID = "RECORD_INVALID"


class HearingRecordBuildError(ContractViolation):
    """Completed checkpoints do not form one valid append-only hearing record."""

    def __init__(self, reason_code: HearingRecordBuildFailureCode) -> None:
        if not isinstance(reason_code, HearingRecordBuildFailureCode):
            raise TypeError("reason_code must be HearingRecordBuildFailureCode")
        self.reason_code = reason_code
        super().__init__(f"hearing record build failed: {reason_code.value}")


def _fail(reason: HearingRecordBuildFailureCode) -> NoReturn:
    raise HearingRecordBuildError(reason)


def build_hearing_round(checkpoint: HearingCheckpoint) -> HearingRound:
    """Project one exact ``ROUND_COMPLETE`` checkpoint into a durable round."""

    if type(checkpoint) is not HearingCheckpoint:
        _fail(HearingRecordBuildFailureCode.INVALID_ARGUMENT)
    if checkpoint.phase != HearingCheckpointPhase.ROUND_COMPLETE:
        _fail(HearingRecordBuildFailureCode.CHECKPOINT_NOT_ROUND_COMPLETE)
    retrieval = checkpoint.precedent_retrieval_receipt
    prosecutor = checkpoint.prosecutor_output
    defender = checkpoint.defender_output
    judge = checkpoint.judge_output
    if retrieval is None or prosecutor is None or defender is None or judge is None:
        _fail(HearingRecordBuildFailureCode.CHECKPOINT_SCOPE_MISMATCH)
    try:
        hearing_round = HearingRound(
            run_id=checkpoint.run_id,
            case_id=checkpoint.case_id,
            hearing_session_id=checkpoint.hearing_session_id,
            round_index=checkpoint.judge_cycle,
            prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
            prior_rework_rounds=checkpoint.prior_rework_rounds,
            current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
            current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
            precedent_retrieval_degraded=(
                retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED
            ),
            precedent_retrieval_receipt=retrieval,
            initial_trigger_review_ref=checkpoint.initial_trigger_review_ref,
            initial_defect_codes=checkpoint.initial_defect_codes,
            rework_review_ref=checkpoint.cycle_trigger_review_ref,
            rework_defect_codes=checkpoint.cycle_trigger_defect_codes,
            prosecutor_output=prosecutor,
            defender_output=defender,
            judge_output=judge,
            acquisition_request=checkpoint.acquisition_request,
            tool_execution_receipt=checkpoint.tool_execution_receipt,
            manifest_id=checkpoint.manifest_id,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(HearingRecordBuildFailureCode.ROUND_INVALID)
    if (
        hearing_round.resulting_evidence_pack_id != checkpoint.current_evidence_pack_id
        or hearing_round.resulting_evidence_pack_version != checkpoint.current_evidence_pack_version
        or hearing_round.cycle_scope_id != checkpoint.cycle_scope_id
        or hearing_round.cycle_scope_sha256 != checkpoint.cycle_scope_sha256
    ):
        _fail(HearingRecordBuildFailureCode.CHECKPOINT_SCOPE_MISMATCH)
    return hearing_round


def _stable_unique_refs(
    checkpoints: tuple[HearingCheckpoint, ...],
    attribute: str,
) -> tuple[ArtifactRef, ...]:
    refs = tuple(ref for checkpoint in checkpoints for ref in getattr(checkpoint, attribute))
    keys = tuple(ref.sort_key for ref in refs)
    if len(keys) != len(set(keys)):
        _fail(HearingRecordBuildFailureCode.TRACE_CONFLICT)
    return tuple(sorted(refs, key=lambda ref: ref.sort_key))


def _stable_usage(
    checkpoints: tuple[HearingCheckpoint, ...],
) -> tuple[HearingUsageReceipt, ...]:
    usage = tuple(item for checkpoint in checkpoints for item in checkpoint.usage_receipts)
    keys = tuple(
        (item.round_index, item.role.value, item.request_ref.artifact_id) for item in usage
    )
    if len(keys) != len(set(keys)):
        _fail(HearingRecordBuildFailureCode.TRACE_CONFLICT)
    return tuple(
        sorted(
            usage,
            key=lambda item: (
                item.round_index,
                item.role.value,
                item.request_ref.artifact_id,
            ),
        )
    )


def _stable_failures(
    checkpoints: tuple[HearingCheckpoint, ...],
) -> tuple[HearingModelCallFailureAuthority, ...]:
    failures = tuple(item for checkpoint in checkpoints for item in checkpoint.failure_authorities)
    keys = tuple(item.authority_id for item in failures)
    if len(keys) != len(set(keys)):
        _fail(HearingRecordBuildFailureCode.TRACE_CONFLICT)
    return tuple(
        sorted(
            failures,
            key=lambda item: (
                item.request.round_index,
                item.role.value,
                item.request.request_id,
                item.authority_id,
            ),
        )
    )


def build_hearing_record(
    session: HearingSession,
    completed_checkpoints: tuple[HearingCheckpoint, ...],
) -> HearingRecord:
    """Build the complete prefix record from one round-complete checkpoint each."""

    if type(session) is not HearingSession or (
        not isinstance(completed_checkpoints, tuple)
        or not completed_checkpoints
        or any(type(item) is not HearingCheckpoint for item in completed_checkpoints)
    ):
        _fail(HearingRecordBuildFailureCode.INVALID_ARGUMENT)
    expected_indexes = tuple(range(1, len(completed_checkpoints) + 1))
    if tuple(item.judge_cycle for item in completed_checkpoints) != expected_indexes:
        _fail(HearingRecordBuildFailureCode.CHECKPOINT_SEQUENCE_INVALID)
    if any(
        item.run_id != session.run_id
        or item.case_id != session.case_id
        or item.hearing_session_id != session.session_id
        or item.hearing_session_sha256 != session.session_sha256
        or item.manifest_id != session.manifest_id
        for item in completed_checkpoints
    ):
        _fail(HearingRecordBuildFailureCode.CHECKPOINT_SCOPE_MISMATCH)
    rounds = tuple(build_hearing_round(item) for item in completed_checkpoints)
    try:
        return HearingRecord(
            run_id=session.run_id,
            case_id=session.case_id,
            version=len(rounds),
            session=session,
            screening_id=session.screening_id,
            initial_evidence_pack_id=session.initial_evidence_pack_id,
            initial_evidence_pack_version=session.initial_evidence_pack_version,
            acquisition_round_limit=session.acquisition_round_limit,
            rework_round_limit=session.rework_round_limit,
            rounds=rounds,
            model_request_refs=_stable_unique_refs(
                completed_checkpoints,
                "model_request_refs",
            ),
            model_response_refs=_stable_unique_refs(
                completed_checkpoints,
                "model_response_refs",
            ),
            parse_receipt_refs=_stable_unique_refs(
                completed_checkpoints,
                "parse_receipt_refs",
            ),
            usage_receipts=_stable_usage(completed_checkpoints),
            failure_authorities=_stable_failures(completed_checkpoints),
            manifest_id=session.manifest_id,
        )
    except HearingRecordBuildError:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(HearingRecordBuildFailureCode.RECORD_INVALID)


__all__ = [
    "HearingRecordBuildError",
    "HearingRecordBuildFailureCode",
    "build_hearing_record",
    "build_hearing_round",
]
