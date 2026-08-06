"""Derive executable acquisition authority from one persisted Judge output.

The Judge may only propose an acquisition.  This module is the narrow
application boundary that turns that proposal into an executable, case-scoped
request after every persisted session and checkpoint binding has been checked.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.enums import VlmRole
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingPrecedentRetrievalStatus,
    HearingRoleOutput,
    HearingSession,
    JudgeAcquisitionDecisionPayload,
    JudgeModelPayload,
)
from labcourt.exceptions import LabCourtError


class AcquisitionRequestBuildFailureCode(StrEnum):
    """Stable, non-sensitive acquisition-request construction failures."""

    SESSION_SCOPE_MISMATCH = "SESSION_SCOPE_MISMATCH"
    CHECKPOINT_PHASE_INVALID = "CHECKPOINT_PHASE_INVALID"
    ACQUISITION_LIMIT_EXHAUSTED = "ACQUISITION_LIMIT_EXHAUSTED"
    JUDGE_OUTPUT_SCOPE_MISMATCH = "JUDGE_OUTPUT_SCOPE_MISMATCH"
    JUDGE_OUTPUT_BINDING_MISMATCH = "JUDGE_OUTPUT_BINDING_MISMATCH"
    JUDGE_OUTCOME_NOT_ACQUISITION = "JUDGE_OUTCOME_NOT_ACQUISITION"


class AcquisitionRequestBuildError(LabCourtError):
    """Expected failure to derive executable authority from a Judge proposal."""

    def __init__(self, reason_code: AcquisitionRequestBuildFailureCode) -> None:
        if not isinstance(reason_code, AcquisitionRequestBuildFailureCode):
            raise TypeError("reason_code must be an AcquisitionRequestBuildFailureCode")
        self.reason_code = reason_code
        super().__init__(f"acquisition request build failed: {reason_code.value}")


def _fail(code: AcquisitionRequestBuildFailureCode) -> NoReturn:
    raise AcquisitionRequestBuildError(code)


def _validate_session_checkpoint(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
) -> None:
    if (
        checkpoint.run_id != session.run_id
        or checkpoint.case_id != session.case_id
        or checkpoint.hearing_session_id != session.session_id
        or checkpoint.hearing_session_sha256 != session.session_sha256
        or checkpoint.manifest_id != session.manifest_id
    ):
        _fail(AcquisitionRequestBuildFailureCode.SESSION_SCOPE_MISMATCH)
    if checkpoint.phase != HearingCheckpointPhase.JUDGE_PENDING:
        _fail(AcquisitionRequestBuildFailureCode.CHECKPOINT_PHASE_INVALID)
    if checkpoint.prior_acquisition_rounds >= session.acquisition_round_limit:
        _fail(AcquisitionRequestBuildFailureCode.ACQUISITION_LIMIT_EXHAUSTED)


def _validate_judge_output(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    output: HearingRoleOutput,
) -> JudgeAcquisitionDecisionPayload:
    payload = output.payload
    if output.role != VlmRole.JUDGE or not isinstance(payload, JudgeModelPayload):
        _fail(AcquisitionRequestBuildFailureCode.JUDGE_OUTPUT_SCOPE_MISMATCH)
    outcome = payload.outcome
    if not isinstance(outcome, JudgeAcquisitionDecisionPayload):
        _fail(AcquisitionRequestBuildFailureCode.JUDGE_OUTCOME_NOT_ACQUISITION)

    if (
        output.run_id != checkpoint.run_id
        or output.case_id != checkpoint.case_id
        or output.hearing_session_id != checkpoint.hearing_session_id
        or output.round_index != checkpoint.judge_cycle
        or output.prior_acquisition_rounds != checkpoint.prior_acquisition_rounds
        or output.prior_rework_rounds != checkpoint.prior_rework_rounds
        or output.current_evidence_pack_id != checkpoint.cycle_evidence_pack_id
        or output.current_evidence_pack_version != checkpoint.cycle_evidence_pack_version
        or output.manifest_id != checkpoint.manifest_id
        or output.model_manifest_id != session.judge_model_manifest_id
        or output.prompt_manifest.prompt_bundle_sha256 != session.hearing_prompt_bundle_sha256
    ):
        _fail(AcquisitionRequestBuildFailureCode.JUDGE_OUTPUT_SCOPE_MISMATCH)

    retrieval = checkpoint.precedent_retrieval_receipt
    prosecutor = checkpoint.prosecutor_output
    defender = checkpoint.defender_output
    if (
        retrieval is None
        or prosecutor is None
        or defender is None
        or checkpoint.judge_output is not None
        or checkpoint.acquisition_request is not None
        or checkpoint.tool_execution_receipt is not None
        or output.prosecutor_output_id != prosecutor.output_id
        or output.defender_output_id != defender.output_id
        or output.precedent_retrieval_degraded
        != (retrieval.status == HearingPrecedentRetrievalStatus.DEGRADED)
        or output.precedent_retrieval_receipt_id != retrieval.receipt_id
        or output.precedent_retrieval_receipt_sha256 != retrieval.receipt_sha256
        or output.initial_trigger_review_ref != checkpoint.initial_trigger_review_ref
        or output.initial_defect_codes != checkpoint.initial_defect_codes
        or output.rework_review_ref != checkpoint.cycle_trigger_review_ref
        or output.rework_defect_codes != checkpoint.cycle_trigger_defect_codes
    ):
        _fail(AcquisitionRequestBuildFailureCode.JUDGE_OUTPUT_BINDING_MISMATCH)
    return outcome


def build_acquisition_request(
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    judge_output: HearingRoleOutput,
) -> AcquisitionRequest:
    """Build the sole executable request matching a persisted Judge proposal."""

    if not isinstance(session, HearingSession):
        raise TypeError("session must be a HearingSession")
    if not isinstance(checkpoint, HearingCheckpoint):
        raise TypeError("checkpoint must be a HearingCheckpoint")
    if not isinstance(judge_output, HearingRoleOutput):
        raise TypeError("judge_output must be a HearingRoleOutput")

    _validate_session_checkpoint(session, checkpoint)
    outcome = _validate_judge_output(session, checkpoint, judge_output)
    return AcquisitionRequest(
        run_id=checkpoint.run_id,
        case_id=checkpoint.case_id,
        hearing_session_id=checkpoint.hearing_session_id,
        round_index=checkpoint.judge_cycle,
        prior_acquisition_rounds=checkpoint.prior_acquisition_rounds,
        prior_rework_rounds=checkpoint.prior_rework_rounds,
        current_evidence_pack_id=checkpoint.cycle_evidence_pack_id,
        current_evidence_pack_version=checkpoint.cycle_evidence_pack_version,
        source_judge_output_id=judge_output.output_id,
        source_model_request_ref=judge_output.request_ref,
        source_model_response_ref=judge_output.response_ref,
        request_payload=outcome.request,
        manifest_id=checkpoint.manifest_id,
    )
