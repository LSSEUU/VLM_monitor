"""Pure construction and exact binding of M4 hearing Verdict proposals.

The builder maps only the latest terminal Judge ``FINAL`` payload.  It copies
the same cycle's advocate payloads, derives an acquisition log from durable tool
receipts, and retains the exact stable set of role-call response references.
It deliberately performs no L5 review and never repairs or normalizes a Judge
decision; structurally valid but procedurally defective proposals remain
bindable for the deterministic review layer.
"""

from __future__ import annotations

from typing import NamedTuple

from labcourt.contracts.enums import ArtifactKind, ViolationType
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingRecord,
    HearingVerdictBinding,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
    ToolExecutionReceipt,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import AcquisitionLogEntry, ProceduralReview, Verdict


class HearingVerdictBuildError(ValueError):
    """Typed hearing authority cannot be mapped to the requested Verdict."""


class HearingVerdictBuildResult(NamedTuple):
    """The immutable proposal and its independently persistable binding."""

    verdict: Verdict
    binding: HearingVerdictBinding


class HearingReviewClosure(NamedTuple):
    """Exact persisted authorities consumed by one procedural-review transition."""

    record: HearingRecord
    verdict: Verdict
    binding: HearingVerdictBinding
    review: ProceduralReview


def _require_positive_version(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("verdict version must be a positive integer")


def _exact_stable_refs(
    record: HearingRecord,
    attribute: str,
    expected_kind: ArtifactKind,
) -> tuple[ArtifactRef, ...]:
    refs = getattr(record, attribute)
    if not isinstance(refs, tuple):
        raise HearingVerdictBuildError(f"hearing {attribute} authority is not a tuple")
    if any(not isinstance(ref, ArtifactRef) or ref.kind != expected_kind for ref in refs):
        raise HearingVerdictBuildError(f"hearing {attribute} set contains the wrong ref kind")
    keys = tuple(ref.sort_key for ref in refs)
    if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
        raise HearingVerdictBuildError(f"hearing {attribute} set must be exact and stable")
    return refs


def _acquisition_summary(receipt: ToolExecutionReceipt) -> str:
    """Return bounded deterministic audit prose from typed execution closure."""

    result = receipt.tool_result
    return (
        f"{result.action.value} completed; tool_result_id={result.tool_result_id}; "
        f"output_count={len(result.output_refs)}."
    )


def _acquisition_log(record: HearingRecord) -> tuple[AcquisitionLogEntry, ...]:
    entries: list[AcquisitionLogEntry] = []
    for hearing_round in record.rounds:
        receipt = hearing_round.tool_execution_receipt
        if receipt is None:
            continue
        entries.append(
            AcquisitionLogEntry(
                round_index=hearing_round.round_index,
                action=receipt.request.action,
                request_ref=receipt.request.source_model_request_ref,
                tool_result_ref=ArtifactRef(
                    kind=ArtifactKind.TOOL_RESULT,
                    artifact_id=receipt.tool_result.tool_result_id,
                ),
                outcome_summary=_acquisition_summary(receipt),
            )
        )
    return tuple(entries)


def _terminal_payload(record: HearingRecord) -> JudgeFinalDecisionPayload:
    if not record.rounds:
        # Pydantic currently prevents this, but retain an explicit domain error
        # for deserialized or future aggregate implementations.
        raise HearingVerdictBuildError("hearing record has no Judge cycle")
    payload = record.rounds[-1].judge_output.payload
    if not isinstance(payload, JudgeModelPayload):
        raise HearingVerdictBuildError("terminal hearing output is not a Judge payload")
    if not isinstance(payload.outcome, JudgeFinalDecisionPayload):
        raise HearingVerdictBuildError("latest Judge output is not terminal FINAL")
    return payload.outcome


def _build_verdict(
    record: HearingRecord,
    violation_type: ViolationType,
    version: int,
) -> Verdict:
    terminal_round = record.rounds[-1]
    final = _terminal_payload(record)
    prosecutor = terminal_round.prosecutor_output.payload
    defender = terminal_round.defender_output.payload
    judge = terminal_round.judge_output.payload
    if not isinstance(prosecutor, ProsecutorModelPayload):
        raise HearingVerdictBuildError("terminal round lacks its Prosecutor payload")
    if not isinstance(defender, DefenderModelPayload):
        raise HearingVerdictBuildError("terminal round lacks its Defender payload")
    if not isinstance(judge, JudgeModelPayload):
        raise HearingVerdictBuildError("terminal round lacks its Judge payload")

    return Verdict(
        run_id=record.run_id,
        case_id=record.case_id,
        version=version,
        screening_id=record.screening_id,
        violation_type=violation_type,
        evidence_pack_id=terminal_round.current_evidence_pack_id,
        evidence_pack_version=terminal_round.current_evidence_pack_version,
        # Every field below is copied, not adjudicated.  L5 owns semantic and
        # cardinality defects, including an unanswered defense point.
        decision=final.decision,
        confidence=final.confidence,
        recommended_alert_level=final.recommended_alert_level,
        rationale_summary=final.rationale_summary,
        evidence_citations=final.evidence_citations,
        prosecution_arguments=prosecutor.arguments,
        defense_arguments=defender.arguments,
        judge_responses=judge.judge_responses,
        precedent_applications=judge.precedent_applications,
        acquisition_log=_acquisition_log(record),
        objective_claims=final.objective_claims,
        observation_sufficiency=final.observation_sufficiency,
        model_response_refs=_exact_stable_refs(
            record,
            "model_response_refs",
            ArtifactKind.MODEL_RESPONSE,
        ),
        manifest_id=record.manifest_id,
    )


def _build_binding(record: HearingRecord, verdict: Verdict) -> HearingVerdictBinding:
    terminal_round = record.rounds[-1]
    return HearingVerdictBinding(
        run_id=record.run_id,
        case_id=record.case_id,
        hearing_session_id=record.hearing_session_id,
        hearing_record_id=record.record_id,
        hearing_record_version=record.version,
        hearing_record_sha256=record.record_sha256,
        judge_round_id=terminal_round.round_id,
        judge_round_index=terminal_round.round_index,
        evidence_pack_id=terminal_round.current_evidence_pack_id,
        evidence_pack_version=terminal_round.current_evidence_pack_version,
        prosecutor_output_id=terminal_round.prosecutor_output.output_id,
        defender_output_id=terminal_round.defender_output.output_id,
        judge_output_id=terminal_round.judge_output.output_id,
        verdict_id=verdict.verdict_id,
        verdict_version=verdict.version,
        verdict_input_sha256=verdict.verdict_input_sha256,
        verdict_sha256=verdict.verdict_sha256,
        model_request_refs=_exact_stable_refs(
            record,
            "model_request_refs",
            ArtifactKind.MODEL_REQUEST,
        ),
        model_response_refs=_exact_stable_refs(
            record,
            "model_response_refs",
            ArtifactKind.MODEL_RESPONSE,
        ),
        parse_receipt_refs=_exact_stable_refs(
            record,
            "parse_receipt_refs",
            ArtifactKind.MODEL_PARSE_RECEIPT,
        ),
        manifest_id=record.manifest_id,
    )


def build_hearing_verdict(
    record: HearingRecord,
    violation_type: ViolationType,
    *,
    version: int = 1,
) -> HearingVerdictBuildResult:
    """Build and exactly bind the latest terminal hearing proposal."""

    if not isinstance(record, HearingRecord):
        raise TypeError("record must be a HearingRecord")
    if not isinstance(violation_type, ViolationType):
        raise TypeError("violation_type must be a ViolationType")
    _require_positive_version(version)
    verdict = _build_verdict(record, violation_type, version)
    binding = _build_binding(record, verdict)
    result = HearingVerdictBuildResult(verdict=verdict, binding=binding)
    validate_hearing_verdict_binding(
        record,
        verdict,
        binding,
        violation_type=violation_type,
    )
    return result


def validate_hearing_verdict_binding(
    record: HearingRecord,
    verdict: Verdict,
    binding: HearingVerdictBinding,
    *,
    violation_type: ViolationType | None = None,
) -> None:
    """Verify an exact record/output/Verdict closure, including all ref sets.

    ``violation_type`` should be supplied by the application when validating
    against current Case authority.  When omitted, the function still proves
    the complete hearing mapping and binding hashes using the frozen Verdict's
    own typed violation value.
    """

    if not isinstance(record, HearingRecord):
        raise TypeError("record must be a HearingRecord")
    if not isinstance(verdict, Verdict):
        raise TypeError("verdict must be a Verdict")
    if not isinstance(binding, HearingVerdictBinding):
        raise TypeError("binding must be a HearingVerdictBinding")
    expected_violation_type = verdict.violation_type if violation_type is None else violation_type
    if not isinstance(expected_violation_type, ViolationType):
        raise TypeError("violation_type must be a ViolationType")
    expected_verdict = _build_verdict(record, expected_violation_type, verdict.version)
    if verdict != expected_verdict:
        raise HearingVerdictBuildError(
            "verdict is not the exact frozen projection of the terminal hearing round"
        )
    expected_binding = _build_binding(record, expected_verdict)
    if binding != expected_binding:
        raise HearingVerdictBuildError(
            "hearing verdict binding does not exactly match its record and verdict"
        )


def validate_hearing_review_closure(closure: HearingReviewClosure) -> None:
    """Prove the Review targets the exact frozen hearing Verdict and pack."""

    if not isinstance(closure, HearingReviewClosure):
        raise TypeError("closure must be a HearingReviewClosure")
    record = closure.record
    verdict = closure.verdict
    binding = closure.binding
    review = closure.review
    validate_hearing_verdict_binding(record, verdict, binding)
    if not isinstance(review, ProceduralReview):
        raise TypeError("closure review must be a ProceduralReview")
    if (
        review.run_id != verdict.run_id
        or review.case_id != verdict.case_id
        or review.evidence_pack_id != verdict.evidence_pack_id
        or review.evidence_pack_version != verdict.evidence_pack_version
        or review.reviewed_verdict_id != verdict.verdict_id
        or review.reviewed_verdict_version != verdict.version
        or review.reviewed_verdict_sha256 != verdict.verdict_sha256
        or review.manifest_id != verdict.manifest_id
        or binding.verdict_id != review.reviewed_verdict_id
        or binding.verdict_version != review.reviewed_verdict_version
        or binding.verdict_input_sha256 != verdict.verdict_input_sha256
        or binding.verdict_sha256 != review.reviewed_verdict_sha256
        or binding.evidence_pack_id != review.evidence_pack_id
        or binding.evidence_pack_version != review.evidence_pack_version
    ):
        raise HearingVerdictBuildError(
            "procedural review does not close the exact hearing verdict binding"
        )


__all__ = [
    "HearingReviewClosure",
    "HearingVerdictBuildError",
    "HearingVerdictBuildResult",
    "build_hearing_verdict",
    "validate_hearing_review_closure",
    "validate_hearing_verdict_binding",
]
