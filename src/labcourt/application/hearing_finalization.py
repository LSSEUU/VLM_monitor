"""Persist an M4 round and finalize only a terminal Judge proposal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from labcourt.application.hearing_history import (
    build_hearing_call_history,
    derive_hearing_evidence_grant,
)
from labcourt.application.hearing_record import build_hearing_round
from labcourt.application.hearing_rework import cycle_scope_from_checkpoint
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing import (
    HearingCheckpoint,
    HearingRecord,
    HearingSession,
    HearingVerdictBinding,
)
from labcourt.contracts.storage import ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.evidence_authority import HearingEvidenceGrant
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    record_procedural_review,
    start_cycle_after_acquisition,
)
from labcourt.domain.hearing_verdict_builder import (
    HearingReviewClosure,
    build_hearing_verdict,
)
from labcourt.ports.evidence_repository import (
    AuditHead,
    CaseSnapshot,
    EvidenceRepository,
)
from labcourt.ports.hearing_repository import HearingRepository


class HearingReviewVerifier(Protocol):
    """Deterministically rebuild the frozen L5 review from hearing roots."""

    def rebuild_review(
        self,
        *,
        record: HearingRecord,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        evidence_pack: EvidencePack,
        current_closure: ClosureReport,
        call_history: tuple[HearingCallClosure, ...],
        evidence_grant: HearingEvidenceGrant,
        review_version: int,
    ) -> ProceduralReview: ...


@dataclass(frozen=True, slots=True)
class HearingRoundAdvance:
    """The next cycle, failed proposal, or successful terminal proposal."""

    checkpoint: HearingCheckpoint
    case: CaseSnapshot | None = None
    record: HearingRecord | None = None
    verdict: Verdict | None = None
    review: ProceduralReview | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint, HearingCheckpoint):
            raise TypeError("checkpoint must be a HearingCheckpoint")
        expected = (
            (self.case, CaseSnapshot, "case"),
            (self.record, HearingRecord, "record"),
            (self.verdict, Verdict, "verdict"),
            (self.review, ProceduralReview, "review"),
        )
        for value, kind, name in expected:
            if value is not None and not isinstance(value, kind):
                raise TypeError(f"{name} has the wrong contract type")
        if (self.verdict is None) != (self.review is None):
            raise ValueError("verdict and review must be returned together")


def _history_for_record(
    repository: HearingRepository,
    record: HearingRecord,
) -> tuple[HearingCallClosure, ...]:
    request_ids = {item.artifact_id for item in record.model_request_refs}
    response_ids = {item.artifact_id for item in record.model_response_refs}
    parse_ids = {item.artifact_id for item in record.parse_receipt_refs}
    usage_ids = {item.usage_receipt_id for item in record.usage_receipts}
    requests = tuple(
        item
        for item in repository.list_hearing_model_requests(
            record.run_id,
            record.hearing_session_id,
        )
        if item.request_id in request_ids
    )
    responses = tuple(
        item
        for item in repository.list_hearing_model_responses(
            record.run_id,
            record.hearing_session_id,
        )
        if item.response_id in response_ids
    )
    parses = tuple(
        item
        for item in repository.list_hearing_parse_receipts(
            record.run_id,
            record.hearing_session_id,
        )
        if item.parse_receipt_id in parse_ids
    )
    usage = tuple(
        item
        for item in repository.list_hearing_usage_receipts(
            record.run_id,
            record.hearing_session_id,
        )
        if item.usage_receipt_id in usage_ids
    )
    return build_hearing_call_history(
        record,
        requests=requests,
        responses=responses,
        parse_receipts=parses,
        usage_receipts=usage,
    )


def complete_and_review_hearing_round(
    *,
    session: HearingSession,
    checkpoint: HearingCheckpoint,
    source_case: CaseSnapshot,
    audit_head: AuditHead,
    repository: HearingRepository,
    evidence_repository: EvidenceRepository,
    review_verifier: HearingReviewVerifier,
) -> HearingRoundAdvance:
    """Persist one complete round, then open a cycle or atomically review."""

    hearing_round = build_hearing_round(checkpoint)
    repository.complete_hearing_round(checkpoint.run_id, hearing_round)
    if checkpoint.tool_execution_receipt is not None:
        transition = start_cycle_after_acquisition(session, checkpoint)
        if transition.human_review_receipt is not None:
            human_committed = repository.commit_hearing_human_review(
                checkpoint.run_id,
                source_case.revision,
                audit_head,
                transition.human_review_receipt,
                transition.checkpoint,
            )
            return HearingRoundAdvance(
                checkpoint=human_committed.checkpoint,
                case=human_committed.case,
            )
        cycle = cycle_scope_from_checkpoint(transition.checkpoint)
        repository.append_hearing_cycle(checkpoint.run_id, cycle)
        repository.append_hearing_checkpoint(
            checkpoint.run_id,
            transition.checkpoint,
        )
        return HearingRoundAdvance(checkpoint=transition.checkpoint)

    record = repository.load_hearing_record(
        checkpoint.run_id,
        session.session_id,
    )
    if record is None:
        raise ValueError("terminal hearing round did not produce a record")
    current_case = source_case.case
    if (
        not current_case.evidence_packs
        or current_case.evidence_packs[-1].pack_id != record.current_evidence_pack_id
        or current_case.evidence_packs[-1].version != record.current_evidence_pack_version
    ):
        raise ValueError("terminal hearing record conflicts with current Case evidence")
    evidence_pack = current_case.evidence_packs[-1]
    built = build_hearing_verdict(
        record,
        evidence_pack.event.violation_type,
        version=len(current_case.verdicts) + 1,
    )
    history = _history_for_record(repository, record)
    grant = derive_hearing_evidence_grant(record, history)
    closure = evidence_repository.verify_current_pack(
        checkpoint.run_id,
        evidence_pack.pack_id,
    )
    review = review_verifier.rebuild_review(
        record=record,
        verdict=built.verdict,
        binding=built.binding,
        evidence_pack=evidence_pack,
        current_closure=closure,
        call_history=history,
        evidence_grant=grant,
        review_version=len(current_case.procedural_reviews) + 1,
    )
    review_closure = HearingReviewClosure(
        record=record,
        verdict=built.verdict,
        binding=built.binding,
        review=review,
    )
    successor = record_procedural_review(
        session,
        checkpoint,
        review_closure,
    )
    verdict_committed = repository.commit_hearing_verdict_review(
        checkpoint.run_id,
        source_case.revision,
        audit_head,
        built.verdict,
        built.binding,
        review,
        successor,
    )
    return HearingRoundAdvance(
        checkpoint=verdict_committed.checkpoint,
        case=verdict_committed.case,
        record=record,
        verdict=built.verdict,
        review=review,
    )


__all__ = [
    "HearingReviewVerifier",
    "HearingRoundAdvance",
    "complete_and_review_hearing_round",
]
