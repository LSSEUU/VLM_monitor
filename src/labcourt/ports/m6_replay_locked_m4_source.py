"""Narrow verified source input for a locked M4 plus Gate terminal route."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    ScreeningDecision,
    VlmRole,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalStatus,
    HearingRecord,
    HearingSessionEntryStatus,
    HearingVerdictBinding,
)
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6LockedRetrievalOutcomeKind,
    M6ReplayAuthorityKind,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.m6_source_authority import M6GateCurrentClosureReceipt
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.domain.hearing_verdict_builder import (
    HearingReviewClosure,
    validate_hearing_review_closure,
    validate_hearing_verdict_binding,
)
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_model(
    value: object,
    model_type: type[_ModelT],
    label: str,
) -> _ModelT:
    if type(value) is not model_type:
        raise TypeError(f"{label} requires the exact contract type")
    try:
        controlled = model_type.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError(f"{label} is not canonical") from None
    if controlled != value:
        raise ValueError(f"{label} is not canonical")
    return controlled


def _document_sha256(value: BaseModel) -> str:
    document = canonical_json(value.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _expected_current_closure(pack: EvidencePack) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


@dataclass(frozen=True, slots=True)
class M6ReplayLockedCandidateGateCurrentClosure:
    """Candidate-run Gate closure proven to differ only by its ``run_id``."""

    source_receipt: M6GateCurrentClosureReceipt
    candidate_evidence_pack: EvidencePack
    current_closure: ClosureReport

    def __post_init__(self) -> None:
        receipt = _canonical_model(
            self.source_receipt,
            M6GateCurrentClosureReceipt,
            "M6 locked candidate Gate source receipt",
        )
        pack = _canonical_model(
            self.candidate_evidence_pack,
            EvidencePack,
            "M6 locked candidate Gate evidence pack",
        )
        closure = _canonical_model(
            self.current_closure,
            ClosureReport,
            "M6 locked candidate Gate current closure",
        )
        expected = _expected_current_closure(pack)
        source_payload = expected.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        source_payload["run_id"] = receipt.run_id
        try:
            source_equivalent = ClosureReport.model_validate(source_payload)
        except (TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked candidate Gate closure cannot be rebound") from None
        if (
            pack.run_id == receipt.run_id
            or pack.case_id != receipt.case_id
            or pack.manifest_id != receipt.manifest_id
            or pack.pack_id != receipt.evidence_pack_id
            or pack.version != receipt.evidence_pack_version
            or closure != expected
            or receipt.current_closure != source_equivalent
        ):
            raise ValueError("M6 locked candidate Gate closure differs beyond the candidate run_id")


@dataclass(frozen=True, slots=True)
class M6ReplayLockedM4GateTerminalSource:
    """Exact source authority for one atomic M4 hearing plus Gate terminal."""

    source_identity_sha256: str
    closure: M6ReplayInputClosureAuthority
    projection_context: M6VerifiedProjectionContext
    hearing_record: HearingRecord
    hearing_verdict_binding: HearingVerdictBinding
    gate_current_closure_receipt: M6GateCurrentClosureReceipt
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if not _is_sha256(self.source_identity_sha256):
            raise ValueError("M6 locked M4 source identity must be a SHA-256")
        if type(self.projection_context) is not M6VerifiedProjectionContext:
            raise TypeError("M6 locked M4 source requires an exact projection context")
        closure = _canonical_model(
            self.closure,
            M6ReplayInputClosureAuthority,
            "M6 locked M4 replay closure",
        )
        record = _canonical_model(
            self.hearing_record,
            HearingRecord,
            "M6 locked M4 hearing record",
        )
        binding = _canonical_model(
            self.hearing_verdict_binding,
            HearingVerdictBinding,
            "M6 locked M4 hearing Verdict binding",
        )
        receipt = _canonical_model(
            self.gate_current_closure_receipt,
            M6GateCurrentClosureReceipt,
            "M6 locked M4 Gate current-closure receipt",
        )
        snapshot = _canonical_model(
            self.source_snapshot,
            M6CaseReplaySnapshot,
            "M6 locked M4 source snapshot",
        )
        try:
            context = M6VerifiedProjectionContext(
                case=self.projection_context.case,
                perception=self.projection_context.perception,
                historical_source_run_id=(self.projection_context.historical_source_run_id),
                historical_source_case_id=(self.projection_context.historical_source_case_id),
                historical_source_manifest_id=(
                    self.projection_context.historical_source_manifest_id
                ),
                model_reference_authority=(self.projection_context.model_reference_authority),
                procedural_gate_authority=(self.projection_context.procedural_gate_authority),
                model_responses=self.projection_context.model_responses,
                retrieval_cycles=self.projection_context.retrieval_cycles,
                acquisitions=self.projection_context.acquisitions,
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked M4 projection context is not canonical") from None
        case = context.case
        revision = closure.source_case_revision
        if revision is None:
            raise ValueError("M6 locked M4 source requires a selected Case revision")
        try:
            derived_snapshot = build_m6_case_replay_snapshot(
                context=context,
                sample_id=closure.sample_id,
                source_case_revision=revision,
            )
            resolved_responses = resolve_m6_locked_model_responses(closure.model_calls)
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked M4 source cannot be deterministically rebuilt") from None
        if (
            context != self.projection_context
            or derived_snapshot != snapshot
            or closure.source_case_id != case.case_id
            or closure.source_case_document_sha256 != snapshot.source_case_document_sha256
            or closure.source_run_id != case.run_id
            or closure.source_manifest_id != case.manifest_id
            or snapshot.source_run_id != case.run_id
            or snapshot.source_case_id != case.case_id
            or snapshot.manifest_id != case.manifest_id
            or self.source_identity_sha256
            != context.model_reference_authority.source_identity_sha256
            or self.source_identity_sha256
            != context.procedural_gate_authority.source_identity_sha256
            or resolved_responses != context.model_responses
        ):
            raise ValueError("M6 locked M4 source authorities are cross-grafted")
        self._require_exact_route_shape(case, context, closure, record)
        self._require_terminal_join(case, context, record, binding, receipt)

    @staticmethod
    def _require_exact_route_shape(
        case: Case,
        context: M6VerifiedProjectionContext,
        closure: M6ReplayInputClosureAuthority,
        record: HearingRecord,
    ) -> None:
        expected_calls = (
            (M6LockedModelCallLayer.SCREENING, M6LockedModelRole.SCREENING),
            (M6LockedModelCallLayer.HEARING, M6LockedModelRole.PROSECUTOR),
            (M6LockedModelCallLayer.HEARING, M6LockedModelRole.DEFENDER),
            (M6LockedModelCallLayer.HEARING, M6LockedModelRole.JUDGE),
        )
        references = context.model_reference_authority
        gates = context.procedural_gate_authority
        cycles = context.retrieval_cycles
        cut = closure.historical_cut.retrieval_cycles
        if (
            len(case.evidence_packs) != 1
            or case.evidence_packs[0].version != 1
            or case.evidence_packs[0].tool_results
            or len(case.screening_results) != 1
            or case.screening_results[0].decision != ScreeningDecision.ESCALATE
            or len(case.verdicts) != 1
            or len(case.procedural_reviews) != 1
            or record.version != 1
            or len(record.rounds) != 1
            or len(record.model_request_refs) != 3
            or len(record.model_response_refs) != 3
            or len(record.parse_receipt_refs) != 3
            or len(record.usage_receipts) != 3
            or record.failure_authorities
            or record.total_retry_count != 0
            or any(item.retry_count != 0 for item in record.usage_receipts)
            or len(closure.model_calls) != 4
            or tuple((item.layer, item.role) for item in closure.model_calls) != expected_calls
            or any(
                item.attempt_index != 0
                or item.result_kind != M6LockedModelCallResultKind.RESPONSE
                or item.parsed_output_ref is None
                for item in closure.model_calls
            )
            or closure.embeddings
            or closure.tool_results
            or context.acquisitions
            or len(context.model_responses) != 4
            or tuple((item.layer, item.role) for item in context.model_responses) != expected_calls
            or any(item.attempt_index != 0 for item in context.model_responses)
            or len(references.screening_bindings) != 1
            or len(references.verdict_bindings) != 1
            or references.fast_verdict_bindings
            or len(gates.inputs) != 1
            or gates.inputs[0].precedent_resolutions
            or any(
                item.scope.allowed_precedent_refs
                for item in references.verdict_bindings[0].role_bindings
            )
            or len(cycles) != 1
            or cycles[0].cycle_index != 1
            or cycles[0].success_exposure is not None
            or cycles[0].degraded_receipt is None
            or len(cut) != 1
            or cut[0].outcome != M6LockedRetrievalOutcomeKind.DEGRADED
            or cut[0].authority_ref.kind != M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT
        ):
            raise ValueError("source Case is outside the first locked M4 plus Gate route")
        hearing_round = record.rounds[0]
        retrieval = cycles[0].degraded_receipt
        assert retrieval is not None
        if (
            record.session.entry_status != HearingSessionEntryStatus.ESCALATED
            or record.session.initial_trigger_review_ref is not None
            or record.session.initial_defect_codes
            or record.acquisition_rounds_used != 0
            or record.rework_rounds_used != 0
            or hearing_round.round_index != 1
            or hearing_round.prior_acquisition_rounds != 0
            or hearing_round.prior_rework_rounds != 0
            or hearing_round.initial_trigger_review_ref is not None
            or hearing_round.initial_defect_codes
            or hearing_round.rework_review_ref is not None
            or hearing_round.rework_defect_codes
            or hearing_round.acquisition_request is not None
            or hearing_round.tool_execution_receipt is not None
            or not hearing_round.precedent_retrieval_degraded
            or hearing_round.precedent_retrieval_receipt != retrieval
            or retrieval.status != HearingPrecedentRetrievalStatus.DEGRADED
            or retrieval.candidate_precedent_refs
            or retrieval.visible_precedent_refs
            or retrieval.scored_precedents
            or cut[0].source_run_id != case.run_id
            or cut[0].source_case_id != case.case_id
            or cut[0].hearing_session_id != record.hearing_session_id
            or cut[0].cycle_index != cycles[0].cycle_index
            or cut[0].cycle_scope_id != cycles[0].cycle_scope_id
            or cut[0].authority_ref.artifact_id != retrieval.receipt_id
            or cut[0].authority_ref.document_sha256 != _document_sha256(retrieval)
        ):
            raise ValueError("first locked M4 route is not one empty degraded hearing cycle")

    @staticmethod
    def _require_terminal_join(
        case: Case,
        context: M6VerifiedProjectionContext,
        record: HearingRecord,
        binding: HearingVerdictBinding,
        receipt: M6GateCurrentClosureReceipt,
    ) -> None:
        if not case.verdicts or not case.procedural_reviews:
            raise ValueError("M6 locked M4 source lacks a terminal Verdict and Gate review")
        verdict = case.verdicts[-1]
        review = case.procedural_reviews[-1]
        expected_status = (
            CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
        )
        if (
            case.status != expected_status
            or case.alerts
            or case.appeals
            or case.final_decision is not None
            or case.current_backlog_item_id is not None
            or binding.verdict_id != verdict.verdict_id
            or binding.verdict_version != verdict.version
            or receipt.run_id != case.run_id
            or receipt.case_id != case.case_id
            or receipt.manifest_id != case.manifest_id
            or receipt.source_review_id != review.review_id
            or receipt.review_version != review.version
        ):
            raise ValueError("source Case is outside the locked M4 plus Gate terminal route")
        try:
            validate_hearing_review_closure(HearingReviewClosure(record, verdict, binding, review))
            validate_hearing_verdict_binding(
                record,
                verdict,
                binding,
                violation_type=case.event.violation_type,
            )
            gate_input = context.procedural_gate_authority.input_for_review(review)
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked M4 hearing and Gate closure cannot be rebuilt") from None
        packs = tuple(
            pack
            for pack in case.evidence_packs
            if (
                pack.pack_id == receipt.evidence_pack_id
                and pack.version == receipt.evidence_pack_version
            )
        )
        reference_bindings = tuple(
            item
            for item in context.model_reference_authority.verdict_bindings
            if item.verdict_id == verdict.verdict_id
        )
        if len(packs) != 1 or len(reference_bindings) != 1:
            raise ValueError("M6 locked M4 terminal authorities are not uniquely resolvable")
        pack = packs[0]
        reference_binding = reference_bindings[0]
        terminal_round = record.rounds[-1]
        outputs = {
            VlmRole.PROSECUTOR: terminal_round.prosecutor_output,
            VlmRole.DEFENDER: terminal_round.defender_output,
            VlmRole.JUDGE: terminal_round.judge_output,
        }
        role_bindings_match = all(
            item.output_id == outputs[item.role].output_id
            and item.final_request_id == outputs[item.role].request_ref.artifact_id
            and item.response_id == outputs[item.role].response_ref.artifact_id
            for item in reference_binding.role_bindings
        )
        if (
            reference_binding.hearing_record_id != record.record_id
            or reference_binding.judge_round_id != terminal_round.round_id
            or not role_bindings_match
            or gate_input.verdict != verdict
            or gate_input.evidence_pack != pack
            or gate_input.rebuild_review() != review
            or gate_input.current_closure != receipt.current_closure
            or receipt.source_review_document_sha256 != _document_sha256(review)
            or receipt.evidence_pack_document_sha256 != _document_sha256(pack)
        ):
            raise ValueError("M6 locked M4 terminal authorities do not form one exact join")


@runtime_checkable
class M6ReplayLockedM4GateTerminalSourceProvider(Protocol):
    def load_m4_gate_terminal_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedM4GateTerminalSource: ...


__all__ = [
    "M6ReplayLockedCandidateGateCurrentClosure",
    "M6ReplayLockedM4GateTerminalSource",
    "M6ReplayLockedM4GateTerminalSourceProvider",
]
