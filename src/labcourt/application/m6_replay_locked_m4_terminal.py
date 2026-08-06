"""Build one M4 hearing-plus-Gate terminal candidate without live capabilities."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, UsageSummary
from labcourt.contracts.enums import CaseStatus, ScreeningDecision
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing_state import HearingRecord, HearingVerdictBinding
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_source_authority import M6GateCurrentClosureReceipt
from labcourt.contracts.screening import ParsedScreeningOutput
from labcourt.contracts.storage import ClosureReport
from labcourt.contracts.verdicts import Verdict
from labcourt.domain.hearing_verdict_builder import (
    HearingReviewClosure,
    HearingVerdictBuildError,
    build_hearing_verdict,
    validate_hearing_review_closure,
    validate_hearing_verdict_binding,
)
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
    M6ScreeningModelReferenceBinding,
    M6VerdictModelReferenceBinding,
)
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
)
from labcourt.domain.m6_semantic_projection import (
    M6ReplayLockedM4CandidateProjectionContext,
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.domain.screening_router import (
    ScreeningRouteError,
    ScreeningRoutePolicy,
    ScreeningRouter,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyM4PrePolicySource,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedCandidateGateCurrentClosure,
    M6ReplayLockedM4GateTerminalSource,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class _M4TerminalSourceFacts(Protocol):
    @property
    def source_identity_sha256(self) -> str: ...

    @property
    def closure(self) -> M6ReplayInputClosureAuthority: ...

    @property
    def projection_context(self) -> M6VerifiedProjectionContext: ...

    @property
    def hearing_record(self) -> HearingRecord: ...

    @property
    def hearing_verdict_binding(self) -> HearingVerdictBinding: ...

    @property
    def gate_current_closure_receipt(self) -> M6GateCurrentClosureReceipt: ...

    @property
    def source_snapshot(self) -> M6CaseReplaySnapshot: ...


class M6ReplayLockedM4TerminalErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    SOURCE_INPUT_REJECTED = "SOURCE_INPUT_REJECTED"
    ROUTE_REJECTED = "ROUTE_REJECTED"
    HEARING_REBUILD_REJECTED = "HEARING_REBUILD_REJECTED"
    CANDIDATE_GATE_REJECTED = "CANDIDATE_GATE_REJECTED"
    SEMANTIC_DIVERGENCE = "SEMANTIC_DIVERGENCE"
    CANDIDATE_REJECTED = "CANDIDATE_REJECTED"


class M6ReplayLockedM4TerminalError(LabCourtError):
    """Payload-free failure from the pure M4 hearing-plus-Gate builder."""

    def __init__(self, code: M6ReplayLockedM4TerminalErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedM4TerminalErrorCode):
            raise TypeError("code must be an M6 locked M4 terminal error code")
        self.code = code
        super().__init__(f"M6 locked M4 terminal candidate failed: {code.value}")


def _fail(code: M6ReplayLockedM4TerminalErrorCode) -> NoReturn:
    raise M6ReplayLockedM4TerminalError(code)


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedM4TerminalErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4TerminalErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedM4TerminalErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_source(value: object) -> M6ReplayLockedM4GateTerminalSource:
    if type(value) is not M6ReplayLockedM4GateTerminalSource:
        _fail(M6ReplayLockedM4TerminalErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedM4GateTerminalSource(
            source_identity_sha256=value.source_identity_sha256,
            closure=value.closure,
            projection_context=value.projection_context,
            hearing_record=value.hearing_record,
            hearing_verdict_binding=value.hearing_verdict_binding,
            gate_current_closure_receipt=value.gate_current_closure_receipt,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4TerminalErrorCode.SOURCE_INPUT_REJECTED)
    if controlled != value:
        _fail(M6ReplayLockedM4TerminalErrorCode.SOURCE_INPUT_REJECTED)
    return controlled


def _controlled_closed_policy_source(
    value: object,
) -> M6ReplayLockedClosedPolicyM4PrePolicySource:
    if type(value) is not M6ReplayLockedClosedPolicyM4PrePolicySource:
        _fail(M6ReplayLockedM4TerminalErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedClosedPolicyM4PrePolicySource(
            source_identity_sha256=value.source_identity_sha256,
            source_binding=value.source_binding,
            catalog_closure=value.catalog_closure,
            source_ready_case_revision=value.source_ready_case_revision,
            projection_context=value.projection_context,
            hearing_record=value.hearing_record,
            hearing_verdict_binding=value.hearing_verdict_binding,
            gate_current_closure_receipt=value.gate_current_closure_receipt,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4TerminalErrorCode.SOURCE_INPUT_REJECTED)
    if controlled != value:
        _fail(M6ReplayLockedM4TerminalErrorCode.SOURCE_INPUT_REJECTED)
    return controlled


def _document_sha256(value: BaseModel) -> str:
    document = canonical_json(value.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _require_scope(
    scope: M6ReplayLockedExecutionScopeAuthority,
    pending: M6ReplayLockedPendingSampleCommitmentAuthority,
    source: _M4TerminalSourceFacts,
) -> None:
    closure = source.closure
    sequence = pending.ledger_sequence
    if sequence >= len(scope.execution_dataset.entries):
        _fail(M6ReplayLockedM4TerminalErrorCode.SCOPE_MISMATCH)
    entry = scope.execution_dataset.entries[sequence]
    expected_binding = (
        closure.sample_id,
        closure.input_authority_id,
        closure.input_authority_document_sha256,
        closure.replay_input_closure_authority_id,
        closure.replay_input_closure_document_sha256,
    )
    observed_binding = (
        entry.sample_id,
        entry.input_authority_id,
        entry.input_authority_document_sha256,
        entry.replay_input_closure_authority_id,
        entry.replay_input_closure_document_sha256,
    )
    if (
        pending.execution_scope_authority_id != scope.execution_scope_authority_id
        or pending.candidate_run_id != scope.candidate_run_id
        or pending.command_id != scope.command.command_id
        or pending.execution_dataset_snapshot_id
        != scope.execution_dataset.execution_dataset_snapshot_id
        or pending.execution_component_authority_id
        != scope.execution_component.component_authority_id
        or pending.execution_entry != entry
        or pending.source_catalog_entry_id != scope.source_catalog_entry_ids[sequence]
        or pending.route != M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
        or pending.route not in scope.execution_component.supported_routes
        or observed_binding != expected_binding
        or scope.candidate_run_id == closure.source_run_id
        or closure.source_run_id not in scope.source_run_ids
        or closure.source_manifest_id != scope.locked_manifest.manifest_id
        or closure.source_manifest_document_sha256 != scope.locked_manifest_content_sha256
        or scope.command.baseline_manifest_id != closure.source_manifest_id
        or scope.command.candidate_manifest_id != closure.source_manifest_id
    ):
        _fail(M6ReplayLockedM4TerminalErrorCode.SCOPE_MISMATCH)


def _require_closed_policy_scope(
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    source: M6ReplayLockedClosedPolicyM4PrePolicySource,
) -> None:
    if (
        pending.execution_scope_authority_id != scope.execution_scope_authority_id
        or pending.execution_component_authority_id
        != scope.execution_component.component_authority_id
        or pending.locked_config_sha256 != scope.locked_config_sha256
        or pending.pre_policy_execution_scope_authority_id
        != scope.pre_policy_execution_scope_authority_id
        or source.source_binding != pending.source_binding
    ):
        _fail(M6ReplayLockedM4TerminalErrorCode.SCOPE_MISMATCH)
    _require_scope(
        scope.pre_policy_execution_scope,
        pending.pre_policy_pending_commitment,
        source,
    )


def _rebind_pack(source: EvidencePack, candidate_run_id: str) -> EvidencePack:
    payload = source.model_dump(mode="json", exclude_computed_fields=True)
    closure_payload = source.closure_report.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    payload["run_id"] = candidate_run_id
    payload["closure_report"] = {**closure_payload, "run_id": candidate_run_id}
    candidate = EvidencePack.model_validate(payload)
    if (
        candidate.pack_id != source.pack_id
        or candidate.semantic_projection() != source.semantic_projection()
    ):
        _fail(M6ReplayLockedM4TerminalErrorCode.CANDIDATE_REJECTED)
    return candidate


def _project_hearing_verdict(
    source: Verdict,
    *,
    candidate_run_id: str,
    candidate_screening_id: str,
) -> Verdict:
    payload = source.model_dump(mode="json", exclude_computed_fields=True)
    payload["run_id"] = candidate_run_id
    payload["screening_id"] = candidate_screening_id
    candidate = Verdict.model_validate(payload)
    if (
        candidate.verdict_id == source.verdict_id
        or candidate.model_response_refs != source.model_response_refs
        or candidate.evidence_pack_id != source.evidence_pack_id
        or candidate.evidence_pack_version != source.evidence_pack_version
    ):
        _fail(M6ReplayLockedM4TerminalErrorCode.HEARING_REBUILD_REJECTED)
    return candidate


@dataclass(frozen=True, slots=True)
class M6ReplayLockedM4GateTerminalCandidate:
    """One pure candidate Case whose M4 history retains source provenance."""

    case: Case
    projection_context: M6ReplayLockedM4CandidateProjectionContext
    candidate_snapshot: M6CaseReplaySnapshot
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if (
            type(self.case) is not Case
            or type(self.projection_context) is not M6ReplayLockedM4CandidateProjectionContext
            or type(self.candidate_snapshot) is not M6CaseReplaySnapshot
            or type(self.source_snapshot) is not M6CaseReplaySnapshot
        ):
            raise TypeError("M6 locked M4 candidate requires exact authority types")
        try:
            case = Case.model_validate(
                self.case.model_dump(mode="json", exclude_computed_fields=True)
            )
            candidate_snapshot = M6CaseReplaySnapshot.model_validate(
                self.candidate_snapshot.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            source_snapshot = M6CaseReplaySnapshot.model_validate(
                self.source_snapshot.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            rebuilt = build_m6_case_replay_snapshot(
                context=self.projection_context,
                sample_id=candidate_snapshot.sample_id,
                source_case_revision=candidate_snapshot.source_case_revision,
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked M4 candidate is not canonical") from None
        if (
            case != self.case
            or candidate_snapshot != self.candidate_snapshot
            or source_snapshot != self.source_snapshot
            or self.projection_context.case != case
            or rebuilt != candidate_snapshot
            or candidate_snapshot.sample_id != source_snapshot.sample_id
            or candidate_snapshot.source_case_revision != 1
            or candidate_snapshot.stage_roots != source_snapshot.stage_roots
            or candidate_snapshot.semantic_case_hash != source_snapshot.semantic_case_hash
            or candidate_snapshot.case_status != source_snapshot.case_status
            or candidate_snapshot.final_decision != source_snapshot.final_decision
            or candidate_snapshot.highest_alert_level != source_snapshot.highest_alert_level
            or candidate_snapshot.terminal_appeal_status != source_snapshot.terminal_appeal_status
        ):
            raise ValueError("M6 locked M4 candidate differs from its source semantics")

    @property
    def canonical_case_document(self) -> str:
        return canonical_json(self.case.model_dump(mode="json"))


def build_m6_replay_locked_m4_gate_terminal_candidate(
    *,
    execution_scope: object,
    pending_commitment: object,
    source: object,
) -> M6ReplayLockedM4GateTerminalCandidate:
    """Re-execute saved M4 mapping and Gate as one atomic terminal slice."""

    scope = _canonical_model(execution_scope, M6ReplayLockedExecutionScopeAuthority)
    pending = _canonical_model(
        pending_commitment,
        M6ReplayLockedPendingSampleCommitmentAuthority,
    )
    controlled_source = _controlled_source(source)
    _require_scope(scope, pending, controlled_source)

    return _build_m6_replay_locked_m4_gate_terminal_candidate(
        scope=scope,
        pending=pending,
        controlled_source=controlled_source,
    )


def build_m6_replay_locked_closed_policy_m4_pre_policy_candidate(
    *,
    execution_scope: object,
    pending_commitment: object,
    source: object,
) -> M6ReplayLockedM4GateTerminalCandidate:
    """Re-execute one V2 M4 READY predecessor against its real CLOSED cut."""

    scope = _canonical_model(
        execution_scope,
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    )
    pending = _canonical_model(
        pending_commitment,
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    )
    controlled_source = _controlled_closed_policy_source(source)
    _require_closed_policy_scope(scope, pending, controlled_source)

    return _build_m6_replay_locked_m4_gate_terminal_candidate(
        scope=scope.pre_policy_execution_scope,
        pending=pending.pre_policy_pending_commitment,
        controlled_source=controlled_source,
    )


def _build_m6_replay_locked_m4_gate_terminal_candidate(
    *,
    scope: M6ReplayLockedExecutionScopeAuthority,
    pending: M6ReplayLockedPendingSampleCommitmentAuthority,
    controlled_source: _M4TerminalSourceFacts,
) -> M6ReplayLockedM4GateTerminalCandidate:

    source_context = controlled_source.projection_context
    source_case = source_context.case
    source_pack = source_case.evidence_packs[0]
    source_screening = source_case.screening_results[0]
    source_verdict = source_case.verdicts[0]
    source_review = source_case.procedural_reviews[0]
    source_screening_binding = source_context.model_reference_authority.screening_bindings[0]
    source_verdict_binding = source_context.model_reference_authority.verdict_bindings[0]
    source_gate = source_context.procedural_gate_authority.inputs[0]
    screening_config = scope.locked_config.screening
    if (
        source_screening.low_probability != screening_config.low_probability
        or source_screening.high_probability != screening_config.high_probability
        or source_screening.strong_signal_threshold != screening_config.strong_signal_threshold
        or source_screening.router_version != screening_config.router_version
        or source_screening.conflict_policy_version != screening_config.conflict_policy_version
        or source_gate.gate_config != scope.locked_config.procedural_gate
        or source_gate.alert_config != scope.locked_config.alerts
        or source_gate.current_closure
        != controlled_source.gate_current_closure_receipt.current_closure
    ):
        _fail(M6ReplayLockedM4TerminalErrorCode.SOURCE_INPUT_REJECTED)

    try:
        rebuilt = build_hearing_verdict(
            controlled_source.hearing_record,
            source_case.event.violation_type,
            version=source_verdict.version,
        )
        validate_hearing_verdict_binding(
            controlled_source.hearing_record,
            source_verdict,
            controlled_source.hearing_verdict_binding,
            violation_type=source_case.event.violation_type,
        )
        validate_hearing_review_closure(
            HearingReviewClosure(
                controlled_source.hearing_record,
                source_verdict,
                controlled_source.hearing_verdict_binding,
                source_review,
            )
        )
    except (HearingVerdictBuildError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4TerminalErrorCode.HEARING_REBUILD_REJECTED)
    if (
        rebuilt.verdict != source_verdict
        or rebuilt.binding != controlled_source.hearing_verdict_binding
    ):
        _fail(M6ReplayLockedM4TerminalErrorCode.HEARING_REBUILD_REJECTED)

    try:
        candidate_pack = _rebind_pack(source_pack, scope.candidate_run_id)
        parsed_payload = source_screening.parsed_output.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        parsed_payload["run_id"] = scope.candidate_run_id
        candidate_parsed = ParsedScreeningOutput.model_validate(parsed_payload)
        candidate_screening = ScreeningRouter(
            ScreeningRoutePolicy(
                low_probability=screening_config.low_probability,
                high_probability=screening_config.high_probability,
                strong_signal_threshold=screening_config.strong_signal_threshold,
                router_version=screening_config.router_version,
                conflict_policy_version=screening_config.conflict_policy_version,
            )
        ).route(
            candidate_parsed,
            candidate_pack,
            version=source_screening.version,
        )
        if candidate_screening.decision != ScreeningDecision.ESCALATE:
            _fail(M6ReplayLockedM4TerminalErrorCode.ROUTE_REJECTED)
        candidate_verdict = _project_hearing_verdict(
            source_verdict,
            candidate_run_id=scope.candidate_run_id,
            candidate_screening_id=candidate_screening.screening_id,
        )
        closure_payload = source_gate.current_closure.model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        closure_payload["run_id"] = scope.candidate_run_id
        candidate_current_closure = ClosureReport.model_validate(closure_payload)
        M6ReplayLockedCandidateGateCurrentClosure(
            source_receipt=controlled_source.gate_current_closure_receipt,
            candidate_evidence_pack=candidate_pack,
            current_closure=candidate_current_closure,
        )
        provisional_gate = M6ProceduralGateExecutionInput(
            source_review_id="m6-locked-m4-review-provisional",
            source_review_document_sha256="0" * 64,
            verdict=candidate_verdict,
            evidence_pack=candidate_pack,
            current_closure=candidate_current_closure,
            gate_config=scope.locked_config.procedural_gate,
            alert_config=scope.locked_config.alerts,
            review_version=source_review.version,
            unknown_reference_attempts=source_gate.unknown_reference_attempts,
            precedent_resolutions=source_gate.precedent_resolutions,
            artifact_bounds=source_gate.artifact_bounds,
        )
        candidate_review = provisional_gate.rebuild_review()
        candidate_status = (
            CaseStatus.READY_FOR_ALERT_POLICY
            if candidate_review.passed
            else CaseStatus.REWORK_REQUIRED
        )
        candidate_case = Case(
            run_id=scope.candidate_run_id,
            status=candidate_status,
            event=source_case.event,
            evidence_packs=(candidate_pack,),
            screening_results=(candidate_screening,),
            verdicts=(candidate_verdict,),
            procedural_reviews=(candidate_review,),
            usage=UsageSummary(),
            manifest_id=scope.locked_manifest.manifest_id,
        )
        candidate_screening_binding = M6ScreeningModelReferenceBinding(
            screening_id=candidate_screening.screening_id,
            parsed_output_id=candidate_parsed.parsed_output_id,
            final_request_id=source_screening_binding.final_request_id,
            scope=source_screening_binding.scope,
        )
        candidate_verdict_binding = M6VerdictModelReferenceBinding(
            verdict_id=candidate_verdict.verdict_id,
            hearing_record_id=source_verdict_binding.hearing_record_id,
            judge_round_id=source_verdict_binding.judge_round_id,
            role_bindings=source_verdict_binding.role_bindings,
        )
        references = M6CaseModelReferenceAuthority(
            source_identity_sha256=controlled_source.source_identity_sha256,
            run_id=scope.candidate_run_id,
            case_id=candidate_case.case_id,
            manifest_id=candidate_case.manifest_id,
            screening_bindings=(candidate_screening_binding,),
            verdict_bindings=(candidate_verdict_binding,),
        )
        candidate_gate = M6ProceduralGateExecutionInput(
            source_review_id=candidate_review.review_id,
            source_review_document_sha256=_document_sha256(candidate_review),
            verdict=candidate_verdict,
            evidence_pack=candidate_pack,
            current_closure=candidate_current_closure,
            gate_config=scope.locked_config.procedural_gate,
            alert_config=scope.locked_config.alerts,
            review_version=candidate_review.version,
            unknown_reference_attempts=source_gate.unknown_reference_attempts,
            precedent_resolutions=source_gate.precedent_resolutions,
            artifact_bounds=source_gate.artifact_bounds,
        )
        gates = M6CaseProceduralGateAuthority(
            source_identity_sha256=controlled_source.source_identity_sha256,
            run_id=scope.candidate_run_id,
            case_id=candidate_case.case_id,
            manifest_id=candidate_case.manifest_id,
            inputs=(candidate_gate,),
        )
        candidate_context = M6ReplayLockedM4CandidateProjectionContext(
            case=candidate_case,
            source_context=source_context,
            model_reference_authority=references,
            procedural_gate_authority=gates,
        )
        candidate_snapshot = build_m6_case_replay_snapshot(
            context=candidate_context,
            sample_id=pending.sample_id,
            source_case_revision=1,
        )
    except M6ReplayLockedM4TerminalError:
        raise
    except ScreeningRouteError:
        _fail(M6ReplayLockedM4TerminalErrorCode.ROUTE_REJECTED)
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4TerminalErrorCode.CANDIDATE_GATE_REJECTED)

    if (
        candidate_pack.closure_report.run_id != scope.candidate_run_id
        or candidate_parsed.request_id != source_screening.parsed_output.request_id
        or candidate_parsed.response_id != source_screening.parsed_output.response_id
        or candidate_parsed.response_content_sha256
        != source_screening.parsed_output.response_content_sha256
        or candidate_verdict.model_response_refs != source_verdict.model_response_refs
        or candidate_review.passed != source_review.passed
        or candidate_snapshot.stage_roots != controlled_source.source_snapshot.stage_roots
        or candidate_snapshot.semantic_case_hash
        != controlled_source.source_snapshot.semantic_case_hash
    ):
        _fail(M6ReplayLockedM4TerminalErrorCode.SEMANTIC_DIVERGENCE)
    try:
        return M6ReplayLockedM4GateTerminalCandidate(
            case=candidate_case,
            projection_context=candidate_context,
            candidate_snapshot=candidate_snapshot,
            source_snapshot=controlled_source.source_snapshot,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4TerminalErrorCode.CANDIDATE_REJECTED)


__all__ = [
    "M6ReplayLockedM4GateTerminalCandidate",
    "M6ReplayLockedM4TerminalError",
    "M6ReplayLockedM4TerminalErrorCode",
    "build_m6_replay_locked_closed_policy_m4_pre_policy_candidate",
    "build_m6_replay_locked_m4_gate_terminal_candidate",
]
