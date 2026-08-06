"""Build one deterministic M3 fast-terminal candidate without external capabilities."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, UsageSummary
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.evidence import EvidencePack
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
from labcourt.contracts.screening import ParsedScreeningOutput
from labcourt.contracts.storage import ClosureReport
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
    M6FastVerdictModelReferenceBinding,
    M6ScreeningModelReferenceBinding,
)
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
)
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.domain.screening_router import (
    FastVerdictBuilder,
    ScreeningRouteError,
    ScreeningRoutePolicy,
    ScreeningRouter,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
)
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class _FastTerminalSourceFacts(Protocol):
    @property
    def source_identity_sha256(self) -> str: ...

    @property
    def closure(self) -> M6ReplayInputClosureAuthority: ...

    @property
    def projection_context(self) -> M6VerifiedProjectionContext: ...

    @property
    def source_snapshot(self) -> M6CaseReplaySnapshot: ...


class M6ReplayLockedFastTerminalErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    SOURCE_INPUT_REJECTED = "SOURCE_INPUT_REJECTED"
    ROUTE_REJECTED = "ROUTE_REJECTED"
    SEMANTIC_DIVERGENCE = "SEMANTIC_DIVERGENCE"
    CANDIDATE_REJECTED = "CANDIDATE_REJECTED"


class M6ReplayLockedFastTerminalError(LabCourtError):
    """Payload-free failure from the pure locked fast-terminal builder."""

    def __init__(self, code: M6ReplayLockedFastTerminalErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedFastTerminalErrorCode):
            raise TypeError("code must be an M6 locked fast-terminal error code")
        self.code = code
        super().__init__(f"M6 locked fast-terminal candidate failed: {code.value}")


def _fail(code: M6ReplayLockedFastTerminalErrorCode) -> NoReturn:
    raise M6ReplayLockedFastTerminalError(code)


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedFastTerminalErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastTerminalErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedFastTerminalErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_source(value: object) -> M6ReplayLockedFastTerminalSource:
    if type(value) is not M6ReplayLockedFastTerminalSource:
        _fail(M6ReplayLockedFastTerminalErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedFastTerminalSource(
            source_identity_sha256=value.source_identity_sha256,
            closure=value.closure,
            projection_context=value.projection_context,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastTerminalErrorCode.SOURCE_INPUT_REJECTED)
    if controlled != value:
        _fail(M6ReplayLockedFastTerminalErrorCode.SOURCE_INPUT_REJECTED)
    return controlled


def _controlled_closed_policy_source(
    value: object,
) -> M6ReplayLockedClosedPolicyFastPrePolicySource:
    if type(value) is not M6ReplayLockedClosedPolicyFastPrePolicySource:
        _fail(M6ReplayLockedFastTerminalErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6ReplayLockedClosedPolicyFastPrePolicySource(
            source_identity_sha256=value.source_identity_sha256,
            source_binding=value.source_binding,
            catalog_closure=value.catalog_closure,
            source_ready_case_revision=value.source_ready_case_revision,
            projection_context=value.projection_context,
            source_snapshot=value.source_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastTerminalErrorCode.SOURCE_INPUT_REJECTED)
    if controlled != value:
        _fail(M6ReplayLockedFastTerminalErrorCode.SOURCE_INPUT_REJECTED)
    return controlled


def _document_sha256(value: BaseModel) -> str:
    document = canonical_json(value.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class M6ReplayLockedFastTerminalCandidate:
    """One pure candidate Case plus the authority context that rebuilds it."""

    case: Case
    projection_context: M6VerifiedProjectionContext
    candidate_snapshot: M6CaseReplaySnapshot
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if (
            type(self.case) is not Case
            or type(self.projection_context) is not M6VerifiedProjectionContext
            or type(self.candidate_snapshot) is not M6CaseReplaySnapshot
            or type(self.source_snapshot) is not M6CaseReplaySnapshot
        ):
            raise TypeError("M6 locked fast candidate requires exact authority types")
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
            raise ValueError("M6 locked fast candidate is not canonical") from None
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
            raise ValueError("M6 locked fast candidate differs from its source semantics")

    @property
    def canonical_case_document(self) -> str:
        return canonical_json(self.case.model_dump(mode="json"))


def _require_scope(
    scope: M6ReplayLockedExecutionScopeAuthority,
    pending: M6ReplayLockedPendingSampleCommitmentAuthority,
    source: _FastTerminalSourceFacts,
) -> None:
    closure = source.closure
    sequence = pending.ledger_sequence
    if sequence >= len(scope.execution_dataset.entries):
        _fail(M6ReplayLockedFastTerminalErrorCode.SCOPE_MISMATCH)
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
        or pending.route != M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE
        or pending.route not in scope.execution_component.supported_routes
        or observed_binding != expected_binding
        or scope.candidate_run_id == closure.source_run_id
        or closure.source_run_id not in scope.source_run_ids
        or closure.source_manifest_id != scope.locked_manifest.manifest_id
        or closure.source_manifest_document_sha256 != scope.locked_manifest_content_sha256
        or scope.command.baseline_manifest_id != closure.source_manifest_id
        or scope.command.candidate_manifest_id != closure.source_manifest_id
    ):
        _fail(M6ReplayLockedFastTerminalErrorCode.SCOPE_MISMATCH)


def _require_closed_policy_scope(
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    source: M6ReplayLockedClosedPolicyFastPrePolicySource,
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
        _fail(M6ReplayLockedFastTerminalErrorCode.SCOPE_MISMATCH)
    _require_scope(
        scope.pre_policy_execution_scope,
        pending.pre_policy_pending_commitment,
        source,
    )


def _rebind_pack(source_pack: EvidencePack, candidate_run_id: str) -> EvidencePack:
    payload = source_pack.model_dump(mode="json", exclude_computed_fields=True)
    closure_payload = source_pack.closure_report.model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    payload["run_id"] = candidate_run_id
    payload["closure_report"] = {**closure_payload, "run_id": candidate_run_id}
    candidate = EvidencePack.model_validate(payload)
    if (
        candidate.pack_id != source_pack.pack_id
        or candidate.semantic_projection() != source_pack.semantic_projection()
    ):
        _fail(M6ReplayLockedFastTerminalErrorCode.CANDIDATE_REJECTED)
    return candidate


def _rebind_closure(source: ClosureReport, candidate_run_id: str) -> ClosureReport:
    payload = source.model_dump(mode="json", exclude_computed_fields=True)
    payload["run_id"] = candidate_run_id
    return ClosureReport.model_validate(payload)


def build_m6_replay_locked_fast_terminal_candidate(
    *,
    execution_scope: object,
    pending_commitment: object,
    source: object,
) -> M6ReplayLockedFastTerminalCandidate:
    """Re-execute the saved post-parse M3 route and require semantic equality."""

    scope = _canonical_model(execution_scope, M6ReplayLockedExecutionScopeAuthority)
    pending = _canonical_model(
        pending_commitment,
        M6ReplayLockedPendingSampleCommitmentAuthority,
    )
    controlled_source = _controlled_source(source)
    _require_scope(scope, pending, controlled_source)

    return _build_m6_replay_locked_fast_terminal_candidate(
        scope=scope,
        pending=pending,
        controlled_source=controlled_source,
    )


def build_m6_replay_locked_closed_policy_fast_pre_policy_candidate(
    *,
    execution_scope: object,
    pending_commitment: object,
    source: object,
) -> M6ReplayLockedFastTerminalCandidate:
    """Re-execute one V2 Fast READY predecessor against its real CLOSED cut."""

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

    return _build_m6_replay_locked_fast_terminal_candidate(
        scope=scope.pre_policy_execution_scope,
        pending=pending.pre_policy_pending_commitment,
        controlled_source=controlled_source,
    )


def _build_m6_replay_locked_fast_terminal_candidate(
    *,
    scope: M6ReplayLockedExecutionScopeAuthority,
    pending: M6ReplayLockedPendingSampleCommitmentAuthority,
    controlled_source: _FastTerminalSourceFacts,
) -> M6ReplayLockedFastTerminalCandidate:

    source_context = controlled_source.projection_context
    source_case = source_context.case
    source_pack = source_case.evidence_packs[0]
    source_screening = source_case.screening_results[0]
    source_verdict = source_case.verdicts[0]
    source_review = source_case.procedural_reviews[0]
    source_screening_binding = source_context.model_reference_authority.screening_bindings[0]
    source_fast_binding = source_context.model_reference_authority.fast_verdict_bindings[0]
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
    ):
        _fail(M6ReplayLockedFastTerminalErrorCode.SOURCE_INPUT_REJECTED)

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
        candidate_verdict = FastVerdictBuilder().build(
            candidate_screening,
            candidate_pack,
            version=source_verdict.version,
            model_response_refs=source_verdict.model_response_refs,
        )
        candidate_current_closure = _rebind_closure(
            source_gate.current_closure,
            scope.candidate_run_id,
        )
        provisional_gate = M6ProceduralGateExecutionInput(
            source_review_id="m6-locked-fast-review-provisional",
            source_review_document_sha256="0" * 64,
            verdict=candidate_verdict,
            evidence_pack=candidate_pack,
            current_closure=candidate_current_closure,
            gate_config=scope.locked_config.procedural_gate,
            alert_config=scope.locked_config.alerts,
            review_version=source_review.version,
            unknown_reference_attempts=source_gate.unknown_reference_attempts,
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
        candidate_identity = sha256_hex(
            [
                "m6-replay-locked-fast-terminal-candidate-authority",
                1,
                scope.execution_scope_authority_id,
                pending.pending_commitment_authority_id,
                controlled_source.source_identity_sha256,
            ]
        )
        candidate_screening_binding = M6ScreeningModelReferenceBinding(
            screening_id=candidate_screening.screening_id,
            parsed_output_id=candidate_parsed.parsed_output_id,
            final_request_id=source_screening_binding.final_request_id,
            scope=source_screening_binding.scope,
        )
        candidate_fast_binding = M6FastVerdictModelReferenceBinding(
            verdict_id=candidate_verdict.verdict_id,
            screening_id=candidate_screening.screening_id,
            response_ids=source_fast_binding.response_ids,
            scope=source_fast_binding.scope,
        )
        references = M6CaseModelReferenceAuthority(
            source_identity_sha256=candidate_identity,
            run_id=scope.candidate_run_id,
            case_id=candidate_case.case_id,
            manifest_id=candidate_case.manifest_id,
            screening_bindings=(candidate_screening_binding,),
            verdict_bindings=(),
            fast_verdict_bindings=(candidate_fast_binding,),
        )
        candidate_gate_input = M6ProceduralGateExecutionInput(
            source_review_id=candidate_review.review_id,
            source_review_document_sha256=_document_sha256(candidate_review),
            verdict=candidate_verdict,
            evidence_pack=candidate_pack,
            current_closure=candidate_current_closure,
            gate_config=scope.locked_config.procedural_gate,
            alert_config=scope.locked_config.alerts,
            review_version=candidate_review.version,
            unknown_reference_attempts=source_gate.unknown_reference_attempts,
            artifact_bounds=source_gate.artifact_bounds,
        )
        gates = M6CaseProceduralGateAuthority(
            source_identity_sha256=candidate_identity,
            run_id=scope.candidate_run_id,
            case_id=candidate_case.case_id,
            manifest_id=candidate_case.manifest_id,
            inputs=(candidate_gate_input,),
        )
        candidate_context = M6VerifiedProjectionContext(
            case=candidate_case,
            perception=source_context.perception,
            historical_source_run_id=scope.candidate_run_id,
            historical_source_case_id=candidate_case.case_id,
            historical_source_manifest_id=candidate_case.manifest_id,
            model_reference_authority=references,
            procedural_gate_authority=gates,
            model_responses=source_context.model_responses,
        )
        candidate_snapshot = build_m6_case_replay_snapshot(
            context=candidate_context,
            sample_id=pending.sample_id,
            source_case_revision=1,
        )
    except M6ReplayLockedFastTerminalError:
        raise
    except ScreeningRouteError:
        _fail(M6ReplayLockedFastTerminalErrorCode.ROUTE_REJECTED)
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastTerminalErrorCode.CANDIDATE_REJECTED)

    if (
        candidate_pack.closure_report.run_id != scope.candidate_run_id
        or candidate_parsed.request_id != source_screening.parsed_output.request_id
        or candidate_parsed.response_id != source_screening.parsed_output.response_id
        or candidate_parsed.response_content_sha256
        != source_screening.parsed_output.response_content_sha256
        or candidate_review.passed != source_review.passed
        or candidate_snapshot.stage_roots != controlled_source.source_snapshot.stage_roots
        or candidate_snapshot.semantic_case_hash
        != controlled_source.source_snapshot.semantic_case_hash
    ):
        _fail(M6ReplayLockedFastTerminalErrorCode.SEMANTIC_DIVERGENCE)
    try:
        return M6ReplayLockedFastTerminalCandidate(
            case=candidate_case,
            projection_context=candidate_context,
            candidate_snapshot=candidate_snapshot,
            source_snapshot=controlled_source.source_snapshot,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedFastTerminalErrorCode.CANDIDATE_REJECTED)


__all__ = [
    "M6ReplayLockedFastTerminalCandidate",
    "M6ReplayLockedFastTerminalError",
    "M6ReplayLockedFastTerminalErrorCode",
    "build_m6_replay_locked_closed_policy_fast_pre_policy_candidate",
    "build_m6_replay_locked_fast_terminal_candidate",
]
