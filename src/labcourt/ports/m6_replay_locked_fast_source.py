"""Narrow verified source input for the first locked M3 terminal route."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus, ScreeningDecision
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelRole,
    M6ReplayInputClosureAuthority,
)
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class M6ReplayLockedFastTerminalSource:
    """One source Case proven suitable for ``M3_FAST_TERMINAL_POST_PARSE``.

    Raw response bodies and mutable provider/cache capabilities are deliberately
    absent.  The candidate executor receives only the already-validated parsed
    output, response content identities, deterministic Gate input, perception,
    and exact source semantic snapshot.
    """

    source_identity_sha256: str
    closure: M6ReplayInputClosureAuthority
    projection_context: M6VerifiedProjectionContext
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if not _is_sha256(self.source_identity_sha256):
            raise ValueError("M6 locked fast source identity must be a SHA-256")
        if (
            type(self.closure) is not M6ReplayInputClosureAuthority
            or type(self.projection_context) is not M6VerifiedProjectionContext
            or type(self.source_snapshot) is not M6CaseReplaySnapshot
        ):
            raise TypeError("M6 locked fast source requires exact authority types")
        try:
            closure = M6ReplayInputClosureAuthority.model_validate(
                self.closure.model_dump(mode="json", exclude_computed_fields=True)
            )
            snapshot = M6CaseReplaySnapshot.model_validate(
                self.source_snapshot.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
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
            raise ValueError("M6 locked fast source is not canonical") from None
        case = context.case
        revision = closure.source_case_revision
        if revision is None:
            raise ValueError("M6 locked fast source requires a selected Case revision")
        try:
            derived = build_m6_case_replay_snapshot(
                context=context,
                sample_id=closure.sample_id,
                source_case_revision=revision,
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked fast source snapshot cannot be rebuilt") from None
        if (
            closure != self.closure
            or snapshot != self.source_snapshot
            or context != self.projection_context
            or derived != snapshot
            or closure.source_case_id != case.case_id
            or closure.source_case_document_sha256 != snapshot.source_case_document_sha256
            or closure.source_run_id != case.run_id
            or closure.source_manifest_id != case.manifest_id
            or self.source_identity_sha256
            != context.model_reference_authority.source_identity_sha256
            or self.source_identity_sha256
            != context.procedural_gate_authority.source_identity_sha256
            or resolve_m6_locked_model_responses(closure.model_calls) != context.model_responses
        ):
            raise ValueError("M6 locked fast source authorities are cross-grafted")
        self._require_exact_route_shape(case, context)

    @staticmethod
    def _require_exact_route_shape(
        case: Case,
        context: M6VerifiedProjectionContext,
    ) -> None:
        references = context.model_reference_authority
        gates = context.procedural_gate_authority
        if (
            len(case.evidence_packs) != 1
            or len(case.screening_results) != 1
            or len(case.verdicts) != 1
            or len(case.procedural_reviews) != 1
            or case.alerts
            or case.appeals
            or case.final_decision is not None
            or case.current_backlog_item_id is not None
            or case.evidence_packs[0].version != 1
            or case.evidence_packs[0].tool_results
            or case.screening_results[0].decision == ScreeningDecision.ESCALATE
            or len(references.screening_bindings) != 1
            or references.verdict_bindings
            or len(references.fast_verdict_bindings) != 1
            or len(gates.inputs) != 1
            or context.retrieval_cycles
            or context.acquisitions
            or not context.model_responses
            or any(
                item.layer != M6LockedModelCallLayer.SCREENING
                or item.role != M6LockedModelRole.SCREENING
                for item in context.model_responses
            )
        ):
            raise ValueError("source Case is outside the locked M3 fast terminal route")
        pack = case.evidence_packs[0]
        screening = case.screening_results[0]
        verdict = case.verdicts[0]
        review = case.procedural_reviews[0]
        gate = gates.inputs[0]
        expected_status = (
            CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
        )
        if (
            case.status != expected_status
            or screening.evidence_pack_id != pack.pack_id
            or verdict.screening_id != screening.screening_id
            or verdict.evidence_pack_id != pack.pack_id
            or review.reviewed_verdict_id != verdict.verdict_id
            or gate.verdict != verdict
            or gate.evidence_pack != pack
            or gate.rebuild_review() != review
            or gate.precedent_resolutions
            or references.fast_verdict_bindings[0].verdict_id != verdict.verdict_id
        ):
            raise ValueError("source Case does not close the locked M3 fast terminal route")


@runtime_checkable
class M6ReplayLockedFastTerminalSourceProvider(Protocol):
    def load_fast_terminal_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedFastTerminalSource: ...


__all__ = [
    "M6ReplayLockedFastTerminalSource",
    "M6ReplayLockedFastTerminalSourceProvider",
]
