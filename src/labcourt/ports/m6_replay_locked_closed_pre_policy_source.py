"""Candidate-safe READY predecessors for replaying a CLOSED source Case."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, TypeAlias, runtime_checkable

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.hearing_state import (
    HearingRecord,
    HearingVerdictBinding,
)
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
)
from labcourt.contracts.m6_source_authority import M6GateCurrentClosureReceipt
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_context(value: object) -> M6VerifiedProjectionContext:
    if type(value) is not M6VerifiedProjectionContext:
        raise TypeError("M6 CLOSED pre-policy source requires an exact projection context")
    try:
        return M6VerifiedProjectionContext(
            case=value.case,
            perception=value.perception,
            historical_source_run_id=value.historical_source_run_id,
            historical_source_case_id=value.historical_source_case_id,
            historical_source_manifest_id=value.historical_source_manifest_id,
            model_reference_authority=value.model_reference_authority,
            procedural_gate_authority=value.procedural_gate_authority,
            model_responses=value.model_responses,
            retrieval_cycles=value.retrieval_cycles,
            acquisitions=value.acquisitions,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M6 CLOSED pre-policy projection context is not canonical") from None


def _canonical_closure(value: object) -> M6ReplayInputClosureAuthority:
    if type(value) is not M6ReplayInputClosureAuthority:
        raise TypeError("M6 CLOSED pre-policy source requires an exact catalog closure")
    try:
        controlled = M6ReplayInputClosureAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M6 CLOSED pre-policy catalog closure is not canonical") from None
    if controlled != value:
        raise ValueError("M6 CLOSED pre-policy catalog closure is not canonical")
    return controlled


def _canonical_binding(
    value: object,
) -> M6ReplayLockedClosedPolicySourceBindingAuthority:
    if type(value) is not M6ReplayLockedClosedPolicySourceBindingAuthority:
        raise TypeError("M6 CLOSED pre-policy source requires an exact safe binding")
    try:
        controlled = M6ReplayLockedClosedPolicySourceBindingAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M6 CLOSED pre-policy safe binding is not canonical") from None
    if controlled != value:
        raise ValueError("M6 CLOSED pre-policy safe binding is not canonical")
    return controlled


def _canonical_snapshot(value: object) -> M6CaseReplaySnapshot:
    if type(value) is not M6CaseReplaySnapshot:
        raise TypeError("M6 CLOSED pre-policy source requires an exact snapshot")
    try:
        controlled = M6CaseReplaySnapshot.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M6 CLOSED pre-policy snapshot is not canonical") from None
    if controlled != value:
        raise ValueError("M6 CLOSED pre-policy snapshot is not canonical")
    return controlled


def _validate_common(
    *,
    source_identity_sha256: object,
    source_binding: object,
    catalog_closure: object,
    source_ready_case_revision: object,
    projection_context: object,
    source_snapshot: object,
    expected_route: M6ReplayLockedExecutionRoute,
) -> tuple[
    M6ReplayLockedClosedPolicySourceBindingAuthority,
    M6ReplayInputClosureAuthority,
    M6VerifiedProjectionContext,
    M6CaseReplaySnapshot,
]:
    if not _is_sha256(source_identity_sha256):
        raise ValueError("M6 CLOSED pre-policy source identity must be a SHA-256")
    if (
        not isinstance(source_ready_case_revision, int)
        or isinstance(source_ready_case_revision, bool)
        or source_ready_case_revision < 1
    ):
        raise ValueError("M6 CLOSED pre-policy READY revision must be positive")
    binding = _canonical_binding(source_binding)
    closure = _canonical_closure(catalog_closure)
    context = _canonical_context(projection_context)
    snapshot = _canonical_snapshot(source_snapshot)
    case = context.case
    try:
        derived = build_m6_case_replay_snapshot(
            context=context,
            sample_id=closure.sample_id,
            source_case_revision=source_ready_case_revision,
        )
        ready_document = canonical_json(case.model_dump(mode="json"))
        ready_sha256 = hashlib.sha256(ready_document.encode("utf-8")).hexdigest()
        resolved_responses = resolve_m6_locked_model_responses(closure.model_calls)
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M6 CLOSED pre-policy READY source cannot be rebuilt") from None
    if (
        binding.pre_policy_route != expected_route
        or binding.sample_id != closure.sample_id
        or binding.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
        or binding.replay_input_closure_document_sha256
        != closure.replay_input_closure_document_sha256
        or closure.source_case_id is None
        or closure.source_case_revision is None
        or closure.source_case_document_sha256 is None
        or closure.source_case_revision != source_ready_case_revision + 1
        or closure.source_case_id != case.case_id
        or closure.source_run_id != case.run_id
        or closure.source_manifest_id != case.manifest_id
        or closure.source_case_document_sha256 == ready_sha256
        or case.status != CaseStatus.READY_FOR_ALERT_POLICY
        or case.alerts
        or case.appeals
        or case.final_decision is not None
        or case.current_backlog_item_id is not None
        or derived != snapshot
        or snapshot.source_case_document_sha256 != ready_sha256
        or snapshot.source_case_revision != source_ready_case_revision
        or source_identity_sha256 != context.model_reference_authority.source_identity_sha256
        or source_identity_sha256 != context.procedural_gate_authority.source_identity_sha256
        or resolved_responses != context.model_responses
    ):
        raise ValueError("M6 CLOSED pre-policy source authorities are cross-grafted")
    return binding, closure, context, snapshot


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyFastPrePolicySource:
    """Sanitized M3 READY predecessor; no source policy or CLOSED body."""

    source_identity_sha256: str
    source_binding: M6ReplayLockedClosedPolicySourceBindingAuthority
    catalog_closure: M6ReplayInputClosureAuthority
    source_ready_case_revision: int
    projection_context: M6VerifiedProjectionContext
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        binding, closure, context, snapshot = _validate_common(
            source_identity_sha256=self.source_identity_sha256,
            source_binding=self.source_binding,
            catalog_closure=self.catalog_closure,
            source_ready_case_revision=self.source_ready_case_revision,
            projection_context=self.projection_context,
            source_snapshot=self.source_snapshot,
            expected_route=M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
        )
        M6ReplayLockedFastTerminalSource._require_exact_route_shape(
            context.case,
            context,
        )
        object.__setattr__(self, "source_binding", binding)
        object.__setattr__(self, "catalog_closure", closure)
        object.__setattr__(self, "projection_context", context)
        object.__setattr__(self, "source_snapshot", snapshot)

    @property
    def closure(self) -> M6ReplayInputClosureAuthority:
        """Expose the real catalog closure under the shared terminal-source shape."""

        return self.catalog_closure


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyM4PrePolicySource:
    """Sanitized M4 READY predecessor; no source policy or CLOSED body."""

    source_identity_sha256: str
    source_binding: M6ReplayLockedClosedPolicySourceBindingAuthority
    catalog_closure: M6ReplayInputClosureAuthority
    source_ready_case_revision: int
    projection_context: M6VerifiedProjectionContext
    hearing_record: HearingRecord
    hearing_verdict_binding: HearingVerdictBinding
    gate_current_closure_receipt: M6GateCurrentClosureReceipt
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        binding, closure, context, snapshot = _validate_common(
            source_identity_sha256=self.source_identity_sha256,
            source_binding=self.source_binding,
            catalog_closure=self.catalog_closure,
            source_ready_case_revision=self.source_ready_case_revision,
            projection_context=self.projection_context,
            source_snapshot=self.source_snapshot,
            expected_route=(M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE),
        )
        try:
            record = HearingRecord.model_validate(
                self.hearing_record.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            verdict_binding = HearingVerdictBinding.model_validate(
                self.hearing_verdict_binding.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            gate_receipt = M6GateCurrentClosureReceipt.model_validate(
                self.gate_current_closure_receipt.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 CLOSED M4 pre-policy authorities are not canonical") from None
        if (
            type(self.hearing_record) is not HearingRecord
            or type(self.hearing_verdict_binding) is not HearingVerdictBinding
            or type(self.gate_current_closure_receipt) is not M6GateCurrentClosureReceipt
            or record != self.hearing_record
            or verdict_binding != self.hearing_verdict_binding
            or gate_receipt != self.gate_current_closure_receipt
        ):
            raise ValueError("M6 CLOSED M4 pre-policy authorities are cross-grafted")
        M6ReplayLockedM4GateTerminalSource._require_exact_route_shape(
            context.case,
            context,
            closure,
            record,
        )
        M6ReplayLockedM4GateTerminalSource._require_terminal_join(
            context.case,
            context,
            record,
            verdict_binding,
            gate_receipt,
        )
        object.__setattr__(self, "source_binding", binding)
        object.__setattr__(self, "catalog_closure", closure)
        object.__setattr__(self, "projection_context", context)
        object.__setattr__(self, "hearing_record", record)
        object.__setattr__(self, "hearing_verdict_binding", verdict_binding)
        object.__setattr__(self, "gate_current_closure_receipt", gate_receipt)
        object.__setattr__(self, "source_snapshot", snapshot)

    @property
    def closure(self) -> M6ReplayInputClosureAuthority:
        """Expose the real catalog closure under the shared terminal-source shape."""

        return self.catalog_closure


M6ReplayLockedClosedPolicyPrePolicySource: TypeAlias = (
    M6ReplayLockedClosedPolicyFastPrePolicySource | M6ReplayLockedClosedPolicyM4PrePolicySource
)


@runtime_checkable
class M6ReplayLockedClosedPolicyPrePolicySourceProvider(Protocol):
    def load_closed_policy_pre_policy_source(
        self,
        closure: M6ReplayInputClosureAuthority,
        source_binding: M6ReplayLockedClosedPolicySourceBindingAuthority,
    ) -> M6ReplayLockedClosedPolicyPrePolicySource: ...


__all__ = [
    "M6ReplayLockedClosedPolicyFastPrePolicySource",
    "M6ReplayLockedClosedPolicyM4PrePolicySource",
    "M6ReplayLockedClosedPolicyPrePolicySource",
    "M6ReplayLockedClosedPolicyPrePolicySourceProvider",
]
