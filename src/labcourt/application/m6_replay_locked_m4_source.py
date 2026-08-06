"""Narrow one verified SQLite projection to the first locked M4 terminal source."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_verified_projection_context import M6SqliteProjectionAssembly
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import AuditAction, CaseStatus
from labcourt.contracts.hearing_state import HearingRecord, HearingVerdictBinding
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority import M6GateCurrentClosureReceipt
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedM4SourceErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    ROUTE_REJECTED = "ROUTE_REJECTED"
    MODEL_CALL_CLOSURE_MISMATCH = "MODEL_CALL_CLOSURE_MISMATCH"
    HEARING_CLOSURE_MISMATCH = "HEARING_CLOSURE_MISMATCH"
    HISTORICAL_CUT_MISMATCH = "HISTORICAL_CUT_MISMATCH"
    SOURCE_GATE_INVALID = "SOURCE_GATE_INVALID"
    PROJECTION_INVALID = "PROJECTION_INVALID"


class M6ReplayLockedM4SourceError(LabCourtError):
    """Payload-free failure while narrowing a sealed M4 source authority."""

    def __init__(self, code: M6ReplayLockedM4SourceErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedM4SourceErrorCode):
            raise TypeError("code must be an M6 locked M4 source error code")
        self.code = code
        super().__init__(f"M6 locked M4 source failed: {code.value}")


def _fail(code: M6ReplayLockedM4SourceErrorCode) -> NoReturn:
    raise M6ReplayLockedM4SourceError(code)


def _canonical_model(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        _fail(M6ReplayLockedM4SourceErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4SourceErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ReplayLockedM4SourceErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_context(value: object) -> M6VerifiedProjectionContext:
    if type(value) is not M6VerifiedProjectionContext:
        _fail(M6ReplayLockedM4SourceErrorCode.PROJECTION_INVALID)
    try:
        controlled = M6VerifiedProjectionContext(
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
        _fail(M6ReplayLockedM4SourceErrorCode.PROJECTION_INVALID)
    if controlled != value:
        _fail(M6ReplayLockedM4SourceErrorCode.PROJECTION_INVALID)
    return controlled


def _document_sha256(value: BaseModel) -> str:
    document = canonical_json(value.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _controlled_assembly(value: object) -> M6SqliteProjectionAssembly:
    if type(value) is not M6SqliteProjectionAssembly:
        _fail(M6ReplayLockedM4SourceErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6SqliteProjectionAssembly(
            source_identity_sha256=value.source_identity_sha256,
            closure=value.closure,
            model_calls=value.model_calls,
            embeddings=value.embeddings,
            projection_context=value.projection_context,
            case_replay_snapshot=value.case_replay_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4SourceErrorCode.PROJECTION_INVALID)
    if controlled != value:
        _fail(M6ReplayLockedM4SourceErrorCode.PROJECTION_INVALID)
    return controlled


@dataclass(frozen=True, slots=True)
class M6ReplayLockedM4PrePolicyProjection:
    """Sanitized READY projection proven from one real adjacent CLOSED cut.

    ``catalog_closure`` is the real CLOSED catalog authority.  The private
    READY selector used by a storage adapter is deliberately absent, as are
    the source policy and CLOSED Case body.
    """

    source_identity_sha256: str
    catalog_closure: M6ReplayInputClosureAuthority
    source_ready_case_revision: int
    projection_context: M6VerifiedProjectionContext
    hearing_record: HearingRecord
    hearing_verdict_binding: HearingVerdictBinding
    gate_current_closure_receipt: M6GateCurrentClosureReceipt
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_identity_sha256, str)
            or len(self.source_identity_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.source_identity_sha256)
            or not isinstance(self.source_ready_case_revision, int)
            or isinstance(self.source_ready_case_revision, bool)
            or self.source_ready_case_revision < 1
        ):
            raise ValueError("M6 CLOSED M4 predecessor identity is invalid")
        try:
            closure = M6ReplayInputClosureAuthority.model_validate(
                self.catalog_closure.model_dump(
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
            record = HearingRecord.model_validate(
                self.hearing_record.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            binding = HearingVerdictBinding.model_validate(
                self.hearing_verdict_binding.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            receipt = M6GateCurrentClosureReceipt.model_validate(
                self.gate_current_closure_receipt.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            snapshot = M6CaseReplaySnapshot.model_validate(
                self.source_snapshot.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                )
            )
            rebuilt = build_m6_case_replay_snapshot(
                context=context,
                sample_id=closure.sample_id,
                source_case_revision=self.source_ready_case_revision,
            )
            resolved_responses = resolve_m6_locked_model_responses(closure.model_calls)
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 CLOSED M4 predecessor authorities are not canonical") from None
        ready = context.case
        if (
            type(self.catalog_closure) is not M6ReplayInputClosureAuthority
            or type(self.projection_context) is not M6VerifiedProjectionContext
            or type(self.hearing_record) is not HearingRecord
            or type(self.hearing_verdict_binding) is not HearingVerdictBinding
            or type(self.gate_current_closure_receipt) is not M6GateCurrentClosureReceipt
            or type(self.source_snapshot) is not M6CaseReplaySnapshot
            or closure != self.catalog_closure
            or context != self.projection_context
            or record != self.hearing_record
            or binding != self.hearing_verdict_binding
            or receipt != self.gate_current_closure_receipt
            or snapshot != self.source_snapshot
            or closure.source_case_revision != self.source_ready_case_revision + 1
            or closure.source_case_id != ready.case_id
            or closure.source_run_id != ready.run_id
            or closure.source_manifest_id != ready.manifest_id
            or closure.source_case_document_sha256 == snapshot.source_case_document_sha256
            or ready.status != CaseStatus.READY_FOR_ALERT_POLICY
            or ready.alerts
            or ready.appeals
            or ready.final_decision is not None
            or ready.current_backlog_item_id is not None
            or rebuilt != snapshot
            or resolved_responses != context.model_responses
            or self.source_identity_sha256
            != context.model_reference_authority.source_identity_sha256
            or self.source_identity_sha256
            != context.procedural_gate_authority.source_identity_sha256
        ):
            raise ValueError("M6 CLOSED M4 predecessor authorities are cross-grafted")
        M6ReplayLockedM4GateTerminalSource._require_exact_route_shape(
            ready,
            context,
            closure,
            record,
        )
        M6ReplayLockedM4GateTerminalSource._require_terminal_join(
            ready,
            context,
            record,
            binding,
            receipt,
        )
        object.__setattr__(self, "catalog_closure", closure)
        object.__setattr__(self, "projection_context", context)
        object.__setattr__(self, "hearing_record", record)
        object.__setattr__(self, "hearing_verdict_binding", binding)
        object.__setattr__(self, "gate_current_closure_receipt", receipt)
        object.__setattr__(self, "source_snapshot", snapshot)


def _ready_projection_context(
    closed_context: M6VerifiedProjectionContext,
    ready_case: Case,
) -> M6VerifiedProjectionContext:
    try:
        return M6VerifiedProjectionContext(
            case=ready_case,
            perception=closed_context.perception,
            historical_source_run_id=closed_context.historical_source_run_id,
            historical_source_case_id=closed_context.historical_source_case_id,
            historical_source_manifest_id=(closed_context.historical_source_manifest_id),
            model_reference_authority=closed_context.model_reference_authority,
            procedural_gate_authority=closed_context.procedural_gate_authority,
            model_responses=closed_context.model_responses,
            retrieval_cycles=closed_context.retrieval_cycles,
            acquisitions=closed_context.acquisitions,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4SourceErrorCode.PROJECTION_INVALID)


def assemble_m6_replay_locked_closed_policy_m4_predecessor_projection(
    *,
    catalog_closure: object,
    closed_projection_assembly: object,
    ready_case: object,
    ready_case_revision: object,
    hearing_record: object,
    hearing_verdict_binding: object,
    gate_current_closure_receipt: object,
) -> M6ReplayLockedM4PrePolicyProjection:
    """Rebase a proven CLOSED assembly to its persisted M4 READY predecessor.

    This pure boundary accepts the real CLOSED catalog closure.  It never
    constructs or returns a synthetic READY closure.
    """

    closure = _canonical_model(
        catalog_closure,
        M6ReplayInputClosureAuthority,
    )
    assembly = _controlled_assembly(closed_projection_assembly)
    ready = _canonical_model(ready_case, Case)
    record = _canonical_model(hearing_record, HearingRecord)
    binding = _canonical_model(hearing_verdict_binding, HearingVerdictBinding)
    receipt = _canonical_model(
        gate_current_closure_receipt,
        M6GateCurrentClosureReceipt,
    )
    if (
        not isinstance(ready_case_revision, int)
        or isinstance(ready_case_revision, bool)
        or ready_case_revision < 1
    ):
        _fail(M6ReplayLockedM4SourceErrorCode.INVALID_ARGUMENT)

    closed_context = _controlled_context(assembly.projection_context)
    closed = closed_context.case
    if (
        assembly.closure != closure
        or closure.source_case_revision != ready_case_revision + 1
        or closure.source_case_id != closed.case_id
        or closure.source_run_id != closed.run_id
        or closure.source_manifest_id != closed.manifest_id
        or closure.source_case_document_sha256 != _document_sha256(closed)
        or ready.run_id != closed.run_id
        or ready.case_id != closed.case_id
        or ready.manifest_id != closed.manifest_id
        or ready.status != CaseStatus.READY_FOR_ALERT_POLICY
        or closed.status != CaseStatus.CLOSED
        or ready.alerts
        or ready.appeals
        or ready.final_decision is not None
        or ready.current_backlog_item_id is not None
        or closed.appeals
        or closed.current_backlog_item_id is not None
        or closed.final_decision is None
        or len(closed.alerts) > 1
        or len(closed.timeline) != len(ready.timeline) + 1
        or closed.timeline[:-1] != ready.timeline
    ):
        _fail(M6ReplayLockedM4SourceErrorCode.SOURCE_SCOPE_MISMATCH)
    terminal = closed.timeline[-1]
    ready_payload = ready.model_dump(
        mode="json",
        exclude_computed_fields=True,
        exclude={"status", "alerts", "final_decision", "timeline"},
    )
    closed_payload = closed.model_dump(
        mode="json",
        exclude_computed_fields=True,
        exclude={"status", "alerts", "final_decision", "timeline"},
    )
    if (
        ready_payload != closed_payload
        or _document_sha256(ready) == closure.source_case_document_sha256
        or terminal.sequence != len(ready.timeline)
        or terminal.action != AuditAction.CASE_CLOSED.value
        or terminal.stage != "ALERT_POLICY"
        or terminal.details.get("status") != CaseStatus.CLOSED.value
    ):
        _fail(M6ReplayLockedM4SourceErrorCode.SOURCE_SCOPE_MISMATCH)
    if (
        assembly.source_identity_sha256
        != closed_context.model_reference_authority.source_identity_sha256
        or assembly.source_identity_sha256
        != closed_context.procedural_gate_authority.source_identity_sha256
    ):
        _fail(M6ReplayLockedM4SourceErrorCode.SNAPSHOT_IDENTITY_MISMATCH)

    ready_context = _ready_projection_context(closed_context, ready)
    try:
        ready_snapshot = build_m6_case_replay_snapshot(
            context=ready_context,
            sample_id=closure.sample_id,
            source_case_revision=ready_case_revision,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4SourceErrorCode.PROJECTION_INVALID)
    try:
        return M6ReplayLockedM4PrePolicyProjection(
            source_identity_sha256=assembly.source_identity_sha256,
            catalog_closure=closure,
            source_ready_case_revision=ready_case_revision,
            projection_context=ready_context,
            hearing_record=record,
            hearing_verdict_binding=binding,
            gate_current_closure_receipt=receipt,
            source_snapshot=ready_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4SourceErrorCode.ROUTE_REJECTED)


def narrow_m6_replay_locked_m4_gate_terminal_source(
    *,
    projection_assembly: object,
    hearing_record: object,
    hearing_verdict_binding: object,
    gate_current_closure_receipt: object,
) -> M6ReplayLockedM4GateTerminalSource:
    """Select the exact terminal M4/Gate join from one verified projection cut."""

    assembly = _controlled_assembly(projection_assembly)
    if (
        type(hearing_record) is not HearingRecord
        or type(hearing_verdict_binding) is not HearingVerdictBinding
        or type(gate_current_closure_receipt) is not M6GateCurrentClosureReceipt
    ):
        _fail(M6ReplayLockedM4SourceErrorCode.INVALID_ARGUMENT)
    try:
        return M6ReplayLockedM4GateTerminalSource(
            source_identity_sha256=assembly.source_identity_sha256,
            closure=assembly.closure,
            projection_context=assembly.projection_context,
            hearing_record=hearing_record,
            hearing_verdict_binding=hearing_verdict_binding,
            gate_current_closure_receipt=gate_current_closure_receipt,
            source_snapshot=assembly.case_replay_snapshot,
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ReplayLockedM4SourceErrorCode.ROUTE_REJECTED)


__all__ = [
    "M6ReplayLockedM4PrePolicyProjection",
    "M6ReplayLockedM4SourceError",
    "M6ReplayLockedM4SourceErrorCode",
    "assemble_m6_replay_locked_closed_policy_m4_predecessor_projection",
    "narrow_m6_replay_locked_m4_gate_terminal_source",
]
