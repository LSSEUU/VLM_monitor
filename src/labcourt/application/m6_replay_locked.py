"""Fail-closed receipt construction for one M6 ``REPLAY_LOCKED`` sample."""

from __future__ import annotations

import re
from enum import StrEnum

from labcourt.contracts.enums import ReproducibilityMode
from labcourt.contracts.frames import SHA256_PATTERN
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionExecutionEntry,
    M6RegressionRunCommand,
    M6ReplayExecutionOutcome,
    M6ReplayExecutionReceipt,
)
from labcourt.contracts.m6_replay_locked import (
    M6ProviderTrapAuthority,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import LabCourtError

_SHA256 = re.compile(SHA256_PATTERN)


class M6ReplayLockedReceiptErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    MODE_NOT_REPLAY_LOCKED = "MODE_NOT_REPLAY_LOCKED"
    EXECUTION_ENTRY_CLOSURE_MISMATCH = "EXECUTION_ENTRY_CLOSURE_MISMATCH"
    COMMAND_CLOSURE_MANIFEST_MISMATCH = "COMMAND_CLOSURE_MANIFEST_MISMATCH"
    PROVIDER_TRAP_SCOPE_MISMATCH = "PROVIDER_TRAP_SCOPE_MISMATCH"
    PROVIDER_CAPABILITY_USED = "PROVIDER_CAPABILITY_USED"
    OUTCOME_SNAPSHOT_MISMATCH = "OUTCOME_SNAPSHOT_MISMATCH"
    CANDIDATE_SNAPSHOT_SCOPE_MISMATCH = "CANDIDATE_SNAPSHOT_SCOPE_MISMATCH"


class M6ReplayLockedReceiptError(LabCourtError):
    """One cross-authority relationship cannot be proven for a locked receipt."""

    def __init__(self, code: M6ReplayLockedReceiptErrorCode) -> None:
        if not isinstance(code, M6ReplayLockedReceiptErrorCode):
            raise TypeError("code must be an M6ReplayLockedReceiptErrorCode")
        self.code = code
        super().__init__(f"M6 REPLAY_LOCKED receipt construction failed: {code.value}")


def _require_argument_types(
    *,
    command: object,
    execution_entry: object,
    closure: object,
    provider_trap: object,
    candidate_run_id: object,
    execution_component_manifest_id: object,
    outcome: object,
    candidate_snapshot: object,
) -> tuple[
    M6RegressionRunCommand,
    M6RegressionExecutionEntry,
    M6ReplayInputClosureAuthority,
    M6ProviderTrapAuthority,
    M6CaseReplaySnapshot | None,
]:
    if (
        not isinstance(command, M6RegressionRunCommand)
        or not isinstance(execution_entry, M6RegressionExecutionEntry)
        or not isinstance(closure, M6ReplayInputClosureAuthority)
        or not isinstance(provider_trap, M6ProviderTrapAuthority)
        or not isinstance(candidate_run_id, str)
        or not isinstance(execution_component_manifest_id, str)
        or not isinstance(outcome, M6ReplayExecutionOutcome)
        or (
            candidate_snapshot is not None
            and not isinstance(candidate_snapshot, M6CaseReplaySnapshot)
        )
    ):
        raise M6ReplayLockedReceiptError(M6ReplayLockedReceiptErrorCode.INVALID_ARGUMENT)
    try:
        require_reference_token(candidate_run_id, "M6 candidate_run_id")
    except (TypeError, ValueError):
        raise M6ReplayLockedReceiptError(M6ReplayLockedReceiptErrorCode.INVALID_ARGUMENT) from None
    if _SHA256.fullmatch(execution_component_manifest_id) is None:
        raise M6ReplayLockedReceiptError(M6ReplayLockedReceiptErrorCode.INVALID_ARGUMENT)
    try:
        canonical_command = M6RegressionRunCommand.model_validate(command.model_dump(mode="json"))
        canonical_entry = M6RegressionExecutionEntry.model_validate(
            execution_entry.model_dump(mode="json")
        )
        canonical_closure = M6ReplayInputClosureAuthority.model_validate(
            closure.model_dump(mode="json")
        )
        canonical_trap = M6ProviderTrapAuthority.model_validate(
            provider_trap.model_dump(mode="json")
        )
        canonical_snapshot = (
            M6CaseReplaySnapshot.model_validate(candidate_snapshot.model_dump(mode="json"))
            if candidate_snapshot is not None
            else None
        )
    except (AttributeError, TypeError, ValueError):
        raise M6ReplayLockedReceiptError(M6ReplayLockedReceiptErrorCode.INVALID_ARGUMENT) from None
    return (
        canonical_command,
        canonical_entry,
        canonical_closure,
        canonical_trap,
        canonical_snapshot,
    )


def build_m6_replay_locked_execution_receipt(
    *,
    command: M6RegressionRunCommand,
    execution_entry: M6RegressionExecutionEntry,
    closure: M6ReplayInputClosureAuthority,
    provider_trap: M6ProviderTrapAuthority,
    candidate_run_id: str,
    execution_component_manifest_id: str,
    outcome: M6ReplayExecutionOutcome,
    candidate_snapshot: M6CaseReplaySnapshot | None,
) -> M6ReplayExecutionReceipt:
    """Derive a receipt only after every locked-input and zero-provider link closes."""

    command, execution_entry, closure, provider_trap, candidate_snapshot = _require_argument_types(
        command=command,
        execution_entry=execution_entry,
        closure=closure,
        provider_trap=provider_trap,
        candidate_run_id=candidate_run_id,
        execution_component_manifest_id=execution_component_manifest_id,
        outcome=outcome,
        candidate_snapshot=candidate_snapshot,
    )
    if command.mode != ReproducibilityMode.REPLAY_LOCKED:
        raise M6ReplayLockedReceiptError(M6ReplayLockedReceiptErrorCode.MODE_NOT_REPLAY_LOCKED)

    expected_entry_closure = (
        closure.sample_id,
        closure.input_authority_id,
        closure.input_authority_document_sha256,
        closure.replay_input_closure_authority_id,
        closure.replay_input_closure_document_sha256,
    )
    observed_entry_closure = (
        execution_entry.sample_id,
        execution_entry.input_authority_id,
        execution_entry.input_authority_document_sha256,
        execution_entry.replay_input_closure_authority_id,
        execution_entry.replay_input_closure_document_sha256,
    )
    if observed_entry_closure != expected_entry_closure:
        raise M6ReplayLockedReceiptError(
            M6ReplayLockedReceiptErrorCode.EXECUTION_ENTRY_CLOSURE_MISMATCH
        )
    if (
        command.baseline_manifest_id != closure.source_manifest_id
        or command.candidate_manifest_id != closure.source_manifest_id
    ):
        raise M6ReplayLockedReceiptError(
            M6ReplayLockedReceiptErrorCode.COMMAND_CLOSURE_MANIFEST_MISMATCH
        )

    expected_trap_scope = (
        command.command_id,
        candidate_run_id,
        execution_component_manifest_id,
    )
    observed_trap_scope = (
        provider_trap.command_id,
        provider_trap.candidate_run_id,
        provider_trap.execution_component_manifest_id,
    )
    if observed_trap_scope != expected_trap_scope:
        raise M6ReplayLockedReceiptError(
            M6ReplayLockedReceiptErrorCode.PROVIDER_TRAP_SCOPE_MISMATCH
        )
    if (
        not provider_trap.clean
        or provider_trap.external_capability_call_count != 0
        or provider_trap.counters.total != 0
    ):
        raise M6ReplayLockedReceiptError(M6ReplayLockedReceiptErrorCode.PROVIDER_CAPABILITY_USED)

    has_snapshot = candidate_snapshot is not None
    if has_snapshot != (outcome == M6ReplayExecutionOutcome.CASE_REPLAYED):
        raise M6ReplayLockedReceiptError(M6ReplayLockedReceiptErrorCode.OUTCOME_SNAPSHOT_MISMATCH)
    if candidate_snapshot is not None and (
        candidate_snapshot.sample_id != execution_entry.sample_id
        or candidate_snapshot.source_run_id != candidate_run_id
        or candidate_snapshot.manifest_id != command.candidate_manifest_id
    ):
        raise M6ReplayLockedReceiptError(
            M6ReplayLockedReceiptErrorCode.CANDIDATE_SNAPSHOT_SCOPE_MISMATCH
        )

    return M6ReplayExecutionReceipt(
        command_id=command.command_id,
        mode=command.mode,
        sample_id=execution_entry.sample_id,
        execution_entry_id=execution_entry.execution_entry_id,
        candidate_run_id=candidate_run_id,
        candidate_manifest_id=command.candidate_manifest_id,
        execution_component_manifest_id=execution_component_manifest_id,
        outcome=outcome,
        candidate_snapshot_id=(
            candidate_snapshot.snapshot_id if candidate_snapshot is not None else None
        ),
        detection_count=closure.detection_count,
        detection_inventory_root_sha256=closure.detection_inventory_root_sha256,
        model_response_count=closure.model_response_count,
        model_response_inventory_root_sha256=closure.model_response_inventory_root_sha256,
        embedding_count=closure.embedding_count,
        embedding_inventory_root_sha256=closure.embedding_inventory_root_sha256,
        tool_result_count=closure.tool_result_count,
        tool_result_inventory_root_sha256=closure.tool_result_inventory_root_sha256,
        provider_call_count=provider_trap.external_capability_call_count,
        provider_trap_authority_id=provider_trap.provider_trap_authority_id,
        provider_trap_document_sha256=provider_trap.provider_trap_document_sha256,
    )


__all__ = [
    "M6ReplayLockedReceiptError",
    "M6ReplayLockedReceiptErrorCode",
    "build_m6_replay_locked_execution_receipt",
]
