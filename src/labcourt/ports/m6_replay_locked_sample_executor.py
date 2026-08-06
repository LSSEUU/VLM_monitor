"""One-sample execution boundary for the dedicated M6 locked replay path."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.exceptions import ContractViolation


class M6ReplayLockedSampleExecutorFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNSUPPORTED_ROUTE = "UNSUPPORTED_ROUTE"
    SOURCE_INPUT_REJECTED = "SOURCE_INPUT_REJECTED"
    CANDIDATE_STATE_CONFLICT = "CANDIDATE_STATE_CONFLICT"
    CAPABILITY_TRAP_TRIGGERED = "CAPABILITY_TRAP_TRIGGERED"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6ReplayLockedSampleExecutorError(ContractViolation):
    """Payload-free failure from the isolated deterministic sample executor."""

    def __init__(self, reason_code: M6ReplayLockedSampleExecutorFailureCode) -> None:
        if not isinstance(reason_code, M6ReplayLockedSampleExecutorFailureCode):
            raise TypeError("reason_code must be an M6 locked sample-executor failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 locked sample execution failed: {reason_code.value}")


@runtime_checkable
class M6ReplayLockedSampleExecutor(Protocol):
    """Materialize one exact Pending into candidate state, without returning claims."""

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None: ...


__all__ = [
    "M6ReplayLockedSampleExecutor",
    "M6ReplayLockedSampleExecutorError",
    "M6ReplayLockedSampleExecutorFailureCode",
]
