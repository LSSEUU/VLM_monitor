"""One-sample execution boundary for additive M6 CLOSED-policy replay."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.exceptions import ContractViolation


class M6ReplayLockedClosedPolicySampleExecutorFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNSUPPORTED_ROUTE = "UNSUPPORTED_ROUTE"
    SOURCE_INPUT_REJECTED = "SOURCE_INPUT_REJECTED"
    CANDIDATE_STATE_CONFLICT = "CANDIDATE_STATE_CONFLICT"
    POLICY_REJECTED = "POLICY_REJECTED"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6ReplayLockedClosedPolicySampleExecutorError(ContractViolation):
    """Payload-free failure from the isolated CLOSED-policy sample executor."""

    def __init__(
        self,
        reason_code: M6ReplayLockedClosedPolicySampleExecutorFailureCode,
    ) -> None:
        if not isinstance(
            reason_code,
            M6ReplayLockedClosedPolicySampleExecutorFailureCode,
        ):
            raise TypeError("reason_code must be an M6 CLOSED-policy executor failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 CLOSED-policy sample execution failed: {reason_code.value}")


@runtime_checkable
class M6ReplayLockedClosedPolicySampleExecutor(Protocol):
    """Materialize one exact V2 Pending into durable policy plus CLOSED Case."""

    def execute_sample(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        replay_input_closure: M6ReplayInputClosureAuthority,
    ) -> None: ...


__all__ = [
    "M6ReplayLockedClosedPolicySampleExecutor",
    "M6ReplayLockedClosedPolicySampleExecutorError",
    "M6ReplayLockedClosedPolicySampleExecutorFailureCode",
]
