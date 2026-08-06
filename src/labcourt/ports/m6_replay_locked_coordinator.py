"""Public orchestration boundary for crash-recoverable M6 locked replay."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)


class M6ReplayLockedCoordinatorFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_REJECTED = "SCOPE_REJECTED"
    SCOPE_CATALOG_MISMATCH = "SCOPE_CATALOG_MISMATCH"
    EXECUTION_STATE_INVALID = "EXECUTION_STATE_INVALID"
    PENDING_REJECTED = "PENDING_REJECTED"
    SOURCE_PROJECTION_REJECTED = "SOURCE_PROJECTION_REJECTED"
    SAMPLE_EXECUTION_REJECTED = "SAMPLE_EXECUTION_REJECTED"
    CANDIDATE_OBSERVATION_MISSING = "CANDIDATE_OBSERVATION_MISSING"
    CANDIDATE_OBSERVATION_REJECTED = "CANDIDATE_OBSERVATION_REJECTED"
    RECORD_REJECTED = "RECORD_REJECTED"
    AUDIT_HEAD_REJECTED = "AUDIT_HEAD_REJECTED"
    SEAL_REJECTED = "SEAL_REJECTED"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORAGE_REJECTED = "STORAGE_REJECTED"
    COORDINATION_STALLED = "COORDINATION_STALLED"


class M6ReplayLockedCoordinatorError(ContractViolation):
    """Payload-free terminal coordinator failure."""

    def __init__(self, reason_code: M6ReplayLockedCoordinatorFailureCode) -> None:
        if not isinstance(reason_code, M6ReplayLockedCoordinatorFailureCode):
            raise TypeError("reason_code must be an M6 locked coordinator failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 locked execution coordination failed: {reason_code.value}")


@runtime_checkable
class M6ReplayLockedCoordinator(Protocol):
    def run_to_terminal(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        stored_source_catalog: M6StoredRegressionExecutionSourceCatalog,
    ) -> M6ReplayLockedExecutionSealAuthority: ...


__all__ = [
    "M6ReplayLockedCoordinator",
    "M6ReplayLockedCoordinatorError",
    "M6ReplayLockedCoordinatorFailureCode",
]
