"""Trusted orchestration boundary for one protocol-V3 candidate execution."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.exceptions import ContractViolation


class M6UpgradeCandidateCoordinatorFailureCode(StrEnum):
    """Closed orchestration failures without durable or physical payloads."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_CONFLICT = "SCOPE_CONFLICT"
    EXECUTION_STATE_INVALID = "EXECUTION_STATE_INVALID"
    OBSERVATION_REJECTED = "OBSERVATION_REJECTED"
    SAMPLE_REJECTED = "SAMPLE_REJECTED"
    SEAL_REJECTED = "SEAL_REJECTED"
    RUN_CUT_REJECTED = "RUN_CUT_REJECTED"
    TERMINAL_OUTPUT_REJECTED = "TERMINAL_OUTPUT_REJECTED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    COORDINATION_STALLED = "COORDINATION_STALLED"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeCandidateCoordinatorError(ContractViolation):
    """Payload-free failure at the terminal candidate coordinator boundary."""

    def __init__(self, reason_code: M6UpgradeCandidateCoordinatorFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeCandidateCoordinatorFailureCode):
            raise TypeError("reason_code must be an M6 candidate coordinator failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 candidate coordination failed: {reason_code.value}")


@runtime_checkable
class M6UpgradeCandidateCoordinatorV3(Protocol):
    """Drive one durable V3 execution through Seal, Run Cut, and Inventory."""

    def run_to_terminal(
        self,
        execution_scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3: ...

    def resume_to_terminal(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3: ...


__all__ = [
    "M6UpgradeCandidateCoordinatorError",
    "M6UpgradeCandidateCoordinatorFailureCode",
    "M6UpgradeCandidateCoordinatorV3",
]
