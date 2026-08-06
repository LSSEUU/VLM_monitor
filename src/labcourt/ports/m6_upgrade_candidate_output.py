"""Trusted boundary for one terminal M6 candidate output inventory."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.exceptions import ContractViolation


class M6UpgradeCandidateOutputFailureCode(StrEnum):
    """Controlled failures without authority payloads or physical host details."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    LEDGER_VERSION_UNSUPPORTED = "LEDGER_VERSION_UNSUPPORTED"
    LEDGER_NOT_SEALED = "LEDGER_NOT_SEALED"
    RUN_CUT_NOT_FOUND = "RUN_CUT_NOT_FOUND"
    RUN_CUT_MISMATCH = "RUN_CUT_MISMATCH"
    OBSERVATION_CLOSURE_MISMATCH = "OBSERVATION_CLOSURE_MISMATCH"
    CASE_BINDING_MISMATCH = "CASE_BINDING_MISMATCH"
    MODEL_CALL_CLOSURE_MISMATCH = "MODEL_CALL_CLOSURE_MISMATCH"
    PHYSICAL_ARTIFACT_REJECTED = "PHYSICAL_ARTIFACT_REJECTED"
    INVENTORY_CLOSURE_MISMATCH = "INVENTORY_CLOSURE_MISMATCH"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    SNAPSHOT_REJECTED = "SNAPSHOT_REJECTED"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeCandidateOutputError(ContractViolation):
    """Typed, payload-free failure at the terminal candidate-output boundary."""

    def __init__(self, reason_code: M6UpgradeCandidateOutputFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeCandidateOutputFailureCode):
            raise TypeError("reason_code must be an M6UpgradeCandidateOutputFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 upgrade candidate output build failed: {reason_code.value}")


@runtime_checkable
class M6UpgradeCandidateOutputBuilder(Protocol):
    """Build terminal Inventory V3 from two durable scope identities.

    Implementations own the sealed V3 state, run-cut, selected-Case, physical
    artifact, model-call, snapshot, and receipt joins. Callers cannot supply or
    amend any authority used to construct the terminal inventory.
    """

    def build_terminal_inventory(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateOutputInventoryAuthorityV3: ...


__all__ = [
    "M6UpgradeCandidateOutputBuilder",
    "M6UpgradeCandidateOutputError",
    "M6UpgradeCandidateOutputFailureCode",
]
