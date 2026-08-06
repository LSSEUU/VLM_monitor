"""Trusted public boundary for one recoverable protocol-V3 sample append."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.exceptions import ContractViolation


class M6UpgradeDurableSampleAppenderFailureCode(StrEnum):
    """Closed failures without record bodies, database text, or host paths."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    OBSERVATION_NOT_FOUND = "OBSERVATION_NOT_FOUND"
    APPEND_STATE_MISMATCH = "APPEND_STATE_MISMATCH"
    LEDGER_COMPLETE = "LEDGER_COMPLETE"
    LEDGER_SEALED = "LEDGER_SEALED"
    COMMITMENT_CONFLICT = "COMMITMENT_CONFLICT"
    RECORD_CONFLICT = "RECORD_CONFLICT"
    PHYSICAL_ARTIFACT_REJECTED = "PHYSICAL_ARTIFACT_REJECTED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    SNAPSHOT_REJECTED = "SNAPSHOT_REJECTED"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeDurableSampleAppenderError(ContractViolation):
    """Payload-free failure at the recoverable V3 sample-append boundary."""

    def __init__(self, reason_code: M6UpgradeDurableSampleAppenderFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeDurableSampleAppenderFailureCode):
            raise TypeError("reason_code must be an M6 durable sample-appender failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 durable sample append failed: {reason_code.value}")


@runtime_checkable
class M6UpgradeDurableSampleAppenderV3(Protocol):
    """Close one already-durable Observation V2 into its exact ledger record.

    Callers provide only the two immutable scope identities. The implementation
    owns record reconstruction, physical revalidation, commitment construction,
    commitment persistence, and the final ledger append.
    """

    def append_pending_sample(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2: ...


__all__ = [
    "M6UpgradeDurableSampleAppenderError",
    "M6UpgradeDurableSampleAppenderFailureCode",
    "M6UpgradeDurableSampleAppenderV3",
]
