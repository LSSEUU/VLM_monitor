"""Append-only persistence boundary for pre-ledger M6 execution observations."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.exceptions import ContractViolation


class M6UpgradeExecutionObservationFailureCode(StrEnum):
    """Controlled failures with no database text, host path, or payload bytes."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    OBSERVATION_NOT_FOUND = "OBSERVATION_NOT_FOUND"
    OBSERVATION_CONFLICT = "OBSERVATION_CONFLICT"
    PENDING_OBSERVATION_EXISTS = "PENDING_OBSERVATION_EXISTS"
    OBSERVATION_OUT_OF_ORDER = "OBSERVATION_OUT_OF_ORDER"
    LEGACY_LEDGER_UNSUPPORTED = "LEGACY_LEDGER_UNSUPPORTED"
    LEDGER_SEALED = "LEDGER_SEALED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeExecutionObservationError(ContractViolation):
    """Typed, payload-free failure at the observation persistence boundary."""

    def __init__(self, reason_code: M6UpgradeExecutionObservationFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeExecutionObservationFailureCode):
            raise TypeError("reason_code must be an M6UpgradeExecutionObservationFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 execution observation failed: {reason_code.value}")


class M6UpgradeExecutionObservationRepository(Protocol):
    """Persist immutable observations before their corresponding ledger entries.

    This is a storage boundary, not a truth oracle.  Application composition
    must keep it behind the trusted candidate coordinator; accepting a
    caller-supplied authority here would merely persist a self-report.
    """

    def append(
        self,
        observation: M6UpgradeSampleExecutionObservationAuthority,
    ) -> M6UpgradeSampleExecutionObservationAuthority: ...

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradeSampleExecutionObservationAuthority: ...


class M6UpgradeExecutionObservationV3Repository(Protocol):
    """Persist exact Observation V2 authorities under protocol V3.

    This additive boundary deliberately does not widen the frozen V2 port.
    The first V3 storage slice permits one durable pending observation; later
    protocol slices close that observation into the existing record family.
    """

    def append(
        self,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2: ...

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2: ...


__all__ = [
    "M6UpgradeExecutionObservationError",
    "M6UpgradeExecutionObservationFailureCode",
    "M6UpgradeExecutionObservationRepository",
    "M6UpgradeExecutionObservationV3Repository",
]
