"""Persistence boundary for one append-only M6 upgrade execution ledger."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.m6_regression import M6RegressionExecutionEntry
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.exceptions import ContractViolation


class M6UpgradeExecutionLedgerFailureCode(StrEnum):
    """Controlled ledger failures without SQLite text, host paths, or payload bytes."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_CONFLICT = "SCOPE_CONFLICT"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    LEDGER_VERSION_UNSUPPORTED = "LEDGER_VERSION_UNSUPPORTED"
    VERIFIER_REQUIRED = "VERIFIER_REQUIRED"
    VERIFIER_INVALID = "VERIFIER_INVALID"
    PHYSICAL_ARTIFACT_REJECTED = "PHYSICAL_ARTIFACT_REJECTED"
    PHYSICAL_ARTIFACT_CONFLICT = "PHYSICAL_ARTIFACT_CONFLICT"
    SAMPLE_CONFLICT = "SAMPLE_CONFLICT"
    SAMPLE_OUT_OF_ORDER = "SAMPLE_OUT_OF_ORDER"
    LEDGER_SEALED = "LEDGER_SEALED"
    LEDGER_INCOMPLETE = "LEDGER_INCOMPLETE"
    LEDGER_NOT_SEALED = "LEDGER_NOT_SEALED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    SQLITE_REJECTED = "SQLITE_REJECTED"


class M6UpgradeExecutionLedgerError(ContractViolation):
    """Typed failure at the M6 upgrade-ledger persistence boundary."""

    def __init__(self, reason_code: M6UpgradeExecutionLedgerFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeExecutionLedgerFailureCode):
            raise TypeError("reason_code must be an M6UpgradeExecutionLedgerFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 upgrade execution ledger failed: {reason_code.value}")


class M6UpgradeExecutionLedgerStatus(StrEnum):
    ACTIVE = "ACTIVE"
    READY_TO_SEAL = "READY_TO_SEAL"
    SEALED = "SEALED"


@dataclass(frozen=True, slots=True)
class M6UpgradeExecutionResume:
    """Validated restart point derived only from persisted ledger authority."""

    status: M6UpgradeExecutionLedgerStatus
    execution_scope: M6UpgradeExecutionScopeAuthority
    committed_sample_count: int
    ledger_head_hash: str
    next_execution_entry: M6RegressionExecutionEntry | None
    seal: M6UpgradeExecutionLedgerSeal | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, M6UpgradeExecutionLedgerStatus):
            raise TypeError("status must be an M6UpgradeExecutionLedgerStatus")
        if not isinstance(self.execution_scope, M6UpgradeExecutionScopeAuthority):
            raise TypeError("execution_scope must be a typed M6 execution scope")
        if (
            not isinstance(self.committed_sample_count, int)
            or isinstance(self.committed_sample_count, bool)
            or self.committed_sample_count < 0
        ):
            raise ValueError("committed_sample_count must be a non-negative integer")
        if (
            not isinstance(self.ledger_head_hash, str)
            or len(self.ledger_head_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.ledger_head_hash)
        ):
            raise ValueError("ledger_head_hash must be a lowercase SHA-256")
        expected_count = len(self.execution_scope.execution_dataset.entries)
        if self.committed_sample_count > expected_count:
            raise ValueError("committed samples exceed the execution dataset")
        if self.status == M6UpgradeExecutionLedgerStatus.ACTIVE:
            if (
                self.committed_sample_count >= expected_count
                or not isinstance(self.next_execution_entry, M6RegressionExecutionEntry)
                or self.seal is not None
            ):
                raise ValueError("active M6 resume state is inconsistent")
            expected_entry = self.execution_scope.execution_dataset.entries[
                self.committed_sample_count
            ]
            if self.next_execution_entry != expected_entry:
                raise ValueError("active M6 resume entry differs from the execution dataset")
        elif self.status == M6UpgradeExecutionLedgerStatus.READY_TO_SEAL:
            if (
                self.committed_sample_count != expected_count
                or self.next_execution_entry is not None
                or self.seal is not None
            ):
                raise ValueError("ready-to-seal M6 resume state is inconsistent")
        elif (
            self.committed_sample_count != expected_count
            or self.next_execution_entry is not None
            or type(self.seal) is not M6UpgradeExecutionLedgerSeal
            or self.seal.execution_scope != self.execution_scope
            or self.ledger_head_hash != self.seal.ledger_preseal_hash
        ):
            raise ValueError("sealed M6 resume state is inconsistent")
        if self.committed_sample_count == 0 and self.ledger_head_hash != AUDIT_GENESIS_HASH:
            raise ValueError("empty M6 ledger must use the ledger genesis hash")


class M6UpgradeSampleArtifactVerifier(Protocol):
    """Observe one complete sample artifact closure the ledger cannot trust."""

    def verify_m6_upgrade_sample_artifacts(
        self,
        record: M6UpgradeSampleExecutionRecord,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]: ...


class M6UpgradeExecutionLedgerRepository(Protocol):
    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority: ...

    def resume(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResume: ...

    def append_sample(
        self,
        record: M6UpgradeSampleExecutionRecord,
        verifier: M6UpgradeSampleArtifactVerifier | None = None,
    ) -> M6UpgradeSampleExecutionRecord: ...

    def seal(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSeal: ...

    def load_sealed(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSeal: ...


__all__ = [
    "M6UpgradeExecutionLedgerError",
    "M6UpgradeExecutionLedgerFailureCode",
    "M6UpgradeExecutionLedgerRepository",
    "M6UpgradeExecutionLedgerStatus",
    "M6UpgradeExecutionResume",
    "M6UpgradeSampleArtifactVerifier",
]
