"""Append-only persistence boundaries for unchanged pre-ledger M6 commitments."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.exceptions import ContractViolation


class M6UpgradePendingSampleCommitmentFailureCode(StrEnum):
    """Controlled failures without database text, paths, or record payload bytes."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    OBSERVATION_NOT_FOUND = "OBSERVATION_NOT_FOUND"
    OBSERVATION_MISMATCH = "OBSERVATION_MISMATCH"
    COMMITMENT_NOT_FOUND = "COMMITMENT_NOT_FOUND"
    COMMITMENT_CONFLICT = "COMMITMENT_CONFLICT"
    COMMITMENT_OUT_OF_ORDER = "COMMITMENT_OUT_OF_ORDER"
    PENDING_COMMITMENT_EXISTS = "PENDING_COMMITMENT_EXISTS"
    LEGACY_LEDGER_UNSUPPORTED = "LEGACY_LEDGER_UNSUPPORTED"
    LEDGER_SEALED = "LEDGER_SEALED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradePendingSampleCommitmentError(ContractViolation):
    """Typed, payload-free pending-commitment persistence failure."""

    def __init__(self, reason_code: M6UpgradePendingSampleCommitmentFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradePendingSampleCommitmentFailureCode):
            raise TypeError("reason_code must be an M6UpgradePendingSampleCommitmentFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 pending sample commitment failed: {reason_code.value}")


class M6UpgradePendingSampleCommitmentRepository(Protocol):
    """Persist commitments after observations and before the ledger transaction.

    The first successful append wins. A retry may return the existing authority
    only when it is byte-for-byte identical; another value for the same key is a
    commitment conflict. No implementation can recover a commitment that was
    never successfully persisted before a crash.
    """

    def append(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        """Append once or return the exact already-persisted authority."""
        ...

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        """Load one validated commitment by its complete persistence key."""
        ...


class M6UpgradePendingSampleCommitmentV3Repository(Protocol):
    """Persist the unchanged Pending V1 wire only under protocol V3.

    This additive port keeps protocol ownership explicit even though its input
    and output contract remains byte-for-byte identical to the V2 boundary.
    """

    def append(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradePendingSampleCommitmentAuthority: ...

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradePendingSampleCommitmentAuthority: ...


__all__ = [
    "M6UpgradePendingSampleCommitmentError",
    "M6UpgradePendingSampleCommitmentFailureCode",
    "M6UpgradePendingSampleCommitmentRepository",
    "M6UpgradePendingSampleCommitmentV3Repository",
]
