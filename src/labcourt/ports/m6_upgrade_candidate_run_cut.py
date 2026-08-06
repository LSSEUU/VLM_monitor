"""Trusted boundary for one immutable M6 candidate-run cut."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression_execution import M6UpgradeCandidateRunCutAuthority
from labcourt.exceptions import ContractViolation


class M6UpgradeCandidateRunCutFailureCode(StrEnum):
    """Controlled failures without durable authority payloads or host details."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    LEDGER_VERSION_UNSUPPORTED = "LEDGER_VERSION_UNSUPPORTED"
    LEDGER_NOT_SEALED = "LEDGER_NOT_SEALED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    AUDIT_HEAD_MISMATCH = "AUDIT_HEAD_MISMATCH"
    VALIDATION_REPORT_REJECTED = "VALIDATION_REPORT_REJECTED"
    RUN_CUT_NOT_FOUND = "RUN_CUT_NOT_FOUND"
    RUN_CUT_CONFLICT = "RUN_CUT_CONFLICT"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    SNAPSHOT_REJECTED = "SNAPSHOT_REJECTED"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeCandidateRunCutError(ContractViolation):
    """Typed, payload-free failure at the candidate-run cut boundary."""

    def __init__(self, reason_code: M6UpgradeCandidateRunCutFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeCandidateRunCutFailureCode):
            raise TypeError("reason_code must be an M6UpgradeCandidateRunCutFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 upgrade candidate run cut failed: {reason_code.value}")


@runtime_checkable
class M6UpgradeCandidateRunCutRepository(Protocol):
    """Build or replay a run cut using only its durable scope identities.

    Implementations own the sealed-ledger, manifest, config, audit-head, and
    validation-report reads. Callers cannot supply any of those authorities or
    a preassembled run cut for persistence.
    """

    def build_or_load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateRunCutAuthority: ...


@runtime_checkable
class M6UpgradeCandidateValidationReportProvider(Protocol):
    """Resolve the exact passing report for a sealed historical audit head.

    The provider is fixed in the trusted composition root. It is not supplied
    by a per-call API and must not silently substitute the current run head.
    """

    def load_m6_upgrade_candidate_validation_report(
        self,
        candidate_run_id: str,
        audit_head_sequence: int,
        audit_head_hash: str,
    ) -> M5ArtifactValidationReport: ...


__all__ = [
    "M6UpgradeCandidateRunCutError",
    "M6UpgradeCandidateRunCutFailureCode",
    "M6UpgradeCandidateRunCutRepository",
    "M6UpgradeCandidateValidationReportProvider",
]
