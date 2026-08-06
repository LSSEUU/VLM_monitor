"""Trusted boundary for deriving one complete M6 V2 sample record."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.exceptions import ContractViolation


class M6UpgradeWholeSampleRecordBuilderFailureCode(StrEnum):
    """Controlled failures without authority payloads or physical host details."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    LEDGER_VERSION_UNSUPPORTED = "LEDGER_VERSION_UNSUPPORTED"
    OBSERVATION_NOT_FOUND = "OBSERVATION_NOT_FOUND"
    OBSERVATION_CLOSURE_MISMATCH = "OBSERVATION_CLOSURE_MISMATCH"
    CASE_PREFIX_MISMATCH = "CASE_PREFIX_MISMATCH"
    CASE_BINDING_MISMATCH = "CASE_BINDING_MISMATCH"
    MODEL_CALL_CLOSURE_MISMATCH = "MODEL_CALL_CLOSURE_MISMATCH"
    ROUTE_REJECTED = "ROUTE_REJECTED"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    LINK_LIMIT_EXCEEDED = "LINK_LIMIT_EXCEEDED"
    PHYSICAL_BYTE_LIMIT_EXCEEDED = "PHYSICAL_BYTE_LIMIT_EXCEEDED"
    CANONICAL_DOCUMENT_TOO_LARGE = "CANONICAL_DOCUMENT_TOO_LARGE"
    PIXEL_AUTHORITY_REJECTED = "PIXEL_AUTHORITY_REJECTED"
    RAW_RESPONSE_REJECTED = "RAW_RESPONSE_REJECTED"
    RECORD_TOO_LARGE = "RECORD_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    SNAPSHOT_REJECTED = "SNAPSHOT_REJECTED"


class M6UpgradeWholeSampleRecordBuilderError(ContractViolation):
    """Typed, payload-free failure at the whole-sample builder boundary."""

    def __init__(self, reason_code: M6UpgradeWholeSampleRecordBuilderFailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeWholeSampleRecordBuilderFailureCode):
            raise TypeError("reason_code must be an M6UpgradeWholeSampleRecordBuilderFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 upgrade whole-sample record build failed: {reason_code.value}")


class M6UpgradeWholeSampleRecordBuilder(Protocol):
    """Derive a record from trusted scope, observation, and physical authorities.

    The implementation owns every authority lookup, physical verification, and
    chain binding. Callers cannot supply an observation, record fragment,
    artifact reference, digest, size, container, previous hash, or verifier.
    """

    def build_m6_upgrade_sample_record(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2: ...


__all__ = [
    "M6UpgradeWholeSampleRecordBuilder",
    "M6UpgradeWholeSampleRecordBuilderError",
    "M6UpgradeWholeSampleRecordBuilderFailureCode",
]
