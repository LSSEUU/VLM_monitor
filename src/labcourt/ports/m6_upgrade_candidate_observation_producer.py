"""Trusted boundary for deriving the next protocol-V3 candidate observation."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.exceptions import ContractViolation


class M6UpgradeCandidateObservationProducerFailureCode(StrEnum):
    """Closed failures without catalog bodies, labels, paths, or runtime facts."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    OBSERVATION_ALREADY_EXISTS = "OBSERVATION_ALREADY_EXISTS"
    APPEND_STATE_MISMATCH = "APPEND_STATE_MISMATCH"
    LEDGER_COMPLETE = "LEDGER_COMPLETE"
    LEDGER_SEALED = "LEDGER_SEALED"
    CATALOG_NOT_FOUND = "CATALOG_NOT_FOUND"
    CATALOG_REJECTED = "CATALOG_REJECTED"
    CANDIDATE_PERCEPTION_REJECTED = "CANDIDATE_PERCEPTION_REJECTED"
    SOURCE_CLOSURE_REJECTED = "SOURCE_CLOSURE_REJECTED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeCandidateObservationProducerError(ContractViolation):
    """Payload-free failure at the trusted candidate execution boundary."""

    def __init__(
        self,
        reason_code: M6UpgradeCandidateObservationProducerFailureCode,
    ) -> None:
        if not isinstance(reason_code, M6UpgradeCandidateObservationProducerFailureCode):
            raise TypeError("reason_code must be an M6 candidate observation-producer failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 candidate observation production failed: {reason_code.value}")


@runtime_checkable
class M6UpgradeCandidateObservationProducerV3(Protocol):
    """Execute one exact next entry without accepting caller-reported facts.

    The composition root fixes the candidate executor and candidate-safe source
    catalog provider. Public callers can name only the immutable run and scope.
    """

    def produce_next_observation(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2: ...


__all__ = [
    "M6UpgradeCandidateObservationProducerError",
    "M6UpgradeCandidateObservationProducerFailureCode",
    "M6UpgradeCandidateObservationProducerV3",
]
