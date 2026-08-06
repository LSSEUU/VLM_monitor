"""M4-only bounded acquisition execution boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.enums import AcquisitionExecutionMode
from labcourt.contracts.hearing import AcquisitionRequest
from labcourt.domain.evidence_authority import (
    AcquisitionExecution,
    EvidenceAuthority,
)
from labcourt.exceptions import ContractViolation


class HearingAcquisitionExecutorFailureCode(StrEnum):
    """Controlled executor failures with no tool internals or host details."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    FIXTURE_MISSING = "FIXTURE_MISSING"
    FIXTURE_CONFLICT = "FIXTURE_CONFLICT"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    OUTPUT_INVALID = "OUTPUT_INVALID"


class HearingAcquisitionDeliveryCertainty(StrEnum):
    """What is known after a non-pure tool boundary fails."""

    DEFINITELY_NOT_STARTED = "DEFINITELY_NOT_STARTED"
    COMPLETED = "COMPLETED"
    UNKNOWN = "UNKNOWN"


class HearingAcquisitionRecoveryStatus(StrEnum):
    """Authoritative idempotency lookup result for an expired execution."""

    COMPLETED = "COMPLETED"
    DEFINITELY_NOT_STARTED = "DEFINITELY_NOT_STARTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class HearingAcquisitionRecovery:
    """Exact recovered execution or a controlled absence of retry authority."""

    status: HearingAcquisitionRecoveryStatus
    execution: AcquisitionExecution | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, HearingAcquisitionRecoveryStatus):
            raise TypeError("status must be a HearingAcquisitionRecoveryStatus")
        if self.status == HearingAcquisitionRecoveryStatus.COMPLETED:
            if not isinstance(self.execution, AcquisitionExecution):
                raise ValueError("completed acquisition recovery requires exact execution")
        elif self.execution is not None:
            raise ValueError("non-completed acquisition recovery cannot carry execution")


class HearingAcquisitionExecutorError(ContractViolation):
    """A bounded acquisition could not produce trusted typed output."""

    def __init__(
        self,
        reason_code: HearingAcquisitionExecutorFailureCode,
        delivery_certainty: HearingAcquisitionDeliveryCertainty = (
            HearingAcquisitionDeliveryCertainty.UNKNOWN
        ),
    ) -> None:
        if not isinstance(reason_code, HearingAcquisitionExecutorFailureCode):
            raise TypeError("reason_code must be a HearingAcquisitionExecutorFailureCode")
        if not isinstance(delivery_certainty, HearingAcquisitionDeliveryCertainty):
            raise TypeError("delivery_certainty must be a HearingAcquisitionDeliveryCertainty")
        self.reason_code = reason_code
        self.delivery_certainty = delivery_certainty
        super().__init__(f"hearing acquisition failed: {reason_code.value}")


class HearingAcquisitionExecutor(Protocol):
    """Execute one exact whitelisted request against current evidence authority."""

    @property
    def execution_mode(self) -> AcquisitionExecutionMode: ...

    def execute(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> AcquisitionExecution: ...

    def recover(
        self,
        request: AcquisitionRequest,
        authority: EvidenceAuthority,
        *,
        idempotency_key: str,
    ) -> HearingAcquisitionRecovery: ...


__all__ = [
    "HearingAcquisitionDeliveryCertainty",
    "HearingAcquisitionExecutor",
    "HearingAcquisitionExecutorError",
    "HearingAcquisitionExecutorFailureCode",
    "HearingAcquisitionRecovery",
    "HearingAcquisitionRecoveryStatus",
]
