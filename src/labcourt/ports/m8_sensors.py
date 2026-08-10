"""Port for manifest-pinned sensor polling, replay, and raw signal access."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorPollResultV1,
)
from labcourt.exceptions import ContractViolation


class M8SensorAdapterFailureCode(StrEnum):
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    REPLAY_NOT_FOUND = "REPLAY_NOT_FOUND"
    RAW_SIGNAL_NOT_FOUND = "RAW_SIGNAL_NOT_FOUND"


class M8SensorAdapterError(ContractViolation):
    """Typed, sanitized failure from a sensor adapter boundary."""

    def __init__(self, reason_code: M8SensorAdapterFailureCode) -> None:
        if not isinstance(reason_code, M8SensorAdapterFailureCode):
            raise TypeError("reason_code must be an M8SensorAdapterFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M8 sensor adapter failed: {reason_code.value}")


class M8SensorAdapter(Protocol):
    def capability_authority(self) -> M8SensorAdapterCapabilityAuthorityV1: ...

    def poll(self, request: M8SensorPollRequestV1) -> M8SensorPollResultV1: ...

    def replay(self, request_id: str) -> M8SensorPollResultV1: ...

    def read_raw_signal(self, raw_signal_ref: str) -> bytes: ...


__all__ = [
    "M8SensorAdapter",
    "M8SensorAdapterError",
    "M8SensorAdapterFailureCode",
]
