"""Port for offline Feishu request conformance, replay, and raw-response access."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuCardDispatchPreflightV1,
    M8FeishuConformanceResultV1,
)
from labcourt.exceptions import ContractViolation


class M8FeishuConformanceAdapterFailureCode(StrEnum):
    CARD_BYTES_MISMATCH = "CARD_BYTES_MISMATCH"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    PREFLIGHT_MISMATCH = "PREFLIGHT_MISMATCH"
    PREFLIGHT_REPLAY_NOT_FOUND = "PREFLIGHT_REPLAY_NOT_FOUND"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    RAW_RESPONSE_NOT_FOUND = "RAW_RESPONSE_NOT_FOUND"


class M8FeishuConformanceAdapterError(ContractViolation):
    def __init__(self, reason_code: M8FeishuConformanceAdapterFailureCode) -> None:
        if not isinstance(reason_code, M8FeishuConformanceAdapterFailureCode):
            raise TypeError("reason_code must be an M8FeishuConformanceAdapterFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M8 Feishu conformance adapter failed: {reason_code.value}")


class M8FeishuConformanceAdapter(Protocol):
    def profile_authority(self) -> M8FeishuAdapterProfileV1: ...

    def conform(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
    ) -> M8FeishuConformanceResultV1: ...

    def replay(self, preflight_id: str) -> M8FeishuConformanceResultV1: ...

    def read_raw_response(self, raw_response_ref: str) -> bytes: ...


__all__ = [
    "M8FeishuConformanceAdapter",
    "M8FeishuConformanceAdapterError",
    "M8FeishuConformanceAdapterFailureCode",
]
