"""M4-only model-call boundaries.

The frozen M3 screening ports deliberately accept only screening and screening
repair requests.  A hearing call has different role, retry, budget, and cache
semantics, so it uses a separate capability surface instead of widening the M3
protocols.
"""

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelRequest,
    HearingModelResponse,
)
from labcourt.exceptions import ContractViolation


class HearingModelResponseStoreFailureCode(StrEnum):
    """Controlled M4 storage/cache failures with no host paths or raw bytes."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CALL_BUDGET_EXCEEDED = "CALL_BUDGET_EXCEEDED"
    RUN_SCOPE_MISMATCH = "RUN_SCOPE_MISMATCH"
    RESPONSE_NOT_FOUND = "RESPONSE_NOT_FOUND"
    RESPONSE_CONFLICT = "RESPONSE_CONFLICT"
    RESPONSE_INTEGRITY_FAILURE = "RESPONSE_INTEGRITY_FAILURE"
    RESPONSE_RECEIPT_INVALID = "RESPONSE_RECEIPT_INVALID"
    WORKSPACE_REJECTED = "WORKSPACE_REJECTED"
    READ_LIMIT_EXCEEDED = "READ_LIMIT_EXCEEDED"
    RESPONSE_UTF8_INVALID = "RESPONSE_UTF8_INVALID"
    CACHE_CONFLICT = "CACHE_CONFLICT"
    CACHE_INTEGRITY_FAILURE = "CACHE_INTEGRITY_FAILURE"


class HearingModelResponseStoreError(ContractViolation):
    """M4-only response/cache error that never exposes provider or host details."""

    def __init__(self, reason_code: HearingModelResponseStoreFailureCode) -> None:
        if not isinstance(reason_code, HearingModelResponseStoreFailureCode):
            raise TypeError("reason_code must be a HearingModelResponseStoreFailureCode")
        self.reason_code = reason_code
        super().__init__(f"hearing model response store failed: {reason_code.value}")


class HearingVLMClient(Protocol):
    """Complete one exact prosecutor, defender, or Judge request."""

    def complete(self, request: HearingModelRequest) -> HearingModelResponse: ...


class HearingModelResponsePublisher(Protocol):
    """Publish arbitrary response bytes before any hearing parser sees them."""

    def publish(
        self,
        request: HearingModelRequest,
        raw_response: bytes,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
    ) -> HearingModelResponse: ...


class HearingRawModelResponseVerifier(Protocol):
    """Physically verify one exact request-bound M4 response."""

    def verify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelResponse: ...


class HearingModelResponseStore(HearingModelResponsePublisher, Protocol):
    """Private, journaled storage for M4 response bytes."""

    def probe_recovery(self, request: HearingModelRequest) -> HearingModelResponse | None: ...

    def recover(self, request: HearingModelRequest) -> HearingModelResponse | None: ...

    def acknowledge(
        self,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None: ...

    def read_bytes(
        self,
        run_id: str,
        response: HearingModelResponse,
        max_bytes: int,
    ) -> bytes: ...

    def read_json(
        self,
        run_id: str,
        response: HearingModelResponse,
        max_bytes: int,
    ) -> str: ...

    def verify(
        self,
        run_id: str,
        response: HearingModelResponse,
    ) -> HearingModelResponse: ...

    def verify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelResponse: ...


class HearingVLMResponseCache(Protocol):
    """Immutable M4 cache bindings; raw bytes stay in the response store."""

    def get(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> HearingModelCacheEntry | None: ...

    def put(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelCacheEntry: ...


__all__ = [
    "HearingModelResponsePublisher",
    "HearingModelResponseStore",
    "HearingModelResponseStoreError",
    "HearingModelResponseStoreFailureCode",
    "HearingRawModelResponseVerifier",
    "HearingVLMClient",
    "HearingVLMResponseCache",
]
