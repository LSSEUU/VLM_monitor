"""Structured VLM request port."""

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.model_call_failures import (
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.screening import (
    CachedModelResponse,
    VLMCallRequest,
    VLMResponse,
)
from labcourt.exceptions import ContractViolation, ProviderUnavailable


class VLMProviderError(ProviderUnavailable):
    """Controlled provider failure without endpoint, secret, or upstream bytes."""

    def __init__(
        self,
        reason_code: VLMProviderFailureCode,
        delivery_certainty: VLMDeliveryCertainty = VLMDeliveryCertainty.UNKNOWN,
    ) -> None:
        if not isinstance(reason_code, VLMProviderFailureCode):
            raise TypeError("reason_code must be a VLMProviderFailureCode")
        if not isinstance(delivery_certainty, VLMDeliveryCertainty):
            raise TypeError("delivery_certainty must be a VLMDeliveryCertainty")
        self.reason_code = reason_code
        self.delivery_certainty = delivery_certainty
        super().__init__(f"VLM provider failed: {reason_code.value}")


class ModelResponseStoreFailureCode(StrEnum):
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


class ModelResponseStoreError(ContractViolation):
    """Controlled response-store error without bytes or host paths."""

    def __init__(self, reason_code: ModelResponseStoreFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"model response store failed: {reason_code.value}")


class VLMClient(Protocol):
    def complete(self, request: VLMCallRequest) -> VLMResponse: ...


class RawModelResponseVerifier(Protocol):
    """Physically verify one exact request-bound raw model response."""

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse: ...


class ModelResponseStore(RawModelResponseVerifier, Protocol):
    def probe_recovery(self, request: VLMCallRequest) -> VLMResponse | None: ...

    def recover(self, request: VLMCallRequest) -> VLMResponse | None: ...

    def acknowledge(self, request: VLMCallRequest, response: VLMResponse) -> None: ...

    def read_bytes(
        self,
        run_id: str,
        response: VLMResponse,
        max_bytes: int,
    ) -> bytes: ...

    def read_json(self, run_id: str, response: VLMResponse, max_bytes: int) -> str: ...

    def verify(self, run_id: str, response: VLMResponse) -> VLMResponse: ...


class VLMResponseCache(Protocol):
    def get(
        self,
        run_id: str,
        request: VLMCallRequest,
    ) -> CachedModelResponse | None: ...

    def put(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> CachedModelResponse: ...


__all__ = [
    "ModelResponseStore",
    "ModelResponseStoreError",
    "ModelResponseStoreFailureCode",
    "RawModelResponseVerifier",
    "VLMClient",
    "VLMDeliveryCertainty",
    "VLMProviderError",
    "VLMProviderFailureCode",
    "VLMResponseCache",
]
