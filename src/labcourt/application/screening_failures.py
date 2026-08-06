"""Deterministic classification of controlled M3 screening failures."""

from __future__ import annotations

from typing import Final

from labcourt.application.model_parser import ModelParserInputError
from labcourt.application.structure_repair import StructureRepairPreparationError
from labcourt.contracts.enums import BacklogReasonCode
from labcourt.exceptions import (
    BudgetExceeded,
    ConcurrentModification,
    ContractViolation,
    EvidenceMissing,
    ManifestMismatch,
    ModelOutputInvalid,
    PrivacyPolicyViolation,
    ProviderUnavailable,
)
from labcourt.ports.prompts import PromptRenderError
from labcourt.ports.vlm import (
    ModelResponseStoreError,
    ModelResponseStoreFailureCode,
    VLMProviderError,
    VLMProviderFailureCode,
)

_VLM_FAILURE_REASONS: Final = {
    VLMProviderFailureCode.FIXTURE_MISSING: BacklogReasonCode.PROVIDER_UNAVAILABLE,
    VLMProviderFailureCode.PROVIDER_OUTAGE: BacklogReasonCode.PROVIDER_UNAVAILABLE,
    VLMProviderFailureCode.PROVIDER_TIMEOUT: BacklogReasonCode.PROVIDER_UNAVAILABLE,
    VLMProviderFailureCode.TRANSPORT_UNAVAILABLE: BacklogReasonCode.PROVIDER_UNAVAILABLE,
    VLMProviderFailureCode.REQUEST_IDENTITY_MISMATCH: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
    VLMProviderFailureCode.PROMPT_MISSING: BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
    VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE: (BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
    VLMProviderFailureCode.MEDIA_POLICY_REJECTED: (BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
    VLMProviderFailureCode.MEDIA_INTEGRITY_FAILURE: (BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
    VLMProviderFailureCode.RESPONSE_ENVELOPE_INVALID: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
    VLMProviderFailureCode.RESPONSE_TOO_LARGE: BacklogReasonCode.BUDGET_EXCEEDED,
    VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED: (BacklogReasonCode.BUDGET_EXCEEDED),
    VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED: (BacklogReasonCode.BUDGET_EXCEEDED),
    VLMProviderFailureCode.RESPONSE_PERSISTENCE_FAILURE: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
}

_STORE_FAILURE_REASONS: Final = {
    ModelResponseStoreFailureCode.INVALID_ARGUMENT: (BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
    ModelResponseStoreFailureCode.CALL_BUDGET_EXCEEDED: (BacklogReasonCode.BUDGET_EXCEEDED),
    ModelResponseStoreFailureCode.RUN_SCOPE_MISMATCH: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
    ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
    ModelResponseStoreFailureCode.RESPONSE_CONFLICT: (BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
    ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
    ModelResponseStoreFailureCode.RESPONSE_RECEIPT_INVALID: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
    ModelResponseStoreFailureCode.WORKSPACE_REJECTED: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
    ModelResponseStoreFailureCode.READ_LIMIT_EXCEEDED: BacklogReasonCode.BUDGET_EXCEEDED,
    ModelResponseStoreFailureCode.RESPONSE_UTF8_INVALID: (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    ),
}


def classify_screening_failure(error: BaseException) -> BacklogReasonCode | None:
    """Return an enqueue reason for an explicitly controlled screening failure.

    The classification is based only on exception classes and typed reason codes.
    Exception messages, causes, and tracebacks are intentionally ignored.
    """

    if not isinstance(error, BaseException):
        raise TypeError("error must be a BaseException")

    # These two subclasses must precede their broader application categories.
    if isinstance(error, VLMProviderError):
        return _VLM_FAILURE_REASONS.get(error.reason_code)
    if isinstance(error, ModelResponseStoreError):
        return _STORE_FAILURE_REASONS.get(error.reason_code)

    # ModelParserInputError subclasses ValueError, so it precedes programming errors.
    if isinstance(error, ModelParserInputError):
        return BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    if isinstance(error, BudgetExceeded):
        return BacklogReasonCode.BUDGET_EXCEEDED
    if isinstance(error, ModelOutputInvalid):
        return BacklogReasonCode.MODEL_OUTPUT_INVALID
    if isinstance(error, ConcurrentModification):
        return BacklogReasonCode.CURRENT_PACK_CHANGED
    if isinstance(error, ProviderUnavailable):
        return BacklogReasonCode.PROVIDER_UNAVAILABLE
    if isinstance(
        error,
        (
            ManifestMismatch,
            PrivacyPolicyViolation,
            EvidenceMissing,
            PromptRenderError,
            StructureRepairPreparationError,
            ContractViolation,
        ),
    ):
        return BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE

    # Ordinary language/runtime programming errors are not operational backlog work.
    if isinstance(error, (TypeError, ValueError, AssertionError)):
        return None
    return None


__all__ = ["classify_screening_failure"]
