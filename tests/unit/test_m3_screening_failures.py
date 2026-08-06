from __future__ import annotations

from typing import cast

import pytest

from labcourt.adapters.jinja_prompt_renderer import (
    PromptRenderError,
    PromptRenderFailureCode,
)
from labcourt.adapters.storage.model_response_store import (
    ModelResponseStoreError,
    ModelResponseStoreFailureCode,
)
from labcourt.adapters.vlm.errors import VLMProviderError, VLMProviderFailureCode
from labcourt.application import classify_screening_failure
from labcourt.application.model_parser import ModelParserInputError, ModelParserInputErrorCode
from labcourt.application.structure_repair import (
    StructureRepairPreparationError,
    StructureRepairPreparationErrorCode,
)
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

_VLM_PROVIDER_UNAVAILABLE = frozenset(
    {
        VLMProviderFailureCode.FIXTURE_MISSING,
        VLMProviderFailureCode.PROVIDER_OUTAGE,
        VLMProviderFailureCode.PROVIDER_TIMEOUT,
        VLMProviderFailureCode.TRANSPORT_UNAVAILABLE,
    }
)
_VLM_BUDGET = frozenset(
    {
        VLMProviderFailureCode.RESPONSE_TOO_LARGE,
        VLMProviderFailureCode.RESPONSE_TOKEN_BUDGET_EXCEEDED,
        VLMProviderFailureCode.RESPONSE_COST_BUDGET_EXCEEDED,
    }
)
_VLM_MAINTENANCE_ONLY = frozenset(
    {
        VLMProviderFailureCode.EXPIRED_CLAIM_REQUIRES_RECOVERY,
    }
)
_STORE_BUDGET = frozenset(
    {
        ModelResponseStoreFailureCode.CALL_BUDGET_EXCEEDED,
        ModelResponseStoreFailureCode.READ_LIMIT_EXCEEDED,
    }
)


@pytest.mark.parametrize("reason_code", tuple(VLMProviderFailureCode))
def test_every_vlm_provider_failure_code_has_an_explicit_classification(
    reason_code: VLMProviderFailureCode,
) -> None:
    if reason_code in _VLM_PROVIDER_UNAVAILABLE:
        expected: BacklogReasonCode | None = BacklogReasonCode.PROVIDER_UNAVAILABLE
    elif reason_code in _VLM_BUDGET:
        expected = BacklogReasonCode.BUDGET_EXCEEDED
    elif reason_code in _VLM_MAINTENANCE_ONLY:
        expected = None
    else:
        expected = BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE

    assert classify_screening_failure(VLMProviderError(reason_code)) == expected


@pytest.mark.parametrize("reason_code", tuple(ModelResponseStoreFailureCode))
def test_every_model_response_store_failure_code_has_an_explicit_classification(
    reason_code: ModelResponseStoreFailureCode,
) -> None:
    expected = (
        BacklogReasonCode.BUDGET_EXCEEDED
        if reason_code in _STORE_BUDGET
        else BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    )
    assert classify_screening_failure(ModelResponseStoreError(reason_code)) == expected


@pytest.mark.parametrize("reason_code", tuple(ModelParserInputErrorCode))
def test_every_model_parser_input_error_is_an_integrity_failure(
    reason_code: ModelParserInputErrorCode,
) -> None:
    assert classify_screening_failure(ModelParserInputError(reason_code)) == (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    )


@pytest.mark.parametrize("reason_code", tuple(PromptRenderFailureCode))
def test_every_prompt_render_error_is_an_integrity_failure(
    reason_code: PromptRenderFailureCode,
) -> None:
    assert classify_screening_failure(PromptRenderError(reason_code)) == (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    )


@pytest.mark.parametrize("reason_code", tuple(StructureRepairPreparationErrorCode))
def test_every_structure_repair_preparation_error_is_an_integrity_failure(
    reason_code: StructureRepairPreparationErrorCode,
) -> None:
    assert classify_screening_failure(StructureRepairPreparationError(reason_code)) == (
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProviderUnavailable("provider marker"), BacklogReasonCode.PROVIDER_UNAVAILABLE),
        (BudgetExceeded("budget marker"), BacklogReasonCode.BUDGET_EXCEEDED),
        (ModelOutputInvalid("model marker"), BacklogReasonCode.MODEL_OUTPUT_INVALID),
        (
            ConcurrentModification("concurrency marker"),
            BacklogReasonCode.CURRENT_PACK_CHANGED,
        ),
        (ManifestMismatch("manifest marker"), BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
        (
            PrivacyPolicyViolation("privacy marker"),
            BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
        ),
        (EvidenceMissing("evidence marker"), BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
        (ContractViolation("contract marker"), BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE),
    ],
)
def test_controlled_application_failures_map_without_message_parsing(
    error: BaseException,
    expected: BacklogReasonCode,
) -> None:
    assert classify_screening_failure(error) == expected


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("unknown marker"),
        OSError("unknown marker"),
        TypeError("programming marker"),
        ValueError("programming marker"),
        AssertionError("programming marker"),
    ],
)
def test_unknown_and_programming_errors_are_not_backlogged(error: BaseException) -> None:
    assert classify_screening_failure(error) is None


def test_classifier_never_reads_exception_text_or_cause() -> None:
    class MessageMustNotBeRead(ProviderUnavailable):
        def __str__(self) -> str:
            raise AssertionError("classifier inspected exception text")

    error = MessageMustNotBeRead()
    error.__cause__ = RuntimeError("sensitive upstream body")
    assert classify_screening_failure(error) == BacklogReasonCode.PROVIDER_UNAVAILABLE


def test_non_exception_argument_is_rejected_without_rendering_it() -> None:
    class ReprMustNotBeRead:
        def __repr__(self) -> str:
            raise AssertionError("classifier rendered a non-exception argument")

    with pytest.raises(TypeError, match="error must be a BaseException"):
        classify_screening_failure(cast(BaseException, ReprMustNotBeRead()))


def test_controlled_examples_cover_every_screening_backlog_reason() -> None:
    examples: tuple[BaseException, ...] = (
        ProviderUnavailable(),
        ModelOutputInvalid(),
        BudgetExceeded(),
        ContractViolation(),
        ConcurrentModification(),
    )
    assert {classify_screening_failure(error) for error in examples} == (
        set(BacklogReasonCode) - {BacklogReasonCode.WORKER_LEASE_EXPIRED}
    )
