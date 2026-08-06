from __future__ import annotations

import pytest

from labcourt.application.hearing_budget import (
    HearingBudgetPolicyError,
    HearingBudgetPolicyFailureCode,
    HearingCallBudgetLimits,
    derive_hearing_call_budget_limits,
)


def _limits(**updates: object) -> HearingCallBudgetLimits:
    values: dict[str, object] = {
        "primary": True,
        "selected_pixels": 200,
        "reserved_images": 1,
        "accounted_output_tokens": 20,
        "max_total_images": 3,
        "max_total_output_tokens": 100,
        "max_input_pixels": 400,
        "max_output_tokens": 50,
        "manifest_max_output_tokens": None,
    }
    values.update(updates)
    return derive_hearing_call_budget_limits(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("updates", "expected"),
    (
        ({}, HearingCallBudgetLimits(1, 200, 50)),
        (
            {"manifest_max_output_tokens": 30},
            HearingCallBudgetLimits(1, 200, 30),
        ),
        (
            {"accounted_output_tokens": 80},
            HearingCallBudgetLimits(1, 200, 20),
        ),
        (
            {
                "primary": False,
                "selected_pixels": 0,
                "reserved_images": 3,
            },
            HearingCallBudgetLimits(0, 0, 50),
        ),
    ),
)
def test_additive_budget_selects_the_tightest_limit(
    updates: dict[str, object],
    expected: HearingCallBudgetLimits,
) -> None:
    assert _limits(**updates) == expected


@pytest.mark.parametrize(
    ("updates", "reason"),
    (
        (
            {"reserved_images": 3},
            HearingBudgetPolicyFailureCode.IMAGE_BUDGET_EXHAUSTED,
        ),
        (
            {"selected_pixels": 401},
            HearingBudgetPolicyFailureCode.INPUT_PIXEL_BUDGET_EXCEEDED,
        ),
        (
            {"accounted_output_tokens": 100},
            HearingBudgetPolicyFailureCode.OUTPUT_TOKEN_BUDGET_EXHAUSTED,
        ),
    ),
)
def test_each_budget_boundary_has_one_typed_failure(
    updates: dict[str, object],
    reason: HearingBudgetPolicyFailureCode,
) -> None:
    with pytest.raises(HearingBudgetPolicyError) as raised:
        _limits(**updates)

    assert raised.value.reason_code == reason
    assert str(raised.value) == reason.value


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("selected_pixels", -1),
        ("reserved_images", -1),
        ("accounted_output_tokens", -1),
        ("max_total_images", -1),
        ("max_total_output_tokens", -1),
        ("max_input_pixels", -1),
        ("max_output_tokens", -1),
        ("selected_pixels", True),
        ("selected_pixels", 1.5),
    ),
)
def test_nonnegative_integer_inputs_are_strict(field: str, value: object) -> None:
    with pytest.raises(TypeError):
        _limits(**{field: value})


def test_primary_flag_is_strict() -> None:
    with pytest.raises(TypeError):
        _limits(primary=1)


@pytest.mark.parametrize(
    "updates",
    (
        {"max_total_images": 0},
        {"max_total_output_tokens": 0},
        {"max_output_tokens": 0},
    ),
)
def test_positive_totals_cannot_be_zero(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _limits(**updates)


@pytest.mark.parametrize("value", (0, -1, True, 1.5))
def test_optional_manifest_token_cap_is_strict(value: object) -> None:
    with pytest.raises(TypeError):
        _limits(manifest_max_output_tokens=value)


@pytest.mark.parametrize(
    ("args", "error"),
    (
        ((2, 0, 1), ValueError),
        ((0, -1, 1), TypeError),
        ((0, True, 1), TypeError),
        ((0, 0, 0), TypeError),
        ((0, 0, True), TypeError),
        ((0, 1, 1), ValueError),
        ((1, 0, 1), ValueError),
    ),
)
def test_derived_limit_contract_rejects_impossible_shapes(
    args: tuple[object, object, object],
    error: type[Exception],
) -> None:
    with pytest.raises(error):
        HearingCallBudgetLimits(*args)  # type: ignore[arg-type]


def test_budget_error_requires_its_typed_reason() -> None:
    with pytest.raises(TypeError):
        HearingBudgetPolicyError("IMAGE_BUDGET_EXHAUSTED")  # type: ignore[arg-type]
