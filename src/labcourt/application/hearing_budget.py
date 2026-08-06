"""Small, exhaustive M4 hearing-call budget policy.

Request construction owns provider/config binding.  This module owns only the
additive image/token boundary so its complete decision table can be tested
independently from prompt and evidence assembly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class HearingBudgetPolicyFailureCode(StrEnum):
    """Stable additive-budget refusal reasons."""

    IMAGE_BUDGET_EXHAUSTED = "IMAGE_BUDGET_EXHAUSTED"
    INPUT_PIXEL_BUDGET_EXCEEDED = "INPUT_PIXEL_BUDGET_EXCEEDED"
    OUTPUT_TOKEN_BUDGET_EXHAUSTED = "OUTPUT_TOKEN_BUDGET_EXHAUSTED"


class HearingBudgetPolicyError(ValueError):
    """One call cannot be reserved inside the immutable hearing totals."""

    def __init__(self, reason_code: HearingBudgetPolicyFailureCode) -> None:
        if not isinstance(reason_code, HearingBudgetPolicyFailureCode):
            raise TypeError("reason_code must be a HearingBudgetPolicyFailureCode")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


@dataclass(frozen=True, slots=True)
class HearingCallBudgetLimits:
    """Provider-independent limits for the next primary or repair call."""

    max_images: int
    max_input_pixels: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        if self.max_images not in {0, 1}:
            raise ValueError("hearing call may reserve zero or one image")
        if (
            not isinstance(self.max_input_pixels, int)
            or isinstance(self.max_input_pixels, bool)
            or self.max_input_pixels < 0
        ):
            raise TypeError("max_input_pixels must be a non-negative integer")
        if (
            not isinstance(self.max_output_tokens, int)
            or isinstance(self.max_output_tokens, bool)
            or self.max_output_tokens < 1
        ):
            raise TypeError("max_output_tokens must be a positive integer")
        if (self.max_images == 0) != (self.max_input_pixels == 0):
            raise ValueError("repair calls must reserve neither image nor pixels")


def derive_hearing_call_budget_limits(
    *,
    primary: bool,
    selected_pixels: int,
    reserved_images: int,
    accounted_output_tokens: int,
    max_total_images: int,
    max_total_output_tokens: int,
    max_input_pixels: int,
    max_output_tokens: int,
    manifest_max_output_tokens: int | None,
) -> HearingCallBudgetLimits:
    """Apply additive totals and the optional manifest cap to one call."""

    integer_values = (
        selected_pixels,
        reserved_images,
        accounted_output_tokens,
        max_total_images,
        max_total_output_tokens,
        max_input_pixels,
        max_output_tokens,
    )
    if not isinstance(primary, bool):
        raise TypeError("primary must be a bool")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in integer_values
    ):
        raise TypeError("hearing budget inputs must be non-negative integers")
    if max_total_images < 1 or max_total_output_tokens < 1 or max_output_tokens < 1:
        raise ValueError("hearing total and per-call token budgets must be positive")
    if manifest_max_output_tokens is not None and (
        not isinstance(manifest_max_output_tokens, int)
        or isinstance(manifest_max_output_tokens, bool)
        or manifest_max_output_tokens < 1
    ):
        raise TypeError("manifest_max_output_tokens must be a positive integer or None")

    remaining_images = max_total_images - reserved_images
    if primary and remaining_images < 1:
        raise HearingBudgetPolicyError(HearingBudgetPolicyFailureCode.IMAGE_BUDGET_EXHAUSTED)
    if selected_pixels > max_input_pixels:
        raise HearingBudgetPolicyError(HearingBudgetPolicyFailureCode.INPUT_PIXEL_BUDGET_EXCEEDED)
    remaining_tokens = max_total_output_tokens - accounted_output_tokens
    if remaining_tokens < 1:
        raise HearingBudgetPolicyError(HearingBudgetPolicyFailureCode.OUTPUT_TOKEN_BUDGET_EXHAUSTED)
    candidates: tuple[int, ...] = (max_output_tokens, remaining_tokens)
    if manifest_max_output_tokens is not None:
        candidates = (*candidates, manifest_max_output_tokens)
    return HearingCallBudgetLimits(
        max_images=int(primary),
        max_input_pixels=selected_pixels if primary else 0,
        max_output_tokens=min(candidates),
    )


__all__ = [
    "HearingBudgetPolicyError",
    "HearingBudgetPolicyFailureCode",
    "HearingCallBudgetLimits",
    "derive_hearing_call_budget_limits",
]
