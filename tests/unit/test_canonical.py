import math

import pytest

from labcourt.domain.canonical import canonical_json, sha256_hex


def test_canonical_json_is_key_order_independent() -> None:
    left = {"b": 2, "a": {"y": 1, "x": 0}}
    right = {"a": {"x": 0, "y": 1}, "b": 2}

    assert canonical_json(left) == canonical_json(right)
    assert sha256_hex(left) == sha256_hex(right)


def test_canonical_json_preserves_array_order_and_utf8() -> None:
    assert canonical_json({"值": [2, 1]}) == '{"值":[2,1]}'
    assert sha256_hex([1, 2]) != sha256_hex([2, 1])


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_canonical_json_rejects_non_finite_floats(value: float) -> None:
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_json({"value": value})


@pytest.mark.parametrize(
    "value",
    [
        {"set": {1, 2}},
        {"bytes": b"unsafe"},
        {1: "non-string key"},
    ],
)
def test_canonical_json_rejects_non_json_types(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        canonical_json(value)
