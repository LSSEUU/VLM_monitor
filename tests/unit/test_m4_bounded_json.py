from __future__ import annotations

import pytest

from labcourt.application._bounded_json import (
    BoundedJsonError,
    BoundedJsonFailureCode,
    load_bounded_json_object,
)


def _load(document: bytes, **overrides: int) -> dict[str, object]:
    limits = {
        "max_depth": 8,
        "max_fields": 32,
        "max_string_chars": 128,
        **overrides,
    }
    return load_bounded_json_object(document, **limits)


def test_bounded_json_returns_only_an_object_and_preserves_exact_values() -> None:
    assert _load(b'{"a":[1,true,null],"b":"\\ud83d\\ude00"}') == {
        "a": [1, True, None],
        "b": "😀",
    }

    with pytest.raises(BoundedJsonError) as captured:
        _load(b"[]")
    assert captured.value.reason_code == BoundedJsonFailureCode.ROOT_NOT_OBJECT


@pytest.mark.parametrize(
    "document",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":"\\ud800"}',
        b'{"a":"\\udc00"}',
        b'{"a":"unterminated}',
        b'{"a":1} trailing',
        b"\xff",
    ],
)
def test_bounded_json_rejects_malformed_or_ambiguous_documents(document: bytes) -> None:
    with pytest.raises(BoundedJsonError) as captured:
        _load(document)
    assert captured.value.reason_code == BoundedJsonFailureCode.MALFORMED_JSON
    assert document.decode("utf-8", errors="replace") not in str(captured.value)


@pytest.mark.parametrize(
    ("document", "overrides"),
    [
        (b'{"a":{"b":{"c":1}}}', {"max_depth": 2}),
        (b'{"a":1,"b":2}', {"max_fields": 1}),
        (b'{"a":"1234"}', {"max_string_chars": 4}),
    ],
)
def test_bounded_json_rejects_limits_before_model_validation(
    document: bytes,
    overrides: dict[str, int],
) -> None:
    with pytest.raises(BoundedJsonError) as captured:
        _load(document, **overrides)
    assert captured.value.reason_code == BoundedJsonFailureCode.RESPONSE_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    "limits",
    [
        {"max_depth": 0, "max_fields": 1, "max_string_chars": 1},
        {"max_depth": True, "max_fields": 1, "max_string_chars": 1},
    ],
)
def test_bounded_json_rejects_invalid_application_limits(
    limits: dict[str, int],
) -> None:
    with pytest.raises(TypeError):
        load_bounded_json_object(b"{}", **limits)
