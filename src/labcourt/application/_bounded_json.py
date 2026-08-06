"""Provider-text-neutral JSON loading with lexical resource limits."""

from __future__ import annotations

import json
import math
from enum import StrEnum
from typing import Any

_JSON_WHITESPACE = frozenset({" ", "\t", "\r", "\n"})
_SIMPLE_ESCAPES = frozenset({'"', "\\", "/", "b", "f", "n", "r", "t"})
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class BoundedJsonFailureCode(StrEnum):
    MALFORMED_JSON = "MALFORMED_JSON"
    RESPONSE_LIMIT_EXCEEDED = "RESPONSE_LIMIT_EXCEEDED"
    ROOT_NOT_OBJECT = "ROOT_NOT_OBJECT"


class BoundedJsonError(ValueError):
    """Controlled failure that never includes provider-authored content."""

    def __init__(self, reason_code: BoundedJsonFailureCode) -> None:
        if not isinstance(reason_code, BoundedJsonFailureCode):
            raise TypeError("reason_code must be a BoundedJsonFailureCode")
        self.reason_code = reason_code
        super().__init__(f"bounded JSON load failed: {reason_code.value}")


class _JsonLimitExceeded(Exception):
    pass


class _MalformedJson(Exception):
    pass


def _raise_constant(_: str) -> None:
    raise _MalformedJson


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _MalformedJson
        output[key] = value
    return output


def _count_string_character(total: int, maximum: int) -> int:
    total += 1
    if total > maximum:
        raise _JsonLimitExceeded
    return total


def _scan_json_limits(
    text: str,
    *,
    max_depth: int,
    max_fields: int,
    max_string_chars: int,
) -> None:
    """Enforce budgets before Python constructs an attacker-sized JSON tree."""

    depth = 0
    fields = 0
    string_chars = 0
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        if char in _JSON_WHITESPACE:
            index += 1
            continue
        if char in "{[":
            depth += 1
            if depth > max_depth:
                raise _JsonLimitExceeded
            index += 1
            continue
        if char in "}]":
            depth -= 1
            if depth < 0:
                raise _MalformedJson
            index += 1
            continue
        if char == ":":
            fields += 1
            if fields > max_fields:
                raise _JsonLimitExceeded
            index += 1
            continue
        if char != '"':
            if 0xD800 <= ord(char) <= 0xDFFF:
                raise _MalformedJson
            index += 1
            continue

        index += 1
        while index < length:
            char = text[index]
            if char == '"':
                index += 1
                break
            if char == "\\":
                index += 1
                if index >= length:
                    raise _MalformedJson
                escape = text[index]
                if escape in _SIMPLE_ESCAPES:
                    string_chars = _count_string_character(string_chars, max_string_chars)
                    index += 1
                    continue
                if escape != "u" or index + 4 >= length:
                    raise _MalformedJson
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(digit not in _HEX_DIGITS for digit in digits):
                    raise _MalformedJson
                codepoint = int(digits, 16)
                index += 5
                if 0xD800 <= codepoint <= 0xDBFF:
                    if index + 5 >= length or text[index : index + 2] != "\\u":
                        raise _MalformedJson
                    low_digits = text[index + 2 : index + 6]
                    if len(low_digits) != 4 or any(
                        digit not in _HEX_DIGITS for digit in low_digits
                    ):
                        raise _MalformedJson
                    low_codepoint = int(low_digits, 16)
                    if not 0xDC00 <= low_codepoint <= 0xDFFF:
                        raise _MalformedJson
                    index += 6
                elif 0xDC00 <= codepoint <= 0xDFFF:
                    raise _MalformedJson
                string_chars = _count_string_character(string_chars, max_string_chars)
                continue
            if ord(char) < 0x20 or 0xD800 <= ord(char) <= 0xDFFF:
                raise _MalformedJson
            string_chars = _count_string_character(string_chars, max_string_chars)
            index += 1
        else:
            raise _MalformedJson

    if depth != 0:
        raise _MalformedJson


def _contains_non_finite_number(root: object) -> bool:
    pending = [root]
    while pending:
        value = pending.pop()
        if isinstance(value, float) and not math.isfinite(value):
            return True
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return False


def load_bounded_json_object(
    raw_document: bytes,
    *,
    max_depth: int,
    max_fields: int,
    max_string_chars: int,
) -> dict[str, Any]:
    """Decode one exact UTF-8 JSON object or raise a constant controlled code."""

    if not isinstance(raw_document, bytes):
        raise TypeError("raw_document must be bytes")
    limits = (max_depth, max_fields, max_string_chars)
    if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in limits):
        raise TypeError("bounded JSON limits must be positive integers")
    try:
        text = raw_document.decode("utf-8", errors="strict")
        _scan_json_limits(
            text,
            max_depth=max_depth,
            max_fields=max_fields,
            max_string_chars=max_string_chars,
        )
    except _JsonLimitExceeded:
        raise BoundedJsonError(BoundedJsonFailureCode.RESPONSE_LIMIT_EXCEEDED) from None
    except (UnicodeDecodeError, _MalformedJson):
        raise BoundedJsonError(BoundedJsonFailureCode.MALFORMED_JSON) from None

    try:
        root = json.loads(
            text,
            parse_constant=_raise_constant,
            object_pairs_hook=_unique_object,
        )
    except (ValueError, _MalformedJson, OverflowError, RecursionError):
        raise BoundedJsonError(BoundedJsonFailureCode.MALFORMED_JSON) from None
    if not isinstance(root, dict):
        raise BoundedJsonError(BoundedJsonFailureCode.ROOT_NOT_OBJECT)
    if _contains_non_finite_number(root):
        raise BoundedJsonError(BoundedJsonFailureCode.MALFORMED_JSON)
    return root


__all__ = [
    "BoundedJsonError",
    "BoundedJsonFailureCode",
    "load_bounded_json_object",
]
