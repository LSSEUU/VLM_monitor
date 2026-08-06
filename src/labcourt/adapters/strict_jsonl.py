"""Bounded strict UTF-8 JSONL ingestion for authored offline command fixtures."""

from __future__ import annotations

import json
import math
from enum import StrEnum
from pathlib import Path

MAX_STRICT_JSON_DEPTH = 32
MAX_STRICT_JSON_NODES = 1_000_000
MAX_STRICT_JSON_NUMBER_CHARS = 128


class StrictJsonlFailureCode(StrEnum):
    ENTRY_BUDGET_EXCEEDED = "ENTRY_BUDGET_EXCEEDED"
    FILE_BYTES_EXCEEDED = "FILE_BYTES_EXCEEDED"
    FILE_UNAVAILABLE = "FILE_UNAVAILABLE"
    JSON_INVALID = "JSON_INVALID"
    LINE_BYTES_EXCEEDED = "LINE_BYTES_EXCEEDED"
    ROOT_INVALID = "ROOT_INVALID"
    UTF8_INVALID = "UTF8_INVALID"


class StrictJsonlError(ValueError):
    def __init__(self, reason_code: StrictJsonlFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code.value)


class _JsonInvalid(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _JsonInvalid
        result[key] = value
    return result


def _reject_constant(_token: str) -> object:
    raise _JsonInvalid


def _parse_integer(token: str) -> int:
    if len(token) > MAX_STRICT_JSON_NUMBER_CHARS:
        raise _JsonInvalid
    value = int(token)
    if not -(1 << 63) <= value <= (1 << 63) - 1:
        raise _JsonInvalid
    return value


def _parse_float(token: str) -> float:
    if len(token) > MAX_STRICT_JSON_NUMBER_CHARS:
        raise _JsonInvalid
    value = float(token)
    if not math.isfinite(value):
        raise _JsonInvalid
    return value


def _validate_tree(root: object) -> None:
    pending: list[tuple[object, int]] = [(root, 1)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_STRICT_JSON_NODES or depth > MAX_STRICT_JSON_DEPTH:
            raise _JsonInvalid
        if isinstance(value, dict):
            pending.extend((key, depth + 1) for key in value)
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            if "\x00" in value or "\ufeff" in value:
                raise _JsonInvalid
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                raise _JsonInvalid from None


def load_strict_jsonl(
    path: Path,
    *,
    max_file_bytes: int,
    max_line_bytes: int,
    max_entries: int,
) -> tuple[dict[str, object], ...]:
    """Read object-only JSONL without duplicate keys, non-finite numbers, or BOMs."""

    for value in (max_file_bytes, max_line_bytes, max_entries):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise TypeError("strict JSONL budgets must be positive integers")
    try:
        with path.open("rb") as source:
            payload = source.read(max_file_bytes + 1)
    except OSError:
        raise StrictJsonlError(StrictJsonlFailureCode.FILE_UNAVAILABLE) from None
    if len(payload) > max_file_bytes:
        raise StrictJsonlError(StrictJsonlFailureCode.FILE_BYTES_EXCEEDED)
    if payload.startswith(b"\xef\xbb\xbf") or b"\x00" in payload:
        raise StrictJsonlError(StrictJsonlFailureCode.UTF8_INVALID)
    try:
        decoded = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise StrictJsonlError(StrictJsonlFailureCode.UTF8_INVALID) from None

    lines = decoded.splitlines()
    if len(lines) > max_entries:
        raise StrictJsonlError(StrictJsonlFailureCode.ENTRY_BUDGET_EXCEEDED)
    records: list[dict[str, object]] = []
    for line in lines:
        if not line or line.isspace():
            raise StrictJsonlError(StrictJsonlFailureCode.JSON_INVALID)
        try:
            if len(line.encode("utf-8")) > max_line_bytes:
                raise StrictJsonlError(StrictJsonlFailureCode.LINE_BYTES_EXCEEDED)
        except UnicodeEncodeError:
            raise StrictJsonlError(StrictJsonlFailureCode.UTF8_INVALID) from None
        try:
            record = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
                parse_int=_parse_integer,
                parse_float=_parse_float,
            )
            _validate_tree(record)
        except StrictJsonlError:
            raise
        except (ValueError, OverflowError, RecursionError):
            raise StrictJsonlError(StrictJsonlFailureCode.JSON_INVALID) from None
        if not isinstance(record, dict):
            raise StrictJsonlError(StrictJsonlFailureCode.ROOT_INVALID)
        records.append(record)
    return tuple(records)


__all__ = ["StrictJsonlError", "StrictJsonlFailureCode", "load_strict_jsonl"]
