"""Hard-capped JSONL loader dedicated to public M5 PRESET imports."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.strict_jsonl import load_strict_jsonl
from labcourt.contracts.m5_precedents import MAX_M5_PRECEDENTS

MAX_M5_IMPORT_FILE_BYTES = 64 * 1024 * 1024
MAX_M5_IMPORT_LINE_BYTES = 1024 * 1024
MAX_M5_IMPORT_ENTRIES = MAX_M5_PRECEDENTS


def _require_ceiling(value: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise TypeError(f"{name} must be an integer in [1, {maximum}]")
    return value


def load_m5_precedent_jsonl(
    path: Path,
    *,
    max_file_bytes: int = MAX_M5_IMPORT_FILE_BYTES,
    max_line_bytes: int = MAX_M5_IMPORT_LINE_BYTES,
    max_entries: int = MAX_M5_IMPORT_ENTRIES,
) -> tuple[dict[str, object], ...]:
    """Load a PRESET import without allowing caller-selected budget expansion."""

    return load_strict_jsonl(
        path,
        max_file_bytes=_require_ceiling(
            max_file_bytes,
            MAX_M5_IMPORT_FILE_BYTES,
            "M5 import max_file_bytes",
        ),
        max_line_bytes=_require_ceiling(
            max_line_bytes,
            MAX_M5_IMPORT_LINE_BYTES,
            "M5 import max_line_bytes",
        ),
        max_entries=_require_ceiling(
            max_entries,
            MAX_M5_IMPORT_ENTRIES,
            "M5 import max_entries",
        ),
    )


__all__ = [
    "MAX_M5_IMPORT_ENTRIES",
    "MAX_M5_IMPORT_FILE_BYTES",
    "MAX_M5_IMPORT_LINE_BYTES",
    "load_m5_precedent_jsonl",
]
