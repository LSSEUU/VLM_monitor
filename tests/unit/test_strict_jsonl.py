from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.m5_precedent_jsonl import (
    MAX_M5_IMPORT_ENTRIES,
    MAX_M5_IMPORT_FILE_BYTES,
    MAX_M5_IMPORT_LINE_BYTES,
    load_m5_precedent_jsonl,
)
from labcourt.adapters.strict_jsonl import (
    StrictJsonlError,
    StrictJsonlFailureCode,
    load_strict_jsonl,
)


def _load(path: Path, **budgets: int) -> tuple[dict[str, object], ...]:
    return load_strict_jsonl(
        path,
        max_file_bytes=budgets.get("max_file_bytes", 1_024),
        max_line_bytes=budgets.get("max_line_bytes", 512),
        max_entries=budgets.get("max_entries", 10),
    )


def test_strict_jsonl_reads_unique_object_records(tmp_path: Path) -> None:
    source = tmp_path / "authorities.jsonl"
    source.write_bytes(b'{"id":"one","score":0.5}\r\n{"id":"two","items":[]}\n')

    assert _load(source) == (
        {"id": "one", "score": 0.5},
        {"id": "two", "items": []},
    )


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b'{"id":"one","id":"two"}\n', StrictJsonlFailureCode.JSON_INVALID),
        (b'{"score":NaN}\n', StrictJsonlFailureCode.JSON_INVALID),
        (b'["not-an-object"]\n', StrictJsonlFailureCode.ROOT_INVALID),
        (b"\xef\xbb\xbf{}\n", StrictJsonlFailureCode.UTF8_INVALID),
        (b"{}\n\n", StrictJsonlFailureCode.JSON_INVALID),
    ],
)
def test_strict_jsonl_rejects_ambiguous_or_nonportable_input(
    tmp_path: Path,
    payload: bytes,
    code: StrictJsonlFailureCode,
) -> None:
    source = tmp_path / "bad.jsonl"
    source.write_bytes(payload)
    with pytest.raises(StrictJsonlError) as raised:
        _load(source)
    assert raised.value.reason_code == code


def test_strict_jsonl_enforces_file_line_and_entry_budgets(tmp_path: Path) -> None:
    source = tmp_path / "bounded.jsonl"
    source.write_bytes(b'{"id":"one"}\n{"id":"two"}\n')

    with pytest.raises(StrictJsonlError) as file_error:
        _load(source, max_file_bytes=10)
    assert file_error.value.reason_code == StrictJsonlFailureCode.FILE_BYTES_EXCEEDED
    with pytest.raises(StrictJsonlError) as line_error:
        _load(source, max_line_bytes=5)
    assert line_error.value.reason_code == StrictJsonlFailureCode.LINE_BYTES_EXCEEDED
    with pytest.raises(StrictJsonlError) as entry_error:
        _load(source, max_entries=1)
    assert entry_error.value.reason_code == StrictJsonlFailureCode.ENTRY_BUDGET_EXCEEDED


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("max_file_bytes", MAX_M5_IMPORT_FILE_BYTES + 1),
        ("max_line_bytes", MAX_M5_IMPORT_LINE_BYTES + 1),
        ("max_entries", MAX_M5_IMPORT_ENTRIES + 1),
    ],
)
def test_m5_precedent_loader_rejects_budget_expansion(
    tmp_path: Path,
    name: str,
    value: int,
) -> None:
    source = tmp_path / "precedents.jsonl"
    source.write_bytes(b"{}\n")
    budgets = {
        "max_file_bytes": MAX_M5_IMPORT_FILE_BYTES,
        "max_line_bytes": MAX_M5_IMPORT_LINE_BYTES,
        "max_entries": MAX_M5_IMPORT_ENTRIES,
        name: value,
    }

    with pytest.raises(TypeError, match=name):
        load_m5_precedent_jsonl(source, **budgets)
