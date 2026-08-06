"""Stable JSON Schema rendering shared by CLI and build scripts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from labcourt.schema_registry import (
    SCHEMA_MODELS,
    SCHEMA_VALIDATION_MODELS,
    SCHEMA_VERSION,
)

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_BASE = "https://schemas.labcourt.local/v2"


def _render_json(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def expected_schema_files() -> dict[str, str]:
    rendered: dict[str, str] = {}
    index_entries: list[dict[str, str]] = []
    for name, model in sorted(SCHEMA_MODELS.items()):
        filename = f"{name}.schema.json"
        mode: Literal["validation", "serialization"] = (
            "validation" if name in SCHEMA_VALIDATION_MODELS else "serialization"
        )
        schema = model.model_json_schema(mode=mode)
        schema["$schema"] = JSON_SCHEMA_DIALECT
        schema["$id"] = f"{SCHEMA_ID_BASE}/{filename}"
        rendered[filename] = _render_json(schema)
        index_entries.append(
            {
                "name": name,
                "file": filename,
                "model": f"{model.__module__}.{model.__name__}",
                "mode": mode,
            }
        )
    rendered["index.json"] = _render_json(
        {
            "$schema": JSON_SCHEMA_DIALECT,
            "$id": f"{SCHEMA_ID_BASE}/index.json",
            "schema_version": SCHEMA_VERSION,
            "schemas": index_entries,
        }
    )
    return rendered


def export_schemas(output_dir: Path, *, check: bool) -> list[str]:
    expected = expected_schema_files()
    errors: list[str] = []
    if check:
        for filename, content in expected.items():
            path = output_dir / filename
            if not path.exists():
                errors.append(f"missing schema: {filename}")
            elif path.read_text(encoding="utf-8") != content:
                errors.append(f"schema drift: {filename}")
        existing = (
            {path.name for path in output_dir.glob("*.json")} if output_dir.exists() else set()
        )
        unexpected = existing - set(expected)
        errors.extend(f"unexpected schema: {filename}" for filename in sorted(unexpected))
        return errors

    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in expected.items():
        (output_dir / filename).write_text(content, encoding="utf-8", newline="\n")
    return errors
