"""Shared fail-closed helpers for explicit Feishu operator commands."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import NoReturn

import typer

from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.m8_adapter_commissioning import MAX_M8_RUNTIME_CONFIG_BYTES
from labcourt.exceptions import ConcurrentModification, ContractViolation, EvidenceMissing

OPERATOR_FAILURES = (
    ConcurrentModification,
    ContractViolation,
    EvidenceMissing,
    RepositoryIntegrityError,
    OSError,
    TypeError,
    ValueError,
    sqlite3.DatabaseError,
)


def read_document(path: Path, name: str) -> bytes:
    document = path.read_bytes()
    if not 0 < len(document) <= MAX_M8_RUNTIME_CONFIG_BYTES:
        raise ValueError(f"Feishu {name} exceeds the allowed bound")
    return document


def parse_utc(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"Feishu {name} must be an ISO-8601 UTC time") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"Feishu {name} must be an ISO-8601 UTC time")
    return parsed


def fail(operation: str, error: Exception) -> NoReturn:
    typer.echo(f"Feishu {operation} failed: {error}", err=True)
    raise typer.Exit(code=2)


def echo_summary(summary: dict[str, object], json_output: bool, message: str) -> None:
    typer.echo(json.dumps(summary, ensure_ascii=True, sort_keys=True) if json_output else message)


__all__ = [
    "OPERATOR_FAILURES",
    "echo_summary",
    "fail",
    "parse_utc",
    "read_document",
]
