"""Minimal structural type for caller-owned SQLite read transactions."""

from __future__ import annotations

from typing import Any, Protocol


class SQLiteReadSession(Protocol):
    """Read surface shared by raw trusted connections and sealed M6 readers."""

    @property
    def in_transaction(self) -> bool: ...

    def execute(self, sql: str, parameters: Any = (), /) -> Any: ...


__all__ = ["SQLiteReadSession"]
