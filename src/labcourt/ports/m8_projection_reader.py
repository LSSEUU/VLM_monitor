"""Read port for a stable current M8 campus operations projection."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_projections import M8OperationsProjectionV1


class M8OperationsProjectionReader(Protocol):
    def current_projection(self, campus_id: str) -> M8OperationsProjectionV1: ...


__all__ = ["M8OperationsProjectionReader"]
