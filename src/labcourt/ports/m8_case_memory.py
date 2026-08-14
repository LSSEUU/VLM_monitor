"""Read-only boundary for role-scoped persisted Case precedent projections."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_knowledge_projection import M8CaseMemoryProjectionV1


class M8CaseMemoryAdapter(Protocol):
    def query(
        self,
        principal: M8ApiPrincipalV1,
        normalized_query: str,
        limit: int,
    ) -> M8CaseMemoryProjectionV1: ...


__all__ = ["M8CaseMemoryAdapter"]
