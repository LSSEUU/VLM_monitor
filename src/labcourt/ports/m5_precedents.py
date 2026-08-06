"""Persistence and deterministic embedding boundaries for M5 precedents."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from labcourt.contracts.m5_precedents import (
    M5AppealWindowSnapshot,
    M5EmbeddingRequest,
    M5EmbeddingVector,
    M5PrecedentActivationResult,
    M5PrecedentAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictSnapshot,
    M5PrecedentRetrievalQuery,
    M5PrecedentRevocationResult,
)


class M5PrecedentEmbeddingProvider(Protocol):
    def embed(self, request: M5EmbeddingRequest, payload: bytes) -> M5EmbeddingVector: ...


class M5PrecedentRepository(Protocol):
    def get(
        self,
        run_id: str,
        precedent_id: str,
    ) -> M5PrecedentAuthority | None: ...

    def list_for_retrieval(
        self,
        query: M5PrecedentRetrievalQuery,
    ) -> tuple[M5PrecedentAuthority, ...]: ...

    def list_conflicts(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[M5PrecedentAuthority, ...]: ...

    def load_conflict_snapshot(
        self,
        run_id: str,
        limit: int,
    ) -> M5PrecedentConflictSnapshot:
        """Return the complete ACTIVE inventory at one authority-only causal cut."""
        ...

    def list_activation_candidates(
        self,
        run_id: str,
        evaluated_at: datetime,
        limit: int,
    ) -> tuple[M5PrecedentAuthority, ...]:
        """Return due heads without an appeal-present receipt for that exact authority."""
        ...

    def load_appeal_window_snapshot(
        self,
        run_id: str,
        source_case_id: str,
        observed_through: datetime,
    ) -> M5AppealWindowSnapshot: ...

    def append_authority(
        self,
        authority: M5PrecedentAuthority,
        expected_revision: int | None,
    ) -> M5PrecedentAuthority: ...

    def append_authorities(
        self,
        run_id: str,
        authorities: tuple[M5PrecedentAuthority, ...],
    ) -> tuple[M5PrecedentAuthority, ...]:
        """Atomically import one complete, stably ordered PRESET batch."""
        ...

    def commit_citation(
        self,
        commit: M5PrecedentCitationCommit,
    ) -> M5PrecedentCitationCommit: ...

    def commit_activation(
        self,
        result: M5PrecedentActivationResult,
    ) -> M5PrecedentActivationResult: ...

    def citation_snapshot(
        self,
        run_id: str,
        precedent_id: str,
    ) -> M5PrecedentCitationSnapshot: ...

    def commit_conflict_batch(
        self,
        resolution: M5PrecedentConflictBatchResolution,
    ) -> M5PrecedentConflictBatchResolution: ...

    def commit_revocation(
        self,
        result: M5PrecedentRevocationResult,
    ) -> M5PrecedentRevocationResult: ...


__all__ = ["M5PrecedentEmbeddingProvider", "M5PrecedentRepository"]
