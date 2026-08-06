"""Offline deterministic embedding fake for M5 contract and retrieval tests."""

from __future__ import annotations

from labcourt.application.m5_embedding_integrity import (
    MAX_M5_FAKE_EMBEDDING_INPUT_BYTES,
    derive_m5_fake_sha256_signed_projection,
)
from labcourt.contracts.m5_precedents import M5EmbeddingRequest, M5EmbeddingVector

MAX_FAKE_EMBEDDING_INPUT_BYTES = MAX_M5_FAKE_EMBEDDING_INPUT_BYTES


class DeterministicFakePrecedentEmbeddingProvider:
    """Hash-project authored fixture bytes; it performs no model or network call."""

    def embed(self, request: M5EmbeddingRequest, payload: bytes) -> M5EmbeddingVector:
        return derive_m5_fake_sha256_signed_projection(request, payload)


__all__ = [
    "MAX_FAKE_EMBEDDING_INPUT_BYTES",
    "DeterministicFakePrecedentEmbeddingProvider",
]
