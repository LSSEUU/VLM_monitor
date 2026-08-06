"""Read-only M4 authority boundary for M6 acquisition projection."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument


@dataclass(frozen=True, slots=True)
class M6ValidatedM4ReplayAuthoritySnapshot:
    """Canonical M4 replay documents captured from one immutable snapshot."""

    source_identity_sha256: str
    run_id: str
    documents: tuple[M6HistoricalAuthorityDocument, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_identity_sha256, str)
            or len(self.source_identity_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.source_identity_sha256)
        ):
            raise ValueError("source snapshot identity must be a lowercase SHA-256")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("run_id must be a non-empty string")
        if not isinstance(self.documents, tuple) or any(
            not isinstance(item, M6HistoricalAuthorityDocument) for item in self.documents
        ):
            raise TypeError("documents must be a typed tuple")
        if any(not isinstance(item.kind, M4ProjectionArtifactKind) for item in self.documents):
            raise ValueError("documents contains a non-M4 authority kind")
        keys = tuple(item.sort_key for item in self.documents)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("documents must use stable unique authority order")


__all__ = ["M6ValidatedM4ReplayAuthoritySnapshot"]
