"""Immutable M4 history boundary used to reconstruct M6 Gate inputs."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument

MAX_M6_GATE_HISTORY_DOCUMENTS = 65_536
MAX_M6_GATE_HISTORY_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_GATE_HISTORY_TOTAL_BYTES = 512 * 1024 * 1024


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class M6ProceduralGateHistorySnapshot:
    """Canonical full-M4 documents captured from one validated snapshot."""

    source_identity_sha256: str
    run_id: str
    source_m4_authority_root_sha256: str
    documents: tuple[M6HistoricalAuthorityDocument, ...]
    failure_count: int = 0

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "M6 Gate source identity")
        _require_sha256(
            self.source_m4_authority_root_sha256,
            "M6 Gate M4 authority root",
        )
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("M6 Gate run_id must be a non-empty string")
        if not isinstance(self.documents, tuple) or any(
            not isinstance(item, M6HistoricalAuthorityDocument) for item in self.documents
        ):
            raise TypeError("M6 Gate documents must be a typed tuple")
        if len(self.documents) > MAX_M6_GATE_HISTORY_DOCUMENTS:
            raise ValueError("M6 Gate history exceeds its document-count budget")
        if any(not isinstance(item.kind, M4ProjectionArtifactKind) for item in self.documents):
            raise ValueError("M6 Gate history contains a non-M4 authority document")
        keys = tuple(item.sort_key for item in self.documents)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M6 Gate history documents must be unique and ordered")
        sizes = tuple(len(item.canonical_document.encode("utf-8")) for item in self.documents)
        if any(size > MAX_M6_GATE_HISTORY_DOCUMENT_BYTES for size in sizes):
            raise ValueError("M6 Gate history document exceeds its byte budget")
        if sum(sizes) > MAX_M6_GATE_HISTORY_TOTAL_BYTES:
            raise ValueError("M6 Gate history exceeds its total byte budget")
        if (
            not isinstance(self.failure_count, int)
            or isinstance(self.failure_count, bool)
            or self.failure_count < 0
        ):
            raise ValueError("M6 Gate history failure_count must be non-negative")


__all__ = [
    "MAX_M6_GATE_HISTORY_DOCUMENTS",
    "MAX_M6_GATE_HISTORY_DOCUMENT_BYTES",
    "MAX_M6_GATE_HISTORY_TOTAL_BYTES",
    "M6ProceduralGateHistorySnapshot",
]
