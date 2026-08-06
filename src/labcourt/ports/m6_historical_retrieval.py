"""Application boundary for one-source M6 historical retrieval authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_projection import M5AuthorityKind


@dataclass(frozen=True, slots=True)
class M6HistoricalAuthorityDocument:
    """One canonical document exported by a read-only authority validator."""

    kind: M4ProjectionArtifactKind | M5AuthorityKind
    artifact_id: str
    canonical_document: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, M4ProjectionArtifactKind | M5AuthorityKind):
            raise TypeError("kind must be an M4 or M5 authority kind")
        if not isinstance(self.artifact_id, str) or not self.artifact_id:
            raise TypeError("artifact_id must be a non-empty string")
        if not isinstance(self.canonical_document, str) or not self.canonical_document:
            raise TypeError("canonical_document must be a non-empty string")

    @property
    def document_sha256(self) -> str:
        return hashlib.sha256(self.canonical_document.encode("utf-8")).hexdigest()

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.kind.value, self.artifact_id


@dataclass(frozen=True, slots=True)
class M6ValidatedHistoricalRetrievalSnapshots:
    """M4 and M5 validation results explicitly tied to one snapshot identity."""

    source_identity_sha256: str
    run_id: str
    manifest_id: str
    m4_documents: tuple[M6HistoricalAuthorityDocument, ...]
    m5_documents: tuple[M6HistoricalAuthorityDocument, ...]
    m4_failure_count: int = 0
    m5_failure_count: int = 0
    dataset_retention_failure_count: int = 0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_identity_sha256, str)
            or len(self.source_identity_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.source_identity_sha256)
        ):
            raise ValueError("source snapshot identity must be a lowercase SHA-256")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("run_id must be a non-empty string")
        if (
            not isinstance(self.manifest_id, str)
            or len(self.manifest_id) != 64
            or any(character not in "0123456789abcdef" for character in self.manifest_id)
        ):
            raise ValueError("manifest_id must be a lowercase SHA-256")
        if not isinstance(self.m4_documents, tuple) or any(
            not isinstance(item, M6HistoricalAuthorityDocument) for item in self.m4_documents
        ):
            raise TypeError("m4_documents must be a typed tuple")
        if not isinstance(self.m5_documents, tuple) or any(
            not isinstance(item, M6HistoricalAuthorityDocument) for item in self.m5_documents
        ):
            raise TypeError("m5_documents must be a typed tuple")
        if any(not isinstance(item.kind, M4ProjectionArtifactKind) for item in self.m4_documents):
            raise ValueError("m4_documents contains a non-M4 authority kind")
        if any(not isinstance(item.kind, M5AuthorityKind) for item in self.m5_documents):
            raise ValueError("m5_documents contains a non-M5 authority kind")
        for count in (
            self.m4_failure_count,
            self.m5_failure_count,
            self.dataset_retention_failure_count,
        ):
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError("snapshot failure counts must be non-negative integers")

    @property
    def authority_valid(self) -> bool:
        return (
            self.m4_failure_count == 0
            and self.m5_failure_count == 0
            and self.dataset_retention_failure_count == 0
        )


__all__ = [
    "M6HistoricalAuthorityDocument",
    "M6ValidatedHistoricalRetrievalSnapshots",
]
