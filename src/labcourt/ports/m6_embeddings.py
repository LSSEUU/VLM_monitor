"""Validated M5 documents available to the M6 embedding closure resolver."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from labcourt.contracts.m5_projection import M5AuthorityKind


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class M6EmbeddingAuthorityDocument:
    """One canonical M5 embedding or exposure document."""

    kind: M5AuthorityKind
    artifact_id: str
    canonical_document: str
    document_sha256: str

    def __post_init__(self) -> None:
        if self.kind not in {
            M5AuthorityKind.PRECEDENT_EMBEDDING,
            M5AuthorityKind.PRECEDENT_EXPOSURE,
        }:
            raise ValueError("M6 embedding authority document kind is invalid")
        if not isinstance(self.artifact_id, str) or not self.artifact_id:
            raise TypeError("artifact_id must be a non-empty string")
        if not isinstance(self.canonical_document, str) or not self.canonical_document:
            raise TypeError("canonical_document must be a non-empty string")
        _require_sha256(self.document_sha256, "document_sha256")
        observed = hashlib.sha256(self.canonical_document.encode("utf-8")).hexdigest()
        if observed != self.document_sha256:
            raise ValueError("M6 embedding authority document hash is invalid")

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.kind.value, self.artifact_id


@dataclass(frozen=True, slots=True)
class M6EmbeddingAuthoritySnapshot:
    """M5 replay subset read from one private SQLite snapshot."""

    source_identity_sha256: str
    run_id: str
    manifest_id: str
    source_authority_root_sha256: str
    documents: tuple[M6EmbeddingAuthorityDocument, ...]
    authority_failure_count: int = 0
    dataset_retention_failure_count: int = 0

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "source_identity_sha256")
        _require_sha256(self.manifest_id, "manifest_id")
        _require_sha256(self.source_authority_root_sha256, "source_authority_root_sha256")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise TypeError("run_id must be a non-empty string")
        if not isinstance(self.documents, tuple) or any(
            not isinstance(item, M6EmbeddingAuthorityDocument) for item in self.documents
        ):
            raise TypeError("documents must be a typed tuple")
        keys = tuple(item.sort_key for item in self.documents)
        if keys != tuple(sorted(keys)):
            raise ValueError("M6 embedding authority documents must use stable order")
        if len(keys) != len(set(keys)):
            raise ValueError("M6 embedding authority documents must be unique")
        for count in (
            self.authority_failure_count,
            self.dataset_retention_failure_count,
        ):
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError("M6 embedding authority failure counts must be non-negative")

    @property
    def authority_valid(self) -> bool:
        return self.authority_failure_count == 0 and self.dataset_retention_failure_count == 0


__all__ = [
    "M6EmbeddingAuthorityDocument",
    "M6EmbeddingAuthoritySnapshot",
]
