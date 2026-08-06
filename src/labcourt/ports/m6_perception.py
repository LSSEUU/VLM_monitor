"""Read-only authority documents used to resolve locked M6 perception inputs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class M6FrameAuthorityDocument:
    """One frame row and its indexed source-scope claims."""

    run_id: str
    manifest_id: str
    frame_id: str
    content_sha256: str
    canonical_document: str
    document_sha256: str


@dataclass(frozen=True, slots=True)
class M6DetectionAuthorityDocument:
    """One detection row and its indexed source-scope claims."""

    run_id: str
    manifest_id: str
    detection_id: str
    frame_id: str
    model_manifest_id: str
    canonical_document: str
    document_sha256: str


@dataclass(frozen=True, slots=True)
class M6PerceptionAuthoritySnapshot:
    """Exact documents read from one immutable private SQLite snapshot.

    This boundary intentionally retains both canonical documents and indexed
    columns.  The application assembler revalidates both directions before any
    value can enter the pure semantic projection.
    """

    source_identity_sha256: str
    run_id: str
    manifest_id: str
    manifest_canonical_document: str
    manifest_document_sha256: str
    source_case_id: str | None
    source_case_revision: int | None
    source_case_canonical_document: str | None
    source_case_document_sha256: str | None
    frames: tuple[M6FrameAuthorityDocument, ...]
    detections: tuple[M6DetectionAuthorityDocument, ...]


__all__ = [
    "M6DetectionAuthorityDocument",
    "M6FrameAuthorityDocument",
    "M6PerceptionAuthoritySnapshot",
]
