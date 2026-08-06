"""Read M6 embedding closure authority from one immutable M5 snapshot."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.application.m6_embedding_authority import (
    M6EmbeddingAuthorityError,
    M6EmbeddingAuthorityErrorCode,
    assemble_m6_resolved_embeddings,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.references import require_reference_token
from labcourt.domain.m6_embedding_authority import M6ResolvedEmbeddingAuthority
from labcourt.ports.m6_embeddings import (
    M6EmbeddingAuthorityDocument,
    M6EmbeddingAuthoritySnapshot,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity


class ReadonlyM6EmbeddingAuthorityRepository:
    """Resolve embeddings without invoking a provider or writable cache."""

    __slots__ = ("_config", "_snapshot")

    def __init__(self, snapshot: str | Path, *, config: AppConfig) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        self._snapshot = Path(snapshot).absolute()
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))

    def read_authority_snapshot(self, run_id: str) -> M6EmbeddingAuthoritySnapshot:
        controlled = require_reference_token(run_id, "M6 embedding authority run_id")
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        m5 = ReadonlyM5ArtifactRepository(
            self._snapshot,
            config=self._config,
            immutable=True,
        ).scan(controlled)
        if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_EMBEDDING_READ")
        documents = tuple(
            M6EmbeddingAuthorityDocument(
                kind=document.kind,
                artifact_id=document.artifact_id,
                canonical_document=document.canonical_document,
                document_sha256=document.document_sha256,
            )
            for document in m5.documents
            if document.kind
            in {
                M5AuthorityKind.PRECEDENT_EMBEDDING,
                M5AuthorityKind.PRECEDENT_EXPOSURE,
            }
        )
        return M6EmbeddingAuthoritySnapshot(
            source_identity_sha256=before.identity_sha256,
            run_id=m5.run_id,
            manifest_id=m5.manifest_id,
            source_authority_root_sha256=m5.authority_root_sha256,
            documents=documents,
            authority_failure_count=len(m5.failures),
            dataset_retention_failure_count=len(m5.dataset_retention_failures),
        )

    def assemble(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> tuple[M6ResolvedEmbeddingAuthority, ...]:
        if not isinstance(closure, M6ReplayInputClosureAuthority):
            raise M6EmbeddingAuthorityError(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
        try:
            canonical = M6ReplayInputClosureAuthority.model_validate(
                closure.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (TypeError, ValueError):
            raise M6EmbeddingAuthorityError(
                M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT
            ) from None
        if canonical != closure:
            raise M6EmbeddingAuthorityError(M6EmbeddingAuthorityErrorCode.INVALID_ARGUMENT)
        snapshot = self.read_authority_snapshot(canonical.source_run_id)
        return assemble_m6_resolved_embeddings(closure=canonical, snapshot=snapshot)


__all__ = ["ReadonlyM6EmbeddingAuthorityRepository"]
