"""Read-only adapter for one-source M6 historical retrieval cuts."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from labcourt.adapters.storage.readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.application.m6_historical_retrieval_cut import (
    M6HistoricalRetrievalCutError,
    M6HistoricalRetrievalCutErrorCode,
    assemble_m6_historical_retrieval_cut,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_replay_locked import M6HistoricalCausalCut
from labcourt.contracts.references import require_reference_token
from labcourt.ports.m6_historical_retrieval import (
    M6HistoricalAuthorityDocument,
    M6ValidatedHistoricalRetrievalSnapshots,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity


def _controlled_case(source_case: object) -> Case:
    if not isinstance(source_case, Case):
        raise M6HistoricalRetrievalCutError(M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT)
    try:
        controlled = Case.model_validate(
            source_case.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        raise M6HistoricalRetrievalCutError(
            M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT
        ) from None
    if controlled != source_case:
        raise M6HistoricalRetrievalCutError(M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT)
    return controlled


class ReadonlyM6HistoricalRetrievalCutRepository:
    """Scan M4 and M5 through one immutable private SQLite snapshot.

    ``snapshot`` is expected to be the private path yielded by
    :func:`readonly_sqlite_snapshot`, not the writable production database.
    No current precedent head or training-label tail is queried by this adapter.
    """

    __slots__ = ("_config", "_snapshot")

    def __init__(self, snapshot: str | Path, *, config: AppConfig) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        self._snapshot = Path(snapshot).absolute()
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))

    def load_validated_snapshots(
        self,
        run_id: str,
    ) -> M6ValidatedHistoricalRetrievalSnapshots:
        controlled_run_id = require_reference_token(run_id, "M6 historical cut run_id")
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        m4 = ReadonlyM4ArtifactRepository(
            self._snapshot,
            immutable=True,
        ).scan(controlled_run_id)
        if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_RETRIEVAL_CUT")
        m5 = ReadonlyM5ArtifactRepository(
            self._snapshot,
            config=self._config,
            immutable=True,
        ).scan(controlled_run_id)
        if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_RETRIEVAL_CUT")
        return M6ValidatedHistoricalRetrievalSnapshots(
            source_identity_sha256=before.identity_sha256,
            run_id=controlled_run_id,
            manifest_id=m5.manifest_id,
            m4_documents=tuple(
                M6HistoricalAuthorityDocument(
                    kind=document.kind,
                    artifact_id=document.artifact_id,
                    canonical_document=document.canonical_document,
                )
                for document in m4.documents
                if document.kind
                in {
                    M4ProjectionArtifactKind.HEARING_CYCLE,
                    M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
                }
            ),
            m5_documents=tuple(
                M6HistoricalAuthorityDocument(
                    kind=document.kind,
                    artifact_id=document.artifact_id,
                    canonical_document=document.canonical_document,
                )
                for document in m5.documents
                if document.kind == M5AuthorityKind.PRECEDENT_EXPOSURE
            ),
            m4_failure_count=len(m4.failures),
            m5_failure_count=len(m5.failures),
            dataset_retention_failure_count=len(m5.dataset_retention_failures),
        )

    def assemble(self, source_case: Case) -> M6HistoricalCausalCut:
        controlled_case = _controlled_case(source_case)
        snapshots = self.load_validated_snapshots(controlled_case.run_id)
        return assemble_m6_historical_retrieval_cut(
            source_case=controlled_case,
            snapshots=snapshots,
        )


__all__ = [
    "M6ValidatedHistoricalRetrievalSnapshots",
    "ReadonlyM6HistoricalRetrievalCutRepository",
]
