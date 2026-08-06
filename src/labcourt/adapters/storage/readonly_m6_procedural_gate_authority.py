"""Read the complete validated M4 graph needed by M6 procedural Gate replay."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.readonly_m4_artifacts import (
    ReadonlyM4ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.contracts.references import require_reference_token
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from labcourt.ports.m6_procedural_gate_authority import (
    M6ProceduralGateHistorySnapshot,
)

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity


class ReadonlyM6ProceduralGateAuthorityRepository:
    """Export full M4 documents only after graph and snapshot validation."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: str | Path) -> None:
        self._snapshot = Path(snapshot).absolute()

    def load_validated_snapshot(
        self,
        run_id: str,
    ) -> M6ProceduralGateHistorySnapshot:
        controlled_run_id = require_reference_token(run_id, "M6 procedural Gate run_id")
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        authority = ReadonlyM4ArtifactRepository(
            self._snapshot,
            immutable=True,
        ).scan(controlled_run_id)
        if authority.failures:
            raise ReadOnlySnapshotError("DATABASE_AUTHORITY_INVALID")
        if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_GATE_SCAN")
        return M6ProceduralGateHistorySnapshot(
            source_identity_sha256=before.identity_sha256,
            run_id=authority.run_id,
            source_m4_authority_root_sha256=authority.authority_root_sha256,
            documents=tuple(
                M6HistoricalAuthorityDocument(
                    kind=item.kind,
                    artifact_id=item.artifact_id,
                    canonical_document=item.canonical_document,
                )
                for item in authority.documents
            ),
        )


__all__ = ["ReadonlyM6ProceduralGateAuthorityRepository"]
