"""Read-only adapter for M6 acquisition semantic authority."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from labcourt.adapters.storage.readonly_m4_artifacts import (
    ReadonlyM4ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import ReadOnlySnapshotError
from labcourt.application.m6_acquisition_projection import (
    M6AcquisitionProjectionError,
    M6AcquisitionProjectionErrorCode,
    resolve_m6_locked_acquisitions,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.m6_replay_locked import M6LockedToolResultInput
from labcourt.contracts.references import require_reference_token
from labcourt.domain.m6_semantic_projection import M6ResolvedAcquisition
from labcourt.ports.m6_acquisition_authority import (
    M6ValidatedM4ReplayAuthoritySnapshot,
)
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity


def _controlled_case(source_case: object) -> Case:
    if not isinstance(source_case, Case):
        raise M6AcquisitionProjectionError(M6AcquisitionProjectionErrorCode.INVALID_ARGUMENT)
    try:
        controlled = Case.model_validate(
            source_case.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        raise M6AcquisitionProjectionError(
            M6AcquisitionProjectionErrorCode.INVALID_ARGUMENT
        ) from None
    if controlled != source_case:
        raise M6AcquisitionProjectionError(M6AcquisitionProjectionErrorCode.INVALID_ARGUMENT)
    return controlled


class ReadonlyM6AcquisitionAuthorityRepository:
    """Resolve acquisitions from one immutable, fully validated M4 snapshot."""

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: str | Path) -> None:
        self._snapshot = Path(snapshot).absolute()

    def load_validated_snapshot(
        self,
        run_id: str,
    ) -> M6ValidatedM4ReplayAuthoritySnapshot:
        controlled_run_id = require_reference_token(run_id, "M6 acquisition run_id")
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        authority = ReadonlyM4ArtifactRepository(
            self._snapshot,
            immutable=True,
        ).scan_replay_authority(controlled_run_id)
        if capture_m6_readonly_snapshot_identity(self._snapshot) != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_ACQUISITION_SCAN")
        return M6ValidatedM4ReplayAuthoritySnapshot(
            source_identity_sha256=before.identity_sha256,
            run_id=authority.run_id,
            documents=tuple(
                M6HistoricalAuthorityDocument(
                    kind=item.kind,
                    artifact_id=item.artifact_id,
                    canonical_document=item.canonical_document,
                )
                for item in authority.documents
            ),
        )

    def resolve(
        self,
        *,
        source_case: Case,
        locked_tool_results: tuple[M6LockedToolResultInput, ...],
    ) -> tuple[M6ResolvedAcquisition, ...]:
        controlled_case = _controlled_case(source_case)
        snapshot = self.load_validated_snapshot(controlled_case.run_id)
        return resolve_m6_locked_acquisitions(
            source_case=controlled_case,
            snapshot=snapshot,
            locked_tool_results=locked_tool_results,
        )


__all__ = ["ReadonlyM6AcquisitionAuthorityRepository"]
