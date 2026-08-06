from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.readonly_m6_historical_retrieval import (
    ReadonlyM6HistoricalRetrievalCutRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_historical_retrieval_cut import (
    assemble_m6_historical_retrieval_cut,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_replay_locked import (
    M6LockedRetrievalOutcomeKind,
    M6ReplayAuthorityKind,
)
from tests.integration.test_m5_precedent_exposure_sqlite import _proposed, _runtime


def test_repository_assembles_exact_cut_from_one_private_snapshot(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    runtime.committer.commit(_proposed(runtime))
    exposure = runtime.committer.load_exposure(
        runtime.prepared.session.run_id,
        runtime.prepared.cycle_scope.cycle_id,
    )
    assert exposure is not None

    with readonly_sqlite_snapshot(runtime.database) as snapshot:
        repository = ReadonlyM6HistoricalRetrievalCutRepository(
            snapshot,
            config=runtime.config,
        )
        authorities = repository.load_validated_snapshots(runtime.prepared.session.run_id)
        cut = assemble_m6_historical_retrieval_cut(
            source_case=runtime.prepared.source_case.case,
            snapshots=authorities,
        )

    assert {document.kind for document in authorities.m4_documents} == {
        M4ProjectionArtifactKind.HEARING_CYCLE,
        M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
    }
    assert {document.kind for document in authorities.m5_documents} == {
        M5AuthorityKind.PRECEDENT_EXPOSURE
    }
    assert cut.retrieval_cycle_count == 1
    item = cut.retrieval_cycles[0]
    assert item.cycle_scope_id == runtime.prepared.cycle_scope.cycle_id
    assert item.outcome == M6LockedRetrievalOutcomeKind.SUCCESS
    assert item.authority_ref.kind == M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE
    assert item.authority_ref.artifact_id == exposure.exposure_id
