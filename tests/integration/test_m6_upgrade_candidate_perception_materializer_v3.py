from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.adapters.storage.m6_source_authority_store import M6SourceAuthorityPublisher
from labcourt.adapters.storage.m6_upgrade_candidate_source_seal import (
    ReadonlyM6UpgradeCandidateSourceSealProvider,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_source_authority_builder import M6SealedSourceBundle
from labcourt.application.m6_upgrade_candidate_perception_materializer import (
    M6PrecomputedCandidatePerceptionMaterializerV3,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.m6_upgrade_candidate_perception_materializer import (
    M6UpgradeCandidatePerceptionMaterializerError,
    M6UpgradeCandidatePerceptionMaterializerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Status,
)
from tests.unit.test_m6_regression_execution_source_catalog import (
    _catalog,
    _execution_scope,
)
from tests.unit.test_m6_regression_source_catalog import _sealed_source
from tests.unit.test_m6_source_authority import _bundle

BUSY_TIMEOUT_MS = 2_000


class _SourcePerception:
    def __init__(self, perception: M6ResolvedPerception) -> None:
        self.perception = perception
        self.calls = 0

    def assemble(self, _closure: object) -> M6ResolvedPerception:
        self.calls += 1
        return self.perception


class _CrashAfterFrameWriter:
    def __init__(self, delegate: SQLiteEvidenceRepository) -> None:
        self.delegate = delegate

    def load_run_manifest(self, run_id: str):  # type: ignore[no-untyped-def]
        return self.delegate.load_run_manifest(run_id)

    def register_frame(self, run_id: str, frame: FrameRef) -> None:
        self.delegate.register_frame(run_id, frame)
        raise RuntimeError("simulated crash after durable Frame append")

    def register_detection(self, run_id: str, detection: object) -> None:
        raise AssertionError((run_id, detection))


def _sealed_bundle() -> tuple[object, object, M6SealedSourceBundle]:
    source_scope, source = _sealed_source()
    return (
        source_scope,
        source,
        M6SealedSourceBundle(
            replay_input_closure=source.replay_input_closure,
            replay_input_authority=source.replay_input_authority,
            source_validation_report=source.source_validation_report,
            source_case=source.source_case,
            source_manifest=source.source_manifest,
            seal=source.source_seal,
            replay_input_closure_document=source.replay_input_closure_document,
            replay_input_authority_document=source.replay_input_authority_document,
            source_validation_report_document=source.source_validation_report_document,
            source_case_document=source.source_case_document,
            source_manifest_document=source.source_manifest_document,
        ),
    )


def test_real_candidate_sqlite_recovers_partial_frame_materialization_exactly(
    tmp_path: Path,
) -> None:
    source_scope, source, sealed = _sealed_bundle()
    source_root = tmp_path / "source-authority"
    M6SourceAuthorityPublisher(source_root).publish(sealed, config=_bundle().config)

    built = _catalog()
    assert built.execution_source_catalog.entries[0].source_seal_id == source.source_seal.seal_id
    catalog_root = tmp_path / "candidate-catalog"
    stored = M6RegressionExecutionSourceCatalogPublisher(catalog_root).publish(
        built.execution_source_catalog,
        built.execution_source_catalog_document,
    )
    assert source_scope.source_run_id == source.replay_input_closure.source_run_id
    scope = _execution_scope(stored.source_catalog, stored.content_sha256)

    closure = stored.source_catalog.entries[0].replay_input_closure
    camera_id, stream_id, frame_index = parse_frame_id(closure.frames[0].frame_id)
    frame = FrameRef(
        camera_id=camera_id,
        stream_id=stream_id,
        frame_index=frame_index,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256=closure.frames[0].content_sha256,
    )
    source_perception = _SourcePerception(M6ResolvedPerception(frames=(frame,)))

    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    evidence.register_run(scope.candidate_run_id, scope.candidate_manifest)
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)
    ledger.begin_execution(scope)
    catalogs = ReadonlyM6RegressionExecutionSourceCatalogStore(catalog_root)
    seals = ReadonlyM6UpgradeCandidateSourceSealProvider(source_root)

    crashing = M6PrecomputedCandidatePerceptionMaterializerV3(
        ledger_repository=ledger,
        source_catalog_provider=catalogs,
        source_seal_provider=seals,
        source_perception_reader=source_perception,
        candidate_perception_writer=_CrashAfterFrameWriter(evidence),  # type: ignore[arg-type]
    )
    with pytest.raises(M6UpgradeCandidatePerceptionMaterializerError) as failed:
        crashing.materialize_next_perception(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert failed.value.reason_code == (
        M6UpgradeCandidatePerceptionMaterializerFailureCode.STORAGE_REJECTED
    )
    assert (
        ledger.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ).status
        == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION
    )
    assert evidence.load_frame(scope.candidate_run_id, frame.frame_id) == frame

    recovered = M6PrecomputedCandidatePerceptionMaterializerV3(
        ledger_repository=ledger,
        source_catalog_provider=catalogs,
        source_seal_provider=seals,
        source_perception_reader=source_perception,
        candidate_perception_writer=evidence,
    ).materialize_next_perception(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert recovered == M6ResolvedPerception(frames=(frame,))
    assert evidence.load_frame(scope.candidate_run_id, frame.frame_id) == frame
    assert source_perception.calls == 2
