from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_upgrade_candidate_observation_producer import (
    M6PrecomputedNoCaseObservationProducerV3,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Status,
)
from tests.unit.test_m6_regression_execution_source_catalog import (
    _catalog,
    _execution_scope,
)

BUSY_TIMEOUT_MS = 2_000


class _Materializer:
    def __init__(
        self,
        evidence: SQLiteEvidenceRepository,
        candidate_run_id: str,
        frame: FrameRef,
    ) -> None:
        self.evidence = evidence
        self.candidate_run_id = candidate_run_id
        self.frame = frame
        self.calls = 0

    def materialize_next_perception(
        self,
        candidate_run_id: str,
        _execution_scope_authority_id: str,
    ) -> M6ResolvedPerception:
        assert candidate_run_id == self.candidate_run_id
        self.calls += 1
        self.evidence.register_frame(candidate_run_id, self.frame)
        return M6ResolvedPerception(frames=(self.frame,))


def test_published_blind_catalog_produces_one_exact_durable_v3_observation(
    tmp_path: Path,
) -> None:
    built = _catalog()
    catalog_root = tmp_path / "candidate-catalog"
    stored = M6RegressionExecutionSourceCatalogPublisher(catalog_root).publish(
        built.execution_source_catalog,
        built.execution_source_catalog_document,
    )
    scope = _execution_scope(stored.source_catalog, stored.content_sha256)

    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    evidence.register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observations.begin_execution(scope)
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)
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
    materializer = _Materializer(evidence, scope.candidate_run_id, frame)
    producer = M6PrecomputedNoCaseObservationProducerV3(
        ledger_repository=ledger,
        source_catalog_provider=ReadonlyM6RegressionExecutionSourceCatalogStore(catalog_root),
        perception_materializer=materializer,
    )

    produced = producer.produce_next_observation(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    persisted = observations.append(produced)

    resumed = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert persisted == produced
    assert (
        observations.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
        == produced
    )
    assert resumed.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT
    assert resumed.pending_observation == produced
    assert resumed.pending_commitment is None
    assert produced.model_calls == ()
    assert produced.candidate_case is None
    assert materializer.calls == 1
    assert evidence.load_frame(scope.candidate_run_id, frame.frame_id) == frame
    assert {
        item.artifact_id
        for item in produced.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
    } == {item.frame_id for item in closure.frames}
    assert {
        item.artifact_id
        for item in produced.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.DETECTION
    } == {item.detection_id for item in closure.detections}
