from __future__ import annotations

import hashlib
import sqlite3
import traceback
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_output import (
    SQLiteM6UpgradeCandidateOutputBuilderV3,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_run_cut import (
    SQLiteM6UpgradeCandidateRunCutRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder import (
    SQLiteM6UpgradeWholeSampleRecordBuilderV3,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_upgrade_candidate_output import (
    build_m6_upgrade_candidate_output_inventory,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionStage,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import parse_frame_id
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
)
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
)
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedPerception,
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.ports.m6_upgrade_candidate_output import (
    M6UpgradeCandidateOutputError,
    M6UpgradeCandidateOutputFailureCode,
)
from labcourt.ports.pixels import PixelFrameProvider, RGB8Frame, rgb8_pixel_sha256
from labcourt.ports.vlm import RawModelResponseVerifier
from tests.integration import test_m3_sqlite_repository as m3_fixture
from tests.integration.test_m6_upgrade_candidate_run_cut_migration import (
    _run_cut_for_seal,
)
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3 import (
    BUSY_TIMEOUT_MS,
    _prepare_v3_m3_builder,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3 import (
    _builder as _case_whole_sample_builder,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3 import (
    _prepare_v3 as _prepare_case_v3,
)


class _FixedValidationReportProvider:
    def __init__(
        self,
        report: M5ArtifactValidationReport,
        *,
        fail_if_called: bool = False,
    ) -> None:
        self.report = report
        self.fail_if_called = fail_if_called
        self.calls: list[tuple[str, int, str]] = []

    def load_m6_upgrade_candidate_validation_report(
        self,
        candidate_run_id: str,
        audit_head_sequence: int,
        audit_head_hash: str,
    ) -> M5ArtifactValidationReport:
        self.calls.append((candidate_run_id, audit_head_sequence, audit_head_hash))
        if self.fail_if_called:
            raise AssertionError("durable candidate run-cut replay called its provider")
        return self.report


class _ForbiddenRawResponseVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify_raw_response(self, *_args: object, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("NO_CASE terminal construction must not read model raw response")


class _MappingPixelProvider:
    def __init__(
        self,
        frames: tuple[RGB8Frame, ...],
        events: list[str] | None = None,
    ) -> None:
        self.frames = {item.frame.frame_id: item for item in frames}
        self.requested_ids: list[str] = []
        self.events = events

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        if self.events is not None:
            self.events.append("pixel")
        self.requested_ids.append(frame_id)
        return self.frames[frame_id]


class _TrackingRawResponseVerifier:
    def __init__(
        self,
        events: list[str],
        *,
        fail: bool = False,
    ) -> None:
        self.events = events
        self.fail = fail
        self.calls = 0
        self._delegate = m3_fixture._RawVerifier()

    def verify_raw_response(self, *args: object, **kwargs: object) -> object:
        self.calls += 1
        self.events.append("raw")
        if self.fail:
            raise RuntimeError("private raw response C:\\people\\alice.bin")
        return self._delegate.verify_raw_response(*args, **kwargs)  # type: ignore[arg-type]


class _ExactArtifactVerifier:
    def __init__(self) -> None:
        self._closures: dict[str, tuple[M6UpgradePhysicalArtifactRef, ...]] = {}
        self.calls: list[M6UpgradeSampleExecutionRecordV2] = []

    def allow(self, record: M6UpgradeSampleExecutionRecordV2) -> None:
        self._closures[record.sample_execution_record_id] = tuple(
            link.artifact for link in record.artifact_links
        )

    def verify_m6_upgrade_sample_artifacts(
        self,
        record: M6UpgradeSampleExecutionRecordV2,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        self.calls.append(record)
        return self._closures[record.sample_execution_record_id]


@dataclass(frozen=True, slots=True)
class _NoCasePipeline:
    scope: M6UpgradeExecutionScopeAuthority
    observations: tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...]
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...]
    seal: M6UpgradeExecutionLedgerSealV2 | None
    rgb_frames: tuple[RGB8Frame, ...]
    pixels: _MappingPixelProvider


@dataclass(frozen=True, slots=True)
class _CasePipeline:
    scope: M6UpgradeExecutionScopeAuthority
    observations: tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...]
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...]
    seal: M6UpgradeExecutionLedgerSealV2
    selected_case: Case
    candidate_snapshot: M6CaseReplaySnapshot
    rgb_frames: tuple[RGB8Frame, ...]
    pixels: _MappingPixelProvider


@dataclass(frozen=True, slots=True)
class _M3CasePipeline:
    scope: M6UpgradeExecutionScopeAuthority
    observations: tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...]
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...]
    seal: M6UpgradeExecutionLedgerSealV2
    rgb_frames: tuple[RGB8Frame, ...]
    pixels: _MappingPixelProvider


def _commitment(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradePendingSampleCommitmentAuthority:
    raw = canonical_json(record.model_dump(mode="json"))
    payload = raw.encode("utf-8")
    return M6UpgradePendingSampleCommitmentAuthority(
        execution_scope_authority_id=record.execution_scope_authority_id,
        candidate_run_id=record.candidate_run_id,
        command_id=record.command_id,
        execution_dataset_snapshot_id=record.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=record.ledger_sequence,
        observation_authority_id=record.observation_authority_id,
        sample_execution_record=record,
        sample_execution_record_document_sha256=hashlib.sha256(payload).hexdigest(),
        sample_execution_record_size_bytes=len(payload),
    )


def _terminal_builder(
    database: Path,
    pixels: PixelFrameProvider,
    raw: RawModelResponseVerifier | None = None,
) -> SQLiteM6UpgradeCandidateOutputBuilderV3:
    verifier = raw if raw is not None else _ForbiddenRawResponseVerifier()
    return SQLiteM6UpgradeCandidateOutputBuilderV3(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=pixels,
        m3_raw_response_verifier=verifier,
        m4_raw_response_verifier=verifier,
    )


def _persist_run_cut(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
    seal: M6UpgradeExecutionLedgerSealV2,
    provider: _FixedValidationReportProvider,
) -> M6UpgradeCandidateRunCutAuthority:
    observed = SQLiteM6UpgradeCandidateRunCutRepository(
        database,
        BUSY_TIMEOUT_MS,
        validation_report_provider=provider,
    ).build_or_load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert observed == _run_cut_for_seal(scope, seal)
    return observed


def _whole_sample_builder(
    database: Path,
    pixels: _MappingPixelProvider,
    raw: _ForbiddenRawResponseVerifier,
) -> SQLiteM6UpgradeWholeSampleRecordBuilderV3:
    return SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=pixels,
        m3_raw_response_verifier=raw,
        m4_raw_response_verifier=raw,
    )


def _prepare_no_case_pipeline(
    database: Path,
    *,
    sealed: bool = True,
) -> _NoCasePipeline:
    scope, _source_records = _scope_and_no_case_records()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    evidence.register_run(scope.candidate_run_id, scope.candidate_manifest)

    frames: list[RGB8Frame] = []
    detections: list[Detection] = []
    detector = scope.candidate_manifest.models["detector"]
    for sequence, _entry in enumerate(scope.execution_dataset.entries):
        pixels = bytes(
            (
                sequence + 1,
                sequence + 2,
                sequence + 3,
                sequence + 4,
                sequence + 5,
                sequence + 6,
            )
        )
        frame = FrameRef(
            camera_id="terminal-v3-camera",
            stream_id=f"terminal-v3-stream-{sequence}",
            frame_index=sequence,
            fps_num=25,
            fps_den=1,
            width=2,
            height=1,
            content_sha256=rgb8_pixel_sha256(2, 1, pixels),
        )
        detection = Detection(
            detection_id=f"terminal-v3-detection-{sequence}",
            frame_id=frame.frame_id,
            label="person",
            bbox=BBoxXYXY(x1=0, y1=0, x2=1, y2=1),
            score=0.9,
            model_manifest_id=detector.model_manifest_id,
        )
        evidence.register_frame(scope.candidate_run_id, frame)
        evidence.register_detection(scope.candidate_run_id, detection)
        frames.append(RGB8Frame(frame=frame, pixels=pixels))
        detections.append(detection)

    pixel_provider = _MappingPixelProvider(tuple(frames))
    raw = _ForbiddenRawResponseVerifier()
    verifier = _ExactArtifactVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    observations_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitments_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    ledger.begin_execution(scope)
    record_builder = _whole_sample_builder(database, pixel_provider, raw)
    observations: list[M6UpgradeSampleExecutionObservationAuthorityV2] = []
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    for sequence, (entry, frame, detection) in enumerate(
        zip(scope.execution_dataset.entries, frames, detections, strict=True)
    ):
        observation = M6UpgradeSampleExecutionObservationAuthorityV2(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            execution_entry=entry,
            ledger_sequence=sequence,
            outcome=M6ReplayExecutionOutcome.NO_CASE,
            candidate_case=None,
            selected_case_audit_anchor=None,
            artifacts=tuple(
                sorted(
                    (
                        M6UpgradeObservedArtifactIdentity(
                            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                            kind=M6UpgradePhysicalArtifactKind.FRAME,
                            artifact_id=frame.frame.frame_id,
                            usage=M6UpgradeArtifactUsage.CONSUMED,
                        ),
                        M6UpgradeObservedArtifactIdentity(
                            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                            kind=M6UpgradePhysicalArtifactKind.DETECTION,
                            artifact_id=detection.detection_id,
                            usage=M6UpgradeArtifactUsage.PRODUCED,
                        ),
                    ),
                    key=lambda item: item.sort_key,
                )
            ),
            model_calls=(),
        )
        observations_repository.append(observation)
        record = record_builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        verifier.allow(record)
        commitment = _commitment(record)
        commitments_repository.append(commitment)
        assert ledger.append_committed_sample(commitment) == record
        observations.append(observation)
        records.append(record)

    assert raw.calls == 0
    seal = (
        ledger.seal(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        if sealed
        else None
    )
    return _NoCasePipeline(
        scope=scope,
        observations=tuple(observations),
        records=tuple(records),
        seal=seal,
        rgb_frames=tuple(frames),
        pixels=pixel_provider,
    )


def _prepare_sealed_case_pipeline(
    database: Path,
) -> _CasePipeline:
    scope, first_observation, fixture_pixels = _prepare_case_v3(
        database,
        case_replayed=True,
        include_case_semantic_frames=True,
    )
    binding = first_observation.candidate_case
    assert binding is not None
    assert first_observation.model_calls == ()
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT case_json, document_sha256
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (
                scope.candidate_run_id,
                binding.case_id,
                binding.case_revision,
            ),
        ).fetchone()
    assert row is not None and isinstance(row[0], str) and isinstance(row[1], str)
    selected_case = Case.model_validate_json(row[0])
    assert canonical_json(selected_case.model_dump(mode="json")) == row[0]
    assert hashlib.sha256(row[0].encode("utf-8")).hexdigest() == row[1]
    assert row[1] == binding.case_document_sha256
    assert selected_case.status.value == "CANDIDATE"
    assert selected_case.evidence_packs == ()
    assert selected_case.screening_results == ()
    assert selected_case.verdicts == ()
    assert selected_case.procedural_reviews == ()
    assert selected_case.alerts == ()
    assert selected_case.appeals == ()

    frame_ids = tuple(
        item.artifact_id
        for item in first_observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    detection_ids = tuple(
        item.artifact_id
        for item in first_observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    semantic_frames = tuple(
        fixture_pixels.frames[frame_id].frame for frame_id in sorted(frame_ids, key=parse_frame_id)
    )
    semantic_detections: list[Detection] = []
    with sqlite3.connect(database) as connection:
        for detection_id in detection_ids:
            detection_row = connection.execute(
                """
                SELECT document_json FROM detections
                WHERE run_id = ? AND detection_id = ?
                """,
                (scope.candidate_run_id, detection_id),
            ).fetchone()
            assert detection_row is not None and isinstance(detection_row[0], str)
            detection = Detection.model_validate_json(detection_row[0])
            assert canonical_json(detection.model_dump(mode="json")) == detection_row[0]
            semantic_detections.append(detection)

    source_identity_sha256 = hashlib.sha256(
        f"terminal-case-projection:{binding.case_binding_id}".encode()
    ).hexdigest()
    projection_context = M6VerifiedProjectionContext(
        case=selected_case,
        perception=M6ResolvedPerception(
            frames=semantic_frames,
            detections=tuple(
                sorted(
                    semantic_detections,
                    key=lambda item: (parse_frame_id(item.frame_id), item.detection_id),
                )
            ),
        ),
        historical_source_run_id=selected_case.run_id,
        historical_source_case_id=selected_case.case_id,
        historical_source_manifest_id=selected_case.manifest_id,
        model_reference_authority=M6CaseModelReferenceAuthority(
            source_identity_sha256=source_identity_sha256,
            run_id=selected_case.run_id,
            case_id=selected_case.case_id,
            manifest_id=selected_case.manifest_id,
            screening_bindings=(),
            verdict_bindings=(),
        ),
        procedural_gate_authority=M6CaseProceduralGateAuthority(
            source_identity_sha256=source_identity_sha256,
            run_id=selected_case.run_id,
            case_id=selected_case.case_id,
            manifest_id=selected_case.manifest_id,
            inputs=(),
        ),
    )
    candidate_snapshot = build_m6_case_replay_snapshot(
        context=projection_context,
        sample_id=scope.execution_dataset.entries[0].sample_id,
        source_case_revision=binding.case_revision,
    )
    assert tuple(root.stage for root in candidate_snapshot.stage_roots) == tuple(M6RegressionStage)
    assert candidate_snapshot.source_case_document_sha256 == binding.case_document_sha256

    pixels = _MappingPixelProvider(fixture_pixels.rgb_frames)
    verifier = _ExactArtifactVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    observations_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitments_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    ledger.begin_execution(scope)
    record_builder = _case_whole_sample_builder(database, pixels)
    observations: list[M6UpgradeSampleExecutionObservationAuthorityV2] = []
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    for sequence, entry in enumerate(scope.execution_dataset.entries):
        if sequence == 0:
            observation = first_observation
        else:
            payload = first_observation.model_dump(
                mode="python",
                exclude={"schema_version"},
                exclude_computed_fields=True,
            )
            payload.update(
                ledger_sequence=sequence,
                execution_entry=entry,
                outcome=M6ReplayExecutionOutcome.NO_CASE,
                candidate_case=None,
                selected_case_audit_anchor=None,
            )
            observation = M6UpgradeSampleExecutionObservationAuthorityV2(**payload)
            observations_repository.append(observation)
        record = record_builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        verifier.allow(record)
        commitment = _commitment(record)
        commitments_repository.append(commitment)
        ledger.append_committed_sample(commitment)
        observations.append(observation)
        records.append(record)
    seal = ledger.seal(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    return _CasePipeline(
        scope=scope,
        observations=tuple(observations),
        records=tuple(records),
        seal=seal,
        selected_case=selected_case,
        candidate_snapshot=candidate_snapshot,
        rgb_frames=fixture_pixels.rgb_frames,
        pixels=pixels,
    )


def _prepare_sealed_m3_case_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    include_case_semantic_frames: bool,
) -> _M3CasePipeline:
    fixture = _prepare_v3_m3_builder(
        tmp_path,
        monkeypatch,
        include_case_semantic_frames=include_case_semantic_frames,
    )
    database = tmp_path / "labcourt.sqlite3"
    scope = fixture.scope
    first_observation = fixture.observation
    execution_frame_identity = next(
        item
        for item in first_observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
        and item.artifact_id == fixture.frame.frame_id
    )
    pixels = _MappingPixelProvider(fixture.pixels.rgb_frames)
    verifier = _ExactArtifactVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    observations_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitments_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    ledger.begin_execution(scope)
    raw = m3_fixture._RawVerifier()
    record_builder = SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=pixels,
        m3_raw_response_verifier=raw,
        m4_raw_response_verifier=raw,  # type: ignore[arg-type]
    )
    observations: list[M6UpgradeSampleExecutionObservationAuthorityV2] = []
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    for sequence, entry in enumerate(scope.execution_dataset.entries):
        if sequence == 0:
            observation = first_observation
        else:
            payload = first_observation.model_dump(
                mode="python",
                exclude={"schema_version"},
                exclude_computed_fields=True,
            )
            payload.update(
                ledger_sequence=sequence,
                execution_entry=entry,
                outcome=M6ReplayExecutionOutcome.NO_CASE,
                candidate_case=None,
                selected_case_audit_anchor=None,
                artifacts=(execution_frame_identity,),
                model_calls=(),
            )
            observation = M6UpgradeSampleExecutionObservationAuthorityV2(**payload)
            observations_repository.append(observation)
        record = record_builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        verifier.allow(record)
        commitment = _commitment(record)
        commitments_repository.append(commitment)
        assert ledger.append_committed_sample(commitment) == record
        observations.append(observation)
        records.append(record)
    seal = ledger.seal(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    return _M3CasePipeline(
        scope=scope,
        observations=tuple(observations),
        records=tuple(records),
        seal=seal,
        rgb_frames=fixture.pixels.rgb_frames,
        pixels=pixels,
    )


def _expected_inventory(
    pipeline: _NoCasePipeline,
) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
    seal = pipeline.seal
    assert seal is not None
    cut = _run_cut_for_seal(pipeline.scope, seal)
    return build_m6_upgrade_candidate_output_inventory(
        execution_scope=pipeline.scope,
        execution_ledger=seal,
        run_cut=cut,
        observations=pipeline.observations,
        candidate_snapshots=(None,) * len(pipeline.observations),
        model_call_closures=((),) * len(pipeline.observations),
    )


def _expected_case_inventory(
    pipeline: _CasePipeline,
) -> M6UpgradeCandidateOutputInventoryAuthorityV3:
    return build_m6_upgrade_candidate_output_inventory(
        execution_scope=pipeline.scope,
        execution_ledger=pipeline.seal,
        run_cut=_run_cut_for_seal(pipeline.scope, pipeline.seal),
        observations=pipeline.observations,
        candidate_snapshots=(
            pipeline.candidate_snapshot,
            *(None for _item in pipeline.observations[1:]),
        ),
        model_call_closures=((),) * len(pipeline.observations),
    )


def _assert_failure(
    expected: M6UpgradeCandidateOutputFailureCode,
    builder: SQLiteM6UpgradeCandidateOutputBuilderV3,
    scope: M6UpgradeExecutionScopeAuthority,
) -> M6UpgradeCandidateOutputError:
    with pytest.raises(M6UpgradeCandidateOutputError) as raised:
        builder.build_terminal_inventory(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == expected
    return raised.value


def test_sealed_no_case_pipeline_builds_exact_canonical_inventory_v3_and_replays_cut(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_no_case_pipeline(database)
    seal = pipeline.seal
    assert seal is not None
    expected = _expected_inventory(pipeline)
    report = expected.candidate_run_cut.validation_report
    provider = _FixedValidationReportProvider(report)
    assert _persist_run_cut(database, pipeline.scope, seal, provider) == (
        expected.candidate_run_cut
    )
    raw = _ForbiddenRawResponseVerifier()
    pipeline.pixels.requested_ids.clear()

    observed = _terminal_builder(database, pipeline.pixels, raw).build_terminal_inventory(
        pipeline.scope.candidate_run_id,
        pipeline.scope.execution_scope_authority_id,
    )

    assert observed == expected
    assert observed.model_dump(mode="json") == expected.model_dump(mode="json")
    assert observed.execution_observations == pipeline.observations
    assert observed.execution_ledger == seal
    assert observed.candidate_cases == ()
    for observation, record, output in zip(
        pipeline.observations,
        pipeline.records,
        observed.outputs,
        strict=True,
    ):
        assert record.observation_authority_id == observation.observation_authority_id
        assert output.sample_execution_record_id == record.sample_execution_record_id
        assert output.execution_entry == observation.execution_entry
        assert output.candidate_snapshot is None
        assert output.model_calls == ()
        assert output.frames == tuple(
            link.artifact
            for link in record.artifact_links
            if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
        )
        assert output.detections == tuple(
            link.artifact
            for link in record.artifact_links
            if link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
        )
        assert output.artifact_count == len(record.artifact_links)
        assert output.execution_receipt.outcome == M6ReplayExecutionOutcome.NO_CASE
    assert provider.calls == [
        (
            pipeline.scope.candidate_run_id,
            seal.source_audit_head_sequence,
            seal.source_audit_head_hash,
        )
    ]
    assert raw.calls == 0
    assert pipeline.pixels.requested_ids == [item.frame.frame_id for item in pipeline.rgb_frames]

    pipeline.pixels.requested_ids.clear()
    forbidden = _FixedValidationReportProvider(report, fail_if_called=True)
    assert _persist_run_cut(database, pipeline.scope, seal, forbidden) == (
        expected.candidate_run_cut
    )
    retried = _terminal_builder(
        database,
        pipeline.pixels,
        raw,
    ).build_terminal_inventory(
        pipeline.scope.candidate_run_id,
        pipeline.scope.execution_scope_authority_id,
    )
    assert retried == observed
    assert forbidden.calls == []
    assert raw.calls == 0
    assert pipeline.pixels.requested_ids == [item.frame.frame_id for item in pipeline.rgb_frames]


def test_unsealed_ready_to_seal_state_rejects_before_pixels(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_no_case_pipeline(database, sealed=False)
    pipeline.pixels.requested_ids.clear()

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.LEDGER_NOT_SEALED,
        _terminal_builder(database, pipeline.pixels),
        pipeline.scope,
    )
    assert pipeline.pixels.requested_ids == []


def test_sealed_state_without_durable_run_cut_rejects_before_pixels(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_no_case_pipeline(database)
    pipeline.pixels.requested_ids.clear()

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.RUN_CUT_NOT_FOUND,
        _terminal_builder(database, pipeline.pixels),
        pipeline.scope,
    )
    assert pipeline.pixels.requested_ids == []


def test_basic_case_replayed_builds_exact_snapshot_inventory_v3(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_sealed_case_pipeline(database)
    expected = _expected_case_inventory(pipeline)
    report = expected.candidate_run_cut.validation_report
    provider = _FixedValidationReportProvider(report)
    _persist_run_cut(database, pipeline.scope, pipeline.seal, provider)
    raw = _ForbiddenRawResponseVerifier()
    pipeline.pixels.requested_ids.clear()

    observed = _terminal_builder(database, pipeline.pixels, raw).build_terminal_inventory(
        pipeline.scope.candidate_run_id,
        pipeline.scope.execution_scope_authority_id,
    )

    assert observed == expected
    assert observed.model_dump(mode="json") == expected.model_dump(mode="json")
    assert observed.execution_observations == pipeline.observations
    assert observed.execution_ledger == pipeline.seal
    assert len(observed.candidate_cases) == 1
    case_ref = observed.candidate_cases[0]
    assert case_ref.case_id == pipeline.selected_case.case_id
    assert case_ref.case_revision == pipeline.candidate_snapshot.source_case_revision
    assert case_ref.case_document_sha256 == (
        pipeline.candidate_snapshot.source_case_document_sha256
    )
    first = observed.outputs[0]
    assert first.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED
    assert first.candidate_snapshot == pipeline.candidate_snapshot
    assert first.candidate_snapshot.case_status == pipeline.selected_case.status
    assert tuple(root.stage for root in first.candidate_snapshot.stage_roots) == tuple(
        M6RegressionStage
    )
    assert first.model_calls == ()
    assert first.evidence_packs == ()
    assert all(item.candidate_snapshot is None for item in observed.outputs[1:])
    assert all(item.model_calls == () for item in observed.outputs)
    assert all(item.evidence_packs == () for item in observed.outputs)
    assert raw.calls == 0
    execution_frame_id = next(
        item.artifact_id
        for item in pipeline.observations[0].artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    assert pipeline.pixels.requested_ids.count(execution_frame_id) == len(pipeline.records)


def test_screening_case_builds_terminal_inventory_after_all_raw_before_any_pixel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_sealed_m3_case_pipeline(
        tmp_path,
        monkeypatch,
        include_case_semantic_frames=True,
    )
    cut = _run_cut_for_seal(pipeline.scope, pipeline.seal)
    _persist_run_cut(
        database,
        pipeline.scope,
        pipeline.seal,
        _FixedValidationReportProvider(cut.validation_report),
    )
    events: list[str] = []
    raw = _TrackingRawResponseVerifier(events)
    pipeline.pixels.events = events
    pipeline.pixels.requested_ids.clear()
    real_perception = SQLiteM6UpgradeCandidateOutputBuilderV3._resolved_perception

    def tracked_perception(*args: object, **kwargs: object) -> object:
        events.append("body")
        return real_perception(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        SQLiteM6UpgradeCandidateOutputBuilderV3,
        "_resolved_perception",
        staticmethod(tracked_perception),
    )

    observed = _terminal_builder(database, pipeline.pixels, raw).build_terminal_inventory(
        pipeline.scope.candidate_run_id,
        pipeline.scope.execution_scope_authority_id,
    )

    assert observed.execution_ledger == pipeline.seal
    assert observed.execution_observations == pipeline.observations
    assert len(observed.candidate_cases) == 1
    first = observed.outputs[0]
    assert first.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED
    assert first.candidate_snapshot is not None
    assert tuple(root.stage for root in first.candidate_snapshot.stage_roots) == tuple(
        M6RegressionStage
    )
    assert len(first.model_calls) == 1
    assert first.model_calls[0].provider_invoked is True
    assert len(first.evidence_packs) == 1
    assert first.artifact_count == len(pipeline.records[0].artifact_links)
    assert all(item.outcome == M6ReplayExecutionOutcome.NO_CASE for item in observed.outputs[1:])
    assert all(item.candidate_snapshot is None for item in observed.outputs[1:])
    assert all(item.model_calls == () for item in observed.outputs[1:])
    assert raw.calls == 1
    assert events.count("raw") == 1
    assert events.count("body") == len(pipeline.records)
    assert "pixel" in events
    assert all(item == "body" for item in events[: events.index("raw")])
    assert events.index("raw") < events.index("pixel")


def test_screening_case_missing_semantic_perception_rejects_before_raw_and_pixel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_sealed_m3_case_pipeline(
        tmp_path,
        monkeypatch,
        include_case_semantic_frames=False,
    )
    cut = _run_cut_for_seal(pipeline.scope, pipeline.seal)
    _persist_run_cut(
        database,
        pipeline.scope,
        pipeline.seal,
        _FixedValidationReportProvider(cut.validation_report),
    )
    events: list[str] = []
    raw = _TrackingRawResponseVerifier(events)
    pipeline.pixels.events = events
    pipeline.pixels.requested_ids.clear()

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        _terminal_builder(database, pipeline.pixels, raw),
        pipeline.scope,
    )

    assert raw.calls == 0
    assert events == []
    assert pipeline.pixels.requested_ids == []


def test_screening_raw_failure_rejects_before_every_pixel_and_is_payload_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_sealed_m3_case_pipeline(
        tmp_path,
        monkeypatch,
        include_case_semantic_frames=True,
    )
    cut = _run_cut_for_seal(pipeline.scope, pipeline.seal)
    _persist_run_cut(
        database,
        pipeline.scope,
        pipeline.seal,
        _FixedValidationReportProvider(cut.validation_report),
    )
    events: list[str] = []
    raw = _TrackingRawResponseVerifier(events, fail=True)
    pipeline.pixels.events = events
    pipeline.pixels.requested_ids.clear()

    error = _assert_failure(
        M6UpgradeCandidateOutputFailureCode.PHYSICAL_ARTIFACT_REJECTED,
        _terminal_builder(database, pipeline.pixels, raw),
        pipeline.scope,
    )

    assert raw.calls == 1
    assert events == ["raw"]
    assert pipeline.pixels.requested_ids == []
    assert "alice.bin" not in "".join(traceback.format_exception(error))


def test_tampered_selected_case_body_fails_closed_before_physical_reads(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_sealed_case_pipeline(database)
    report = _run_cut_for_seal(pipeline.scope, pipeline.seal).validation_report
    provider = _FixedValidationReportProvider(report)
    _persist_run_cut(database, pipeline.scope, pipeline.seal, provider)

    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'case_versions_no_update'
            """
        ).fetchone()
        binding = pipeline.observations[0].candidate_case
        assert binding is not None
        row = connection.execute(
            """
            SELECT case_json FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (
                pipeline.scope.candidate_run_id,
                binding.case_id,
                binding.case_revision,
            ),
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        assert row is not None and isinstance(row[0], str)
        connection.execute("DROP TRIGGER case_versions_no_update")
        tampered = row[0] + " "
        connection.execute(
            """
            UPDATE case_versions
            SET case_json = ?, document_sha256 = ?
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (
                tampered,
                hashlib.sha256(tampered.encode("utf-8")).hexdigest(),
                pipeline.scope.candidate_run_id,
                binding.case_id,
                binding.case_revision,
            ),
        )
        connection.execute(trigger_row[0])
        connection.commit()

    pipeline.pixels.requested_ids.clear()
    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.STORED_AUTHORITY_INVALID,
        _terminal_builder(database, pipeline.pixels),
        pipeline.scope,
    )
    assert pipeline.pixels.requested_ids == []


def test_later_sample_metadata_failure_rejects_before_any_pixel_read(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_no_case_pipeline(database)
    seal = pipeline.seal
    assert seal is not None
    report = _run_cut_for_seal(pipeline.scope, seal).validation_report
    _persist_run_cut(
        database,
        pipeline.scope,
        seal,
        _FixedValidationReportProvider(report),
    )
    later_detection_id = next(
        item.artifact_id
        for item in pipeline.observations[1].artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'detections_no_delete'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute("DROP TRIGGER detections_no_delete")
        connection.execute(
            "DELETE FROM detections WHERE run_id = ? AND detection_id = ?",
            (pipeline.scope.candidate_run_id, later_detection_id),
        )
        connection.execute(trigger_row[0])
        connection.commit()

    pipeline.pixels.requested_ids.clear()
    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.OBSERVATION_CLOSURE_MISMATCH,
        _terminal_builder(database, pipeline.pixels),
        pipeline.scope,
    )
    assert pipeline.pixels.requested_ids == []


def test_pixel_authority_drift_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_no_case_pipeline(database)
    expected = _expected_inventory(pipeline)
    first = pipeline.rgb_frames[0]
    changed_pixels = bytes(reversed(first.pixels))
    changed_frame = first.frame.model_copy(
        update={
            "content_sha256": rgb8_pixel_sha256(
                first.frame.width,
                first.frame.height,
                changed_pixels,
            )
        }
    )
    drifted = _MappingPixelProvider(
        (
            RGB8Frame(frame=changed_frame, pixels=changed_pixels),
            *pipeline.rgb_frames[1:],
        )
    )
    provider = _FixedValidationReportProvider(expected.candidate_run_cut.validation_report)
    seal = pipeline.seal
    assert seal is not None
    _persist_run_cut(database, pipeline.scope, seal, provider)

    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.PHYSICAL_ARTIFACT_REJECTED,
        _terminal_builder(database, drifted),
        pipeline.scope,
    )
    assert drifted.requested_ids == [first.frame.frame_id]


def test_tampered_stored_run_cut_body_is_rejected_before_pixels(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pipeline = _prepare_no_case_pipeline(database)
    expected = _expected_inventory(pipeline)
    provider = _FixedValidationReportProvider(expected.candidate_run_cut.validation_report)
    seal = pipeline.seal
    assert seal is not None
    _persist_run_cut(database, pipeline.scope, seal, provider)

    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_candidate_run_cuts_no_update'
            """
        ).fetchone()
        row = connection.execute(
            """
            SELECT run_cut_json FROM m6_upgrade_candidate_run_cuts
            WHERE run_id = ?
            """,
            (pipeline.scope.candidate_run_id,),
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        assert row is not None and isinstance(row[0], str)
        connection.execute("DROP TRIGGER m6_upgrade_candidate_run_cuts_no_update")
        tampered = row[0] + " "
        encoded = tampered.encode("utf-8")
        connection.execute(
            """
            UPDATE m6_upgrade_candidate_run_cuts
            SET run_cut_json = ?, document_sha256 = ?, size_bytes = ?
            WHERE run_id = ?
            """,
            (
                tampered,
                hashlib.sha256(encoded).hexdigest(),
                len(encoded),
                pipeline.scope.candidate_run_id,
            ),
        )
        connection.execute(trigger_row[0])
        connection.commit()

    pipeline.pixels.requested_ids.clear()
    _assert_failure(
        M6UpgradeCandidateOutputFailureCode.STORED_AUTHORITY_INVALID,
        _terminal_builder(database, pipeline.pixels),
        pipeline.scope,
    )
    assert pipeline.pixels.requested_ids == []


def test_public_failure_is_payload_free(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    pixels = _MappingPixelProvider(())
    builder = _terminal_builder(database, pixels)
    forbidden = "unsafe candidate C:\\private\\alice.png"

    with pytest.raises(M6UpgradeCandidateOutputError) as raised:
        builder.build_terminal_inventory(forbidden, "f" * 64)

    error = raised.value
    assert error.reason_code == M6UpgradeCandidateOutputFailureCode.INVALID_ARGUMENT
    assert error.args == ("M6 upgrade candidate output build failed: INVALID_ARGUMENT",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert error.__cause__ is None
    assert error.__context__ is None
    assert forbidden not in "".join(traceback.format_exception(error))
    public_frames = []
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_code.co_name == "build_terminal_inventory":
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    assert "self" not in public_frames[0].f_locals
    assert "candidate_run_id" not in public_frames[0].f_locals
    assert "execution_scope_authority_id" not in public_frames[0].f_locals
