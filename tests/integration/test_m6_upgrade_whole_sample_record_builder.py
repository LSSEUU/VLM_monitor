from __future__ import annotations

import hashlib
import sqlite3
import traceback
from dataclasses import replace
from pathlib import Path

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_case_document as case_document_module
import labcourt.adapters.storage._sqlite_m6_upgrade_frame_document as frame_document_module
import labcourt.adapters.storage._sqlite_m6_upgrade_physical_documents as physical_document_module
import labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder as builder_module
import labcourt.application.m6_upgrade_whole_sample_record as record_module
from labcourt.adapters.storage._sqlite_m6_live_read_cut import M6LiveReader
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseDocumentError,
    M6SQLiteCaseDocumentFailureCode,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_frame_document import (
    M6SQLiteFrameDocumentError,
    M6SQLiteFrameDocumentFailureCode,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_physical_documents import (
    M6SQLitePhysicalDocumentError,
    M6SQLitePhysicalDocumentFailureCode,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    SQLiteM6UpgradeExecutionLedgerV2Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation import (
    SQLiteM6UpgradeExecutionObservationRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment import (
    SQLiteM6UpgradePendingSampleCommitmentRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder import (
    SQLiteM6UpgradeWholeSampleRecordBuilder,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthority,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
)
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256
from tests.integration.test_m2_evidence_builder import _event
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)
from tests.integration.test_m6_upgrade_execution_ledger_v2_repository import (
    MutableExactSampleArtifactVerifier,
)

BUSY_TIMEOUT_MS = 2_000


class _PixelProvider:
    def __init__(self, frame: RGB8Frame) -> None:
        self.frame = frame
        self.requested_ids: list[str] = []

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        self.requested_ids.append(frame_id)
        return self.frame


class _FailingPixelProvider(_PixelProvider):
    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        self.requested_ids.append(frame_id)
        raise RuntimeError("SECRET C:\\people\\alice.png")


class _UnusedPixelProvider:
    def __init__(self) -> None:
        self.requested_ids: list[str] = []

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        self.requested_ids.append(frame_id)
        raise AssertionError("invalid public identity must fail before Pixel")


class _UnusedRawVerifier:
    def verify_raw_response(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("NO_CASE must not invoke a model raw verifier")


def _fixture(
    database: Path,
    *,
    case_replayed: bool = False,
    model_calls: tuple[M6UpgradeObservedModelCall, ...] = (),
    extra_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...] = (),
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionObservationAuthority,
    _PixelProvider,
]:
    scope, _records = _scope_and_no_case_records()
    pixels = bytes((1, 2, 3, 4, 5, 6))
    frame = FrameRef(
        camera_id="camera-builder-live",
        stream_id="stream-builder-live",
        frame_index=0,
        fps_num=25,
        fps_den=1,
        width=2,
        height=1,
        content_sha256=rgb8_pixel_sha256(2, 1, pixels),
    )
    detector = scope.candidate_manifest.models["detector"]
    detection = Detection(
        detection_id="detection-builder-live",
        frame_id=frame.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=0, y1=0, x2=1, y2=1),
        score=0.9,
        model_manifest_id=detector.model_manifest_id,
    )
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    evidence.register_run(scope.candidate_run_id, scope.candidate_manifest)
    evidence.register_frame(scope.candidate_run_id, frame)
    evidence.register_detection(scope.candidate_run_id, detection)
    observation_repository = SQLiteM6UpgradeExecutionObservationRepository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observation_repository.begin_execution(scope)
    candidate_case: M6UpgradeCandidateCaseBinding | None = None
    outcome = M6ReplayExecutionOutcome.NO_CASE
    if case_replayed:
        snapshot = evidence.create_or_get_case(
            scope.candidate_run_id,
            _event(scope.candidate_manifest),
        )
        audit = evidence.list_audit_entries(scope.candidate_run_id)[-1]
        case_raw = canonical_json(snapshot.case.model_dump(mode="json"))
        case_sha256 = hashlib.sha256(case_raw.encode("utf-8")).hexdigest()
        assert audit.after_sha256 == case_sha256
        candidate_case = M6UpgradeCandidateCaseBinding(
            case_id=snapshot.case.case_id,
            case_revision=snapshot.revision,
            case_document_sha256=case_sha256,
            case_audit_sequence=audit.sequence,
            case_audit_entry_hash=audit.entry_hash,
        )
        outcome = M6ReplayExecutionOutcome.CASE_REPLAYED
    observation = M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        ledger_sequence=0,
        outcome=outcome,
        candidate_case=candidate_case,
        artifacts=tuple(
            sorted(
                (
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                        kind=M6UpgradePhysicalArtifactKind.FRAME,
                        artifact_id=frame.frame_id,
                        usage=M6UpgradeArtifactUsage.CONSUMED,
                    ),
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                        kind=M6UpgradePhysicalArtifactKind.DETECTION,
                        artifact_id=detection.detection_id,
                        usage=M6UpgradeArtifactUsage.PRODUCED,
                    ),
                    *extra_artifacts,
                ),
                key=lambda item: item.sort_key,
            )
        ),
        model_calls=model_calls,
    )
    observation_repository.append(observation)
    return scope, observation, _PixelProvider(RGB8Frame(frame=frame, pixels=pixels))


def _builder(database: Path, pixels: _PixelProvider) -> SQLiteM6UpgradeWholeSampleRecordBuilder:
    raw = _UnusedRawVerifier()
    return SQLiteM6UpgradeWholeSampleRecordBuilder(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=pixels,
        m3_raw_response_verifier=raw,  # type: ignore[arg-type]
        m4_raw_response_verifier=raw,  # type: ignore[arg-type]
    )


def _commitment(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradePendingSampleCommitmentAuthority:
    raw = canonical_json(record.model_dump(mode="json"))
    return M6UpgradePendingSampleCommitmentAuthority(
        execution_scope_authority_id=record.execution_scope_authority_id,
        candidate_run_id=record.candidate_run_id,
        command_id=record.command_id,
        execution_dataset_snapshot_id=record.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=record.ledger_sequence,
        observation_authority_id=record.observation_authority_id,
        sample_execution_record=record,
        sample_execution_record_document_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        sample_execution_record_size_bytes=len(raw.encode("utf-8")),
    )


def test_no_case_builder_derives_frame_detection_and_chain_from_one_live_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _fixture(database)
    connection_ids: list[int] = []
    reader_handles: list[object] = []
    real_state = builder_module.load_m6_upgrade_v2_state_from_connection  # type: ignore[attr-defined]
    real_frame = builder_module.plan_m6_sqlite_frame_physical_identity  # type: ignore[attr-defined]
    real_document = builder_module.resolve_m6_sqlite_canonical_physical_identity  # type: ignore[attr-defined]

    def tracked_state(*args: object, **kwargs: object) -> object:
        reader_handles.append(args[1])
        connection_ids.append(id(args[1]))
        return real_state(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_frame(*args: object, **kwargs: object) -> object:
        reader_handles.append(kwargs["connection"])
        connection_ids.append(id(kwargs["connection"]))
        return real_frame(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_document(*args: object, **kwargs: object) -> object:
        reader_handles.append(kwargs["connection"])
        connection_ids.append(id(kwargs["connection"]))
        return real_document(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builder_module, "load_m6_upgrade_v2_state_from_connection", tracked_state)
    monkeypatch.setattr(builder_module, "plan_m6_sqlite_frame_physical_identity", tracked_frame)
    monkeypatch.setattr(
        builder_module,
        "resolve_m6_sqlite_canonical_physical_identity",
        tracked_document,
    )

    record = _builder(database, pixels).build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert record.ledger_sequence == 0
    assert record.previous_ledger_entry_hash == M6_UPGRADE_LEDGER_GENESIS_HASH
    assert record.execution_entry == scope.execution_dataset.entries[0]
    assert record.observation_authority_id == observation.observation_authority_id
    assert pixels.requested_ids == [observation.artifacts[0].artifact_id]
    assert tuple(link.ordinal for link in record.artifact_links) == (0, 1)
    frame_link, detection_link = record.artifact_links
    assert frame_link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    assert frame_link.usage == M6UpgradeArtifactUsage.CONSUMED
    assert detection_link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
    assert detection_link.usage == M6UpgradeArtifactUsage.PRODUCED
    assert detection_link.artifact.container_id == frame_link.artifact.artifact_id
    assert len(connection_ids) == 3
    assert len(set(connection_ids)) == 1
    assert all(isinstance(handle, M6LiveReader) for handle in reader_handles)


def test_aggregate_physical_budget_rejects_before_first_pixel_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database)
    monkeypatch.setattr(builder_module, "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES", 1)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
    )
    assert pixels.requested_ids == []


def test_record_budget_rejects_the_complete_plan_before_first_pixel_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database)
    monkeypatch.setattr(
        record_module,
        "MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES",
        1,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.RECORD_TOO_LARGE
    )
    assert pixels.requested_ids == []


def test_case_replayed_builder_closes_case_and_base_artifacts_on_one_live_cut(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _fixture(database, case_replayed=True)
    connection_ids: list[int] = []
    reader_handles: list[object] = []
    call_order: list[str] = []
    real_state = builder_module.load_m6_upgrade_v2_state_from_connection  # type: ignore[attr-defined]
    real_case = builder_module.read_m6_sqlite_case_authority  # type: ignore[attr-defined]
    real_frame = builder_module.plan_m6_sqlite_frame_physical_identity  # type: ignore[attr-defined]
    real_document = builder_module.resolve_m6_sqlite_canonical_physical_identity  # type: ignore[attr-defined]
    real_pixel = pixels.read_rgb8

    def tracked_state(*args: object, **kwargs: object) -> object:
        call_order.append("state")
        reader_handles.append(args[1])
        connection_ids.append(id(args[1]))
        return real_state(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_case(*args: object, **kwargs: object) -> object:
        call_order.append("case")
        reader_handles.append(kwargs["connection"])
        connection_ids.append(id(kwargs["connection"]))
        return real_case(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_frame(*args: object, **kwargs: object) -> object:
        call_order.append("frame")
        reader_handles.append(kwargs["connection"])
        connection_ids.append(id(kwargs["connection"]))
        return real_frame(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_document(*args: object, **kwargs: object) -> object:
        call_order.append("detection")
        reader_handles.append(kwargs["connection"])
        connection_ids.append(id(kwargs["connection"]))
        return real_document(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_pixel(frame_id: str) -> RGB8Frame:
        call_order.append("pixel")
        return real_pixel(frame_id)

    monkeypatch.setattr(builder_module, "load_m6_upgrade_v2_state_from_connection", tracked_state)
    monkeypatch.setattr(builder_module, "read_m6_sqlite_case_authority", tracked_case)
    monkeypatch.setattr(builder_module, "plan_m6_sqlite_frame_physical_identity", tracked_frame)
    monkeypatch.setattr(
        builder_module,
        "resolve_m6_sqlite_canonical_physical_identity",
        tracked_document,
    )
    monkeypatch.setattr(pixels, "read_rgb8", tracked_pixel)

    record = _builder(database, pixels).build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert record.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED
    assert record.candidate_case == observation.candidate_case
    assert record.observation_authority_id == observation.observation_authority_id
    assert pixels.requested_ids == [observation.artifacts[0].artifact_id]
    assert len(connection_ids) == 4
    assert len(set(connection_ids)) == 1
    assert all(isinstance(handle, M6LiveReader) for handle in reader_handles)
    assert call_order == ["state", "case", "frame", "detection", "pixel"]


@pytest.mark.parametrize(
    ("case_replayed", "expected_outcome"),
    (
        (False, M6ReplayExecutionOutcome.NO_CASE),
        (True, M6ReplayExecutionOutcome.CASE_REPLAYED),
    ),
)
def test_builder_uses_sealed_reader_document_length_fallback_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_replayed: bool,
    expected_outcome: M6ReplayExecutionOutcome,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database, case_replayed=case_replayed)
    monkeypatch.setattr(case_document_module, "_USE_SQLITE_OCTET_LENGTH", False)
    monkeypatch.setattr(frame_document_module, "_USE_SQLITE_OCTET_LENGTH", False)
    monkeypatch.setattr(physical_document_module, "_USE_SQLITE_OCTET_LENGTH", False)

    record = _builder(database, pixels).build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert record.outcome == expected_outcome
    assert tuple(link.artifact.kind for link in record.artifact_links) == (
        M6UpgradePhysicalArtifactKind.FRAME,
        M6UpgradePhysicalArtifactKind.DETECTION,
    )


@pytest.mark.parametrize(
    ("source_code", "expected"),
    (
        (
            M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH,
            M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH,
        ),
        (
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
            M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID,
        ),
        (
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
            M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID,
        ),
    ),
)
def test_case_authority_drift_is_typed_before_physical_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_code: M6SQLiteCaseDocumentFailureCode,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database, case_replayed=True)

    def reject_case(*_args: object, **_kwargs: object) -> object:
        raise M6SQLiteCaseDocumentError(source_code)

    monkeypatch.setattr(builder_module, "read_m6_sqlite_case_authority", reject_case)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == expected
    assert pixels.requested_ids == []


def test_missing_current_case_audit_head_is_storage_corruption_before_pixels(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database, case_replayed=True)
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("DROP TRIGGER runs_m6_audit_head_matches_entry")
        connection.execute(
            """
            UPDATE runs
            SET revision = revision + 1,
                audit_head_sequence = audit_head_sequence + 1,
                audit_head_hash = ?
            WHERE run_id = ?
            """,
            ("f" * 64, scope.candidate_run_id),
        )
    finally:
        connection.close()

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )
    assert pixels.requested_ids == []


@pytest.mark.parametrize(
    "unopened_route",
    (
        "model_call",
        "evidence_pack",
        "tool_execution_manifest",
        "tool_result",
        "embedding",
        "precedent_exposure",
    ),
)
def test_unopened_case_routes_are_rejected_without_pixel_or_raw(
    tmp_path: Path,
    unopened_route: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    model_calls: tuple[M6UpgradeObservedModelCall, ...] = ()
    extra_artifacts: tuple[M6UpgradeObservedArtifactIdentity, ...] = ()
    if unopened_route == "model_call":
        model_calls = (
            M6UpgradeObservedModelCall(
                request_id="c" * 64,
                layer=M6LockedModelCallLayer.SCREENING,
                role=M6LockedModelRole.SCREENING,
                attempt_index=0,
                result_kind=M6LockedModelCallResultKind.FAILURE,
                provider_invoked=False,
            ),
        )
    if unopened_route != "model_call":
        route = {
            "evidence_pack": (
                M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
            ),
            "tool_execution_manifest": (
                M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
            ),
            "tool_result": (
                M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
                M6UpgradePhysicalArtifactKind.TOOL_RESULT,
            ),
            "embedding": (
                M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                M6UpgradePhysicalArtifactKind.EMBEDDING,
            ),
            "precedent_exposure": (
                M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
                M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
            ),
        }[unopened_route]
        extra_artifacts = (
            M6UpgradeObservedArtifactIdentity(
                source=route[0],
                kind=route[1],
                artifact_id=f"case-builder-unopened-{unopened_route}",
                usage=M6UpgradeArtifactUsage.PRODUCED,
            ),
        )
    scope, _observation, pixels = _fixture(
        database,
        case_replayed=True,
        model_calls=model_calls,
        extra_artifacts=extra_artifacts,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED
    assert pixels.requested_ids == []


def test_case_pending_commitment_retry_revalidates_case_and_pixels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database, case_replayed=True)
    case_reads = 0
    real_case = builder_module.read_m6_sqlite_case_authority  # type: ignore[attr-defined]

    def tracked_case(*args: object, **kwargs: object) -> object:
        nonlocal case_reads
        case_reads += 1
        return real_case(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builder_module, "read_m6_sqlite_case_authority", tracked_case)
    builder = _builder(database, pixels)
    first = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(_commitment(first))

    retry = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert retry == first
    assert case_reads == 2
    assert pixels.requested_ids == [
        first.artifact_links[0].artifact.artifact_id,
        first.artifact_links[0].artifact.artifact_id,
    ]


def test_duplicate_prior_case_is_rejected_before_second_pixel(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _fixture(database, case_replayed=True)
    builder = _builder(database, pixels)
    first = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    commitment = SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(_commitment(first))
    verifier = MutableExactSampleArtifactVerifier((first,))
    ledger = SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    assert ledger.append_committed_sample(commitment) == first
    assert observation.candidate_case is not None
    second = M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[1],
        ledger_sequence=1,
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=observation.candidate_case,
        artifacts=observation.artifacts,
        model_calls=(),
    )
    SQLiteM6UpgradeExecutionObservationRepository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(second)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_PREFIX_MISMATCH
    )
    assert pixels.requested_ids == [first.artifact_links[0].artifact.artifact_id]


def test_no_case_can_follow_a_committed_case_without_erasing_case_history(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _fixture(database, case_replayed=True)
    builder = _builder(database, pixels)
    first = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    commitment = SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(_commitment(first))
    ledger = SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier((first,)),
    )
    assert ledger.append_committed_sample(commitment) == first
    second_observation = M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[1],
        ledger_sequence=1,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifacts=observation.artifacts,
        model_calls=(),
    )
    SQLiteM6UpgradeExecutionObservationRepository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(second_observation)

    second = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert second.ledger_sequence == 1
    assert second.previous_ledger_entry_hash == first.sample_execution_record_id
    assert second.outcome == M6ReplayExecutionOutcome.NO_CASE
    assert second.candidate_case is None
    assert pixels.requested_ids == [
        first.artifact_links[0].artifact.artifact_id,
        second.artifact_links[0].artifact.artifact_id,
    ]


@pytest.mark.parametrize(
    ("field", "forged_value"),
    (
        ("sequence", 1),
        ("observation_authority_id", "f" * 64),
        ("pending_sample_commitment_authority_id", "d" * 64),
        ("previous_ledger_entry_hash", "e" * 64),
    ),
)
def test_selector_and_reader_drift_is_rejected_before_pixels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    forged_value: object,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database)
    real_select = builder_module.select_m6_upgrade_v2_pending  # type: ignore[attr-defined]

    def drifted_selection(*args: object, **kwargs: object) -> object:
        selected = real_select(*args, **kwargs)  # type: ignore[arg-type]
        return replace(selected, **{field: forged_value})

    monkeypatch.setattr(builder_module, "select_m6_upgrade_v2_pending", drifted_selection)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert (
        raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
    )
    assert pixels.requested_ids == []


def test_durable_commitment_retry_reverifies_pixels_and_requires_exact_record(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database)
    builder = _builder(database, pixels)
    first = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(_commitment(first))

    retry = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert retry == first
    assert pixels.requested_ids == [
        first.artifact_links[0].artifact.artifact_id,
        first.artifact_links[0].artifact.artifact_id,
    ]

    changed_pixels = bytes((6, 5, 4, 3, 2, 1))
    original_frame = pixels.frame.frame
    changed_frame = original_frame.model_copy(
        update={
            "content_sha256": rgb8_pixel_sha256(
                original_frame.width,
                original_frame.height,
                changed_pixels,
            )
        }
    )
    pixels.frame = RGB8Frame(frame=changed_frame, pixels=changed_pixels)
    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as drift:
        builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert drift.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED
    )
    loaded = SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    ).load(scope.candidate_run_id, scope.execution_scope_authority_id, 0)
    assert loaded.sample_execution_record == first


def test_pending_commitment_requires_full_planned_record_before_second_pixel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database)
    builder = _builder(database, pixels)
    first = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    commitments = SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    )
    durable = commitments.append(_commitment(first))
    real_resolve = builder_module.resolve_m6_sqlite_canonical_physical_identity  # type: ignore[attr-defined]

    def drifted_detection(*args: object, **kwargs: object) -> object:
        resolved = real_resolve(*args, **kwargs)  # type: ignore[arg-type]
        changed_ref = resolved.artifact_ref.model_copy(
            update={"size_bytes": resolved.artifact_ref.size_bytes + 1}
        )
        return replace(resolved, artifact_ref=changed_ref)

    monkeypatch.setattr(
        builder_module,
        "resolve_m6_sqlite_canonical_physical_identity",
        drifted_detection,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert (
        raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )
    assert pixels.requested_ids == [first.artifact_links[0].artifact.artifact_id]
    assert (
        commitments.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
        == durable
    )


def test_public_builder_redacts_pixel_provider_failure_payload(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _fixture(database)
    failing = _FailingPixelProvider(pixels.frame)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, failing).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED
    )
    rendered = (str(raised.value), repr(raised.value), repr(raised.value.args))
    assert all("SECRET" not in item and "alice.png" not in item for item in rendered)
    assert failing.requested_ids == [_observation.artifacts[0].artifact_id]
    formatted_traceback = "".join(traceback.format_exception(raised.value))
    assert "SECRET" not in formatted_traceback
    assert "alice.png" not in formatted_traceback
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None


def test_public_builder_redacts_invalid_identity_payload(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    pixels = _UnusedPixelProvider()
    secret = "SECRET C:\\people\\alice.png"
    raw = _UnusedRawVerifier()
    builder = SQLiteM6UpgradeWholeSampleRecordBuilder(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=pixels,  # type: ignore[arg-type]
        m3_raw_response_verifier=raw,  # type: ignore[arg-type]
        m4_raw_response_verifier=raw,  # type: ignore[arg-type]
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(secret, "a" * 64)
    assert raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT
    rendered = (str(raised.value), repr(raised.value), repr(raised.value.args))
    assert all("SECRET" not in item and "alice.png" not in item for item in rendered)
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert pixels.requested_ids == []


@pytest.mark.parametrize(
    ("translator_name", "source_error", "expected"),
    (
        (
            "_translate_state",
            M6UpgradeExecutionLedgerV2Error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED),
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED,
        ),
        (
            "_translate_state",
            M6UpgradeExecutionLedgerV2Error(
                M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE
            ),
            M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE,
        ),
        (
            "_translate_frame_document",
            M6SQLiteFrameDocumentError(M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED),
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED,
        ),
        (
            "_translate_canonical_document",
            M6SQLitePhysicalDocumentError(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED),
            M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED,
        ),
    ),
)
def test_storage_failures_keep_retryable_or_resource_semantics(
    translator_name: str,
    source_error: Exception,
    expected: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> None:
    translator = getattr(builder_module, translator_name)
    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        translator(source_error)
    assert raised.value.reason_code == expected
