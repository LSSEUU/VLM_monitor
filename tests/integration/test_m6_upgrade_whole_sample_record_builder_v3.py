from __future__ import annotations

import hashlib
import sqlite3
import traceback
from dataclasses import dataclass
from pathlib import Path

import pytest

import labcourt.adapters.storage.sqlite_m6_upgrade_whole_sample_record_builder as subject
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    M6SQLiteCaseDocumentError,
    M6SQLiteCaseDocumentFailureCode,
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
    SQLiteM6UpgradeWholeSampleRecordBuilder,
    SQLiteM6UpgradeWholeSampleRecordBuilderV3,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import derive_case_id
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import ArtifactKind, AuditAction
from labcourt.contracts.evidence import (
    EvidencePack,
    EvidencePackDraft,
    ObservationSufficiencyInput,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeObservedModelCall,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
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
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256
from tests.integration import test_m3_sqlite_repository as m3_fixture
from tests.integration.test_m2_evidence_builder import _event
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder import (
    _fixture as _prepare_v2,
)

BUSY_TIMEOUT_MS = 2_000


class _PixelProvider:
    def __init__(
        self,
        frame: RGB8Frame,
        events: list[str] | None = None,
        *,
        additional_frames: tuple[RGB8Frame, ...] = (),
    ) -> None:
        self.frame = frame
        self.rgb_frames = (frame, *additional_frames)
        self.frames = {item.frame.frame_id: item for item in self.rgb_frames}
        self.events = events
        self.requested_ids: list[str] = []

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        if self.events is not None:
            self.events.append("pixel")
        self.requested_ids.append(frame_id)
        return self.frames[frame_id]


class _FailingPixelProvider(_PixelProvider):
    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        self.requested_ids.append(frame_id)
        raise RuntimeError("SECRET C:\\people\\alice.png")


class _UnusedRawVerifier:
    def verify_raw_response(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("base-route V3 builder must not invoke a raw verifier")


class _ExactArtifactVerifier:
    def __init__(self) -> None:
        self.calls: list[M6UpgradeSampleExecutionRecordV2] = []

    def verify_m6_upgrade_sample_artifacts(
        self,
        record: M6UpgradeSampleExecutionRecordV2,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        self.calls.append(record)
        return tuple(link.artifact for link in record.artifact_links)


def _prepare_v3(
    database: Path,
    *,
    case_replayed: bool,
    events: list[str] | None = None,
    include_case_semantic_frames: bool = False,
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    _PixelProvider,
]:
    scope, _records = _scope_and_no_case_records()
    pixels = bytes((1, 2, 3, 4, 5, 6))
    frame = FrameRef(
        camera_id="camera-builder-v3",
        stream_id="stream-builder-v3",
        frame_index=0,
        fps_num=25,
        fps_den=1,
        width=2,
        height=1,
        content_sha256=rgb8_pixel_sha256(2, 1, pixels),
    )
    detector = scope.candidate_manifest.models["detector"]
    detection = Detection(
        detection_id="detection-builder-v3",
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
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observations.begin_execution(scope)

    candidate_case: M6UpgradeCandidateCaseBinding | None = None
    anchor: M6UpgradeSelectedCaseAuditAnchor | None = None
    outcome = M6ReplayExecutionOutcome.NO_CASE
    additional_frames: list[RGB8Frame] = []
    if case_replayed:
        candidate_event = _event(scope.candidate_manifest)
        snapshot = evidence.create_or_get_case(
            scope.candidate_run_id,
            candidate_event,
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
        anchor = M6UpgradeSelectedCaseAuditAnchor(
            candidate_case_binding_id=candidate_case.case_binding_id,
            action=audit.action,
            object_ref=audit.object_ref,
        )
        outcome = M6ReplayExecutionOutcome.CASE_REPLAYED
        if include_case_semantic_frames:
            semantic_frame_ids = {
                f"{candidate_event.camera_id}:{candidate_event.stream_id}:"
                f"{candidate_event.start_frame}",
                f"{candidate_event.camera_id}:{candidate_event.stream_id}:"
                f"{candidate_event.end_frame_exclusive - 1}",
                f"{candidate_event.camera_id}:{candidate_event.stream_id}:"
                f"{candidate_event.trigger_frame}",
                *candidate_event.confirmation.examined_frame_ids,
                *candidate_event.confirmation.counterevidence_frame_ids,
                *(
                    (candidate_event.confirmation.post_threshold_recovery_frame_id,)
                    if candidate_event.confirmation.post_threshold_recovery_frame_id is not None
                    else ()
                ),
                *(
                    fact.source_ref.artifact_id
                    for fact in candidate_event.objective_facts
                    if fact.source_ref.kind == ArtifactKind.FRAME
                ),
            }
            semantic_frame_ids.discard(frame.frame_id)
            for sequence, frame_id in enumerate(sorted(semantic_frame_ids, key=parse_frame_id)):
                camera_id, stream_id, frame_index = parse_frame_id(frame_id)
                semantic_pixels = bytes((sequence + 10, sequence + 11, sequence + 12))
                semantic_frame = FrameRef(
                    camera_id=camera_id,
                    stream_id=stream_id,
                    frame_index=frame_index,
                    fps_num=30,
                    fps_den=1,
                    width=1,
                    height=1,
                    content_sha256=rgb8_pixel_sha256(1, 1, semantic_pixels),
                )
                evidence.register_frame(scope.candidate_run_id, semantic_frame)
                additional_frames.append(RGB8Frame(frame=semantic_frame, pixels=semantic_pixels))

    observation = M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        ledger_sequence=0,
        outcome=outcome,
        candidate_case=candidate_case,
        selected_case_audit_anchor=anchor,
        artifacts=tuple(
            sorted(
                (
                    *(
                        M6UpgradeObservedArtifactIdentity(
                            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                            kind=M6UpgradePhysicalArtifactKind.FRAME,
                            artifact_id=item.frame_id,
                            usage=M6UpgradeArtifactUsage.CONSUMED,
                        )
                        for item in (frame, *(item.frame for item in additional_frames))
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
    observations.append(observation)
    return (
        scope,
        observation,
        _PixelProvider(
            RGB8Frame(frame=frame, pixels=pixels),
            events,
            additional_frames=tuple(additional_frames),
        ),
    )


def _prepare_v3_evidence_pack(
    database: Path,
    *,
    pack_count: int = 1,
    events: list[str] | None = None,
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    _PixelProvider,
    tuple[EvidencePack, ...],
]:
    assert pack_count in (1, 2)
    scope, _records = _scope_and_no_case_records()
    pixels = bytes((1, 2, 3, 4, 5, 6))
    frame = FrameRef(
        camera_id="camera-builder-v3-pack",
        stream_id="stream-builder-v3-pack",
        frame_index=0,
        fps_num=25,
        fps_den=1,
        width=2,
        height=1,
        content_sha256=rgb8_pixel_sha256(2, 1, pixels),
    )
    detector = scope.candidate_manifest.models["detector"]
    detection = Detection(
        detection_id="detection-builder-v3-pack",
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
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observations.begin_execution(scope)

    event = _event(scope.candidate_manifest)
    event = event.model_copy(
        update={
            "objective_facts": tuple(
                fact.model_copy(update={"source_manifest_id": scope.candidate_manifest.manifest_id})
                for fact in event.objective_facts
            )
        }
    )
    evidence_frame_indices = {event.trigger_frame}
    confirmation_frame_ids = (
        event.confirmation.examined_frame_ids
        + event.confirmation.counterevidence_frame_ids
        + (
            (event.confirmation.post_threshold_recovery_frame_id,)
            if event.confirmation.post_threshold_recovery_frame_id is not None
            else ()
        )
    )
    evidence_frame_indices.update(
        int(frame_id.rsplit(":", maxsplit=1)[1]) for frame_id in confirmation_frame_ids
    )
    evidence_frame_indices.update(
        int(fact.source_ref.artifact_id.rsplit(":", maxsplit=1)[1])
        for fact in event.objective_facts
        if fact.source_ref.kind == ArtifactKind.FRAME
    )
    for frame_index in sorted(evidence_frame_indices):
        evidence.register_frame(
            scope.candidate_run_id,
            FrameRef(
                camera_id=event.camera_id,
                stream_id=event.stream_id,
                frame_index=frame_index,
                fps_num=30,
                fps_den=1,
                width=1,
                height=1,
                content_sha256=hashlib.sha256(str(frame_index).encode("utf-8")).hexdigest(),
            ),
        )
    snapshot = evidence.create_or_get_case(scope.candidate_run_id, event)
    published_packs: list[EvidencePack] = []
    for version in range(1, pack_count + 1):
        published = evidence.publish_pack(
            scope.candidate_run_id,
            snapshot.revision,
            EvidencePackDraft(
                run_id=scope.candidate_run_id,
                case_id=derive_case_id(event.event_id),
                version=version,
                complete=version == pack_count,
                event=event,
                key_frame_ids=(f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}",),
                objective_facts=event.objective_facts,
                track_summary=TrackSummary(
                    primary_track_ref=event.primary_track_ref,
                    start_frame=event.start_frame,
                    end_frame_exclusive=max(evidence_frame_indices) + 1,
                    observed_frame_count=len(evidence_frame_indices),
                ),
                confirmation_record=event.confirmation,
                observation_sufficiency_input=ObservationSufficiencyInput(
                    clear_threshold=0.5,
                    required_clear_count=1,
                    selected_by_observability=False,
                ),
                manifest_id=scope.candidate_manifest.manifest_id,
            ),
        )
        snapshot = published.case
        published_packs.append(published.pack)

    audit = evidence.list_audit_entries(scope.candidate_run_id)[-1]
    case_raw = canonical_json(snapshot.case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_raw.encode("utf-8")).hexdigest()
    assert audit.after_sha256 == case_sha256
    binding = M6UpgradeCandidateCaseBinding(
        case_id=snapshot.case.case_id,
        case_revision=snapshot.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=audit.sequence,
        case_audit_entry_hash=audit.entry_hash,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=audit.action,
        object_ref=audit.object_ref,
    )
    selected_pack = published_packs[-1]
    observation = M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        ledger_sequence=0,
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=binding,
        selected_case_audit_anchor=anchor,
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
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                        kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                        artifact_id=selected_pack.pack_id,
                        usage=M6UpgradeArtifactUsage.PRODUCED,
                    ),
                ),
                key=lambda item: item.sort_key,
            )
        ),
        model_calls=(),
    )
    observations.append(observation)
    return (
        scope,
        observation,
        _PixelProvider(RGB8Frame(frame=frame, pixels=pixels), events),
        tuple(published_packs),
    )


def _builder(database: Path, pixels: _PixelProvider) -> SQLiteM6UpgradeWholeSampleRecordBuilderV3:
    raw = _UnusedRawVerifier()
    return SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=pixels,
        m3_raw_response_verifier=raw,  # type: ignore[arg-type]
        m4_raw_response_verifier=raw,  # type: ignore[arg-type]
    )


def _builder_v2(
    database: Path,
    pixels: _PixelProvider,
) -> SQLiteM6UpgradeWholeSampleRecordBuilder:
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


def _record_with_conflicting_m3_document_hash(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradeSampleExecutionRecordV2:
    links = list(record.artifact_links)
    index = next(
        position
        for position, link in enumerate(links)
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
    )
    link = links[index]
    links[index] = link.model_copy(
        update={
            "artifact": link.artifact.model_copy(
                update={
                    "document_sha256": "f" * 64,
                    "content_sha256": "f" * 64,
                }
            )
        }
    )
    payload = record.model_dump(
        mode="python",
        exclude={"schema_version"},
        exclude_computed_fields=True,
    )
    payload["artifact_links"] = tuple(links)
    return M6UpgradeSampleExecutionRecordV2(**payload)


def test_v3_no_case_builds_without_reading_case_or_raw(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _prepare_v3(database, case_replayed=False)

    def forbidden_case(**_kwargs: object) -> object:
        raise AssertionError("NO_CASE must not read Case authority")

    monkeypatch.setattr(subject, "read_m6_sqlite_case_authority_v3", forbidden_case)
    record = _builder(database, pixels).build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert record.outcome == M6ReplayExecutionOutcome.NO_CASE
    assert record.candidate_case is None
    assert record.observation_authority_id == observation.observation_authority_id
    assert pixels.requested_ids == [observation.artifacts[0].artifact_id]


def test_v3_case_created_reader_precedes_every_physical_or_pixel_read_on_same_b(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    events: list[str] = []
    scope, observation, pixels = _prepare_v3(
        database,
        case_replayed=True,
        events=events,
    )
    readers: list[object] = []
    real_state = subject.load_m6_upgrade_v3_state_from_connection
    real_case = subject.read_m6_sqlite_case_authority_v3
    real_frame = subject.plan_m6_sqlite_frame_physical_identity
    real_detection = subject.resolve_m6_sqlite_canonical_physical_identity
    real_m3_plan = subject.plan_m6_sqlite_m3_model_documents

    def tracked_state(*args: object, **kwargs: object) -> object:
        events.append("state")
        readers.append(args[1])
        return real_state(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_case(*args: object, **kwargs: object) -> object:
        events.append("case")
        readers.append(kwargs["connection"])
        return real_case(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_frame(*args: object, **kwargs: object) -> object:
        events.append("frame")
        readers.append(kwargs["connection"])
        return real_frame(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_detection(*args: object, **kwargs: object) -> object:
        events.append("detection")
        readers.append(kwargs["connection"])
        return real_detection(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_m3_plan(*args: object, **kwargs: object) -> object:
        events.append("m3-plan")
        readers.append(kwargs["connection"])
        return real_m3_plan(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(subject, "load_m6_upgrade_v3_state_from_connection", tracked_state)
    monkeypatch.setattr(subject, "read_m6_sqlite_case_authority_v3", tracked_case)
    monkeypatch.setattr(subject, "plan_m6_sqlite_frame_physical_identity", tracked_frame)
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_canonical_physical_identity",
        tracked_detection,
    )
    monkeypatch.setattr(subject, "plan_m6_sqlite_m3_model_documents", tracked_m3_plan)

    record = _builder(database, pixels).build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    assert record.candidate_case == observation.candidate_case
    assert events[0:2] == ["state", "case"]
    assert events.index("case") < events.index("frame")
    assert events.index("case") < events.index("detection")
    assert events.index("case") < events.index("m3-plan") < events.index("pixel")
    assert events.index("case") < events.index("pixel")
    assert readers and all(reader is readers[0] for reader in readers)


def test_v3_selected_case_pack_is_planned_then_late_resolved_on_the_same_b(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    events: list[str] = []
    scope, observation, pixels, packs = _prepare_v3_evidence_pack(
        database,
        pack_count=2,
        events=events,
    )
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER evidence_packs_no_update")
        connection.execute(
            "UPDATE evidence_packs SET pack_json = '[' || substr(pack_json, 2) "
            "WHERE run_id = ? AND pack_id = ?",
            (scope.candidate_run_id, packs[0].pack_id),
        )

    readers: list[object] = []
    planned_pack_ids: list[str] = []
    real_state = subject.load_m6_upgrade_v3_state_from_connection
    real_case = subject.read_m6_sqlite_case_authority_v3
    real_pack_plan = subject.plan_m6_sqlite_evidence_pack_physical_identity
    real_frame = subject.plan_m6_sqlite_frame_physical_identity
    real_detection = subject.resolve_m6_sqlite_canonical_physical_identity
    real_pack_resolve = subject.resolve_m6_sqlite_evidence_pack_physical_plan

    def tracked_state(*args: object, **kwargs: object) -> object:
        events.append("state")
        readers.append(args[1])
        return real_state(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_case(*args: object, **kwargs: object) -> object:
        events.append("case")
        readers.append(kwargs["connection"])
        return real_case(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_pack_plan(*args: object, **kwargs: object) -> object:
        events.append("pack-plan")
        readers.append(kwargs["connection"])
        planned_pack_ids.append(str(kwargs["pack_id"]))
        return real_pack_plan(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_frame(*args: object, **kwargs: object) -> object:
        events.append("frame-plan")
        readers.append(kwargs["connection"])
        return real_frame(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_detection(*args: object, **kwargs: object) -> object:
        events.append("detection-plan")
        readers.append(kwargs["connection"])
        return real_detection(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_pack_resolve(*args: object, **kwargs: object) -> object:
        events.append("pack-body")
        readers.append(kwargs["connection"])
        return real_pack_resolve(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(subject, "load_m6_upgrade_v3_state_from_connection", tracked_state)
    monkeypatch.setattr(subject, "read_m6_sqlite_case_authority_v3", tracked_case)
    monkeypatch.setattr(
        subject,
        "plan_m6_sqlite_evidence_pack_physical_identity",
        tracked_pack_plan,
    )
    monkeypatch.setattr(subject, "plan_m6_sqlite_frame_physical_identity", tracked_frame)
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_canonical_physical_identity",
        tracked_detection,
    )
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_evidence_pack_physical_plan",
        tracked_pack_resolve,
    )

    record = _builder(database, pixels).build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )

    pack_links = tuple(
        link
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
    )
    assert len(pack_links) == 1
    assert pack_links[0].artifact.artifact_id == packs[-1].pack_id
    assert pack_links[0].usage == M6UpgradeArtifactUsage.PRODUCED
    assert packs[0].pack_id not in {link.artifact.artifact_id for link in record.artifact_links}
    assert planned_pack_ids == [packs[-1].pack_id]
    assert events[0:3] == ["state", "case", "pack-plan"]
    assert events.index("frame-plan") < events.index("pack-body")
    assert events.index("detection-plan") < events.index("pack-body")
    assert events.index("pack-body") < events.index("pixel")
    assert readers and all(reader is readers[0] for reader in readers)
    assert observation.candidate_case == record.candidate_case


def test_v3_pending_retry_revalidates_pack_body_before_the_next_pixel_read(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels, packs = _prepare_v3_evidence_pack(database)
    builder = _builder(database, pixels)
    first = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    commitment = _commitment(first)
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert pending.append(commitment) == commitment
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER evidence_packs_no_update")
        connection.execute(
            "UPDATE evidence_packs SET pack_json = '[' || substr(pack_json, 2) "
            "WHERE run_id = ? AND pack_id = ?",
            (scope.candidate_run_id, packs[0].pack_id),
        )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as rejected:
        builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert rejected.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )
    assert rejected.value.__context__ is None
    assert rejected.value.__cause__ is None
    assert pixels.requested_ids == [
        next(
            link.artifact.artifact_id
            for link in first.artifact_links
            if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
        )
    ]


def test_v3_pack_whole_sample_budget_precedes_pack_body_and_pixels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    events: list[str] = []
    scope, _observation, pixels, _packs = _prepare_v3_evidence_pack(
        database,
        events=events,
    )
    real_pack_plan = subject.plan_m6_sqlite_evidence_pack_physical_identity
    real_frame = subject.plan_m6_sqlite_frame_physical_identity
    real_detection = subject.resolve_m6_sqlite_canonical_physical_identity

    def tracked_pack_plan(*args: object, **kwargs: object) -> object:
        events.append("pack-plan")
        return real_pack_plan(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_frame(*args: object, **kwargs: object) -> object:
        events.append("frame-plan")
        return real_frame(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_detection(*args: object, **kwargs: object) -> object:
        events.append("detection-plan")
        return real_detection(*args, **kwargs)  # type: ignore[arg-type]

    def forbidden_pack_body(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("whole-sample budget must precede EvidencePack body reads")

    monkeypatch.setattr(subject, "MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES", 1)
    monkeypatch.setattr(
        subject,
        "plan_m6_sqlite_evidence_pack_physical_identity",
        tracked_pack_plan,
    )
    monkeypatch.setattr(subject, "plan_m6_sqlite_frame_physical_identity", tracked_frame)
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_canonical_physical_identity",
        tracked_detection,
    )
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_evidence_pack_physical_plan",
        forbidden_pack_body,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as rejected:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert rejected.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED
    )
    assert events == ["pack-plan", "frame-plan", "detection-plan"]
    assert pixels.requested_ids == []


def test_v3_anchor_mismatch_stops_before_physical_pixel_or_raw(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observation, pixels = _prepare_v3(database, case_replayed=True)

    def mismatched_anchor(**_kwargs: object) -> object:
        raise M6SQLiteCaseDocumentError(
            M6SQLiteCaseDocumentFailureCode.SELECTED_AUDIT_ANCHOR_MISMATCH
        )

    def forbidden_physical(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("anchor mismatch must precede physical planning")

    monkeypatch.setattr(subject, "read_m6_sqlite_case_authority_v3", mismatched_anchor)
    monkeypatch.setattr(subject, "plan_m6_sqlite_frame_physical_identity", forbidden_physical)
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_canonical_physical_identity",
        forbidden_physical,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, pixels).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH
    )
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    assert pixels.requested_ids == []


def test_v3_public_failure_recursively_discards_pixel_provider_payload(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _prepare_v3(database, case_replayed=False)
    failing = _FailingPixelProvider(pixels.frame)

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        _builder(database, failing).build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED
    )
    assert failing.requested_ids == [observation.artifacts[0].artifact_id]
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    rendered = (
        str(raised.value),
        repr(raised.value),
        repr(raised.value.args),
        "".join(traceback.format_exception(raised.value)),
    )
    assert all("SECRET" not in item and "alice.png" not in item for item in rendered)
    public_frames = []
    current = raised.value.__traceback__
    while current is not None:
        if current.tb_frame.f_code.co_name == "build_m6_upgrade_sample_record":
            public_frames.append(current.tb_frame)
        current = current.tb_next
    assert len(public_frames) == 1
    assert "self" not in public_frames[0].f_locals
    assert "candidate_run_id" not in public_frames[0].f_locals
    assert "execution_scope_authority_id" not in public_frames[0].f_locals


def test_v2_and_v3_builders_reject_each_others_protocol_before_pixels(
    tmp_path: Path,
) -> None:
    v2_database = tmp_path / "v2" / "labcourt.sqlite3"
    v2_database.parent.mkdir()
    v2_scope, _v2_observation, v2_pixels = _prepare_v2(v2_database)
    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as v3_rejects_v2:
        _builder(v2_database, v2_pixels).build_m6_upgrade_sample_record(
            v2_scope.candidate_run_id,
            v2_scope.execution_scope_authority_id,
        )
    assert v3_rejects_v2.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.LEDGER_VERSION_UNSUPPORTED
    )
    assert v3_rejects_v2.value.__context__ is None
    assert v3_rejects_v2.value.__cause__ is None
    assert v2_pixels.requested_ids == []

    v3_database = tmp_path / "v3" / "labcourt.sqlite3"
    v3_database.parent.mkdir()
    v3_scope, _v3_observation, v3_pixels = _prepare_v3(
        v3_database,
        case_replayed=False,
    )
    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as v2_rejects_v3:
        _builder_v2(v3_database, v3_pixels).build_m6_upgrade_sample_record(
            v3_scope.candidate_run_id,
            v3_scope.execution_scope_authority_id,
        )
    assert v2_rejects_v3.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )
    assert v2_rejects_v3.value.__context__ is None
    assert v2_rejects_v3.value.__cause__ is None
    assert v3_pixels.requested_ids == []


def test_v3_pending_retry_and_committed_progression_remain_exact(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observation, pixels = _prepare_v3(database, case_replayed=False)
    builder = _builder(database, pixels)

    first = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    commitment = _commitment(first)
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert pending.append(commitment) == commitment
    assert (
        builder.build_m6_upgrade_sample_record(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        == first
    )

    verifier = _ExactArtifactVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,  # type: ignore[arg-type]
    )
    assert ledger.append_committed_sample(commitment) == first
    assert verifier.calls == [first]

    payload = observation.model_dump(
        mode="python",
        exclude={"schema_version"},
        exclude_computed_fields=True,
    )
    payload.update(
        ledger_sequence=1,
        execution_entry=scope.execution_dataset.entries[1],
    )
    second_observation = M6UpgradeSampleExecutionObservationAuthorityV2(**payload)
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert observations.append(second_observation) == second_observation

    second = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert second.ledger_sequence == 1
    assert second.previous_ledger_entry_hash == first.sample_execution_record_id
    assert second.observation_authority_id == second_observation.observation_authority_id
    assert pixels.requested_ids == [observation.artifacts[0].artifact_id] * 3


@dataclass(frozen=True, slots=True)
class _V3M3BuilderFixture:
    scope: M6UpgradeExecutionScopeAuthority
    observation: M6UpgradeSampleExecutionObservationAuthorityV2
    pixels: _PixelProvider
    frame: FrameRef
    request_id: str


def _prepare_v3_m3_builder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    events: list[str] | None = None,
    observe_model_call: bool = True,
    include_case_semantic_frames: bool = False,
) -> _V3M3BuilderFixture:
    scope, _records = _scope_and_no_case_records()
    event = m3_fixture._event().model_copy(
        update={"manifest_id": scope.candidate_manifest.manifest_id}
    )
    monkeypatch.setattr(m3_fixture, "RUN_ID", scope.candidate_run_id)
    monkeypatch.setattr(m3_fixture, "_manifest", lambda: scope.candidate_manifest)
    monkeypatch.setattr(m3_fixture, "_event", lambda: event)

    semantic_rgb_frames: list[RGB8Frame] = []
    if include_case_semantic_frames:
        original_draft = m3_fixture._draft
        source_frame = m3_fixture._frame()
        source_pixels = bytes((31, 32, 33)) * (source_frame.width * source_frame.height)
        rgb_backed_source_frame = FrameRef(
            camera_id=source_frame.camera_id,
            stream_id=source_frame.stream_id,
            frame_index=source_frame.frame_index,
            fps_num=source_frame.fps_num,
            fps_den=source_frame.fps_den,
            width=source_frame.width,
            height=source_frame.height,
            content_sha256=rgb8_pixel_sha256(
                source_frame.width,
                source_frame.height,
                source_pixels,
            ),
        )
        monkeypatch.setattr(m3_fixture, "_frame", lambda: rgb_backed_source_frame)

        def rgb_backed_draft(*, version: int, complete: bool) -> EvidencePackDraft:
            draft = original_draft(version=version, complete=complete)
            payload = draft.model_dump(mode="python", exclude_computed_fields=True)
            for field_name in (
                "panorama_crops",
                "subject_crops",
                "focus_crops",
                "temporal_crops",
            ):
                payload[field_name] = tuple(
                    crop.model_copy(
                        update={
                            "source_media_sha256": rgb_backed_source_frame.content_sha256,
                            "local_path": (
                                f"{scope.candidate_run_id}/frames/{crop.media_sha256}.png"
                            ),
                        }
                    )
                    for crop in getattr(draft, field_name)
                )
            return EvidencePackDraft(**payload)

        monkeypatch.setattr(m3_fixture, "_draft", rgb_backed_draft)
        semantic_rgb_frames.append(RGB8Frame(frame=rgb_backed_source_frame, pixels=source_pixels))

    database, evidence = m3_fixture._repository(tmp_path)
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    observations.begin_execution(scope)
    m3_fixture._register_case(evidence)
    published = evidence.publish_pack(
        scope.candidate_run_id,
        1,
        m3_fixture._draft(version=1, complete=True),
    )
    closure = evidence.verify_current_pack(
        scope.candidate_run_id,
        published.pack.pack_id,
    )
    review_verifier = m3_fixture.DeterministicProceduralReviewVerifier(
        scope.candidate_config,
        evidence,
    )
    repository = m3_fixture.SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=m3_fixture._clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=m3_fixture._RawVerifier(),
        procedural_review_verifier=review_verifier,
    )
    request, _response, output, _receipt = m3_fixture._persist_direct_parse(
        repository,
        published.pack,
    )
    screening = m3_fixture._screening_for(published.pack, output)
    committed = repository.commit_screening(
        scope.candidate_run_id,
        published.case.revision,
        evidence.get_audit_head(scope.candidate_run_id),
        closure,
        screening,
    )
    if include_case_semantic_frames:
        selected_case = committed.case.case
        required_frame_ids = {
            f"{selected_case.event.camera_id}:{selected_case.event.stream_id}:"
            f"{selected_case.event.start_frame}",
            f"{selected_case.event.camera_id}:{selected_case.event.stream_id}:"
            f"{selected_case.event.end_frame_exclusive - 1}",
            f"{selected_case.event.camera_id}:{selected_case.event.stream_id}:"
            f"{selected_case.event.trigger_frame}",
            *selected_case.event.confirmation.examined_frame_ids,
            *selected_case.event.confirmation.counterevidence_frame_ids,
            *(
                (selected_case.event.confirmation.post_threshold_recovery_frame_id,)
                if selected_case.event.confirmation.post_threshold_recovery_frame_id is not None
                else ()
            ),
            *(
                fact.source_ref.artifact_id
                for fact in selected_case.event.objective_facts
                if fact.source_ref.kind == ArtifactKind.FRAME
            ),
        }
        for pack in selected_case.evidence_packs:
            required_frame_ids.update(pack.key_frame_ids)
            required_frame_ids.update(pack.confirmation_record.examined_frame_ids)
            required_frame_ids.update(pack.confirmation_record.counterevidence_frame_ids)
            if pack.confirmation_record.post_threshold_recovery_frame_id is not None:
                required_frame_ids.add(pack.confirmation_record.post_threshold_recovery_frame_id)
            for crop in pack.crops:
                required_frame_ids.add(crop.frame_id)
                required_frame_ids.update(
                    ref.artifact_id
                    for ref in (*crop.source_refs, *crop.privacy_receipt.input_refs)
                    if ref.kind == ArtifactKind.FRAME
                )
            required_frame_ids.update(
                fact.source_ref.artifact_id
                for fact in pack.objective_facts
                if fact.source_ref.kind == ArtifactKind.FRAME
            )
        existing_frame_ids = {item.frame.frame_id for item in semantic_rgb_frames}
        for sequence, frame_id in enumerate(
            sorted(required_frame_ids - existing_frame_ids, key=parse_frame_id)
        ):
            camera_id, stream_id, frame_index = parse_frame_id(frame_id)
            semantic_pixels = bytes((sequence + 41, sequence + 42, sequence + 43))
            semantic_frame = FrameRef(
                camera_id=camera_id,
                stream_id=stream_id,
                frame_index=frame_index,
                fps_num=30,
                fps_den=1,
                width=1,
                height=1,
                content_sha256=rgb8_pixel_sha256(1, 1, semantic_pixels),
            )
            evidence.register_frame(scope.candidate_run_id, semantic_frame)
            semantic_rgb_frames.append(RGB8Frame(frame=semantic_frame, pixels=semantic_pixels))
    case_raw = canonical_json(committed.case.case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_raw.encode("utf-8")).hexdigest()
    selected_audit = next(
        audit
        for audit in evidence.list_audit_entries(scope.candidate_run_id)
        if audit.after_sha256 == case_sha256
    )
    assert selected_audit.action == AuditAction.CASE_STATE_CHANGED
    assert selected_audit.object_ref.kind == ArtifactKind.SCREENING_RESULT
    assert selected_audit.object_ref.artifact_id == screening.screening_id
    binding = M6UpgradeCandidateCaseBinding(
        case_id=committed.case.case.case_id,
        case_revision=committed.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    anchor = M6UpgradeSelectedCaseAuditAnchor(
        candidate_case_binding_id=binding.case_binding_id,
        action=selected_audit.action,
        object_ref=selected_audit.object_ref,
    )

    pixel_bytes = bytes((9, 8, 7))
    frame = FrameRef(
        camera_id="camera-builder-v3-m3",
        stream_id="stream-builder-v3-m3",
        frame_index=0,
        fps_num=25,
        fps_den=1,
        width=1,
        height=1,
        content_sha256=rgb8_pixel_sha256(1, 1, pixel_bytes),
    )
    evidence.register_frame(scope.candidate_run_id, frame)
    observation = M6UpgradeSampleExecutionObservationAuthorityV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        ledger_sequence=0,
        outcome=M6ReplayExecutionOutcome.CASE_REPLAYED,
        candidate_case=binding,
        selected_case_audit_anchor=anchor,
        artifacts=tuple(
            sorted(
                (
                    *(
                        M6UpgradeObservedArtifactIdentity(
                            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                            kind=M6UpgradePhysicalArtifactKind.FRAME,
                            artifact_id=item.frame.frame_id,
                            usage=M6UpgradeArtifactUsage.CONSUMED,
                        )
                        for item in semantic_rgb_frames
                    ),
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                        kind=M6UpgradePhysicalArtifactKind.FRAME,
                        artifact_id=frame.frame_id,
                        usage=M6UpgradeArtifactUsage.CONSUMED,
                    ),
                    M6UpgradeObservedArtifactIdentity(
                        source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
                        kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
                        artifact_id=published.pack.pack_id,
                        usage=M6UpgradeArtifactUsage.PRODUCED,
                    ),
                    *(
                        (
                            M6UpgradeObservedArtifactIdentity(
                                source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                                kind=M6UpgradePhysicalArtifactKind.DETECTION,
                                artifact_id=m3_fixture._detection().detection_id,
                                usage=M6UpgradeArtifactUsage.PRODUCED,
                            ),
                        )
                        if include_case_semantic_frames
                        else ()
                    ),
                ),
                key=lambda item: item.sort_key,
            )
        ),
        model_calls=(
            (
                M6UpgradeObservedModelCall(
                    request_id=request.request_id,
                    layer=M6LockedModelCallLayer.SCREENING,
                    role=M6LockedModelRole.SCREENING,
                    attempt_index=0,
                    result_kind=M6LockedModelCallResultKind.RESPONSE,
                    provider_invoked=True,
                ),
            )
            if observe_model_call
            else ()
        ),
    )
    observations.append(observation)
    return _V3M3BuilderFixture(
        scope=scope,
        observation=observation,
        pixels=_PixelProvider(
            RGB8Frame(frame=frame, pixels=pixel_bytes),
            events,
            additional_frames=tuple(semantic_rgb_frames),
        ),
        frame=frame,
        request_id=request.request_id,
    )


def _tracked_v3_m3_builder(
    database: Path,
    fixture: _V3M3BuilderFixture,
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
    *,
    fail_raw: bool = False,
) -> SQLiteM6UpgradeWholeSampleRecordBuilderV3:
    real_m3_body = subject.resolve_m6_sqlite_m3_model_documents
    real_pack_body = subject.resolve_m6_sqlite_evidence_pack_physical_plan
    raw_delegate = m3_fixture._RawVerifier()

    def tracked_m3_body(*args: object, **kwargs: object) -> object:
        events.append("m3-body")
        return real_m3_body(*args, **kwargs)  # type: ignore[arg-type]

    def tracked_pack_body(*args: object, **kwargs: object) -> object:
        events.append("pack")
        return real_pack_body(*args, **kwargs)  # type: ignore[arg-type]

    class _TrackingRawVerifier:
        def verify_raw_response(self, *args: object, **kwargs: object) -> object:
            events.append("raw")
            if fail_raw:
                raise RuntimeError("private raw verifier payload C:\\people\\alice.bin")
            return raw_delegate.verify_raw_response(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(subject, "resolve_m6_sqlite_m3_model_documents", tracked_m3_body)
    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_evidence_pack_physical_plan",
        tracked_pack_body,
    )
    raw = _TrackingRawVerifier()
    return SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=fixture.pixels,
        m3_raw_response_verifier=raw,  # type: ignore[arg-type]
        m4_raw_response_verifier=raw,  # type: ignore[arg-type]
    )


def test_v3_builder_exact_joins_real_m3_and_reads_pack_raw_pixel_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m3_builder(tmp_path, monkeypatch, events=events)
    database = tmp_path / "labcourt.sqlite3"
    scope = fixture.scope
    observation = fixture.observation
    pixels = fixture.pixels
    frame = fixture.frame
    binding = observation.candidate_case
    assert binding is not None

    real_pack_body = subject.resolve_m6_sqlite_evidence_pack_physical_plan

    def tracked_pack_body(*args: object, **kwargs: object) -> object:
        events.append("pack")
        return real_pack_body(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        subject,
        "resolve_m6_sqlite_evidence_pack_physical_plan",
        tracked_pack_body,
    )

    raw_delegate = m3_fixture._RawVerifier()

    class _TrackingRawVerifier:
        def verify_raw_response(self, *args: object, **kwargs: object) -> object:
            events.append("raw")
            return raw_delegate.verify_raw_response(*args, **kwargs)  # type: ignore[arg-type]

    raw = _TrackingRawVerifier()
    builder = SQLiteM6UpgradeWholeSampleRecordBuilderV3(
        database,
        BUSY_TIMEOUT_MS,
        pixel_provider=pixels,
        m3_raw_response_verifier=raw,
        m4_raw_response_verifier=raw,  # type: ignore[arg-type]
    )
    record = builder.build_m6_upgrade_sample_record(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert record.candidate_case == binding
    assert record.observation_authority_id == observation.observation_authority_id
    model_links = tuple(
        link
        for link in record.artifact_links
        if link.artifact.source == M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL
    )
    assert {link.artifact.artifact_id for link in model_links} >= {fixture.request_id}
    assert events == ["pack", "raw", "pixel"]
    assert pixels.requested_ids == [frame.frame_id]


def test_v3_builder_empty_observation_rejects_real_m3_rows_before_any_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m3_builder(
        tmp_path,
        monkeypatch,
        events=events,
        observe_model_call=False,
    )
    database = tmp_path / "labcourt.sqlite3"
    builder = _tracked_v3_m3_builder(
        database,
        fixture,
        monkeypatch,
        events,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            fixture.scope.candidate_run_id,
            fixture.scope.execution_scope_authority_id,
        )

    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH
    )
    assert events == []
    assert fixture.pixels.requested_ids == []


def test_v3_builder_pending_m3_conflict_stops_before_pack_raw_and_pixel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m3_builder(tmp_path, monkeypatch, events=events)
    database = tmp_path / "labcourt.sqlite3"
    builder = _tracked_v3_m3_builder(
        database,
        fixture,
        monkeypatch,
        events,
    )
    first = builder.build_m6_upgrade_sample_record(
        fixture.scope.candidate_run_id,
        fixture.scope.execution_scope_authority_id,
    )
    conflicting = _record_with_conflicting_m3_document_hash(first)
    assert conflicting != first
    commitment = _commitment(conflicting)
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert pending.append(commitment) == commitment
    events.clear()
    fixture.pixels.requested_ids.clear()

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            fixture.scope.candidate_run_id,
            fixture.scope.execution_scope_authority_id,
        )

    assert (
        raised.value.reason_code == M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT
    )
    assert events == []
    assert fixture.pixels.requested_ids == []


def test_v3_builder_pack_body_failure_stops_before_m3_raw_and_pixel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m3_builder(tmp_path, monkeypatch, events=events)
    database = tmp_path / "labcourt.sqlite3"
    pack_id = next(
        item.artifact_id
        for item in fixture.observation.artifacts
        if item.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
    )
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER evidence_packs_no_update")
        connection.execute(
            "UPDATE evidence_packs SET pack_json = '[' || substr(pack_json, 2) "
            "WHERE run_id = ? AND pack_id = ?",
            (fixture.scope.candidate_run_id, pack_id),
        )
    builder = _tracked_v3_m3_builder(
        database,
        fixture,
        monkeypatch,
        events,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            fixture.scope.candidate_run_id,
            fixture.scope.execution_scope_authority_id,
        )

    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID
    )
    assert events == ["m3-body", "pack"]
    assert fixture.pixels.requested_ids == []


def test_v3_builder_m3_raw_failure_stops_before_pixel_and_hides_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m3_builder(tmp_path, monkeypatch, events=events)
    database = tmp_path / "labcourt.sqlite3"
    builder = _tracked_v3_m3_builder(
        database,
        fixture,
        monkeypatch,
        events,
        fail_raw=True,
    )

    with pytest.raises(M6UpgradeWholeSampleRecordBuilderError) as raised:
        builder.build_m6_upgrade_sample_record(
            fixture.scope.candidate_run_id,
            fixture.scope.execution_scope_authority_id,
        )

    rendered = "".join(traceback.format_exception(raised.value))
    assert raised.value.reason_code == (
        M6UpgradeWholeSampleRecordBuilderFailureCode.RAW_RESPONSE_REJECTED
    )
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "alice.bin" not in rendered
    assert "RuntimeError" not in rendered
    assert events == ["m3-body", "pack", "raw"]
    assert fixture.pixels.requested_ids == []


def test_v3_builder_exact_pending_m3_retry_rereads_every_body_and_raw_pixel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    fixture = _prepare_v3_m3_builder(tmp_path, monkeypatch, events=events)
    database = tmp_path / "labcourt.sqlite3"
    builder = _tracked_v3_m3_builder(
        database,
        fixture,
        monkeypatch,
        events,
    )
    first = builder.build_m6_upgrade_sample_record(
        fixture.scope.candidate_run_id,
        fixture.scope.execution_scope_authority_id,
    )
    commitment = _commitment(first)
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert pending.append(commitment) == commitment
    events.clear()
    fixture.pixels.requested_ids.clear()

    retried = builder.build_m6_upgrade_sample_record(
        fixture.scope.candidate_run_id,
        fixture.scope.execution_scope_authority_id,
    )

    assert retried == first
    assert events == ["m3-body", "pack", "raw", "pixel"]
    assert fixture.pixels.requested_ids == [fixture.frame.frame_id]
