from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

import pytest

from labcourt.adapters.pillow_frame_store import PillowFrameStore
from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.json_projector import JsonProjector, ProjectionResult
from labcourt.adapters.storage.secure_retention import SecureRetentionFileOps
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.evidence import (
    EvidenceBuilder,
    EvidenceBuildRequest,
    FrameCropContext,
)
from labcourt.application.integrity import EvidenceIntegrityMonitor
from labcourt.application.retention import RetentionCoordinator
from labcourt.config_loader import load_config
from labcourt.contracts.audit import validate_audit_chain
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection, FrameBundle, Keypoint
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    CaseStatus,
    ClosureDefectCode,
    EvidenceFailureCode,
    ObservationSource,
    PrivacyPolicy,
    PurgeDisposition,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    ObservabilityComponents,
    ObservabilityScore,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import (
    RunManifest,
    SoftwareComponentManifest,
    StreamManifest,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.exceptions import EvidenceMissing, PrivacyPolicyViolation
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
FRAME_COUNT = 160
WIDTH = 32
HEIGHT = 24
RECORDED_AT = datetime(2026, 7, 27, 16, 0, 0, tzinfo=UTC)


def _clock() -> datetime:
    return RECORDED_AT


def _pixels() -> bytes:
    return bytes(
        channel
        for y in range(HEIGHT)
        for x in range(WIDTH)
        for channel in (
            (x * 7) % 256,
            (y * 11) % 256,
            (x * 5 + y * 3) % 256,
        )
    )


class _Pixels:
    def __init__(self, frames: tuple[RGB8Frame, ...]) -> None:
        self._frames = {frame.frame.frame_id: frame for frame in frames}

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        try:
            return self._frames[frame_id]
        except KeyError:
            raise EvidenceMissing("synthetic RGB8 frame is unavailable") from None


class _Verifier:
    def __init__(self, store: PillowFrameStore) -> None:
        self._store = store

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        return self._store.verify_crop(crop)

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id, ref
        return False


def _manifest(config: AppConfig) -> RunManifest:
    base = RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    decoder = SoftwareComponentManifest(
        component="synthetic-decoder",
        package="labcourt-test-video",
        version="1.0.0",
        license_id="synthetic-fixture",
    )
    pillow = SoftwareComponentManifest(
        component="pillow",
        package="Pillow",
        version=version("Pillow"),
        license_id="HPND",
    )
    stream = StreamManifest(
        camera_id="cam-01",
        stream_id="demo-absence",
        input_file_sha256="1" * 64,
        fps_num=30,
        fps_den=1,
        timing_mode="CFR",
        timing_authority="CALLER_ATTESTED",
        timing_evidence_type="CALLER_DECLARATION",
        timing_evidence_sha256="2" * 64,
        width=WIDTH,
        height=HEIGHT,
        frame_count=FRAME_COUNT,
        decoder="synthetic-rgb8",
        decoder_version="1.0.0",
        backend="IN_MEMORY_FIXTURE",
        software_component=decoder.component,
        library=decoder.package,
        library_version=decoder.version,
        codec="FAKE",
        color_conversion="NONE_RGB8",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    return base.model_copy(
        update={
            "config_sha256": config.config_sha256,
            "streams": (stream,),
            "software_components": {
                decoder.component: decoder,
                pillow.component: pillow,
            },
        }
    )


def _event(manifest: RunManifest) -> CandidateEvent:
    base = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    return base.model_copy(update={"manifest_id": manifest.manifest_id})


def _runtime_frames() -> tuple[RGB8Frame, ...]:
    pixels = _pixels()
    digest = rgb8_pixel_sha256(WIDTH, HEIGHT, pixels)
    return tuple(
        RGB8Frame(
            frame=FrameRef(
                camera_id="cam-01",
                stream_id="demo-absence",
                frame_index=frame_index,
                fps_num=30,
                fps_den=1,
                width=WIDTH,
                height=HEIGHT,
                content_sha256=digest,
            ),
            pixels=pixels,
        )
        for frame_index in range(FRAME_COUNT)
    )


def _observability(total: float) -> ObservabilityScore:
    return ObservabilityScore(
        total=total,
        components=ObservabilityComponents(
            person_confidence=total,
            keypoint_visibility=total,
            frontality=total,
            sharpness=total,
            exposure=total,
            non_occlusion=total,
        ),
        source=ObservationSource.PRECOMPUTED_FIXTURE,
    )


def _contexts() -> tuple[FrameCropContext, ...]:
    return tuple(
        FrameCropContext(
            frame_id=f"cam-01:demo-absence:{frame_index}",
            observability=_observability(score),
        )
        for frame_index, score in ((10, 0.91), (80, 0.82), (140, 0.42))
    )


def _bundles(
    manifest: RunManifest,
    runtime_frames: tuple[RGB8Frame, ...],
) -> tuple[FrameBundle, ...]:
    detector_manifest_id = manifest.models["detector"].model_manifest_id
    return tuple(
        FrameBundle(
            frame=item.frame,
            detections=(
                Detection(
                    detection_id=f"person-{item.frame.frame_index:03d}",
                    frame_id=item.frame.frame_id,
                    label="person",
                    bbox=BBoxXYXY(x1=3, y1=1, x2=29, y2=23),
                    score=0.9,
                    track_ref="cam-01:epoch-01:person-01",
                    keypoints=(
                        Keypoint(name="left_eye", x=11.0, y=8.0, score=0.95),
                        Keypoint(name="right_eye", x=20.0, y=8.0, score=0.94),
                    ),
                    model_manifest_id=detector_manifest_id,
                ),
            ),
        )
        for item in runtime_frames
    )


@dataclass(frozen=True, slots=True)
class _Stack:
    run_id: str
    config: AppConfig
    manifest: RunManifest
    event: CandidateEvent
    runtime_frames: tuple[RGB8Frame, ...]
    bundles: tuple[FrameBundle, ...]
    workspace_root: Path
    database: Path
    workspace: SecureWorkspace
    store: PillowFrameStore
    repository: SQLiteEvidenceRepository
    builder: EvidenceBuilder


@contextmanager
def _stack(tmp_path: Path, *, run_id: str, config: AppConfig) -> Iterator[_Stack]:
    manifest = _manifest(config)
    event = _event(manifest)
    runtime_frames = _runtime_frames()
    bundles = _bundles(manifest, runtime_frames)
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    database = workspace_root / config.storage.database_filename
    MigrationRunner(database, config.storage.busy_timeout_ms, clock=_clock).apply_all()

    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        store = PillowFrameStore(
            run_id=run_id,
            workspace=workspace,
            pixels=_Pixels(runtime_frames),
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        repository = SQLiteEvidenceRepository(
            database,
            config.storage.busy_timeout_ms,
            verifier=_Verifier(store),
            clock=_clock,
        )
        yield _Stack(
            run_id=run_id,
            config=config,
            manifest=manifest,
            event=event,
            runtime_frames=runtime_frames,
            bundles=bundles,
            workspace_root=workspace_root,
            database=database,
            workspace=workspace,
            store=store,
            repository=repository,
            builder=EvidenceBuilder(
                config=config,
                manifest=manifest,
                frame_store=store,
                repository=repository,
            ),
        )


def _complete_request(stack: _Stack) -> EvidenceBuildRequest:
    return EvidenceBuildRequest(
        run_id=stack.run_id,
        event=stack.event,
        bundles=stack.bundles,
        crop_contexts=_contexts(),
        available_end_frame_exclusive=FRAME_COUNT,
        complete=True,
    )


def _assert_audit_chain(repository: SQLiteEvidenceRepository, run_id: str) -> None:
    entries = repository.list_audit_entries(run_id)
    head = repository.get_audit_head(run_id)
    assert validate_audit_chain(
        entries,
        expected_run_id=run_id,
        expected_manifest_id=head.manifest_id,
        expected_head_sequence=head.sequence,
        expected_head_hash=head.entry_hash,
    ).passed


def _evidence_counts(database: Path, run_id: str) -> dict[str, int]:
    connection = sqlite3.connect(database)
    try:
        return {
            table: int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
            )
            for table in ("evidence_packs", "media_assets", "evidence_pack_crops")
        }
    finally:
        connection.close()


def _workspace_fingerprint(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and ".sqlite3" not in path.name
    }


def _assert_exact_projection(
    repository: SQLiteEvidenceRepository,
    run_id: str,
    projection: ProjectionResult,
) -> None:
    events = repository.list_events(run_id)
    audits = repository.list_audit_entries(run_id)
    expected_events = b"".join(
        canonical_bytes(event.model_dump(mode="json")) + b"\n" for event in events
    )
    expected_audits = b"".join(
        canonical_bytes(entry.model_dump(mode="json")) + b"\n" for entry in audits
    )

    events_bytes = projection.events_path.read_bytes()
    audits_bytes = projection.audit_path.read_bytes()
    assert events_bytes == expected_events
    assert audits_bytes == expected_audits
    assert events_bytes.endswith(b"\n") and b"\r\n" not in events_bytes
    assert audits_bytes.endswith(b"\n") and b"\r\n" not in audits_bytes
    assert not events_bytes.startswith(b"\xef\xbb\xbf")
    assert not audits_bytes.startswith(b"\xef\xbb\xbf")
    assert [json.loads(line) for line in events_bytes.splitlines()] == [
        event.model_dump(mode="json") for event in events
    ]
    assert [json.loads(line) for line in audits_bytes.splitlines()] == [
        entry.model_dump(mode="json") for entry in audits
    ]

    expected_cases = {
        derive_case_id(event.event_id): repository.load_case(
            run_id, derive_case_id(event.event_id)
        ).case
        for event in events
    }
    actual_case_paths = {path.stem: path for path in projection.case_paths}
    assert set(actual_case_paths) == set(expected_cases)
    for case_id, case in expected_cases.items():
        payload = actual_case_paths[case_id].read_bytes()
        assert payload == canonical_bytes(case.model_dump(mode="json"))
        assert json.loads(payload) == case.model_dump(mode="json")

    expected_packs = {
        indexed.pack_id: repository.load_pack(run_id, indexed.pack_id)
        for case in expected_cases.values()
        for indexed in case.evidence_packs
    }
    actual_pack_paths = {path.stem: path for path in projection.pack_paths}
    assert set(actual_pack_paths) == set(expected_packs)
    for pack_id, pack in expected_packs.items():
        payload = actual_pack_paths[pack_id].read_bytes()
        assert payload == canonical_bytes(pack.model_dump(mode="json"))
        assert json.loads(payload) == pack.model_dump(mode="json")


def test_m2_event_to_real_evidence_projection_reload_and_tamper_escalation(
    tmp_path: Path,
) -> None:
    config = load_config(ROOT / "configs" / "demo.yaml")
    run_id = "m2-e2e-success"
    with _stack(tmp_path, run_id=run_id, config=config) as stack:
        result = stack.builder.build_and_publish(_complete_request(stack))
        case_id = result.publication.case.case.case_id
        pack = result.publication.pack

        assert result.publication.created is True
        assert result.publication.case.revision == 2
        assert result.publication.case.case.status == CaseStatus.EVIDENCE_READY
        assert pack.complete is True
        assert pack.closure_report.passed is True
        assert any(ref.kind == ArtifactKind.DETECTION for ref in pack.closure_report.checked_refs)
        assert all(
            crop.local_path is not None and crop.local_path.startswith(f"{run_id}/frames/")
            for crop in pack.crops
        )

        connection = sqlite3.connect(stack.database)
        try:
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM detections WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
                == FRAME_COUNT
            )
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM detections WHERE run_id <> ?",
                    (run_id,),
                ).fetchone()[0]
                == 0
            )
        finally:
            connection.close()

    # Exercise the same physical verification boundary after all workspace handles
    # and in-memory adapter instances from publication have been closed.
    with SecureWorkspace(
        stack.workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as reloaded_workspace:
        reloaded_store = PillowFrameStore(
            run_id=run_id,
            workspace=reloaded_workspace,
            pixels=_Pixels(stack.runtime_frames),
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        reloaded_repository = SQLiteEvidenceRepository(
            stack.database,
            config.storage.busy_timeout_ms,
            verifier=_Verifier(reloaded_store),
            clock=_clock,
        )
        projector = JsonProjector(reloaded_repository, stack.workspace_root)
        projection = projector.project_run(run_id)
        _assert_exact_projection(reloaded_repository, run_id, projection)

        reloaded_case = reloaded_repository.load_case(run_id, case_id)
        reloaded_pack = reloaded_repository.load_pack(run_id, pack.pack_id)
        current = reloaded_repository.verify_current_pack(run_id, pack.pack_id)
        assert reloaded_case == result.publication.case
        assert reloaded_pack == pack
        assert current.passed is True

        target = pack.temporal_crops[0]
        assert target.local_path is not None
        tampered_png = encode_rgb_png(
            target.output_width,
            target.output_height,
            bytes([255]) * target.output_width * target.output_height * 3,
        )
        (stack.workspace_root / Path(target.local_path)).write_bytes(tampered_png)

        before_evidence_counts = _evidence_counts(stack.database, run_id)
        monitor = EvidenceIntegrityMonitor(reloaded_repository)
        tampered = monitor.verify_and_escalate(run_id, pack.pack_id)
        assert tampered.passed is False
        assert ClosureDefectCode.PIXEL_HASH_MISMATCH in {defect.code for defect in tampered.defects}

        escalated = reloaded_repository.load_case(run_id, case_id)
        assert escalated.revision == 3
        assert escalated.case.status == CaseStatus.HUMAN_REVIEW
        assert len(escalated.case.evidence_packs) == 1
        assert dict(escalated.case.timeline[-1].details) == {
            "failure_code": EvidenceFailureCode.MEDIA_INTEGRITY_FAILURE.value
        }
        assert _evidence_counts(stack.database, run_id) == before_evidence_counts
        assert before_evidence_counts["evidence_packs"] == 1
        assert monitor.verify_and_escalate(run_id, pack.pack_id) == tampered
        assert reloaded_repository.load_case(run_id, case_id) == escalated
        assert [entry.action for entry in reloaded_repository.list_audit_entries(run_id)] == [
            AuditAction.CASE_CREATED,
            AuditAction.EVIDENCE_PACK_PUBLISHED,
            AuditAction.CASE_STATE_CHANGED,
        ]
        _assert_audit_chain(reloaded_repository, run_id)

        rebuilt = projector.project_run(run_id)
        _assert_exact_projection(reloaded_repository, run_id, rebuilt)
        rebuilt_case = json.loads(rebuilt.case_paths[0].read_bytes())
        assert rebuilt_case["status"] == CaseStatus.HUMAN_REVIEW.value
        assert len(rebuilt_case["evidence_packs"]) == 1


def test_m2_legal_retention_blocks_current_pixels_without_case_escalation(
    tmp_path: Path,
) -> None:
    config = load_config(ROOT / "configs" / "demo.yaml")
    run_id = "m2-e2e-retention"
    with _stack(tmp_path, run_id=run_id, config=config) as stack:
        publication = stack.builder.build_and_publish(_complete_request(stack)).publication
        case_id = publication.case.case.case_id
        pack_id = publication.pack.pack_id

        purge_results = RetentionCoordinator(
            repository=stack.repository,
            file_ops=SecureRetentionFileOps(stack.workspace),
            max_items=1,
        ).purge_expired(
            run_id,
            expires_before=RECORDED_AT,
            policy_version="retention-v1",
        )
        assert len(purge_results) == 1
        assert purge_results[0].disposition == PurgeDisposition.PURGED

        before_case = stack.repository.load_case(run_id, case_id)
        before_audits = stack.repository.list_audit_entries(run_id)
        report = EvidenceIntegrityMonitor(stack.repository).verify_and_escalate(run_id, pack_id)

        assert report.passed is False
        assert {defect.code for defect in report.defects} == {
            ClosureDefectCode.MEDIA_PURGED_BY_RETENTION
        }
        after_case = stack.repository.load_case(run_id, case_id)
        assert after_case == before_case
        assert after_case.revision == 2
        assert after_case.case.status == CaseStatus.EVIDENCE_READY
        assert stack.repository.list_audit_entries(run_id) == before_audits
        _assert_audit_chain(stack.repository, run_id)


def _assert_prepublication_failure_is_atomic_and_idempotent(
    stack: _Stack,
    request: EvidenceBuildRequest,
    expected_error: type[Exception],
    expected_code: EvidenceFailureCode,
) -> None:
    with pytest.raises(expected_error):
        stack.builder.build_and_publish(request)

    assert stack.repository.list_events(stack.run_id) == (stack.event,)
    snapshot = stack.repository.load_case(
        stack.run_id,
        derive_case_id(stack.event.event_id),
    )
    assert snapshot.revision == 2
    assert snapshot.case.status == CaseStatus.HUMAN_REVIEW
    assert snapshot.case.evidence_packs == ()
    assert len(snapshot.case.timeline) == 1
    timeline = snapshot.case.timeline[0]
    assert timeline.sequence == 0
    assert timeline.action == AuditAction.CASE_STATE_CHANGED.value
    assert timeline.stage == "EVIDENCE"
    assert timeline.object_ref == snapshot.case.case_id
    assert dict(timeline.details) == {"failure_code": expected_code.value}
    assert _evidence_counts(stack.database, stack.run_id) == {
        "evidence_packs": 0,
        "media_assets": 0,
        "evidence_pack_crops": 0,
    }
    audits = stack.repository.list_audit_entries(stack.run_id)
    audit_count = len(audits)
    assert audit_count == 2
    assert [entry.actor for entry in audits] == ["EVIDENCE", "EVIDENCE"]
    assert [entry.action for entry in audits] == [
        AuditAction.CASE_CREATED,
        AuditAction.CASE_STATE_CHANGED,
    ]
    workspace_before_retry = _workspace_fingerprint(stack.workspace_root)

    with pytest.raises(expected_error):
        stack.builder.build_and_publish(request)

    replayed = stack.repository.load_case(stack.run_id, snapshot.case.case_id)
    assert replayed == snapshot
    assert len(stack.repository.list_audit_entries(stack.run_id)) == audit_count
    assert _evidence_counts(stack.database, stack.run_id) == {
        "evidence_packs": 0,
        "media_assets": 0,
        "evidence_pack_crops": 0,
    }
    assert _workspace_fingerprint(stack.workspace_root) == workspace_before_retry
    _assert_audit_chain(stack.repository, stack.run_id)

    projection = JsonProjector(stack.repository, stack.workspace_root).project_run(stack.run_id)
    assert projection.pack_paths == ()
    _assert_exact_projection(stack.repository, stack.run_id, projection)
    projected = json.loads(projection.case_paths[0].read_text(encoding="utf-8"))
    assert projected["status"] == CaseStatus.HUMAN_REVIEW.value
    assert projected["evidence_packs"] == []


def test_real_sqlite_builder_watermark_failure_is_atomic_and_idempotent(
    tmp_path: Path,
) -> None:
    config = load_config(ROOT / "configs" / "demo.yaml")
    with _stack(tmp_path, run_id="m2-e2e-watermark", config=config) as stack:
        request = EvidenceBuildRequest(
            run_id=stack.run_id,
            event=stack.event,
            bundles=stack.bundles[:150],
            crop_contexts=_contexts(),
            available_end_frame_exclusive=150,
            complete=False,
        )
        _assert_prepublication_failure_is_atomic_and_idempotent(
            stack,
            request,
            EvidenceMissing,
            EvidenceFailureCode.EVIDENCE_MISSING,
        )


def test_real_sqlite_builder_privacy_failure_is_atomic_and_idempotent(
    tmp_path: Path,
) -> None:
    base = load_config(ROOT / "configs" / "demo.yaml")
    config = base.model_copy(
        update={
            "evidence": base.evidence.model_copy(
                update={"privacy_policy": PrivacyPolicy.FULL_REDACTION}
            )
        }
    )
    with _stack(tmp_path, run_id="m2-e2e-privacy", config=config) as stack:
        _assert_prepublication_failure_is_atomic_and_idempotent(
            stack,
            _complete_request(stack),
            PrivacyPolicyViolation,
            EvidenceFailureCode.PRIVACY_POLICY_UNSATISFIED,
        )
