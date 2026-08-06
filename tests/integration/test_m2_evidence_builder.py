from __future__ import annotations

from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from labcourt.adapters.pillow_frame_store import PillowFrameStore
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
from labcourt.config_loader import load_config
from labcourt.contracts.detections import Detection, FrameBundle, Keypoint
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    ObservationSource,
)
from labcourt.contracts.events import CandidateEvent
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
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "m2-evidence-build"
FRAME_COUNT = 160
WIDTH = 32
HEIGHT = 24
RECORDED_AT = datetime(2026, 7, 27, 15, 0, 0, tzinfo=UTC)


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
        return self._frames[frame_id]


class _Verifier:
    def __init__(
        self,
        store: PillowFrameStore,
        detection_ids: frozenset[str],
    ) -> None:
        self._store = store
        self._detection_ids = detection_ids

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        return self._store.verify_crop(crop)

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id
        return ref.kind == ArtifactKind.DETECTION and ref.artifact_id in self._detection_ids


def _manifest() -> RunManifest:
    config = load_config(ROOT / "configs" / "demo.yaml")
    base = RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    component = SoftwareComponentManifest(
        component="synthetic-decoder",
        package="labcourt-test-video",
        version="1.0.0",
        license_id="synthetic-fixture",
    )
    pillow_component = SoftwareComponentManifest(
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
        software_component=component.component,
        library=component.package,
        library_version=component.version,
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
                component.component: component,
                pillow_component.component: pillow_component,
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
    scores = {10: 0.91, 80: 0.82, 140: 0.42}
    return tuple(
        FrameCropContext(
            frame_id=f"cam-01:demo-absence:{frame_index}",
            observability=_observability(score),
        )
        for frame_index, score in scores.items()
    )


def _bundles(
    manifest: RunManifest,
    runtime_frames: tuple[RGB8Frame, ...],
) -> tuple[FrameBundle, ...]:
    detector_manifest_id = manifest.models["detector"].model_manifest_id
    track_ref = "cam-01:epoch-01:person-01"
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
                    track_ref=track_ref,
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


def test_incomplete_then_complete_evidence_is_published_and_replay_idempotent(
    tmp_path: Path,
) -> None:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = _manifest()
    event = _event(manifest)
    runtime_frames = _runtime_frames()
    bundles = _bundles(manifest, runtime_frames)
    detection_ids = frozenset(
        detection.detection_id for bundle in bundles for detection in bundle.detections
    )

    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, config.storage.busy_timeout_ms, clock=_clock).apply_all()

    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        store = PillowFrameStore(
            run_id=RUN_ID,
            workspace=workspace,
            pixels=_Pixels(runtime_frames),
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        repository = SQLiteEvidenceRepository(
            database,
            config.storage.busy_timeout_ms,
            verifier=_Verifier(store, detection_ids),
            clock=_clock,
        )
        builder = EvidenceBuilder(
            config=config,
            manifest=manifest,
            frame_store=store,
            repository=repository,
        )

        incomplete = builder.build_and_publish(
            EvidenceBuildRequest(
                run_id=RUN_ID,
                event=event,
                bundles=tuple(bundle for bundle in bundles if bundle.frame.frame_index < 152),
                crop_contexts=_contexts(),
                available_end_frame_exclusive=152,
                complete=False,
            )
        )
        complete = builder.build_and_publish(
            EvidenceBuildRequest(
                run_id=RUN_ID,
                event=event,
                bundles=bundles,
                crop_contexts=_contexts(),
                available_end_frame_exclusive=160,
                complete=True,
            )
        )
        replay = builder.build_and_publish(
            EvidenceBuildRequest(
                run_id=RUN_ID,
                event=event,
                bundles=bundles,
                crop_contexts=_contexts(),
                available_end_frame_exclusive=160,
                complete=True,
            )
        )

        reloaded = repository.load_case(RUN_ID, complete.publication.case.case.case_id)
        reloaded_pack = repository.load_pack(
            RUN_ID,
            complete.publication.pack.pack_id,
        )

    assert incomplete.publication.created is True
    assert incomplete.publication.pack.version == 1
    assert incomplete.publication.case.case.status == CaseStatus.CANDIDATE
    assert incomplete.publication.pack.complete is False
    assert len(incomplete.publication.pack.panorama_crops) == 1
    assert len(incomplete.publication.pack.subject_crops) == 1
    assert len(incomplete.publication.pack.temporal_crops) == 3

    assert complete.publication.created is True
    assert complete.publication.pack.version == 2
    assert complete.publication.case.case.status == CaseStatus.EVIDENCE_READY
    assert complete.publication.pack.complete is True
    assert complete.publication.pack.closure_report.passed is True
    assert complete.publication.pack.observation_sufficiency_input is not None
    assert len(complete.publication.pack.observation_sufficiency_input.clear_crop_ids) == 2
    assert len(complete.publication.pack.observation_sufficiency_input.unclear_crop_ids) == 1

    assert replay.publication.created is False
    assert replay.publication.pack == complete.publication.pack
    assert replay.publication.case.revision == complete.publication.case.revision
    assert reloaded.case.status == CaseStatus.EVIDENCE_READY
    assert len(reloaded.case.evidence_packs) == 2
    assert reloaded_pack == complete.publication.pack
