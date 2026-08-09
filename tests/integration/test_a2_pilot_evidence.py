from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.opencv_video import BGR8Frame, DecoderMetadata
from labcourt.adapters.perception.local_worker import PerceptionWorkerExchange
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection, FrameBundle, Keypoint
from labcourt.contracts.enums import MediaAccess, PrivacyPolicy, PrivacyReasonCode
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotWorkerBox,
    PilotWorkerDetection,
)
from labcourt.exceptions import ManifestMismatch
from labcourt.services.pilot_evidence import _objective_perception_bundles, run_pilot_a2
from labcourt.services.pilot_operations import (
    build_expected_perception_manifest,
    build_pilot_run_request,
)

PROJECT_ROOT = Path(__file__).parents[2]
WIDTH = 64
HEIGHT = 48
FRAME_COUNT = 32
FPS = 5.0


def _bgr_frame(index: int) -> BGR8Frame:
    pixels = bytearray(WIDTH * HEIGHT * 3)
    for y in range(HEIGHT):
        for x in range(WIDTH):
            offset = (y * WIDTH + x) * 3
            pixels[offset] = (x * 3 + index) % 256
            pixels[offset + 1] = (y * 5 + index * 2) % 256
            pixels[offset + 2] = (x + y + index * 7) % 256
    return BGR8Frame(width=WIDTH, height=HEIGHT, pixels=bytes(pixels))


FRAMES = tuple(_bgr_frame(index) for index in range(FRAME_COUNT))


class _Session:
    def __init__(self) -> None:
        self._position = 0

    def metadata(self) -> DecoderMetadata:
        return DecoderMetadata(
            width=float(WIDTH),
            height=float(HEIGHT),
            frame_count=float(FRAME_COUNT),
            fps=FPS,
            backend="FAKE_A2",
            codec="RAWB",
        )

    def read_bgr8(
        self,
        *,
        expected_width: int,
        expected_height: int,
        max_frame_pixels: int,
    ) -> BGR8Frame | None:
        assert (expected_width, expected_height) == (WIDTH, HEIGHT)
        assert max_frame_pixels >= WIDTH * HEIGHT
        if self._position == len(FRAMES):
            return None
        frame = FRAMES[self._position]
        self._position += 1
        return frame

    def close(self) -> None:
        return None


class _Backend:
    software_component = "fake-a2-decoder"
    library = "labcourt-test-video"
    library_version = "1.0.0"
    decoder = "fake-a2-sequential-decoder"
    module_version = "1.0.0"

    def open(self, decoder_path: str) -> _Session:
        assert decoder_path
        return _Session()


class _MissingGogglesWorker:
    def __init__(self, manifest: PilotPerceptionExecutionManifest) -> None:
        self.manifest = manifest
        self.calls: list[str] = []

    def exchange_with_raw(
        self,
        request: PilotPerceptionWorkerRequest,
    ) -> PerceptionWorkerExchange:
        self.calls.append(request.mode)
        detections = request.replay_detections
        if request.mode == "INFER":
            detections = (
                PilotWorkerDetection(
                    label="person",
                    source_label="person",
                    bbox=PilotWorkerBox(x1=10.0, y1=4.0, x2=54.0, y2=44.0),
                    score=0.93,
                    local_track_id="1",
                ),
            )
        response = PilotPerceptionWorkerResponse(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=request.expected_manifest_id,
            detections=detections,
        )
        return PerceptionWorkerExchange(
            result=response,
            raw_response=canonical_json(response.model_dump(mode="json")).encode("utf-8"),
        )

    def close(self) -> None:
        return None


def _pilot_config() -> AppConfig:
    base = load_config(PROJECT_ROOT / "configs" / "pilot.yaml")
    assert base.pilot is not None
    zone = base.zones[0].model_copy(
        update={"polygon": ((0, 0), (WIDTH - 1, 0), (WIDTH - 1, HEIGHT - 1), (0, HEIGHT - 1))}
    )
    return base.model_copy(
        update={
            "pilot": base.pilot.model_copy(update={"write_debug_preview": False}),
            "zones": (zone,),
        }
    )


def test_advisory_pose_is_projected_out_of_objective_perception_without_mutation() -> None:
    frame = FrameRef(
        camera_id="cam-01",
        stream_id="pose-boundary",
        frame_index=0,
        fps_num=5,
        fps_den=1,
        width=WIDTH,
        height=HEIGHT,
        content_sha256="1" * 64,
    )
    detection = Detection(
        detection_id="person-001",
        frame_id=frame.frame_id,
        label="person",
        bbox={"x1": 10, "y1": 4, "x2": 54, "y2": 44},
        score=0.93,
        track_ref="cam-01:epoch-01:1",
        keypoints=(
            Keypoint(name="left_eye", x=22.0, y=12.0, score=0.95),
            Keypoint(name="right_eye", x=36.0, y=12.0, score=0.94),
        ),
        attributes={
            "observation_source": "PIXEL_COMPUTED",
            "pose_source": "9" * 64,
            "source_label": "person",
        },
        model_manifest_id="8" * 64,
    )
    original = FrameBundle(frame=frame, detections=(detection,))

    projected = _objective_perception_bundles((original,))

    assert original.detections[0].keypoints == detection.keypoints
    assert projected[0].detections[0].keypoints == ()
    assert "pose_source" not in projected[0].detections[0].attributes
    assert projected[0].detections[0].detection_id == detection.detection_id


def test_sealed_detections_reach_one_privacy_safe_evidence_ready_case_idempotently(
    tmp_path: Path,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    (tmp_path / "inputs" / "missing.mp4").write_bytes(b"bounded-a2-video")
    config = _pilot_config()
    request = build_pilot_run_request(
        config=config,
        run_id="pilot-a2-missing",
        video_path=Path("inputs/missing.mp4"),
        project_root=tmp_path,
        resume=True,
    )
    worker = _MissingGogglesWorker(build_expected_perception_manifest(config))

    first = run_pilot_a2(
        config=config,
        request=request,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        project_root=tmp_path,
        decoder_backend=_Backend(),
        raw_transport=worker,
        code_commit="test-a2-commit",
    )
    resumed = run_pilot_a2(
        config=config,
        request=request,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        project_root=tmp_path,
        decoder_backend=_Backend(),
        raw_transport=_MissingGogglesWorker(build_expected_perception_manifest(config)),
        code_commit="test-a2-commit",
    )

    assert resumed == first
    assert first.state == "EVIDENCE_READY"
    assert first.frames_processed == FRAME_COUNT
    assert first.association_count == FRAME_COUNT
    assert first.l0_reminder_count == 1
    assert first.candidate_event_count == first.evidence_pack_count == 1
    assert len(worker.calls) == FRAME_COUNT
    summary = first.evidence_packs[0]
    assert summary.panorama_crop_count == 1
    assert summary.subject_crop_count == 1
    assert summary.focus_crop_count == 0
    assert summary.temporal_crop_count == 3
    assert summary.cloud_allowed_crop_count == 0
    assert summary.local_only_crop_count == 5

    run = tmp_path / "runs" / request.run_id
    assert (run / "pilot" / "run-manifest.json").is_file()
    report_bytes = (run / "pilot" / "a2-report.json").read_bytes()
    assert b"track" not in report_bytes
    assert b"reminder" in report_bytes  # aggregate count only, never a reminder body
    assert not tuple(run.rglob("*reminder*"))

    with sqlite3.connect(run / "labcourt.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM cases").fetchone() == (1,)
        assert connection.execute("SELECT status FROM cases").fetchone() == ("EVIDENCE_READY",)
        rows = connection.execute("SELECT pack_json FROM evidence_packs").fetchall()
    assert len(rows) == 1
    pack = EvidencePack.model_validate_json(rows[0][0])
    crops = pack.panorama_crops + pack.subject_crops + pack.temporal_crops
    assert pack.closure_report.passed is True
    assert all(crop.privacy_receipt.media_access == MediaAccess.LOCAL_ONLY for crop in crops)
    assert all(
        crop.privacy_receipt.policy == PrivacyPolicy.FULL_REDACTION
        for crop in pack.panorama_crops + pack.subject_crops
    )
    assert all(
        crop.privacy_receipt.policy == PrivacyPolicy.PPE_PRESERVING_REDACTION
        for crop in pack.temporal_crops
    )
    assert all(
        crop.privacy_receipt.reason_code == PrivacyReasonCode.BODY_FALLBACK_REGION_LOCAL_ONLY
        and crop.privacy_receipt.preserved_regions
        and not crop.privacy_receipt.keypoints
        for crop in pack.temporal_crops
    )
    assert len({crop.media_sha256 for crop in pack.temporal_crops}) == 3

    (run / "pilot" / "run-manifest.json").unlink()
    with pytest.raises(ManifestMismatch):
        run_pilot_a2(
            config=config,
            request=request,
            config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
            project_root=tmp_path,
            decoder_backend=_Backend(),
            raw_transport=_MissingGogglesWorker(build_expected_perception_manifest(config)),
            code_commit="test-a2-commit",
        )
