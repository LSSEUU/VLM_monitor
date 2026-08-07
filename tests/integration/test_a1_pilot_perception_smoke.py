from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

import pytest

from labcourt.adapters.perception.local_worker import PerceptionWorkerExchange
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotWorkerBox,
    PilotWorkerDetection,
)
from labcourt.services.pilot_operations import (
    build_expected_perception_manifest,
    build_pilot_run_request,
    run_pilot_perception,
)

PROJECT_ROOT = Path(__file__).parents[2]


def _cv2() -> Any:
    pytest.importorskip("cv2")
    providers = importlib.metadata.packages_distributions().get("cv2", [])
    if providers != ["opencv-python-headless"]:
        pytest.skip("smoke test requires only the pinned headless OpenCV distribution")
    import cv2

    return cv2


def _write_short_mp4(path: Path) -> None:
    cv2 = _cv2()
    import numpy as np

    writer = cv2.VideoWriter(
        str(path),
        cv2.VideoWriter_fourcc(*"mp4v"),
        5.0,
        (64, 48),
    )
    if not writer.isOpened():
        pytest.skip("local OpenCV build cannot encode the MP4 smoke fixture")
    try:
        for index in range(3):
            frame = np.zeros((48, 64, 3), dtype=np.uint8)
            frame[:, :, 0] = 30 + index * 20
            frame[8:42, 18:46, 1] = 180
            writer.write(frame)
    finally:
        writer.release()
    assert path.stat().st_size > 0


class _TrackingFakeWorker:
    def __init__(self, manifest: PilotPerceptionExecutionManifest) -> None:
        self.manifest = manifest
        self.calls: list[str] = []
        self.closed = False

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
                    bbox=PilotWorkerBox(x1=18.0, y1=8.0, x2=46.0, y2=42.0),
                    score=0.92,
                    local_track_id="1",
                ),
                PilotWorkerDetection(
                    label="goggles",
                    source_label="safety goggles",
                    bbox=PilotWorkerBox(x1=25.0, y1=10.0, x2=39.0, y2=18.0),
                    score=0.81,
                    local_track_id=None,
                ),
            )
        result = PilotPerceptionWorkerResponse(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=request.expected_manifest_id,
            detections=detections,
        )
        raw = canonical_json(result.model_dump(mode="json")).encode("utf-8")
        return PerceptionWorkerExchange(result=result, raw_response=raw)

    def close(self) -> None:
        self.closed = True


@pytest.mark.video
def test_short_real_mp4_produces_frame_bundles_manifest_receipts_and_preview(
    tmp_path: Path,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    video = tmp_path / "inputs" / "short.mp4"
    _write_short_mp4(video)
    config_path = PROJECT_ROOT / "configs" / "pilot.yaml"
    config = load_config(config_path)
    request = build_pilot_run_request(
        config=config,
        run_id="pilot-smoke",
        video_path=Path("inputs/short.mp4"),
        project_root=tmp_path,
        resume=True,
    )
    worker = _TrackingFakeWorker(build_expected_perception_manifest(config))

    report = run_pilot_perception(
        config=config,
        request=request,
        config_path=config_path,
        project_root=tmp_path,
        raw_transport=worker,
    )

    assert report.frames_processed == 3
    assert report.detection_count == 6
    assert report.person_count == 3
    assert report.goggles_count == 3
    assert report.track_count == 1
    assert report.provider_failures == 0
    assert worker.calls == ["INFER", "INFER", "INFER"]
    assert worker.closed
    run = tmp_path / "runs" / "pilot-smoke"
    assert (run / "input" / "video-manifest.json").is_file()
    assert (run / "perception" / "execution-manifest.json").is_file()
    assert len((run / "perception" / "frame-bundles.jsonl").read_text().splitlines()) == 3
    assert len((run / "perception" / "frame-receipts.jsonl").read_text().splitlines()) == 3
    assert (run / "debug" / "perception-preview.mp4").stat().st_size > 0

    unused_worker = _TrackingFakeWorker(build_expected_perception_manifest(config))
    resumed = run_pilot_perception(
        config=config,
        request=request,
        config_path=config_path,
        project_root=tmp_path,
        raw_transport=unused_worker,
    )
    assert resumed == report
    assert unused_worker.calls == []
