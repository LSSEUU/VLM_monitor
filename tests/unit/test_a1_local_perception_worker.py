from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from labcourt.adapters.perception.local_worker import (
    CachedPerceptionWorkerTransport,
    JsonlPerceptionWorkerClient,
    LocalWorkerPerceptionProvider,
    PerceptionWorkerExchange,
    WorkerResult,
    map_perception_worker_detections,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.frames import FrameData, FrameRef
from labcourt.contracts.manifests import ModelManifest
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionWorkerFailure,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotTrackerThresholds,
    PilotWorkerBox,
    PilotWorkerDetection,
)
from labcourt.exceptions import (
    PerceptionFrameIdentityMismatch,
    PerceptionWorkerCrashed,
    PerceptionWorkerRejected,
    PerceptionWorkerTimeout,
)
from labcourt.perception_worker import (
    GroundingDinoByteTrackBackend,
    _FrameError,
    _RawDetection,
    normalize_grounding_dino_postprocess_result,
    restore_replayed_pose,
    select_trusted_face_keypoints,
    suppress_duplicate_goggle_detections,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256


def _manifest() -> PilotPerceptionExecutionManifest:
    return PilotPerceptionExecutionManifest(
        detector=ModelManifest(
            component="detector",
            provider="HuggingFace",
            model="IDEA-Research/grounding-dino-tiny",
            revision="a2bb814dd30d776dcf7e30523b00659f4f141c71",
            weights_sha256="1a2412ef99bd74bcd3c2a246fa1e48581f8889a1300c9051974741314fc042f3",
            license_id="Apache-2.0",
        ),
        tracker=ModelManifest(
            component="tracker",
            provider="Roboflow",
            model="trackers.ByteTrackTracker",
            revision="2.5.0.post0",
            license_id="Apache-2.0",
        ),
        prompts={
            "person": ("person",),
            "goggles": ("safety goggles", "protective eyewear"),
        },
        device="cpu",
        score_threshold=0.35,
        high_confidence_threshold=0.5,
        bbox_policy="CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1",
        goggles_nms_iou_threshold=0.95,
        tracker_initialization_policy="ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1",
        tracker_thresholds=PilotTrackerThresholds(
            track_activation_threshold=0.25,
            lost_track_buffer=30,
            minimum_iou_threshold=0.1,
            minimum_consecutive_frames=1,
        ),
        software_versions={
            "torch": "2.8.0+cpu",
            "transformers": "5.14.1",
            "trackers": "2.5.0.post0",
            "supervision": "0.29.1",
            "pillow": "12.3.0",
        },
    )


def _frame() -> RGB8Frame:
    width = 20
    height = 12
    pixels = bytes(index % 251 for index in range(width * height * 3))
    return RGB8Frame(
        frame=FrameRef(
            camera_id="cam-01",
            stream_id="pilot-stream",
            frame_index=4,
            fps_num=25,
            fps_den=1,
            width=width,
            height=height,
            content_sha256=rgb8_pixel_sha256(width, height, pixels),
        ),
        pixels=pixels,
    )


class _Pixels:
    def __init__(self, frame: RGB8Frame) -> None:
        self.frame = frame

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        assert frame_id == self.frame.frame.frame_id
        return self.frame


class _FakeTransport:
    def __init__(self, manifest: PilotPerceptionExecutionManifest) -> None:
        self.manifest = manifest
        self.frame_id_override: str | None = None
        self.failure = False

    def exchange(self, request: PilotPerceptionWorkerRequest) -> WorkerResult:
        common = {
            "request_id": request.request_id,
            "frame_id": self.frame_id_override or request.frame_id,
            "frame_content_sha256": request.frame_content_sha256,
            "manifest_id": self.manifest.manifest_id,
        }
        if self.failure:
            return PilotPerceptionWorkerFailure(**common, error_code="INFERENCE_FAILED")
        return PilotPerceptionWorkerResponse(
            **common,
            detections=(
                PilotWorkerDetection(
                    label="person",
                    source_label="person",
                    bbox=PilotWorkerBox(x1=1.2, y1=2.1, x2=18.0, y2=11.0),
                    score=0.91,
                    local_track_id="42",
                ),
                PilotWorkerDetection(
                    label="goggles",
                    source_label="safety goggles",
                    bbox=PilotWorkerBox(x1=6.1, y1=2.2, x2=12.6, y2=5.1),
                    score=0.72,
                    local_track_id=None,
                ),
            ),
        )

    def close(self) -> None:
        return None


def test_adapter_maps_real_worker_output_to_existing_detection_contract() -> None:
    frame = _frame()
    manifest = _manifest()
    provider = LocalWorkerPerceptionProvider(
        pixels=_Pixels(frame),
        transport=_FakeTransport(manifest),
        tracker_epoch="epoch-01",
    )

    detections = provider.detect(
        FrameData(frame=frame.frame, media_ref="verified-video/frame-4", ephemeral=True)
    )

    assert [detection.label for detection in detections] == ["person", "goggles"]
    assert detections[0].track_ref == "cam-01:epoch-01:42"
    assert detections[1].track_ref is None
    assert detections[0].bbox.model_dump() == {"x1": 1, "y1": 2, "x2": 18, "y2": 11}
    assert all(
        detection.model_manifest_id == manifest.detector.model_manifest_id
        for detection in detections
    )
    assert len({detection.detection_id for detection in detections}) == 2


def test_pose_keypoints_cross_worker_boundary_with_exact_manifest_provenance() -> None:
    frame = _frame().frame
    pose = ModelManifest(
        component="pose",
        provider="HuggingFace",
        model="usyd-community/vitpose-plus-small",
        revision="0c30b6534bb621af0162b481176742577264e36e",
        weights_sha256="f" * 64,
        license_id="Apache-2.0",
    )
    manifest = _manifest().model_copy(
        update={
            "pose": pose,
            "pose_dataset_index": 0,
            "pose_keypoint_score_threshold": 0.8,
            "pose_minimum_eye_span_ratio": 0.03,
            "pose_maximum_eye_span_ratio": 0.3,
            "pose_keypoint_policy": "DUAL_EYE_SCORE_AND_GEOMETRY_V1",
        }
    )
    worker_detection = PilotWorkerDetection(
        label="person",
        source_label="person",
        bbox=PilotWorkerBox(x1=1.0, y1=1.0, x2=19.0, y2=11.0),
        score=0.9,
        local_track_id="1",
        keypoints=(
            Keypoint(name="left_eye", x=7.0, y=4.0, score=0.91),
            Keypoint(name="right_eye", x=12.0, y=4.0, score=0.92),
        ),
        pose_manifest_id=pose.model_manifest_id,
    )

    mapped = map_perception_worker_detections(
        frame=frame,
        manifest=manifest,
        tracker_epoch="epoch-01",
        request_id="request-01",
        detections=(worker_detection,),
    )

    assert mapped[0].keypoints == worker_detection.keypoints
    assert mapped[0].attributes["pose_source"] == pose.model_manifest_id
    assert mapped[0].model_manifest_id == manifest.detector.model_manifest_id


def test_pose_trust_gate_rejects_unclear_or_degenerate_eyes_without_guessing() -> None:
    box = PilotWorkerBox(x1=100.0, y1=20.0, x2=300.0, y2=460.0)
    points = [[150.0 + index, 80.0 + index] for index in range(17)]
    points[1] = [170.0, 90.0]
    points[2] = [190.0, 93.0]
    scores = [0.9] * 17

    trusted = select_trusted_face_keypoints(
        keypoints=points,
        scores=scores,
        person_bbox=box,
        frame_width=640,
        frame_height=480,
        score_threshold=0.8,
        minimum_eye_span_ratio=0.03,
        maximum_eye_span_ratio=0.3,
    )
    assert tuple(keypoint.name for keypoint in trusted) == (
        "nose",
        "left_eye",
        "right_eye",
        "left_ear",
        "right_ear",
    )

    low_score = list(scores)
    low_score[2] = 0.55
    assert not select_trusted_face_keypoints(
        keypoints=points,
        scores=low_score,
        person_bbox=box,
        frame_width=640,
        frame_height=480,
        score_threshold=0.8,
        minimum_eye_span_ratio=0.03,
        maximum_eye_span_ratio=0.3,
    )

    degenerate = [list(point) for point in points]
    degenerate[2] = [171.0, 90.0]
    assert not select_trusted_face_keypoints(
        keypoints=degenerate,
        scores=scores,
        person_bbox=box,
        frame_width=640,
        frame_height=480,
        score_threshold=0.8,
        minimum_eye_span_ratio=0.03,
        maximum_eye_span_ratio=0.3,
    )


def test_pose_cache_replay_restores_verified_keypoints_without_rerunning_model() -> None:
    tracked = PilotWorkerDetection(
        label="person",
        source_label="person",
        bbox=PilotWorkerBox(x1=1.0, y1=2.0, x2=18.0, y2=11.0),
        score=0.91,
        local_track_id="42",
    )
    cached = tracked.model_copy(
        update={
            "keypoints": (
                Keypoint(name="left_eye", x=7.0, y=4.0, score=0.91),
                Keypoint(name="right_eye", x=12.0, y=4.0, score=0.92),
            ),
            "pose_manifest_id": "9" * 64,
        }
    )

    assert restore_replayed_pose((tracked,), (cached,)) == (cached,)

    changed = tracked.model_copy(update={"score": 0.90})
    with pytest.raises(_FrameError, match="TRACKER_FAILED"):
        restore_replayed_pose((changed,), (cached,))


def test_worker_frame_identity_mismatch_is_not_accepted() -> None:
    frame = _frame()
    transport = _FakeTransport(_manifest())
    transport.frame_id_override = "cam-01:pilot-stream:5"
    provider = LocalWorkerPerceptionProvider(
        pixels=_Pixels(frame),
        transport=transport,
        tracker_epoch="epoch-01",
    )
    with pytest.raises(PerceptionFrameIdentityMismatch):
        provider.detect(FrameData(frame=frame.frame, media_ref="verified-video/frame-4"))


def test_explicit_worker_failure_is_not_silently_mapped_to_empty_detections() -> None:
    frame = _frame()
    transport = _FakeTransport(_manifest())
    transport.failure = True
    provider = LocalWorkerPerceptionProvider(
        pixels=_Pixels(frame),
        transport=transport,
        tracker_epoch="epoch-01",
    )
    with pytest.raises(PerceptionWorkerRejected, match="INFERENCE_FAILED"):
        provider.detect(FrameData(frame=frame.frame, media_ref="verified-video/frame-4"))


def _write_worker_script(tmp_path: Path, body: str) -> Path:
    ready = json.dumps(
        {
            "protocol_version": "1.0",
            "kind": "READY",
            "manifest": _manifest().model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    path = tmp_path / "fake_worker.py"
    path.write_text(
        "import sys, time\n"
        f"print({ready!r}, flush=True)\n"
        "request = sys.stdin.buffer.readline()\n"
        f"{body}\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def _client(script: Path, *, timeout: float = 0.2) -> JsonlPerceptionWorkerClient:
    return JsonlPerceptionWorkerClient(
        command=(sys.executable, "-u", str(script)),
        expected_manifest=_manifest(),
        startup_timeout_seconds=2.0,
        frame_timeout_seconds=timeout,
        max_request_bytes=1024,
        max_response_bytes=1024 * 1024,
    )


def _small_request() -> PilotPerceptionWorkerRequest:
    return PilotPerceptionWorkerRequest(
        request_id="request-1",
        frame_id="cam-01:pilot-stream:1",
        frame_content_sha256="1" * 64,
        fps_num=25,
        fps_den=1,
        width=1,
        height=1,
        image_sha256="2" * 64,
        image_base64="cG5n",
        expected_manifest_id=_manifest().manifest_id,
    )


def test_jsonl_worker_timeout_kills_the_child_and_returns_typed_failure(tmp_path: Path) -> None:
    script = _write_worker_script(tmp_path, "time.sleep(30)")
    with _client(script, timeout=0.05) as client, pytest.raises(PerceptionWorkerTimeout):
        client.exchange(_small_request())


def test_jsonl_worker_crash_returns_typed_failure(tmp_path: Path) -> None:
    script = _write_worker_script(tmp_path, "sys.exit(7)")
    with _client(script) as client, pytest.raises(PerceptionWorkerCrashed):
        client.exchange(_small_request())


class _RawFakeTransport:
    def __init__(self) -> None:
        self.manifest = _manifest()
        self.calls = 0
        self.modes: list[str] = []

    def exchange_with_raw(
        self,
        request: PilotPerceptionWorkerRequest,
    ) -> PerceptionWorkerExchange:
        self.calls += 1
        self.modes.append(request.mode)
        result = PilotPerceptionWorkerResponse(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=request.expected_manifest_id,
            detections=request.replay_detections,
        )
        raw = canonical_json(result.model_dump(mode="json")).encode("utf-8")
        return PerceptionWorkerExchange(result=result, raw_response=raw)

    def close(self) -> None:
        return None


def test_worker_responses_are_cached_with_raw_response_receipts(tmp_path: Path) -> None:
    raw_transport = _RawFakeTransport()
    request = _small_request()
    with SecureWorkspace(tmp_path, max_file_bytes=1024 * 1024) as workspace:
        cached = CachedPerceptionWorkerTransport(
            transport=raw_transport,
            workspace=workspace,
            run_id="pilot-001",
        )
        assert cached.exchange(request).status == "SUCCEEDED"
        assert raw_transport.calls == 1
        assert raw_transport.modes == ["INFER"]
        assert cached.receipts[0].cache_hit is False

        assert cached.exchange(request).status == "SUCCEEDED"
        assert raw_transport.calls == 2
        assert raw_transport.modes == ["INFER", "REPLAY"]
        receipt = cached.receipts[0]
        assert receipt.cache_hit is True
        assert receipt.raw_response_ref == "runs/pilot-001/raw/perception/request-1.json"
        assert len(receipt.raw_response_sha256) == 64


class _Vector(list[float]):
    def tolist(self) -> list[float]:
        return list(self)


class _NewTracklet:
    def __init__(self, box: _Vector) -> None:
        self.tracker_id = -1
        self._box = box

    def get_state_bbox(self) -> _Vector:
        return self._box


class _NewTrackTracker:
    def __init__(self, tracklet: _NewTracklet) -> None:
        self.tracks = [tracklet]
        self.next_id = 1

    def _allocate_tracker_id(self) -> int:
        allocated = self.next_id
        self.next_id += 1
        return allocated


class _TrackedResult:
    def __init__(self, box: _Vector) -> None:
        self.xyxy = [box]
        self.confidence = [0.9]


def test_pinned_bytetrack_first_detection_receives_a_stable_anonymous_id() -> None:
    box = _Vector([1.0, 2.0, 10.0, 11.0])
    tracklet = _NewTracklet(box)
    tracker = _NewTrackTracker(tracklet)
    tracked = _TrackedResult(box)
    tracker_ids = [-1]
    backend = object.__new__(GroundingDinoByteTrackBackend)
    backend._score_threshold = 0.35

    backend._allocate_first_frame_ids(tracker, tracked, tracker_ids)

    assert tracker_ids == [1]
    assert tracklet.tracker_id == 1


def test_exact_transformers_empty_text_label_sentinel_maps_to_no_detections() -> None:
    boxes: list[object] = []
    scores: list[object] = []

    normalized = normalize_grounding_dino_postprocess_result(
        {
            "boxes": boxes,
            "scores": scores,
            "text_labels": [""],
        }
    )

    assert normalized == (boxes, scores, ())


@pytest.mark.parametrize(
    "labels",
    (["goggles"], ["", ""]),
)
def test_other_postprocess_length_mismatches_still_fail_closed(labels: list[str]) -> None:
    with pytest.raises(_FrameError, match="INFERENCE_FAILED"):
        normalize_grounding_dino_postprocess_result(
            {
                "boxes": [],
                "scores": [],
                "text_labels": labels,
            }
        )


def test_goggles_nms_keeps_highest_overlap_and_preserves_distinct_boxes() -> None:
    person = _RawDetection(
        label="person",
        source_label="person",
        bbox=(0.0, 0.0, 20.0, 30.0),
        score=0.9,
    )
    stronger = _RawDetection(
        label="goggles",
        source_label="safety goggles",
        bbox=(4.0, 3.0, 12.0, 8.0),
        score=0.8,
    )
    duplicate = _RawDetection(
        label="goggles",
        source_label="protective eyewear",
        bbox=(4.05, 3.0, 12.05, 8.0),
        score=0.7,
    )
    distinct = _RawDetection(
        label="goggles",
        source_label="protective eyewear",
        bbox=(30.0, 3.0, 38.0, 8.0),
        score=0.6,
    )

    result = suppress_duplicate_goggle_detections(
        (duplicate, person, distinct, stronger),
        iou_threshold=0.95,
    )

    assert result == (person, stronger, distinct)


@pytest.mark.parametrize("threshold", (-0.1, 1.1, float("nan"), True))
def test_goggles_nms_rejects_invalid_thresholds(threshold: object) -> None:
    with pytest.raises(_FrameError, match="INFERENCE_FAILED"):
        suppress_duplicate_goggle_detections((), iou_threshold=threshold)  # type: ignore[arg-type]
