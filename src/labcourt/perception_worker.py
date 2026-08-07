"""Standalone Grounding DINO + ByteTrack JSONL worker for the v0.2 pilot.

This module is intentionally launched by a separate Python environment. Heavy
model/tracking packages are imported only after strict config validation, so the
default LabCourt process remains CPU-only and offline-capable.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import importlib.metadata
import json
import math
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, NoReturn, cast

from PIL import Image
from pydantic import ValidationError

from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig, PerceptionWorkerConfig
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionWorkerFailure,
    PilotPerceptionWorkerReady,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotPerceptionWorkerStartupFailure,
    PilotWorkerBox,
    PilotWorkerDetection,
)
from labcourt.contracts.references import parse_frame_id
from labcourt.ports.pixels import rgb8_pixel_sha256


class _StartupError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _FrameError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _float_box_iou(
    first: tuple[float, float, float, float],
    second: tuple[float, float, float, float],
) -> float:
    x1 = max(first[0], second[0])
    y1 = max(first[1], second[1])
    x2 = min(first[2], second[2])
    y2 = min(first[3], second[3])
    intersection = max(0.0, x2 - x1) * max(0.0, y2 - y1)
    first_area = (first[2] - first[0]) * (first[3] - first[1])
    second_area = (second[2] - second[0]) * (second[3] - second[1])
    union = first_area + second_area - intersection
    return intersection / union if union > 0 else 0.0


def _box4_from_array(value: Any) -> tuple[float, float, float, float]:
    try:
        raw = value.tolist()
        if len(raw) != 4:
            raise ValueError
        return (float(raw[0]), float(raw[1]), float(raw[2]), float(raw[3]))
    except (AttributeError, TypeError, ValueError):
        raise _FrameError("TRACKER_FAILED") from None


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _strict_json_object(raw: bytes) -> Mapping[str, object]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError):
        raise _FrameError("REQUEST_INVALID") from None
    if not isinstance(parsed, dict):
        raise _FrameError("REQUEST_INVALID")
    return cast(Mapping[str, object], parsed)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise _StartupError("MODEL_LOAD_FAILED") from None
    return digest.hexdigest()


def _distribution_versions(config: PerceptionWorkerConfig) -> dict[str, str]:
    observed: dict[str, str] = {}
    for package, expected in config.required_software_versions.items():
        distribution = "Pillow" if package == "pillow" else package
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            raise _StartupError("DEPENDENCY_INVALID") from None
        if version != expected:
            raise _StartupError("DEPENDENCY_INVALID")
        observed[package] = version
    return observed


def _execution_manifest(
    config: AppConfig,
    software_versions: dict[str, str],
) -> PilotPerceptionExecutionManifest:
    perception = config.perception
    worker = perception.worker
    detector = perception.detector_manifest
    tracker = perception.tracker_manifest
    thresholds = perception.tracker_thresholds
    if worker is None or detector is None or tracker is None or thresholds is None:
        raise _StartupError("CONFIG_INVALID")
    return PilotPerceptionExecutionManifest(
        protocol_version=worker.protocol_version,
        detector=detector,
        tracker=tracker,
        prompts={
            "person": perception.detector.prompts["person"],
            "goggles": perception.detector.prompts["goggles"],
        },
        device=worker.device,
        score_threshold=perception.detector.score_threshold,
        high_confidence_threshold=perception.detector.high_confidence_threshold,
        bbox_policy="CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1",
        tracker_initialization_policy="ALLOCATE_ON_FIRST_ACCEPTED_DETECTION_V1",
        tracker_thresholds=thresholds,
        software_versions=software_versions,
    )


@dataclass(frozen=True, slots=True)
class _RawDetection:
    label: str
    source_label: str
    bbox: tuple[float, float, float, float]
    score: float


class GroundingDinoByteTrackBackend:
    """Pinned local backend; model labels remain an exact closed mapping."""

    def __init__(self, config: AppConfig) -> None:
        perception = config.perception
        worker = perception.worker
        detector = perception.detector_manifest
        tracker_thresholds = perception.tracker_thresholds
        if worker is None or detector is None or tracker_thresholds is None:
            raise _StartupError("CONFIG_INVALID")

        software_versions = _distribution_versions(worker)
        try:
            torch = importlib.import_module("torch")
            transformers = importlib.import_module("transformers")
            trackers = importlib.import_module("trackers")
            supervision = importlib.import_module("supervision")
            numpy = importlib.import_module("numpy")
        except ImportError:
            raise _StartupError("DEPENDENCY_INVALID") from None

        if worker.device.startswith("cuda"):
            try:
                cuda_available = bool(torch.cuda.is_available())
                device_count = int(torch.cuda.device_count())
                device_index = int(worker.device.split(":", 1)[1]) if ":" in worker.device else 0
            except (AttributeError, TypeError, ValueError):
                raise _StartupError("DEVICE_UNAVAILABLE") from None
            if not cuda_available or device_index >= device_count:
                raise _StartupError("DEVICE_UNAVAILABLE")

        try:
            cached_file = transformers.utils.hub.cached_file
            weight_path = cached_file(
                detector.model,
                "model.safetensors",
                revision=detector.revision,
                local_files_only=worker.local_files_only,
            )
        except Exception:
            raise _StartupError("MODEL_LOAD_FAILED") from None
        if not isinstance(weight_path, str) or not weight_path:
            raise _StartupError("MODEL_LOAD_FAILED")
        if _file_sha256(Path(weight_path)) != detector.weights_sha256:
            raise _StartupError("WEIGHT_IDENTITY_MISMATCH")

        try:
            processor = transformers.AutoProcessor.from_pretrained(
                detector.model,
                revision=detector.revision,
                local_files_only=worker.local_files_only,
            )
        except Exception:
            raise _StartupError("MODEL_LOAD_FAILED") from None

        aliases: dict[str, str] = {}
        prompt_batches: list[tuple[str, list[list[str]]]] = []
        for canonical_label in ("person", "goggles"):
            canonical_prompts: list[str] = []
            for prompt in perception.detector.prompts[canonical_label]:
                if prompt in aliases:
                    raise _StartupError("CONFIG_INVALID")
                aliases[prompt] = canonical_label
                canonical_prompts.append(prompt)
            prompt_batches.append((canonical_label, [canonical_prompts]))

        self.manifest = _execution_manifest(config, software_versions)
        self._aliases = aliases
        self._detector_model = detector.model
        self._detector_revision = detector.revision
        self._prompt_batches = tuple(prompt_batches)
        self._local_files_only = worker.local_files_only
        self._model: Any | None = None
        self._numpy = numpy
        self._processor = processor
        self._score_threshold = perception.detector.score_threshold
        self._supervision = supervision
        self._torch = torch
        self._tracker_class = trackers.ByteTrackTracker
        self._tracker_thresholds = tracker_thresholds
        self._transformers = transformers
        self._tracker: Any | None = None
        self._stream_identity: tuple[str, str, int, int] | None = None
        self._next_frame_index = 0

    def _ensure_model(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            model = self._transformers.AutoModelForZeroShotObjectDetection.from_pretrained(
                self._detector_model,
                revision=self._detector_revision,
                local_files_only=self._local_files_only,
                use_safetensors=True,
            )
            model = model.to(self.manifest.device)
            model.eval()
        except Exception:
            raise _FrameError("INFERENCE_FAILED") from None
        self._model = model
        return model

    def _decode_image(self, request: PilotPerceptionWorkerRequest) -> Image.Image:
        try:
            media = base64.b64decode(request.image_base64, validate=True)
        except (ValueError, TypeError):
            raise _FrameError("IMAGE_INVALID") from None
        if hashlib.sha256(media).hexdigest() != request.image_sha256:
            raise _FrameError("IMAGE_INVALID")
        try:
            image = Image.open(BytesIO(media))
            image.load()
        except (OSError, ValueError):
            raise _FrameError("IMAGE_INVALID") from None
        if (
            image.format != "PNG"
            or image.mode != "RGB"
            or image.size != (request.width, request.height)
        ):
            raise _FrameError("IMAGE_INVALID")
        pixels = image.tobytes()
        if rgb8_pixel_sha256(request.width, request.height, pixels) != (
            request.frame_content_sha256
        ):
            raise _FrameError("IMAGE_INVALID")
        return image

    def _validate_sequence(self, request: PilotPerceptionWorkerRequest) -> None:
        try:
            camera_id, stream_id, frame_index = parse_frame_id(request.frame_id)
        except (TypeError, ValueError):
            raise _FrameError("REQUEST_INVALID") from None
        identity = (camera_id, stream_id, request.fps_num, request.fps_den)
        if self._stream_identity is None:
            if frame_index != 0:
                raise _FrameError("REQUEST_INVALID")
            self._stream_identity = identity
            frame_rate = request.fps_num / request.fps_den
            thresholds = self._tracker_thresholds
            try:
                self._tracker = self._tracker_class(
                    lost_track_buffer=thresholds.lost_track_buffer,
                    frame_rate=frame_rate,
                    track_activation_threshold=thresholds.track_activation_threshold,
                    minimum_consecutive_frames=thresholds.minimum_consecutive_frames,
                    minimum_iou_threshold=thresholds.minimum_iou_threshold,
                    high_conf_det_threshold=self._score_threshold,
                )
            except Exception:
                raise _FrameError("TRACKER_FAILED") from None
        if identity != self._stream_identity or frame_index != self._next_frame_index:
            raise _FrameError("REQUEST_INVALID")

    def _infer_raw(self, image: Image.Image) -> tuple[_RawDetection, ...]:
        model = self._ensure_model()
        detections: list[_RawDetection] = []
        for canonical_label, prompt_batch in self._prompt_batches:
            try:
                inputs = self._processor(
                    images=image,
                    text=prompt_batch,
                    return_tensors="pt",
                ).to(self.manifest.device)
                with self._torch.inference_mode():
                    outputs = model(**inputs)
                results = self._processor.post_process_grounded_object_detection(
                    outputs,
                    inputs.input_ids,
                    threshold=self._tracker_thresholds.track_activation_threshold,
                    text_threshold=self._tracker_thresholds.track_activation_threshold,
                    target_sizes=[(image.height, image.width)],
                )
                result = results[0]
                boxes = result["boxes"]
                scores = result["scores"]
                labels = result["text_labels"]
            except Exception:
                raise _FrameError("INFERENCE_FAILED") from None
            if not (len(boxes) == len(scores) == len(labels)):
                raise _FrameError("INFERENCE_FAILED")

            for box_value, score_value, source_label_value in zip(
                boxes,
                scores,
                labels,
                strict=True,
            ):
                try:
                    source_label = str(source_label_value)
                    box_items = tuple(float(value) for value in box_value.tolist())
                    score = float(score_value.item())
                except (AttributeError, TypeError, ValueError):
                    raise _FrameError("INFERENCE_FAILED") from None
                if (
                    not source_label
                    or len(source_label) > 128
                    or len(box_items) != 4
                    or not all(math.isfinite(value) for value in box_items)
                    or not math.isfinite(score)
                    or not 0 <= score <= 1
                ):
                    raise _FrameError("INFERENCE_FAILED")
                clipped = (
                    min(max(0.0, box_items[0]), float(image.width)),
                    min(max(0.0, box_items[1]), float(image.height)),
                    min(max(0.0, box_items[2]), float(image.width)),
                    min(max(0.0, box_items[3]), float(image.height)),
                )
                if clipped[0] >= clipped[2] or clipped[1] >= clipped[3]:
                    raise _FrameError("INFERENCE_FAILED")
                detections.append(
                    _RawDetection(
                        label=canonical_label,
                        source_label=source_label,
                        bbox=clipped,
                        score=score,
                    )
                )
        return tuple(detections)

    def _track_people(
        self,
        detections: Sequence[_RawDetection],
    ) -> tuple[PilotWorkerDetection, ...]:
        people = [detection for detection in detections if detection.label == "person"]
        try:
            xyxy = self._numpy.asarray([item.bbox for item in people], dtype=self._numpy.float32)
            if not people:
                xyxy = self._numpy.empty((0, 4), dtype=self._numpy.float32)
            confidence = self._numpy.asarray(
                [item.score for item in people],
                dtype=self._numpy.float32,
            )
            tracker = self._tracker
            if tracker is None:
                raise _FrameError("TRACKER_FAILED")
            tracked = tracker.update(self._supervision.Detections(xyxy=xyxy, confidence=confidence))
            tracker_ids = tracked.tracker_id
            if tracker_ids is not None:
                self._allocate_first_frame_ids(tracker, tracked, tracker_ids)
        except Exception:
            raise _FrameError("TRACKER_FAILED") from None
        if tracker_ids is None or len(tracker_ids) != len(tracked.xyxy):
            raise _FrameError("TRACKER_FAILED")

        output: list[PilotWorkerDetection] = []
        for box_value, score_value, tracker_id_value in zip(
            tracked.xyxy,
            tracked.confidence,
            tracker_ids,
            strict=True,
        ):
            score = float(score_value)
            if score < self._score_threshold:
                continue
            tracker_id = int(tracker_id_value)
            if tracker_id < 0:
                raise _FrameError("TRACKER_FAILED")
            box = tuple(float(value) for value in box_value.tolist())
            output.append(
                PilotWorkerDetection(
                    label="person",
                    source_label="person",
                    bbox=PilotWorkerBox(
                        x1=box[0],
                        y1=box[1],
                        x2=box[2],
                        y2=box[3],
                    ),
                    score=score,
                    local_track_id=str(tracker_id),
                )
            )
        return tuple(output)

    def _allocate_first_frame_ids(self, tracker: Any, tracked: Any, tracker_ids: Any) -> None:
        """Activate pinned ByteTrack tracks on their first accepted detection.

        Roboflow ByteTrack returns ``-1`` for every newly spawned track even
        when ``minimum_consecutive_frames`` is one. The pilot contract requires
        every emitted person Detection to carry a stable anonymous identity, so
        this pinned adapter allocates ByteTrack's own next ID immediately and
        writes it back to the corresponding new tracklet.
        """

        for index, tracker_id_value in enumerate(tracker_ids):
            if int(tracker_id_value) >= 0 or float(tracked.confidence[index]) < (
                self._score_threshold
            ):
                continue
            box = _box4_from_array(tracked.xyxy[index])
            candidates = [item for item in tracker.tracks if int(item.tracker_id) < 0]
            if not candidates:
                raise _FrameError("TRACKER_FAILED")

            scored = [
                (
                    _float_box_iou(
                        box,
                        _box4_from_array(item.get_state_bbox()),
                    ),
                    -position,
                    item,
                )
                for position, item in enumerate(candidates)
            ]
            score, _, selected = max(scored, key=lambda entry: (entry[0], entry[1]))
            if score < 0.95:
                raise _FrameError("TRACKER_FAILED")
            allocated = int(tracker._allocate_tracker_id())
            selected.tracker_id = allocated
            tracker_ids[index] = allocated

    def infer(self, request: PilotPerceptionWorkerRequest) -> tuple[PilotWorkerDetection, ...]:
        if request.expected_manifest_id != self.manifest.manifest_id:
            raise _FrameError("REQUEST_INVALID")
        self._validate_sequence(request)
        image = self._decode_image(request)
        if request.mode == "INFER":
            raw = self._infer_raw(image)
        else:
            raw = tuple(
                _RawDetection(
                    label=item.label,
                    source_label=item.source_label,
                    bbox=(item.bbox.x1, item.bbox.y1, item.bbox.x2, item.bbox.y2),
                    score=item.score,
                )
                for item in request.replay_detections
            )
        people = self._track_people(raw)
        goggles = tuple(
            PilotWorkerDetection(
                label="goggles",
                source_label=item.source_label,
                bbox=PilotWorkerBox(
                    x1=item.bbox[0],
                    y1=item.bbox[1],
                    x2=item.bbox[2],
                    y2=item.bbox[3],
                ),
                score=item.score,
                local_track_id=None,
            )
            for item in raw
            if item.label == "goggles" and item.score >= self._score_threshold
        )
        if request.mode == "REPLAY" and people + goggles != request.replay_detections:
            raise _FrameError("TRACKER_FAILED")
        self._next_frame_index += 1
        return people + goggles


def _emit(model: object) -> None:
    payload = cast(Any, model).model_dump(mode="json") if hasattr(model, "model_dump") else model
    sys.stdout.write(canonical_json(payload) + "\n")
    sys.stdout.flush()


def _startup_failure(code: str) -> int:
    controlled = (
        code
        if code
        in {
            "CONFIG_INVALID",
            "DEPENDENCY_INVALID",
            "DEVICE_UNAVAILABLE",
            "MODEL_LOAD_FAILED",
            "WEIGHT_IDENTITY_MISMATCH",
        }
        else "MODEL_LOAD_FAILED"
    )
    _emit(PilotPerceptionWorkerStartupFailure(error_code=controlled))
    return 2


def _frame_failure(
    request: PilotPerceptionWorkerRequest,
    manifest: PilotPerceptionExecutionManifest,
    code: str,
) -> None:
    controlled = (
        code
        if code
        in {
            "IMAGE_INVALID",
            "INFERENCE_FAILED",
            "TRACKER_FAILED",
            "REQUEST_INVALID",
        }
        else "INFERENCE_FAILED"
    )
    _emit(
        PilotPerceptionWorkerFailure(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=manifest.manifest_id,
            error_code=controlled,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", required=True)
    try:
        args = parser.parse_args(argv)
        config = load_config(Path(args.config))
        worker_config = config.perception.worker
        if config.perception.provider != "local-worker" or worker_config is None:
            return _startup_failure("CONFIG_INVALID")
        backend = GroundingDinoByteTrackBackend(config)
    except _StartupError as error:
        return _startup_failure(error.code)
    except (OSError, TypeError, ValueError):
        return _startup_failure("CONFIG_INVALID")

    _emit(PilotPerceptionWorkerReady(manifest=backend.manifest))
    while True:
        raw = sys.stdin.buffer.readline(worker_config.max_request_bytes + 2)
        if raw == b"":
            return 0
        if len(raw) > worker_config.max_request_bytes or not raw.endswith(b"\n"):
            return 3
        try:
            request = PilotPerceptionWorkerRequest.model_validate(_strict_json_object(raw[:-1]))
        except (ValidationError, _FrameError):
            return 3
        try:
            detections = backend.infer(request)
        except _FrameError as error:
            _frame_failure(request, backend.manifest, error.code)
            continue
        except Exception:
            _frame_failure(request, backend.manifest, "INFERENCE_FAILED")
            continue
        _emit(
            PilotPerceptionWorkerResponse(
                request_id=request.request_id,
                frame_id=request.frame_id,
                frame_content_sha256=request.frame_content_sha256,
                manifest_id=backend.manifest.manifest_id,
                detections=detections,
            )
        )


if __name__ == "__main__":
    raise SystemExit(main())
