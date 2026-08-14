"""One-shot real Grounding DINO adapter for M8 high-resolution redetection."""

from __future__ import annotations

import base64
import hashlib
import math
import os
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from typing import Literal, TypeAlias

from PIL import Image

from labcourt.adapters.perception.local_worker import (
    JsonlPerceptionWorkerClient,
    RawPerceptionWorkerTransport,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing_common import MAX_ACQUISITION_RETURNED_FRAMES
from labcourt.contracts.m8_acquisition_v2 import (
    M8RedetectionCandidateV1,
    M8RedetectionDetectorRequestV1,
    M8RedetectionOutcomeV1,
)
from labcourt.contracts.pilot import (
    PilotPerceptionWorkerFailure,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotWorkerDetection,
)
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.exceptions import (
    PerceptionFrameIdentityMismatch,
    PerceptionWorkerCrashed,
    PerceptionWorkerProtocolViolation,
    PerceptionWorkerRejected,
    PerceptionWorkerTimeout,
)
from labcourt.ports.pixels import rgb8_pixel_sha256
from labcourt.services.pilot_operations import build_expected_perception_manifest

_ErrorCode: TypeAlias = Literal[
    "IMAGE_INVALID",
    "INFERENCE_FAILED",
    "REQUEST_INVALID",
    "MODEL_UNAVAILABLE",
]
_TransportFactory: TypeAlias = Callable[[], RawPerceptionWorkerTransport]


class M8GroundingDinoRedetector:
    """Run the pinned Pilot worker over one privacy-transformed crop.

    A fresh transport is created and closed for every call.  ``recover`` uses
    the exact same conversion and therefore performs a deterministic rerun
    without introducing an in-memory result authority.
    """

    def __init__(
        self,
        *,
        project_root: Path,
        config_path: Path | None = None,
        raw_transport_factory: _TransportFactory | None = None,
    ) -> None:
        root = project_root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Grounding DINO project root must be a directory")
        selected_config = (
            root / "configs" / "pilot.yaml" if config_path is None else config_path
        ).resolve(strict=True)
        config = load_config(selected_config)
        worker = config.perception.worker
        if worker is None:
            raise ValueError("Pilot perception worker configuration is unavailable")
        manifest = build_expected_perception_manifest(config)
        self._project_root = root
        self._config_path = selected_config
        self._manifest = manifest
        self._max_image_pixels = config.storage.max_image_pixels
        self._max_request_bytes = worker.max_request_bytes
        self._raw_transport_factory = raw_transport_factory
        self._worker_config = worker
        # Resolve the isolated runtime lazily.  Reading a completed hearing
        # must remain available even when the optional acquisition worker is
        # temporarily offline; execution then returns a typed unavailable result.
        self._worker_python: str | None = None
        self._component_manifest_id = sha256_hex(
            [
                "m8-grounding-dino-redetection-adapter",
                1,
                manifest.manifest_id,
                "ONE_SHOT_WORKER_PER_REQUEST_V1",
                "CLIP_TO_FRAME_THEN_FLOOR_CEIL_V1",
            ]
        )

    @property
    def component_manifest_id(self) -> str:
        return self._component_manifest_id

    @property
    def model_manifest_id(self) -> str:
        return self._manifest.detector.model_manifest_id

    def execute(
        self,
        request: M8RedetectionDetectorRequestV1,
        *,
        idempotency_key: str,
    ) -> bytes:
        return self._run(request, idempotency_key=idempotency_key)

    def recover(
        self,
        request: M8RedetectionDetectorRequestV1,
        *,
        idempotency_key: str,
    ) -> bytes:
        return self._run(request, idempotency_key=idempotency_key)

    def _run(
        self,
        request: M8RedetectionDetectorRequestV1,
        *,
        idempotency_key: str,
    ) -> bytes:
        if not isinstance(request, M8RedetectionDetectorRequestV1):
            raise TypeError("redetection requires a typed M8 detector request")
        if (
            idempotency_key != request.request_id
            or request.expected_model_manifest_id != self.model_manifest_id
            or not self._prompts_are_supported(request.prompts)
        ):
            return self._failure(request, "REQUEST_INVALID")
        try:
            pixel_sha256 = self._pixel_sha256(request)
        except (OSError, ValueError):
            return self._failure(request, "IMAGE_INVALID")
        worker_request = self._worker_request(request, pixel_sha256)
        encoded = canonical_json(worker_request.model_dump(mode="json")).encode("utf-8") + b"\n"
        if len(encoded) > self._max_request_bytes:
            return self._failure(request, "REQUEST_INVALID")

        transport: RawPerceptionWorkerTransport | None = None
        try:
            transport = self._new_transport()
            if transport.manifest != self._manifest:
                return self._failure(request, "MODEL_UNAVAILABLE")
            exchange = transport.exchange_with_raw(worker_request)
        except (PerceptionWorkerCrashed, PerceptionWorkerRejected, PerceptionWorkerTimeout):
            return self._failure(request, "MODEL_UNAVAILABLE")
        except (PerceptionFrameIdentityMismatch, PerceptionWorkerProtocolViolation):
            return self._failure(request, "INFERENCE_FAILED")
        finally:
            if transport is not None:
                transport.close()

        result = exchange.result
        if not self._worker_identity_matches(result, worker_request):
            return self._failure(request, "INFERENCE_FAILED")
        if isinstance(result, PilotPerceptionWorkerFailure):
            if result.error_code == "IMAGE_INVALID":
                error_code: _ErrorCode = "IMAGE_INVALID"
            elif result.error_code == "REQUEST_INVALID":
                error_code = "REQUEST_INVALID"
            else:
                error_code = "INFERENCE_FAILED"
            return self._failure(request, error_code)
        try:
            detections = self._map_detections(request, result)
        except ValueError:
            return self._failure(request, "INFERENCE_FAILED")
        return self._serialize(
            M8RedetectionOutcomeV1(
                request_id=request.request_id,
                crop_id=request.crop_id,
                crop_media_sha256=request.crop_media_sha256,
                model_manifest_id=self.model_manifest_id,
                status="SUCCEEDED",
                detections=detections,
            )
        )

    def _resolve_worker_python(self) -> str:
        environment_name = self._worker_config.python_executable_env
        configured = os.environ.get(environment_name)
        candidates = ((Path(configured),) if configured else ()) + (
            self._project_root / ".venv-perception" / "Scripts" / "python.exe",
            self._project_root / ".venv-perception" / "bin" / "python",
        )
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved.is_file():
                return str(resolved)
        raise PerceptionWorkerCrashed("isolated perception Python is unavailable")

    def _new_transport(self) -> RawPerceptionWorkerTransport:
        if self._raw_transport_factory is not None:
            return self._raw_transport_factory()
        worker_python = self._worker_python or self._resolve_worker_python()
        self._worker_python = worker_python
        worker = self._worker_config
        return JsonlPerceptionWorkerClient(
            command=(
                worker_python,
                "-u",
                "-m",
                worker.module,
                "--config",
                str(self._config_path),
            ),
            expected_manifest=self._manifest,
            startup_timeout_seconds=worker.startup_timeout_seconds,
            frame_timeout_seconds=worker.frame_timeout_seconds,
            max_request_bytes=worker.max_request_bytes,
            max_response_bytes=worker.max_response_bytes,
        )

    def _prompts_are_supported(self, prompts: tuple[str, ...]) -> bool:
        supported = set(self._manifest.prompts)
        supported.update(
            prompt for configured in self._manifest.prompts.values() for prompt in configured
        )
        return all(prompt in supported for prompt in prompts)

    def _pixel_sha256(self, request: M8RedetectionDetectorRequestV1) -> str:
        raw = base64.b64decode(request.image_base64, validate=True)
        if hashlib.sha256(raw).hexdigest() != request.image_sha256:
            raise ValueError("redetection PNG hash mismatch")
        with Image.open(BytesIO(raw)) as image:
            if (
                image.format != "PNG"
                or image.mode != "RGB"
                or image.size != (request.width, request.height)
                or request.width * request.height > self._max_image_pixels
            ):
                raise ValueError("redetection image violates the Pilot RGB8 boundary")
            image.load()
            pixels = image.tobytes()
        return rgb8_pixel_sha256(request.width, request.height, pixels)

    def _worker_request(
        self,
        request: M8RedetectionDetectorRequestV1,
        pixel_sha256: str,
    ) -> PilotPerceptionWorkerRequest:
        camera_id, _, _ = parse_frame_id(request.frame_id)
        stream_id = require_reference_token(
            f"redetect-{request.request_id[:16]}",
            "redetection worker stream",
        )
        return PilotPerceptionWorkerRequest(
            request_id=request.request_id,
            frame_id=f"{camera_id}:{stream_id}:0",
            frame_content_sha256=pixel_sha256,
            fps_num=1,
            fps_den=1,
            width=request.width,
            height=request.height,
            image_sha256=request.image_sha256,
            image_base64=request.image_base64,
            expected_manifest_id=self._manifest.manifest_id,
        )

    def _worker_identity_matches(
        self,
        result: PilotPerceptionWorkerResponse | PilotPerceptionWorkerFailure,
        request: PilotPerceptionWorkerRequest,
    ) -> bool:
        return (
            result.request_id == request.request_id
            and result.frame_id == request.frame_id
            and result.frame_content_sha256 == request.frame_content_sha256
            and result.manifest_id == request.expected_manifest_id
        )

    def _map_detections(
        self,
        request: M8RedetectionDetectorRequestV1,
        result: PilotPerceptionWorkerResponse,
    ) -> tuple[M8RedetectionCandidateV1, ...]:
        mapped: list[M8RedetectionCandidateV1] = []
        requested = set(request.prompts)
        for detection in result.detections:
            label = self._requested_label(detection, requested)
            if label is None:
                continue
            mapped.append(
                M8RedetectionCandidateV1(
                    label=label,
                    bbox=self._integer_box(
                        detection,
                        width=request.width,
                        height=request.height,
                    ),
                    score=detection.score,
                )
            )
            if len(mapped) > MAX_ACQUISITION_RETURNED_FRAMES:
                raise ValueError("redetection output exceeds the acquisition bound")
        return tuple(mapped)

    @staticmethod
    def _requested_label(
        detection: PilotWorkerDetection,
        requested: set[str],
    ) -> str | None:
        if detection.source_label in requested:
            return detection.source_label
        if detection.label in requested:
            return detection.label
        return None

    @staticmethod
    def _integer_box(
        detection: PilotWorkerDetection,
        *,
        width: int,
        height: int,
    ) -> BBoxXYXY:
        source = detection.bbox
        clipped = (
            min(max(0.0, source.x1), float(width)),
            min(max(0.0, source.y1), float(height)),
            min(max(0.0, source.x2), float(width)),
            min(max(0.0, source.y2), float(height)),
        )
        if clipped[0] >= clipped[2] or clipped[1] >= clipped[3]:
            raise ValueError("redetection bbox becomes empty after clipping")
        return BBoxXYXY(
            x1=math.floor(clipped[0]),
            y1=math.floor(clipped[1]),
            x2=math.ceil(clipped[2]),
            y2=math.ceil(clipped[3]),
        ).require_within(width, height)

    def _failure(
        self,
        request: M8RedetectionDetectorRequestV1,
        error_code: _ErrorCode,
    ) -> bytes:
        return self._serialize(
            M8RedetectionOutcomeV1(
                request_id=request.request_id,
                crop_id=request.crop_id,
                crop_media_sha256=request.crop_media_sha256,
                model_manifest_id=self.model_manifest_id,
                status="FAILED",
                error_code=error_code,
            )
        )

    @staticmethod
    def _serialize(outcome: M8RedetectionOutcomeV1) -> bytes:
        return canonical_json(outcome.model_dump(mode="json")).encode("utf-8")


__all__ = ["M8GroundingDinoRedetector"]
