from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.m8_grounding_dino_redetection import M8GroundingDinoRedetector
from labcourt.adapters.perception.local_worker import PerceptionWorkerExchange
from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m8_acquisition_v2 import (
    M8RedetectionDetectorRequestV1,
    M8RedetectionOutcomeV1,
)
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionWorkerFailure,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotWorkerBox,
    PilotWorkerDetection,
)
from labcourt.exceptions import PerceptionWorkerCrashed
from labcourt.ports.pixels import rgb8_pixel_sha256
from labcourt.services.pilot_operations import build_expected_perception_manifest

_ResultBuilder = Callable[
    [PilotPerceptionWorkerRequest],
    PilotPerceptionWorkerResponse | PilotPerceptionWorkerFailure,
]


class _RawTransport:
    def __init__(
        self,
        manifest: PilotPerceptionExecutionManifest,
        builder: _ResultBuilder,
        requests: list[PilotPerceptionWorkerRequest],
    ) -> None:
        self.manifest = manifest
        self._builder = builder
        self._requests = requests
        self.closed = False

    def exchange_with_raw(
        self,
        request: PilotPerceptionWorkerRequest,
    ) -> PerceptionWorkerExchange:
        self._requests.append(request)
        result = self._builder(request)
        raw = canonical_json(result.model_dump(mode="json")).encode("utf-8")
        return PerceptionWorkerExchange(result=result, raw_response=raw)

    def close(self) -> None:
        self.closed = True


class _TransportFactory:
    def __init__(
        self,
        manifest: PilotPerceptionExecutionManifest,
        builder: _ResultBuilder,
    ) -> None:
        self._manifest = manifest
        self._builder = builder
        self.requests: list[PilotPerceptionWorkerRequest] = []
        self.transports: list[_RawTransport] = []

    def __call__(self) -> _RawTransport:
        transport = _RawTransport(self._manifest, self._builder, self.requests)
        self.transports.append(transport)
        return transport


def _manifest(root: Path) -> PilotPerceptionExecutionManifest:
    return build_expected_perception_manifest(load_config(root / "configs/pilot.yaml"))


def _request(
    manifest: PilotPerceptionExecutionManifest,
    *,
    prompts: tuple[str, ...] = ("goggles",),
    media: bytes | None = None,
    expected_model_manifest_id: str | None = None,
) -> tuple[M8RedetectionDetectorRequestV1, bytes]:
    pixels = bytes(range(36))
    selected_media = encode_rgb_png(4, 3, pixels) if media is None else media
    media_sha256 = hashlib.sha256(selected_media).hexdigest()
    return (
        M8RedetectionDetectorRequestV1(
            request_id="a" * 64,
            run_id="evaluation-redetection-test",
            crop_id="b" * 64,
            crop_media_sha256=media_sha256,
            frame_id="camera-01:stream-01:27",
            crop_bbox=BBoxXYXY(x1=10, y1=20, x2=14, y2=23),
            width=4,
            height=3,
            prompts=prompts,
            image_base64=base64.b64encode(selected_media).decode("ascii"),
            image_sha256=media_sha256,
            expected_model_manifest_id=(
                manifest.detector.model_manifest_id
                if expected_model_manifest_id is None
                else expected_model_manifest_id
            ),
        ),
        pixels,
    )


def _success(request: PilotPerceptionWorkerRequest) -> PilotPerceptionWorkerResponse:
    return PilotPerceptionWorkerResponse(
        request_id=request.request_id,
        frame_id=request.frame_id,
        frame_content_sha256=request.frame_content_sha256,
        manifest_id=request.expected_manifest_id,
        detections=(
            PilotWorkerDetection(
                label="person",
                source_label="person",
                bbox=PilotWorkerBox(x1=0.0, y1=0.0, x2=4.0, y2=3.0),
                score=0.81,
                local_track_id="1",
            ),
            PilotWorkerDetection(
                label="goggles",
                source_label="protective eyewear",
                bbox=PilotWorkerBox(x1=0.2, y1=0.1, x2=4.7, y2=3.9),
                score=0.93,
            ),
        ),
    )


def test_real_redetector_maps_one_shot_worker_output_and_recovery_deterministically() -> None:
    root = Path(__file__).parents[2]
    manifest = _manifest(root)
    factory = _TransportFactory(manifest, _success)
    adapter = M8GroundingDinoRedetector(
        project_root=root,
        raw_transport_factory=factory,
    )
    request, pixels = _request(manifest)

    first = adapter.execute(request, idempotency_key=request.request_id)
    replay = adapter.recover(request, idempotency_key=request.request_id)

    assert first == replay
    outcome = M8RedetectionOutcomeV1.model_validate_json(first)
    assert first == canonical_json(outcome.model_dump(mode="json")).encode("utf-8")
    assert outcome.status == "SUCCEEDED"
    assert outcome.error_code is None
    assert len(outcome.detections) == 1
    assert outcome.detections[0].label == "goggles"
    assert outcome.detections[0].bbox == BBoxXYXY(x1=0, y1=0, x2=4, y2=3)
    assert outcome.detections[0].score == pytest.approx(0.93)
    assert outcome.model_manifest_id == manifest.detector.model_manifest_id
    assert len(factory.requests) == 2
    assert factory.requests[0] == factory.requests[1]
    worker_request = factory.requests[0]
    assert worker_request.frame_id == f"camera-01:redetect-{request.request_id[:16]}:0"
    assert worker_request.frame_content_sha256 == rgb8_pixel_sha256(4, 3, pixels)
    assert worker_request.expected_manifest_id == manifest.manifest_id
    assert worker_request.fps_num == worker_request.fps_den == 1
    assert len(factory.transports) == 2
    assert all(transport.closed for transport in factory.transports)


def test_empty_worker_success_stays_a_successful_empty_public_outcome() -> None:
    root = Path(__file__).parents[2]
    manifest = _manifest(root)

    def empty(request: PilotPerceptionWorkerRequest) -> PilotPerceptionWorkerResponse:
        return PilotPerceptionWorkerResponse(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=request.expected_manifest_id,
        )

    factory = _TransportFactory(manifest, empty)
    adapter = M8GroundingDinoRedetector(
        project_root=root,
        raw_transport_factory=factory,
    )
    request, _ = _request(manifest)

    outcome = M8RedetectionOutcomeV1.model_validate_json(
        adapter.execute(request, idempotency_key=request.request_id)
    )

    assert outcome.status == "SUCCEEDED"
    assert outcome.detections == ()
    assert outcome.error_code is None
    assert factory.transports[0].closed is True


@pytest.mark.parametrize(
    ("worker_error", "expected_error"),
    (
        ("IMAGE_INVALID", "IMAGE_INVALID"),
        ("REQUEST_INVALID", "REQUEST_INVALID"),
        ("INFERENCE_FAILED", "INFERENCE_FAILED"),
        ("TRACKER_FAILED", "INFERENCE_FAILED"),
    ),
)
def test_worker_failures_are_typed_and_never_become_empty_success(
    worker_error: str,
    expected_error: str,
) -> None:
    root = Path(__file__).parents[2]
    manifest = _manifest(root)

    def fail(request: PilotPerceptionWorkerRequest) -> PilotPerceptionWorkerFailure:
        return PilotPerceptionWorkerFailure(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            manifest_id=request.expected_manifest_id,
            error_code=worker_error,
        )

    factory = _TransportFactory(manifest, fail)
    adapter = M8GroundingDinoRedetector(
        project_root=root,
        raw_transport_factory=factory,
    )
    request, _ = _request(manifest)

    outcome = M8RedetectionOutcomeV1.model_validate_json(
        adapter.execute(request, idempotency_key=request.request_id)
    )

    assert outcome.status == "FAILED"
    assert outcome.error_code == expected_error
    assert outcome.detections == ()
    assert factory.transports[0].closed is True


def test_invalid_prompt_image_model_and_worker_start_are_typed() -> None:
    root = Path(__file__).parents[2]
    manifest = _manifest(root)
    factory = _TransportFactory(manifest, _success)
    adapter = M8GroundingDinoRedetector(
        project_root=root,
        raw_transport_factory=factory,
    )

    unsupported, _ = _request(manifest, prompts=("open reagent container",))
    unsupported_outcome = M8RedetectionOutcomeV1.model_validate_json(
        adapter.execute(unsupported, idempotency_key=unsupported.request_id)
    )
    assert unsupported_outcome.error_code == "REQUEST_INVALID"

    wrong_model, _ = _request(manifest, expected_model_manifest_id="f" * 64)
    wrong_model_outcome = M8RedetectionOutcomeV1.model_validate_json(
        adapter.execute(wrong_model, idempotency_key=wrong_model.request_id)
    )
    assert wrong_model_outcome.error_code == "REQUEST_INVALID"

    invalid_image, _ = _request(manifest, media=b"not-a-png")
    invalid_image_outcome = M8RedetectionOutcomeV1.model_validate_json(
        adapter.execute(invalid_image, idempotency_key=invalid_image.request_id)
    )
    assert invalid_image_outcome.error_code == "IMAGE_INVALID"
    assert factory.transports == []

    def unavailable() -> _RawTransport:
        raise PerceptionWorkerCrashed("worker unavailable")

    unavailable_adapter = M8GroundingDinoRedetector(
        project_root=root,
        raw_transport_factory=unavailable,
    )
    request, _ = _request(manifest)
    unavailable_outcome = M8RedetectionOutcomeV1.model_validate_json(
        unavailable_adapter.execute(request, idempotency_key=request.request_id)
    )
    assert unavailable_outcome.status == "FAILED"
    assert unavailable_outcome.error_code == "MODEL_UNAVAILABLE"
