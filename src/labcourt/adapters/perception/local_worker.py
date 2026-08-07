"""Bounded JSONL subprocess adapter for real local detector/tracker inference."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import subprocess
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from queue import Empty, Queue
from threading import Lock, Thread
from typing import IO, NoReturn, Protocol, TypeAlias, cast

from pydantic import ValidationError

from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Detection
from labcourt.contracts.evidence import Crop
from labcourt.contracts.frames import FrameData, FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.pilot import (
    PilotPerceptionExecutionManifest,
    PilotPerceptionFrameReceipt,
    PilotPerceptionWorkerFailure,
    PilotPerceptionWorkerReady,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotPerceptionWorkerStartupFailure,
    PilotWorkerDetection,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactConflict,
    PathBoundaryViolation,
    PerceptionFrameIdentityMismatch,
    PerceptionWorkerCrashed,
    PerceptionWorkerProtocolViolation,
    PerceptionWorkerRejected,
    PerceptionWorkerTimeout,
)
from labcourt.ports.pixels import PixelFrameProvider, RGB8Frame

WorkerResult: TypeAlias = PilotPerceptionWorkerResponse | PilotPerceptionWorkerFailure


@dataclass(frozen=True, slots=True)
class PerceptionWorkerExchange:
    result: WorkerResult
    raw_response: bytes


class PerceptionWorkerTransport(Protocol):
    """Versioned exchange boundary used by the perception provider and test fake."""

    @property
    def manifest(self) -> PilotPerceptionExecutionManifest: ...

    def exchange(self, request: PilotPerceptionWorkerRequest) -> WorkerResult: ...

    def close(self) -> None: ...


class RawPerceptionWorkerTransport(Protocol):
    @property
    def manifest(self) -> PilotPerceptionExecutionManifest: ...

    def exchange_with_raw(
        self,
        request: PilotPerceptionWorkerRequest,
    ) -> PerceptionWorkerExchange: ...

    def close(self) -> None: ...


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
        text = raw.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise PerceptionWorkerProtocolViolation("worker emitted invalid strict JSON") from None
    if not isinstance(parsed, dict):
        raise PerceptionWorkerProtocolViolation("worker protocol message must be a JSON object")
    return cast(Mapping[str, object], parsed)


class JsonlPerceptionWorkerClient:
    """One persistent shell-free child process with bounded request/response lines."""

    __slots__ = (
        "_closed",
        "_lock",
        "_manifest",
        "_max_request_bytes",
        "_max_response_bytes",
        "_process",
        "_responses",
        "_stdout_thread",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        command: Sequence[str],
        expected_manifest: PilotPerceptionExecutionManifest,
        startup_timeout_seconds: float,
        frame_timeout_seconds: float,
        max_request_bytes: int,
        max_response_bytes: int,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("perception worker command must contain bounded argument strings")
        if any("\x00" in part or len(part) > 32_768 for part in command):
            raise ValueError("perception worker command contains an invalid argument")
        if not isinstance(expected_manifest, PilotPerceptionExecutionManifest):
            raise TypeError("expected_manifest must be a perception execution manifest")
        for timeout in (startup_timeout_seconds, frame_timeout_seconds):
            if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
                raise ValueError("perception worker timeouts must be positive numbers")
        for limit in (max_request_bytes, max_response_bytes):
            if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
                raise ValueError("perception worker byte limits must be positive integers")

        child_environment = None if environment is None else dict(environment)
        try:
            process = subprocess.Popen(
                tuple(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                bufsize=0,
                env=child_environment,
            )
        except (OSError, ValueError):
            raise PerceptionWorkerCrashed("perception worker could not start") from None

        self._process = process
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._timeout_seconds = float(frame_timeout_seconds)
        self._responses: Queue[bytes | BaseException] = Queue()
        self._lock = Lock()
        self._closed = False
        stdout = process.stdout
        if stdout is None:
            self._terminate()
            raise PerceptionWorkerCrashed("perception worker has no protocol output")
        self._stdout_thread = Thread(
            target=self._read_stdout,
            args=(stdout,),
            daemon=True,
            name="labcourt-perception-worker-stdout",
        )
        self._stdout_thread.start()

        try:
            ready_raw = self._next_line(float(startup_timeout_seconds), startup=True)
            ready_payload = _strict_json_object(ready_raw)
            if ready_payload.get("kind") == "STARTUP_FAILED":
                failure = PilotPerceptionWorkerStartupFailure.model_validate(ready_payload)
                self._terminate()
                raise PerceptionWorkerRejected(
                    f"perception worker startup failed: {failure.error_code}"
                )
            ready = PilotPerceptionWorkerReady.model_validate(ready_payload)
        except PerceptionWorkerRejected:
            raise
        except (ValidationError, PerceptionWorkerProtocolViolation):
            self._terminate()
            raise PerceptionWorkerProtocolViolation("worker READY message is invalid") from None
        if ready.manifest != expected_manifest:
            self._terminate()
            raise PerceptionWorkerProtocolViolation("worker manifest does not match configuration")
        self._manifest = ready.manifest

    @property
    def manifest(self) -> PilotPerceptionExecutionManifest:
        return self._manifest

    def _read_stdout(self, stdout: IO[bytes]) -> None:
        try:
            while True:
                line = stdout.readline(self._max_response_bytes + 2)
                self._responses.put(line)
                if not line:
                    return
        except BaseException as error:
            self._responses.put(error)

    def _next_line(self, timeout_seconds: float, *, startup: bool = False) -> bytes:
        try:
            item = self._responses.get(timeout=timeout_seconds)
        except Empty:
            self._terminate()
            phase = "startup" if startup else "frame inference"
            raise PerceptionWorkerTimeout(f"perception worker {phase} timed out") from None
        if isinstance(item, BaseException) or item == b"":
            self._terminate()
            raise PerceptionWorkerCrashed("perception worker closed its protocol stream")
        if len(item) > self._max_response_bytes or not item.endswith(b"\n"):
            self._terminate()
            raise PerceptionWorkerProtocolViolation("worker response exceeded its byte limit")
        return item[:-1]

    def exchange(self, request: PilotPerceptionWorkerRequest) -> WorkerResult:
        return self.exchange_with_raw(request).result

    def exchange_with_raw(
        self,
        request: PilotPerceptionWorkerRequest,
    ) -> PerceptionWorkerExchange:
        if not isinstance(request, PilotPerceptionWorkerRequest):
            raise TypeError("worker request must be a validated pilot request")
        with self._lock:
            if self._closed:
                raise PerceptionWorkerCrashed("perception worker is closed")
            payload = canonical_json(request.model_dump(mode="json")).encode("utf-8") + b"\n"
            if len(payload) > self._max_request_bytes:
                raise PerceptionWorkerProtocolViolation("worker request exceeded its byte limit")
            stdin = self._process.stdin
            if stdin is None:
                self._terminate()
                raise PerceptionWorkerCrashed("perception worker has no protocol input")
            try:
                stdin.write(payload)
                stdin.flush()
            except (BrokenPipeError, OSError):
                self._terminate()
                raise PerceptionWorkerCrashed("perception worker rejected protocol input") from None
            raw = self._next_line(self._timeout_seconds)
            parsed = _strict_json_object(raw)
            status = parsed.get("status")
            try:
                if status == "SUCCEEDED":
                    result: WorkerResult = PilotPerceptionWorkerResponse.model_validate(parsed)
                    return PerceptionWorkerExchange(result=result, raw_response=raw)
                if status == "FAILED":
                    result = PilotPerceptionWorkerFailure.model_validate(parsed)
                    return PerceptionWorkerExchange(result=result, raw_response=raw)
            except ValidationError:
                raise PerceptionWorkerProtocolViolation(
                    "worker result violates the response contract"
                ) from None
            raise PerceptionWorkerProtocolViolation("worker result has an unknown status")

    def _terminate(self) -> None:
        self._closed = True
        process = self._process
        if process.poll() is None:
            with suppress(OSError):
                process.kill()
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                with suppress(OSError):
                    stream.close()
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=5)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._terminate()

    def __enter__(self) -> JsonlPerceptionWorkerClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def parse_perception_worker_result(raw: bytes) -> WorkerResult:
    """Strictly parse one persisted raw worker response for replay validation."""

    parsed = _strict_json_object(raw)
    try:
        if parsed.get("status") == "SUCCEEDED":
            return PilotPerceptionWorkerResponse.model_validate(parsed)
        if parsed.get("status") == "FAILED":
            return PilotPerceptionWorkerFailure.model_validate(parsed)
    except ValidationError:
        raise PerceptionWorkerProtocolViolation("cached worker result is invalid") from None
    raise PerceptionWorkerProtocolViolation("cached worker result has an unknown status")


class CachedPerceptionWorkerTransport:
    """Content-addressed local response cache with per-frame raw-response receipts."""

    __slots__ = ("_receipts", "_run_id", "_transport", "_workspace")

    def __init__(
        self,
        *,
        transport: RawPerceptionWorkerTransport,
        workspace: SecureWorkspace,
        run_id: str,
    ) -> None:
        self._transport = transport
        self._workspace = workspace
        self._run_id = require_reference_token(run_id, "pilot cache run_id")
        self._receipts: dict[str, PilotPerceptionFrameReceipt] = {}
        workspace.ensure_private_directory(self._run_id)
        workspace.ensure_private_directory(f"{self._run_id}/raw")
        workspace.ensure_private_directory(f"{self._run_id}/raw/perception")

    @property
    def manifest(self) -> PilotPerceptionExecutionManifest:
        return self._transport.manifest

    @property
    def receipts(self) -> tuple[PilotPerceptionFrameReceipt, ...]:
        return tuple(self._receipts[key] for key in sorted(self._receipts))

    def exchange(self, request: PilotPerceptionWorkerRequest) -> WorkerResult:
        relative_path = f"{self._run_id}/raw/perception/{request.request_id}.json"
        cache_hit = False
        try:
            snapshot = self._workspace.read_verified(relative_path)
            raw = snapshot.bytes
            raw_sha256 = snapshot.sha256
            cache_hit = True
        except PathBoundaryViolation as error:
            if error.reason_code != "FILE_MISSING":
                raise
            exchange = self._transport.exchange_with_raw(request)
            raw = exchange.raw_response
            raw_sha256 = hashlib.sha256(raw).hexdigest()
            try:
                self._workspace.create_new(relative_path, raw, raw_sha256)
            except ArtifactConflict:
                existing = self._workspace.read_verified(relative_path, raw_sha256)
                raw = existing.bytes
                raw_sha256 = existing.sha256
                cache_hit = True

        result = parse_perception_worker_result(raw)
        if cache_hit and isinstance(result, PilotPerceptionWorkerResponse):
            replay = request.model_copy(
                update={
                    "mode": "REPLAY",
                    "replay_detections": result.detections,
                }
            )
            replayed = self._transport.exchange_with_raw(replay).result
            if replayed != result:
                raise PerceptionWorkerProtocolViolation(
                    "worker replay diverged from the cached perception result"
                )
        if (
            result.request_id != request.request_id
            or result.frame_id != request.frame_id
            or result.frame_content_sha256 != request.frame_content_sha256
            or result.manifest_id != request.expected_manifest_id
        ):
            raise PerceptionFrameIdentityMismatch(
                "cached worker result identity does not match the frame request"
            )
        self._receipts[request.request_id] = PilotPerceptionFrameReceipt(
            request_id=request.request_id,
            frame_id=request.frame_id,
            frame_content_sha256=request.frame_content_sha256,
            raw_response_ref=f"runs/{relative_path}",
            raw_response_sha256=raw_sha256,
            cache_hit=cache_hit,
        )
        return result

    def close(self) -> None:
        self._transport.close()


def _request_id(frame: RGB8Frame, manifest_id: str) -> str:
    content_sha256 = frame.frame.content_sha256
    assert content_sha256 is not None
    digest = hashlib.sha256(
        f"pilot-perception-v1\x00{frame.frame.frame_id}\x00{content_sha256}\x00{manifest_id}".encode()
    ).hexdigest()
    return require_reference_token(f"p{digest[:63]}", "perception request_id")


def _integer_box(
    detection: PilotWorkerDetection,
    *,
    width: int,
    height: int,
) -> BBoxXYXY:
    box = detection.bbox
    if box.x2 > width or box.y2 > height:
        raise PerceptionWorkerProtocolViolation("worker bbox exceeds the requested frame")
    try:
        return BBoxXYXY(
            x1=math.floor(box.x1),
            y1=math.floor(box.y1),
            x2=math.ceil(box.x2),
            y2=math.ceil(box.y2),
        ).require_within(width, height)
    except ValueError:
        raise PerceptionWorkerProtocolViolation("worker bbox cannot map to RGB8 pixels") from None


def map_perception_worker_detections(
    *,
    frame: FrameRef,
    manifest: PilotPerceptionExecutionManifest,
    tracker_epoch: str,
    request_id: str,
    detections: Sequence[PilotWorkerDetection],
) -> tuple[Detection, ...]:
    """Deterministically map model-native output onto authoritative Detection values."""

    controlled_epoch = require_reference_token(tracker_epoch, "tracker_epoch")
    controlled_request_id = require_reference_token(request_id, "perception request_id")
    mapped: list[Detection] = []
    for index, worker_detection in enumerate(detections):
        box = _integer_box(
            worker_detection,
            width=frame.width,
            height=frame.height,
        )
        identity = hashlib.sha256(
            canonical_json(
                [
                    controlled_request_id,
                    index,
                    worker_detection.label,
                    worker_detection.source_label,
                    box.model_dump(mode="json"),
                ]
            ).encode("utf-8")
        ).hexdigest()
        track_ref = (
            f"{frame.camera_id}:{controlled_epoch}:{worker_detection.local_track_id}"
            if worker_detection.local_track_id is not None
            else None
        )
        mapped.append(
            Detection(
                detection_id=f"d{identity[:63]}",
                frame_id=frame.frame_id,
                label=worker_detection.label,
                bbox=box,
                score=worker_detection.score,
                track_ref=track_ref,
                attributes={
                    "observation_source": "PIXEL_COMPUTED",
                    "source_label": worker_detection.source_label,
                },
                model_manifest_id=manifest.detector.model_manifest_id,
            )
        )
    return tuple(mapped)


class LocalWorkerPerceptionProvider:
    """Map strict isolated-worker results onto existing Detection contracts."""

    __slots__ = ("_pixels", "_tracker_epoch", "_transport")

    def __init__(
        self,
        *,
        pixels: PixelFrameProvider,
        transport: PerceptionWorkerTransport,
        tracker_epoch: str,
    ) -> None:
        self._pixels = pixels
        self._transport = transport
        self._tracker_epoch = require_reference_token(tracker_epoch, "tracker_epoch")

    @property
    def manifest(self) -> PilotPerceptionExecutionManifest:
        return self._transport.manifest

    def detect(self, frame: FrameData) -> Sequence[Detection]:
        rgb8 = self._pixels.read_rgb8(frame.frame.frame_id)
        if rgb8.frame != frame.frame:
            raise PerceptionFrameIdentityMismatch(
                "pixel provider frame identity does not match the detection request"
            )
        png = encode_rgb_png(rgb8.frame.width, rgb8.frame.height, rgb8.pixels)
        content_sha256 = rgb8.frame.content_sha256
        assert content_sha256 is not None
        request = PilotPerceptionWorkerRequest(
            request_id=_request_id(rgb8, self.manifest.manifest_id),
            frame_id=rgb8.frame.frame_id,
            frame_content_sha256=content_sha256,
            fps_num=rgb8.frame.fps_num,
            fps_den=rgb8.frame.fps_den,
            width=rgb8.frame.width,
            height=rgb8.frame.height,
            image_sha256=hashlib.sha256(png).hexdigest(),
            image_base64=base64.b64encode(png).decode("ascii"),
            expected_manifest_id=self.manifest.manifest_id,
        )
        result = self._transport.exchange(request)
        if (
            result.request_id != request.request_id
            or result.frame_id != request.frame_id
            or result.frame_content_sha256 != request.frame_content_sha256
        ):
            raise PerceptionFrameIdentityMismatch(
                "worker result identity does not match the requested frame pixels"
            )
        if result.manifest_id != self.manifest.manifest_id:
            raise PerceptionWorkerProtocolViolation("worker result uses an unknown manifest")
        if isinstance(result, PilotPerceptionWorkerFailure):
            raise PerceptionWorkerRejected(f"perception worker failed: {result.error_code}")

        return map_perception_worker_detections(
            frame=rgb8.frame,
            manifest=self.manifest,
            tracker_epoch=self._tracker_epoch,
            request_id=request.request_id,
            detections=result.detections,
        )

    def redetect(self, crop: Crop, prompts: Sequence[str]) -> Sequence[Detection]:
        del crop, prompts
        raise PerceptionWorkerProtocolViolation(
            "pilot local-worker redetection is not available in A1"
        )


__all__ = [
    "CachedPerceptionWorkerTransport",
    "JsonlPerceptionWorkerClient",
    "LocalWorkerPerceptionProvider",
    "PerceptionWorkerExchange",
    "PerceptionWorkerTransport",
    "RawPerceptionWorkerTransport",
    "WorkerResult",
    "map_perception_worker_detections",
    "parse_perception_worker_result",
]
