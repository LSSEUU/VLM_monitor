"""Lazy, local-only OpenCV video decoding behind a verified input lease."""

from __future__ import annotations

import importlib
import importlib.metadata
import math
from collections.abc import Generator, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from threading import Lock
from typing import Protocol, cast

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.frames import FrameData, FrameRef
from labcourt.contracts.manifests import StreamManifest
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.exceptions import (
    EvidenceMissing,
    LabCourtError,
    ManifestMismatch,
    ProviderUnavailable,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256

_OPENCV_PACKAGE = "opencv-python-headless"
_OPENCV_DECODER = "opencv.VideoCapture(CAP_FFMPEG)"
_OPENCV_SOFTWARE_COMPONENT = "opencv"
_COLOR_CONVERSION = "BGR_TO_RGB"
_FPS_RELATIVE_TOLERANCE = 1e-6
_FPS_ABSOLUTE_TOLERANCE = 1e-6


@dataclass(frozen=True, slots=True)
class VerifiedVideoLease:
    """Opaque decoder path kept stable by a verified-input capability."""

    decoder_path: str
    input_file_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.decoder_path, str) or not self.decoder_path:
            raise ValueError("verified video lease requires an opaque decoder path")
        if (
            not isinstance(self.input_file_sha256, str)
            or len(self.input_file_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.input_file_sha256)
        ):
            raise ValueError("verified video lease requires a lowercase SHA-256 digest")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes <= 0
        ):
            raise ValueError("verified video lease requires a positive byte size")


class VideoInputLease(Protocol):
    decoder_path: str
    input_file_sha256: str
    size_bytes: int


class VerifiedVideoInput(Protocol):
    """Provide a locked, already-contained input for the full decoder lifetime."""

    def open_verified_video(
        self,
        relative_path: str,
        max_bytes: int,
    ) -> AbstractContextManager[VideoInputLease]: ...


@dataclass(frozen=True, slots=True)
class DecoderMetadata:
    """Untrusted values reported by one decoder session."""

    width: float
    height: float
    frame_count: float
    fps: float
    backend: str
    codec: str


@dataclass(frozen=True, slots=True)
class BGR8Frame:
    width: int
    height: int
    pixels: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.width, int)
            or isinstance(self.width, bool)
            or not isinstance(self.height, int)
            or isinstance(self.height, bool)
            or self.width <= 0
            or self.height <= 0
        ):
            raise ValueError("decoded BGR8 dimensions must be positive integers")
        if not isinstance(self.pixels, bytes):
            raise TypeError("decoded BGR8 pixels must be bytes")
        if len(self.pixels) != self.width * self.height * 3:
            raise ValueError("decoded BGR8 byte length does not match its dimensions")


class VideoDecoderSession(Protocol):
    def metadata(self) -> DecoderMetadata: ...

    def read_bgr8(
        self,
        *,
        expected_width: int,
        expected_height: int,
        max_frame_pixels: int,
    ) -> BGR8Frame | None: ...

    def close(self) -> None: ...


class VideoDecoderBackend(Protocol):
    software_component: str
    library: str
    library_version: str
    decoder: str
    module_version: str

    def open(self, decoder_path: str) -> VideoDecoderSession: ...


class _ArrayLike(Protocol):
    shape: tuple[int, ...]
    dtype: object

    def tobytes(self, order: str = "C") -> bytes: ...


class _CaptureLike(Protocol):
    def isOpened(self) -> bool: ...

    def get(self, property_id: int) -> float: ...

    def getBackendName(self) -> str: ...

    def read(self) -> tuple[bool, object]: ...

    def release(self) -> None: ...


class _Cv2Module(Protocol):
    __file__: str
    __version__: str
    CAP_FFMPEG: int
    CAP_PROP_FRAME_WIDTH: int
    CAP_PROP_FRAME_HEIGHT: int
    CAP_PROP_FRAME_COUNT: int
    CAP_PROP_FPS: int
    CAP_PROP_FOURCC: int

    def VideoCapture(self, filename: str, api_preference: int) -> _CaptureLike: ...


class _OpenCvSession:
    __slots__ = ("_capture", "_cv2")

    def __init__(self, cv2: _Cv2Module, capture: _CaptureLike) -> None:
        self._cv2 = cv2
        self._capture = capture

    def metadata(self) -> DecoderMetadata:
        try:
            backend = self._capture.getBackendName()
            fourcc = int(self._capture.get(self._cv2.CAP_PROP_FOURCC)) & 0xFFFFFFFF
            codec = bytes((fourcc >> (8 * index)) & 0xFF for index in range(4)).decode("ascii")
            if any(not 0x20 <= ord(character) <= 0x7E for character in codec):
                raise ManifestMismatch("OpenCV returned a non-printable four-byte codec identifier")
            return DecoderMetadata(
                width=self._capture.get(self._cv2.CAP_PROP_FRAME_WIDTH),
                height=self._capture.get(self._cv2.CAP_PROP_FRAME_HEIGHT),
                frame_count=self._capture.get(self._cv2.CAP_PROP_FRAME_COUNT),
                fps=self._capture.get(self._cv2.CAP_PROP_FPS),
                backend=backend,
                codec=codec,
            )
        except LabCourtError:
            raise
        except Exception:
            raise ProviderUnavailable(
                "OpenCV could not report deterministic video metadata"
            ) from None

    def read_bgr8(
        self,
        *,
        expected_width: int,
        expected_height: int,
        max_frame_pixels: int,
    ) -> BGR8Frame | None:
        try:
            ok, raw_frame = self._capture.read()
        except Exception:
            raise ManifestMismatch("OpenCV failed while decoding the verified video") from None
        if not ok:
            return None
        frame = cast(_ArrayLike, raw_frame)
        try:
            shape = tuple(frame.shape)
            dtype = str(frame.dtype)
        except Exception:
            raise ManifestMismatch("OpenCV returned an invalid decoded frame object") from None
        if len(shape) != 3 or shape[2] != 3 or dtype != "uint8":
            raise ManifestMismatch("OpenCV output must be a three-channel uint8 BGR frame")
        if (
            shape[0] != expected_height
            or shape[1] != expected_width
            or shape[0] * shape[1] > max_frame_pixels
        ):
            raise ManifestMismatch(
                "OpenCV output dimensions do not match the bounded stream manifest"
            )
        try:
            pixels = frame.tobytes(order="C")
        except Exception:
            raise ManifestMismatch("OpenCV could not materialize bounded BGR bytes") from None
        return BGR8Frame(width=shape[1], height=shape[0], pixels=pixels)

    def close(self) -> None:
        try:
            self._capture.release()
        except Exception:
            raise ProviderUnavailable("OpenCV failed to release its decoder session") from None


class OpenCvDecoderBackend:
    """Actual backend; importing this class alone never imports ``cv2``."""

    software_component = _OPENCV_SOFTWARE_COMPONENT
    library = _OPENCV_PACKAGE
    decoder = _OPENCV_DECODER

    def __init__(self) -> None:
        try:
            distribution = importlib.metadata.distribution(_OPENCV_PACKAGE)
            providers = importlib.metadata.packages_distributions().get("cv2", [])
            if providers != [_OPENCV_PACKAGE]:
                raise ProviderUnavailable(
                    "cv2 must be provided only by the pinned headless OpenCV distribution"
                )
            module = importlib.import_module("cv2")
        except (ImportError, importlib.metadata.PackageNotFoundError):
            raise ProviderUnavailable(
                "local video decoding requires the optional labcourt[video] dependency"
            ) from None
        except ProviderUnavailable:
            raise
        try:
            cv2 = cast(_Cv2Module, module)
            module_file = Path(cv2.__file__).resolve(strict=True)
            distribution_root = Path(str(distribution.locate_file("cv2"))).resolve(strict=True)
            if not module_file.is_relative_to(distribution_root):
                raise ProviderUnavailable(
                    "loaded cv2 module is not owned by the pinned headless distribution"
                )
            if not cv2.__version__:
                raise ProviderUnavailable("loaded cv2 module has no auditable version")
        except (AttributeError, OSError, TypeError):
            raise ProviderUnavailable("loaded cv2 module identity cannot be verified") from None
        self.library_version = distribution.version
        self.module_version = cv2.__version__
        self._cv2 = cv2

    def open(self, decoder_path: str) -> VideoDecoderSession:
        try:
            capture = self._cv2.VideoCapture(decoder_path, self._cv2.CAP_FFMPEG)
        except Exception:
            raise ProviderUnavailable("OpenCV could not open the verified local video") from None
        try:
            opened = capture.isOpened()
        except Exception:
            try:
                capture.release()
            except Exception:
                raise ProviderUnavailable(
                    "OpenCV failed while cleaning up an unverified decoder session"
                ) from None
            raise ProviderUnavailable(
                "OpenCV could not inspect the local decoder session"
            ) from None
        if not opened:
            try:
                capture.release()
            except Exception:
                raise ProviderUnavailable(
                    "OpenCV failed while cleaning up an unopened decoder session"
                ) from None
            raise ProviderUnavailable("OpenCV could not open the verified local video")
        return _OpenCvSession(self._cv2, capture)


def _bgr8_to_rgb8(frame: BGR8Frame) -> bytes:
    rgb = bytearray(len(frame.pixels))
    rgb[0::3] = frame.pixels[2::3]
    rgb[1::3] = frame.pixels[1::3]
    rgb[2::3] = frame.pixels[0::3]
    return bytes(rgb)


def _reported_integer(value: float, field: str) -> int:
    if not isinstance(value, (float, int)) or isinstance(value, bool):
        raise ManifestMismatch(f"decoder {field} must be a finite integer")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0 or not numeric.is_integer():
        raise ManifestMismatch(f"decoder {field} must be a finite positive integer")
    return int(numeric)


def _range_argument(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    return value


def probe_caller_attested_stream_manifest(
    *,
    camera_id: str,
    stream_id: str,
    input_file_sha256: str,
    verified_input: VerifiedVideoInput,
    relative_path: str,
    max_input_bytes: int,
    max_frame_pixels: int,
    max_total_decoded_pixels: int,
    backend: VideoDecoderBackend | None = None,
) -> StreamManifest:
    """Probe one verified pilot MP4 and bind the caller-selected CFR declaration.

    Selecting the input in the pilot CLI is the caller declaration. Decoder
    metadata remains untrusted until it is bounded here and later revalidated by
    :class:`OpenCvVideoSource` before any frame crosses the adapter boundary.
    """

    controlled_camera = require_reference_token(camera_id, "pilot camera_id")
    controlled_stream = require_reference_token(stream_id, "pilot stream_id")
    controlled_path = require_safe_relative_posix_path(relative_path)
    if not isinstance(max_input_bytes, int) or isinstance(max_input_bytes, bool):
        raise TypeError("max_input_bytes must be an integer")
    if not isinstance(max_frame_pixels, int) or isinstance(max_frame_pixels, bool):
        raise TypeError("max_frame_pixels must be an integer")
    if not isinstance(max_total_decoded_pixels, int) or isinstance(max_total_decoded_pixels, bool):
        raise TypeError("max_total_decoded_pixels must be an integer")
    if max_input_bytes <= 0 or max_frame_pixels <= 0 or max_total_decoded_pixels <= 0:
        raise ValueError("video probe limits must be positive")

    selected_backend = backend if backend is not None else OpenCvDecoderBackend()
    with verified_input.open_verified_video(controlled_path, max_input_bytes) as lease:
        if not compare_digest(lease.input_file_sha256, input_file_sha256):
            raise ManifestMismatch("pilot video bytes changed before decoder probe")
        try:
            session = selected_backend.open(lease.decoder_path)
            metadata = session.metadata()
        except LabCourtError:
            raise
        except Exception:
            raise ProviderUnavailable("video decoder probe failed") from None
        finally:
            if "session" in locals():
                try:
                    session.close()
                except LabCourtError:
                    raise
                except Exception:
                    raise ProviderUnavailable("video decoder probe release failed") from None

    width = _reported_integer(metadata.width, "width")
    height = _reported_integer(metadata.height, "height")
    frame_count = _reported_integer(metadata.frame_count, "frame count")
    if width * height > max_frame_pixels:
        raise ManifestMismatch("probed video dimensions exceed the configured pixel limit")
    if width * height * frame_count > max_total_decoded_pixels:
        raise ManifestMismatch("probed video exceeds the configured decoded-pixel budget")
    if not isinstance(metadata.fps, (float, int)) or isinstance(metadata.fps, bool):
        raise ManifestMismatch("decoder FPS must be finite and positive")
    reported_fps = float(metadata.fps)
    if not math.isfinite(reported_fps) or reported_fps <= 0:
        raise ManifestMismatch("decoder FPS must be finite and positive")
    timebase = Fraction(str(reported_fps)).limit_denominator(1_000_000)
    timing_evidence = canonical_json(
        {
            "authority": "CALLER_ATTESTED",
            "declaration": "selected-pilot-mp4-decoder-cfr-metadata",
            "input_file_sha256": input_file_sha256,
            "fps_num": timebase.numerator,
            "fps_den": timebase.denominator,
            "width": width,
            "height": height,
            "frame_count": frame_count,
        }
    ).encode("utf-8")
    return StreamManifest(
        camera_id=controlled_camera,
        stream_id=controlled_stream,
        input_file_sha256=input_file_sha256,
        fps_num=timebase.numerator,
        fps_den=timebase.denominator,
        timing_mode="CFR",
        timing_authority="CALLER_ATTESTED",
        timing_evidence_type="CALLER_DECLARATION",
        timing_evidence_sha256=sha256(timing_evidence).hexdigest(),
        width=width,
        height=height,
        frame_count=frame_count,
        decoder=selected_backend.decoder,
        decoder_version=selected_backend.module_version,
        backend=metadata.backend,
        software_component=selected_backend.software_component,
        library=selected_backend.library,
        library_version=selected_backend.library_version,
        codec=metadata.codec,
        color_conversion=_COLOR_CONVERSION,
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )


class OpenCvVideoSource:
    """Sequential CFR decoder implementing FrameSource and PixelFrameProvider."""

    __slots__ = (
        "_backend",
        "_input",
        "_manifest",
        "_max_frame_pixels",
        "_max_input_bytes",
        "_max_total_decoded_pixels",
        "_preflight_hashes",
        "_preflight_lock",
        "_relative_path",
    )

    def __init__(
        self,
        *,
        manifest: StreamManifest,
        verified_input: VerifiedVideoInput,
        relative_path: str,
        max_input_bytes: int,
        max_frame_pixels: int,
        max_total_decoded_pixels: int,
        backend: VideoDecoderBackend | None = None,
    ) -> None:
        if not isinstance(manifest, StreamManifest):
            raise TypeError("OpenCvVideoSource requires a validated StreamManifest")
        if not isinstance(max_input_bytes, int) or isinstance(max_input_bytes, bool):
            raise TypeError("max_input_bytes must be an integer")
        if not isinstance(max_frame_pixels, int) or isinstance(max_frame_pixels, bool):
            raise TypeError("max_frame_pixels must be an integer")
        if not isinstance(max_total_decoded_pixels, int) or isinstance(
            max_total_decoded_pixels, bool
        ):
            raise TypeError("max_total_decoded_pixels must be an integer")
        if max_input_bytes <= 0 or max_frame_pixels <= 0 or max_total_decoded_pixels <= 0:
            raise ValueError("video byte and decoded-pixel limits must be positive")
        if manifest.width * manifest.height > max_frame_pixels:
            raise ManifestMismatch("declared video dimensions exceed the configured pixel limit")
        if manifest.width * manifest.height * manifest.frame_count > max_total_decoded_pixels:
            raise ManifestMismatch(
                "declared video exceeds the configured total decoded-pixel budget"
            )
        if manifest.color_conversion != _COLOR_CONVERSION:
            raise ManifestMismatch("stream manifest requires an unsupported color conversion")

        selected_backend = backend if backend is not None else OpenCvDecoderBackend()
        if selected_backend.library != manifest.library:
            raise ManifestMismatch("video decoder library does not match the stream manifest")
        if selected_backend.library_version != manifest.library_version:
            raise ManifestMismatch("video decoder version does not match the stream manifest")
        if selected_backend.decoder != manifest.decoder:
            raise ManifestMismatch(
                "video decoder implementation does not match the stream manifest"
            )
        if selected_backend.module_version != manifest.decoder_version:
            raise ManifestMismatch(
                "loaded decoder module version does not match the stream manifest"
            )
        if selected_backend.software_component != manifest.software_component:
            raise ManifestMismatch("video software component does not match the stream manifest")

        self._manifest = manifest
        self._input = verified_input
        self._relative_path = require_safe_relative_posix_path(relative_path)
        self._max_input_bytes = max_input_bytes
        self._max_frame_pixels = max_frame_pixels
        self._max_total_decoded_pixels = max_total_decoded_pixels
        self._backend = selected_backend
        self._preflight_hashes: tuple[str, ...] | None = None
        self._preflight_lock = Lock()

    @contextmanager
    def _session(self) -> Iterator[VideoDecoderSession]:
        with self._input.open_verified_video(
            self._relative_path,
            self._max_input_bytes,
        ) as lease:
            if lease.size_bytes > self._max_input_bytes:
                raise ManifestMismatch("verified video exceeds the configured byte limit")
            if not compare_digest(
                lease.input_file_sha256,
                self._manifest.input_file_sha256,
            ):
                raise ManifestMismatch("verified video bytes do not match the stream manifest")
            try:
                session = self._backend.open(lease.decoder_path)
            except LabCourtError:
                raise
            except Exception:
                raise ProviderUnavailable("video decoder could not open verified input") from None
            try:
                self._validate_metadata(session.metadata())
                yield session
            finally:
                try:
                    session.close()
                except LabCourtError:
                    raise
                except Exception:
                    raise ProviderUnavailable(
                        "video decoder failed to release its session"
                    ) from None

    def _validate_metadata(self, metadata: DecoderMetadata) -> None:
        width = _reported_integer(metadata.width, "width")
        height = _reported_integer(metadata.height, "height")
        frame_count = _reported_integer(metadata.frame_count, "frame count")
        if width * height > self._max_frame_pixels:
            raise ManifestMismatch("decoded video dimensions exceed the configured pixel limit")
        if (width, height) != (self._manifest.width, self._manifest.height):
            raise ManifestMismatch("decoder dimensions do not match the stream manifest")
        if frame_count != self._manifest.frame_count:
            raise ManifestMismatch("decoder frame count does not match the stream manifest")
        if not isinstance(metadata.fps, (float, int)) or isinstance(metadata.fps, bool):
            raise ManifestMismatch("decoder FPS must be finite and positive")
        reported_fps = float(metadata.fps)
        authoritative_fps = self._manifest.fps_num / self._manifest.fps_den
        if (
            not math.isfinite(reported_fps)
            or reported_fps <= 0
            or not math.isclose(
                reported_fps,
                authoritative_fps,
                rel_tol=_FPS_RELATIVE_TOLERANCE,
                abs_tol=_FPS_ABSOLUTE_TOLERANCE,
            )
        ):
            raise ManifestMismatch("decoder FPS does not match the authoritative CFR timebase")
        if metadata.backend != self._manifest.backend:
            raise ManifestMismatch("decoder backend does not match the stream manifest")
        if metadata.codec != self._manifest.codec:
            raise ManifestMismatch("decoder codec does not match the stream manifest")

    def _decode_once(
        self,
        expected_hashes: tuple[str, ...] | None,
    ) -> Generator[RGB8Frame, None, None]:
        with self._session() as session:
            for frame_index in range(self._manifest.frame_count):
                bgr = session.read_bgr8(
                    expected_width=self._manifest.width,
                    expected_height=self._manifest.height,
                    max_frame_pixels=self._max_frame_pixels,
                )
                if bgr is None:
                    raise ManifestMismatch("video ended before its declared frame count")
                if (bgr.width, bgr.height) != (
                    self._manifest.width,
                    self._manifest.height,
                ):
                    raise ManifestMismatch("decoded frame dimensions changed within the stream")
                pixels = _bgr8_to_rgb8(bgr)
                content_sha256 = rgb8_pixel_sha256(bgr.width, bgr.height, pixels)
                if expected_hashes is not None and not compare_digest(
                    content_sha256,
                    expected_hashes[frame_index],
                ):
                    raise ManifestMismatch(
                        "decoded frame pixels differ from the validated preflight"
                    )
                frame_ref = FrameRef(
                    camera_id=self._manifest.camera_id,
                    stream_id=self._manifest.stream_id,
                    frame_index=frame_index,
                    fps_num=self._manifest.fps_num,
                    fps_den=self._manifest.fps_den,
                    width=bgr.width,
                    height=bgr.height,
                    content_sha256=content_sha256,
                )
                yield RGB8Frame(frame=frame_ref, pixels=pixels)
            if (
                session.read_bgr8(
                    expected_width=self._manifest.width,
                    expected_height=self._manifest.height,
                    max_frame_pixels=self._max_frame_pixels,
                )
                is not None
            ):
                raise ManifestMismatch("video contains frames beyond its declared frame count")

    def validate_stream(self) -> tuple[str, ...]:
        """Fully decode once before any frame can cross the adapter boundary."""

        existing = self._preflight_hashes
        if existing is not None:
            return existing
        with self._preflight_lock:
            existing = self._preflight_hashes
            if existing is not None:
                return existing
            hashes: list[str] = []
            for frame in self._decode_once(expected_hashes=None):
                content_sha256 = frame.frame.content_sha256
                assert content_sha256 is not None
                hashes.append(content_sha256)
            validated = tuple(hashes)
            if len(validated) != self._manifest.frame_count:
                raise ManifestMismatch("video preflight did not validate every declared frame")
            self._preflight_hashes = validated
            return validated

    def iter_rgb8(self) -> Generator[RGB8Frame, None, None]:
        """Preflight the complete input, then decode sequentially with hash comparison."""

        expected_hashes = self.validate_stream()
        yield from self._decode_once(expected_hashes)

    def iter_frames(self) -> Iterator[FrameBundle]:
        return (FrameBundle(frame=frame.frame) for frame in self.iter_rgb8())

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        try:
            camera_id, stream_id, frame_index = parse_frame_id(frame_id)
        except (TypeError, ValueError):
            raise EvidenceMissing("invalid frame_id for the verified video stream") from None
        if (
            camera_id != self._manifest.camera_id
            or stream_id != self._manifest.stream_id
            or frame_index >= self._manifest.frame_count
        ):
            raise EvidenceMissing("unknown frame_id for the verified video stream")
        frames = self.iter_rgb8()
        try:
            for frame in frames:
                if frame.frame.frame_index == frame_index:
                    return frame
        finally:
            frames.close()
        raise EvidenceMissing("video frame could not be decoded")

    def get_frame(self, frame_id: str) -> FrameData:
        return self._frame_data(self.read_rgb8(frame_id))

    def get_range(
        self,
        camera_id: str,
        stream_id: str,
        start: int,
        end: int,
        step: int = 1,
    ) -> Sequence[FrameData]:
        start = _range_argument(start, "start")
        end = _range_argument(end, "end")
        step = _range_argument(step, "step")
        if start < 0 or end < start:
            raise ValueError("frame range must satisfy 0 <= start <= end")
        if step <= 0:
            raise ValueError("frame range step must be positive")
        if camera_id != self._manifest.camera_id or stream_id != self._manifest.stream_id:
            return ()
        stop = min(end, self._manifest.frame_count)
        if start >= stop:
            return ()

        selected: list[FrameData] = []
        frames = self.iter_rgb8()
        try:
            for frame in frames:
                frame_index = frame.frame.frame_index
                if frame_index >= stop:
                    break
                if frame_index >= start and (frame_index - start) % step == 0:
                    selected.append(self._frame_data(frame))
        finally:
            frames.close()
        return tuple(selected)

    @staticmethod
    def _frame_data(frame: RGB8Frame) -> FrameData:
        return FrameData(
            frame=frame.frame,
            media_ref=(
                f"verified-video/{frame.frame.camera_id}/"
                f"{frame.frame.stream_id}/{frame.frame.frame_index}"
            ),
            ephemeral=True,
        )


__all__ = [
    "BGR8Frame",
    "DecoderMetadata",
    "OpenCvDecoderBackend",
    "OpenCvVideoSource",
    "VerifiedVideoInput",
    "VerifiedVideoLease",
    "VideoDecoderBackend",
    "VideoDecoderSession",
    "VideoInputLease",
    "probe_caller_attested_stream_manifest",
]
