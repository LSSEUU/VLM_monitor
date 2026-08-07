"""Non-authoritative bounded MP4 debug preview for pilot perception."""

from __future__ import annotations

import importlib
import importlib.metadata
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Self

from labcourt.contracts.detections import Detection
from labcourt.exceptions import ProviderUnavailable
from labcourt.ports.pixels import RGB8Frame

_OPENCV_PACKAGE = "opencv-python-headless"


class OpenCvPerceptionPreview:
    """Stream annotated RGB8 frames to a temporary MP4, then return bounded bytes."""

    __slots__ = (
        "_closed",
        "_cv2",
        "_height",
        "_numpy",
        "_output",
        "_temporary",
        "_width",
        "_writer",
    )

    def __init__(self, *, width: int, height: int, fps: float) -> None:
        if width <= 0 or height <= 0 or fps <= 0:
            raise ValueError("preview dimensions and FPS must be positive")
        try:
            distribution = importlib.metadata.distribution(_OPENCV_PACKAGE)
            providers = importlib.metadata.packages_distributions().get("cv2", [])
            if providers != [_OPENCV_PACKAGE]:
                raise ProviderUnavailable("preview cv2 must come only from pinned headless OpenCV")
            cv2 = importlib.import_module("cv2")
            numpy = importlib.import_module("numpy")
            module_file = cv2.__file__
            if not isinstance(module_file, str) or not module_file:
                raise ProviderUnavailable("preview OpenCV module has no file identity")
            module_path = Path(module_file).resolve(strict=True)
            distribution_path = Path(str(distribution.locate_file("cv2"))).resolve(strict=True)
            if not module_path.is_relative_to(distribution_path):
                raise ProviderUnavailable("preview OpenCV module identity cannot be verified")
        except (ImportError, AttributeError, OSError, TypeError):
            raise ProviderUnavailable("pinned preview dependencies are unavailable") from None
        except importlib.metadata.PackageNotFoundError:
            raise ProviderUnavailable("pinned preview dependencies are unavailable") from None

        temporary = TemporaryDirectory(prefix="labcourt-preview-")
        output = Path(temporary.name) / "perception-preview.mp4"
        try:
            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            writer = cv2.VideoWriter(str(output), fourcc, fps, (width, height))
            opened = bool(writer.isOpened())
        except Exception:
            temporary.cleanup()
            raise ProviderUnavailable("OpenCV preview writer could not start") from None
        if not opened:
            with suppress(Exception):
                writer.release()
            temporary.cleanup()
            raise ProviderUnavailable("OpenCV preview writer is unavailable")

        self._cv2: Any = cv2
        self._numpy: Any = numpy
        self._writer: Any = writer
        self._temporary = temporary
        self._output = output
        self._width = width
        self._height = height
        self._closed = False

    def add(self, frame: RGB8Frame, detections: tuple[Detection, ...]) -> None:
        if self._closed:
            raise ProviderUnavailable("OpenCV preview writer is closed")
        if (frame.frame.width, frame.frame.height) != (self._width, self._height):
            raise ProviderUnavailable("preview frame dimensions changed")
        try:
            rgb = self._numpy.frombuffer(frame.pixels, dtype=self._numpy.uint8).reshape(
                self._height,
                self._width,
                3,
            )
            bgr = rgb[:, :, ::-1].copy()
            for detection in detections:
                box = detection.bbox
                color = (80, 220, 80) if detection.label == "person" else (40, 180, 255)
                self._cv2.rectangle(
                    bgr,
                    (box.x1, box.y1),
                    (box.x2 - 1, box.y2 - 1),
                    color,
                    2,
                )
                identity = detection.track_ref.rsplit(":", 1)[-1] if detection.track_ref else "-"
                label = f"{detection.label} {detection.score:.2f} t={identity}"
                self._cv2.putText(
                    bgr,
                    label,
                    (box.x1, max(14, box.y1 - 4)),
                    self._cv2.FONT_HERSHEY_SIMPLEX,
                    0.45,
                    color,
                    1,
                    self._cv2.LINE_AA,
                )
            self._writer.write(bgr)
        except Exception:
            raise ProviderUnavailable("OpenCV preview frame encoding failed") from None

    def finish(self, *, max_bytes: int) -> bytes:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
            raise ValueError("preview max_bytes must be a positive integer")
        if self._closed:
            raise ProviderUnavailable("OpenCV preview writer is closed")
        self._closed = True
        try:
            self._writer.release()
            size = self._output.stat().st_size
            if size <= 0 or size > max_bytes:
                raise ProviderUnavailable("OpenCV preview output exceeded its byte budget")
            data = self._output.read_bytes()
        except ProviderUnavailable:
            raise
        except Exception:
            raise ProviderUnavailable("OpenCV preview finalization failed") from None
        finally:
            self._temporary.cleanup()
        return data

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.release()
        finally:
            self._temporary.cleanup()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = ["OpenCvPerceptionPreview"]
