from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from contextlib import AbstractContextManager, contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.adapters.opencv_video import (
    BGR8Frame,
    DecoderMetadata,
    OpenCvDecoderBackend,
    OpenCvVideoSource,
    VerifiedVideoLease,
)
from labcourt.contracts.manifests import StreamManifest
from labcourt.exceptions import EvidenceMissing, ManifestMismatch, ProviderUnavailable

INPUT_SHA256 = "a" * 64


def _manifest(**updates: object) -> StreamManifest:
    payload: dict[str, object] = {
        "camera_id": "cam-01",
        "stream_id": "stream-01",
        "input_file_sha256": INPUT_SHA256,
        "fps_num": 30,
        "fps_den": 1,
        "timing_mode": "CFR",
        "timing_authority": "TRUSTED_SIDECAR",
        "timing_evidence_type": "TRUSTED_SIDECAR_JSON",
        "timing_evidence_sha256": "b" * 64,
        "width": 2,
        "height": 1,
        "frame_count": 2,
        "decoder": "fake-sequential-decoder",
        "decoder_version": "fake-module-7",
        "backend": "FAKE",
        "software_component": "fake-opencv",
        "library": "fake-video",
        "library_version": "1.2.3",
        "codec": "RAWB",
        "color_conversion": "BGR_TO_RGB",
        "pixel_format": "RGB8",
        "pixel_hash_algorithm": "LCPIX1",
    }
    payload.update(updates)
    return StreamManifest.model_validate(payload)


def _metadata(**updates: object) -> DecoderMetadata:
    metadata = DecoderMetadata(
        width=2.0,
        height=1.0,
        frame_count=2.0,
        fps=30.0,
        backend="FAKE",
        codec="RAWB",
    )
    return replace(metadata, **updates)


FRAMES = (
    BGR8Frame(width=2, height=1, pixels=bytes((3, 2, 1, 6, 5, 4))),
    BGR8Frame(width=2, height=1, pixels=bytes((30, 20, 10, 60, 50, 40))),
)


class _FakeSession:
    def __init__(
        self,
        *,
        metadata: DecoderMetadata,
        frames: tuple[BGR8Frame, ...],
        close_error: Exception | None = None,
    ) -> None:
        self._metadata = metadata
        self._frames = frames
        self._position = 0
        self._close_error = close_error
        self.closed = False
        self.read_count = 0

    def metadata(self) -> DecoderMetadata:
        return self._metadata

    def read_bgr8(
        self,
        *,
        expected_width: int,
        expected_height: int,
        max_frame_pixels: int,
    ) -> BGR8Frame | None:
        del expected_width, expected_height, max_frame_pixels
        self.read_count += 1
        if self._position == len(self._frames):
            return None
        frame = self._frames[self._position]
        self._position += 1
        return frame

    def close(self) -> None:
        self.closed = True
        if self._close_error is not None:
            raise self._close_error


class _FakeBackend:
    software_component = "fake-opencv"
    library = "fake-video"
    library_version = "1.2.3"
    decoder = "fake-sequential-decoder"
    module_version = "fake-module-7"

    def __init__(
        self,
        *,
        metadata: DecoderMetadata | None = None,
        frames: tuple[BGR8Frame, ...] = FRAMES,
        open_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self._metadata = metadata or _metadata()
        self._frames = frames
        self._open_error = open_error
        self._close_error = close_error
        self.opened_paths: list[str] = []
        self.sessions: list[_FakeSession] = []

    def open(self, decoder_path: str) -> _FakeSession:
        self.opened_paths.append(decoder_path)
        if self._open_error is not None:
            raise self._open_error
        session = _FakeSession(
            metadata=self._metadata,
            frames=self._frames,
            close_error=self._close_error,
        )
        self.sessions.append(session)
        return session


class _FakeVerifiedInput:
    def __init__(
        self,
        *,
        input_sha256: str = INPUT_SHA256,
        size_bytes: int = 123,
        decoder_path: str = "opaque-locked-video-handle",
    ) -> None:
        self.input_sha256 = input_sha256
        self.size_bytes = size_bytes
        self.decoder_path = decoder_path
        self.calls: list[tuple[str, int]] = []
        self.exit_count = 0

    def open_verified_video(
        self,
        relative_path: str,
        max_bytes: int,
    ) -> AbstractContextManager[VerifiedVideoLease]:
        @contextmanager
        def lease() -> object:
            self.calls.append((relative_path, max_bytes))
            try:
                yield VerifiedVideoLease(
                    decoder_path=self.decoder_path,
                    input_file_sha256=self.input_sha256,
                    size_bytes=self.size_bytes,
                )
            finally:
                self.exit_count += 1

        return lease()


class _CaptureProbe:
    def __init__(self, *, opened: bool = True) -> None:
        self.opened = opened
        self.release_count = 0

    def isOpened(self) -> bool:
        return self.opened

    def release(self) -> None:
        self.release_count += 1


class _Cv2Probe:
    CAP_FFMPEG = 1_900

    def __init__(self, capture: _CaptureProbe) -> None:
        self.capture = capture
        self.calls: list[tuple[str, int]] = []

    def VideoCapture(self, filename: str, api_preference: int) -> _CaptureProbe:
        self.calls.append((filename, api_preference))
        return self.capture


def _source(
    *,
    manifest: StreamManifest | None = None,
    verified_input: _FakeVerifiedInput | None = None,
    backend: _FakeBackend | None = None,
    relative_path: str = "inputs/demo.avi",
    max_input_bytes: int = 1_000,
    max_frame_pixels: int = 100,
    max_total_decoded_pixels: int = 1_000,
) -> OpenCvVideoSource:
    return OpenCvVideoSource(
        manifest=manifest or _manifest(),
        verified_input=verified_input or _FakeVerifiedInput(),
        relative_path=relative_path,
        max_input_bytes=max_input_bytes,
        max_frame_pixels=max_frame_pixels,
        max_total_decoded_pixels=max_total_decoded_pixels,
        backend=backend or _FakeBackend(),
    )


def test_module_import_does_not_import_optional_cv2() -> None:
    project_root = Path(__file__).parents[2]
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "import labcourt.adapters.opencv_video; "
                "raise SystemExit(1 if 'cv2' in sys.modules else 0)"
            ),
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_missing_optional_dependency_is_a_typed_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_distribution(_package: str) -> object:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "distribution", missing_distribution)
    with pytest.raises(ProviderUnavailable, match=r"labcourt\[video\]"):
        OpenCvDecoderBackend()


def test_actual_backend_forces_ffmpeg_without_cap_any_fallback() -> None:
    capture = _CaptureProbe()
    cv2 = _Cv2Probe(capture)
    backend = object.__new__(OpenCvDecoderBackend)
    backend._cv2 = cv2  # type: ignore[assignment]

    session = backend.open("opaque-verified-file")
    session.close()

    assert cv2.calls == [("opaque-verified-file", cv2.CAP_FFMPEG)]
    assert capture.release_count == 1


def test_sequential_decode_converts_bgr_to_rgb_and_freezes_frame_hashes() -> None:
    verified_input = _FakeVerifiedInput()
    backend = _FakeBackend()
    source = _source(verified_input=verified_input, backend=backend)

    frames = tuple(source.iter_rgb8())

    assert [frame.frame.frame_id for frame in frames] == [
        "cam-01:stream-01:0",
        "cam-01:stream-01:1",
    ]
    assert frames[0].pixels == bytes((1, 2, 3, 4, 5, 6))
    assert (
        frames[0].frame.content_sha256
        == "cc6e99d412643ddc652153d20f0085d636d520675266c1d25149730f23bfa896"
    )
    assert frames[1].pixels == bytes((10, 20, 30, 40, 50, 60))
    assert verified_input.calls == [
        ("inputs/demo.avi", 1_000),
        ("inputs/demo.avi", 1_000),
    ]
    assert verified_input.exit_count == 2
    assert backend.opened_paths == [
        "opaque-locked-video-handle",
        "opaque-locked-video-handle",
    ]
    assert backend.sessions[0].read_count == 3
    assert backend.sessions[1].read_count == 3
    assert all(session.closed for session in backend.sessions)


def test_frame_source_methods_decode_forward_without_random_seek() -> None:
    backend = _FakeBackend()
    source = _source(backend=backend)

    second = source.read_rgb8("cam-01:stream-01:1")
    selected = source.get_range("cam-01", "stream-01", 0, 2, step=2)
    wrong_stream = source.get_range("cam-01", "other-stream", 0, 2)

    assert second.pixels == bytes((10, 20, 30, 40, 50, 60))
    assert [item.frame.frame_id for item in selected] == ["cam-01:stream-01:0"]
    assert wrong_stream == ()
    assert len(backend.sessions) == 3
    assert all(session.closed for session in backend.sessions)
    assert not any(hasattr(session, "seek") for session in backend.sessions)


@pytest.mark.parametrize(
    "metadata",
    [
        _metadata(width=3.0),
        _metadata(height=float("nan")),
        _metadata(frame_count=3.0),
        _metadata(fps=29.0),
        _metadata(backend="OTHER"),
        _metadata(codec="OTHER"),
    ],
)
def test_decoder_metadata_must_match_authoritative_manifest(
    metadata: DecoderMetadata,
) -> None:
    source = _source(backend=_FakeBackend(metadata=metadata))

    with pytest.raises(ManifestMismatch):
        next(source.iter_rgb8())


def test_input_hash_size_and_declared_pixel_limits_are_fail_closed() -> None:
    wrong_hash = _source(verified_input=_FakeVerifiedInput(input_sha256="b" * 64))
    too_large = _source(
        verified_input=_FakeVerifiedInput(size_bytes=1_001),
        max_input_bytes=1_000,
    )

    with pytest.raises(ManifestMismatch, match="bytes do not match"):
        next(wrong_hash.iter_rgb8())
    with pytest.raises(ManifestMismatch, match="byte limit"):
        next(too_large.iter_rgb8())
    with pytest.raises(ManifestMismatch, match="pixel limit"):
        _source(max_frame_pixels=1)
    with pytest.raises(ManifestMismatch, match="total decoded-pixel budget"):
        _source(max_total_decoded_pixels=3)


@pytest.mark.parametrize(
    "relative_path",
    [
        "../outside.avi",
        "/absolute/outside.avi",
        "C:/outside.avi",
        "\\\\server\\share\\outside.avi",
        "rtsp://camera/live",
    ],
)
def test_network_absolute_and_traversal_inputs_are_rejected(relative_path: str) -> None:
    verified_input = _FakeVerifiedInput()
    with pytest.raises(ValueError, match=r"workspace-relative|safe"):
        _source(verified_input=verified_input, relative_path=relative_path)
    assert verified_input.calls == []


def test_early_eof_extra_frames_and_dimension_changes_are_rejected() -> None:
    early = _source(backend=_FakeBackend(frames=FRAMES[:1]))
    extra = _source(
        backend=_FakeBackend(frames=(*FRAMES, BGR8Frame(width=2, height=1, pixels=bytes(6))))
    )
    changed = _source(
        backend=_FakeBackend(frames=(FRAMES[0], BGR8Frame(width=1, height=1, pixels=bytes(3))))
    )

    with pytest.raises(ManifestMismatch, match="ended before"):
        tuple(early.iter_rgb8())
    with pytest.raises(ManifestMismatch, match="beyond"):
        tuple(extra.iter_rgb8())
    with pytest.raises(ManifestMismatch, match="dimensions changed"):
        tuple(changed.iter_rgb8())


@pytest.mark.parametrize(
    "frames, message",
    [
        (FRAMES[:1], "ended before"),
        ((*FRAMES, BGR8Frame(width=2, height=1, pixels=bytes(6))), "beyond"),
    ],
)
def test_partial_frame_reads_cannot_bypass_full_stream_preflight(
    frames: tuple[BGR8Frame, ...],
    message: str,
) -> None:
    source = _source(backend=_FakeBackend(frames=frames))

    with pytest.raises(ManifestMismatch, match=message):
        source.read_rgb8("cam-01:stream-01:0")


def test_invalid_frame_ids_are_reported_as_typed_missing_evidence() -> None:
    source = _source()
    with pytest.raises(EvidenceMissing):
        source.read_rgb8("not-a-frame-id")


def test_backend_exceptions_are_redacted_and_lease_is_released() -> None:
    secret_path = r"C:\private\operator-name\video.avi"
    verified_input = _FakeVerifiedInput(decoder_path=secret_path)
    backend = _FakeBackend(open_error=RuntimeError(f"cannot open {secret_path}"))
    source = _source(verified_input=verified_input, backend=backend)

    with pytest.raises(ProviderUnavailable) as raised:
        next(source.iter_rgb8())

    assert secret_path not in str(raised.value)
    assert verified_input.exit_count == 1


def test_decoder_release_failures_are_typed_redacted_and_block_output() -> None:
    secret_path = r"C:\private\release-detail.avi"
    verified_input = _FakeVerifiedInput(decoder_path=secret_path)
    source = _source(
        verified_input=verified_input,
        backend=_FakeBackend(close_error=RuntimeError(f"release failed: {secret_path}")),
    )

    with pytest.raises(ProviderUnavailable) as raised:
        source.read_rgb8("cam-01:stream-01:0")

    assert secret_path not in str(raised.value)
    assert verified_input.exit_count == 1
