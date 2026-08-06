from __future__ import annotations

import importlib
import importlib.metadata
import sys
from hashlib import sha256
from pathlib import Path
from struct import pack

import pytest

from labcourt.adapters.opencv_video import (
    DecoderMetadata,
    OpenCvDecoderBackend,
    OpenCvVideoSource,
)
from labcourt.adapters.storage import SecureWorkspace
from labcourt.contracts.manifests import StreamManifest

_OPENCV_DISTRIBUTION = "opencv-python-headless"
_PINNED_DISTRIBUTION_VERSION = "5.0.0.93"
_PINNED_MODULE_VERSION = "5.0.0"
_EXPECTED_BACKEND = "FFMPEG"
_ENCODER_FOURCC = "FFV1"
_DECODER_FOURCC = "ffv1"
_WIDTH = 16
_HEIGHT = 16
_FRAME_COUNT = 3
_FPS = 5
_VIDEO_RELATIVE_PATH = "inputs/PRIVATE-OPERATOR-CANARY-synthetic-ffv1.avi"


def _load_pinned_video_modules() -> tuple[OpenCvDecoderBackend, object, object]:
    try:
        installed_version = importlib.metadata.version(_OPENCV_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("requires the optional pinned labcourt[video] dependency")

    assert installed_version == _PINNED_DISTRIBUTION_VERSION
    backend = OpenCvDecoderBackend()
    assert backend.library_version == _PINNED_DISTRIBUTION_VERSION
    assert backend.module_version == _PINNED_MODULE_VERSION
    return backend, importlib.import_module("cv2"), importlib.import_module("numpy")


def _synthetic_bgr_frames(numpy: object) -> tuple[object, ...]:
    np = numpy
    frames: list[object] = []
    for frame_index in range(_FRAME_COUNT):
        frame = np.zeros((_HEIGHT, _WIDTH, 3), dtype=np.uint8)  # type: ignore[attr-defined]
        frame[:, :, 0] = 17 + frame_index * 31  # type: ignore[index]
        frame[:, :, 1] = 43 + frame_index * 29  # type: ignore[index]
        frame[:, :, 2] = 91 + frame_index * 23  # type: ignore[index]
        frame[2 + frame_index : 7 + frame_index, 3:11, :] = (  # type: ignore[index]
            151 - frame_index * 7,
            103 + frame_index * 11,
            59 + frame_index * 13,
        )
        frames.append(frame)
    return tuple(frames)


def _write_synthetic_ffv1(path: Path, cv2: object, frames: tuple[object, ...]) -> None:
    writer = cv2.VideoWriter(  # type: ignore[attr-defined]
        str(path),
        cv2.CAP_FFMPEG,  # type: ignore[attr-defined]
        cv2.VideoWriter_fourcc(*_ENCODER_FOURCC),  # type: ignore[attr-defined]
        float(_FPS),
        (_WIDTH, _HEIGHT),
        True,
    )
    try:
        assert writer.isOpened(), "pinned OpenCV could not create the FFV1 smoke fixture"
        assert writer.getBackendName() == _EXPECTED_BACKEND
        for frame in frames:
            writer.write(frame)
    finally:
        writer.release()
    assert path.is_file() and path.stat().st_size > 0


def _expected_rgb(frame: object) -> bytes:
    bgr = frame.tobytes(order="C")  # type: ignore[attr-defined]
    rgb = bytearray(len(bgr))
    rgb[0::3] = bgr[2::3]
    rgb[1::3] = bgr[1::3]
    rgb[2::3] = bgr[0::3]
    return bytes(rgb)


def _lcpix1(pixels: bytes) -> str:
    preimage = b"LCPIX1\x00" + pack(">II", _WIDTH, _HEIGHT) + b"RGB8\x00" + pixels
    return sha256(preimage).hexdigest()


def _stream_manifest(input_sha256: str) -> StreamManifest:
    return StreamManifest(
        camera_id="synthetic-camera",
        stream_id="ffv1-smoke",
        input_file_sha256=input_sha256,
        fps_num=_FPS,
        fps_den=1,
        timing_mode="CFR",
        timing_authority="CALLER_ATTESTED",
        timing_evidence_type="CALLER_DECLARATION",
        timing_evidence_sha256=sha256(b"synthetic-cfr-5/1").hexdigest(),
        width=_WIDTH,
        height=_HEIGHT,
        frame_count=_FRAME_COUNT,
        decoder="opencv.VideoCapture(CAP_FFMPEG)",
        decoder_version=_PINNED_MODULE_VERSION,
        backend=_EXPECTED_BACKEND,
        software_component="opencv",
        library=_OPENCV_DISTRIBUTION,
        library_version=_PINNED_DISTRIBUTION_VERSION,
        codec=_DECODER_FOURCC,
        color_conversion="BGR_TO_RGB",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )


@pytest.mark.video
@pytest.mark.skipif(
    sys.platform != "win32" and not sys.platform.startswith("linux"),
    reason="SecureWorkspace video leases are supported only on Windows and Linux",
)
def test_real_opencv_secure_lease_preflight_rgb_and_lcpix1(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Exercise the pinned native decoder with synthetic, non-person imagery only."""

    backend, cv2, numpy = _load_pinned_video_modules()

    generated_path = tmp_path / "synthetic-source.avi"
    bgr_frames = _synthetic_bgr_frames(numpy)
    _write_synthetic_ffv1(generated_path, cv2, bgr_frames)
    video_bytes = generated_path.read_bytes()
    input_sha256 = sha256(video_bytes).hexdigest()
    expected_rgb = tuple(_expected_rgb(frame) for frame in bgr_frames)
    expected_hashes = tuple(_lcpix1(pixels) for pixels in expected_rgb)

    # Ignore fixture-writer diagnostics; only the verified decoder boundary is under test below.
    capfd.readouterr()
    workspace_root = tmp_path / "workspace-canary"
    workspace_root.mkdir()
    max_input_bytes = max(len(video_bytes) * 2, 1)

    with SecureWorkspace(workspace_root, max_file_bytes=max_input_bytes) as workspace:
        workspace.create_directory("inputs")
        created = workspace.create_new(
            _VIDEO_RELATIVE_PATH,
            video_bytes,
            input_sha256,
        )
        assert created.sha256 == input_sha256

        with workspace.open_verified_video(_VIDEO_RELATIVE_PATH, max_input_bytes) as lease:
            assert lease.input_file_sha256 == input_sha256
            assert lease.size_bytes == len(video_bytes)
            session = backend.open(lease.decoder_path)
            try:
                metadata = session.metadata()
            finally:
                session.close()

        assert metadata == DecoderMetadata(
            width=float(_WIDTH),
            height=float(_HEIGHT),
            frame_count=float(_FRAME_COUNT),
            fps=float(_FPS),
            backend=_EXPECTED_BACKEND,
            codec=_DECODER_FOURCC,
        )

        source = OpenCvVideoSource(
            manifest=_stream_manifest(input_sha256),
            verified_input=workspace,
            relative_path=_VIDEO_RELATIVE_PATH,
            max_input_bytes=max_input_bytes,
            max_frame_pixels=_WIDTH * _HEIGHT,
            max_total_decoded_pixels=_WIDTH * _HEIGHT * _FRAME_COUNT,
            backend=backend,
        )
        assert source.validate_stream() == expected_hashes
        decoded = tuple(source.iter_rgb8())

    assert tuple(frame.pixels for frame in decoded) == expected_rgb
    assert tuple(frame.frame.content_sha256 for frame in decoded) == expected_hashes
    assert [frame.frame.frame_index for frame in decoded] == list(range(_FRAME_COUNT))

    native_output = capfd.readouterr()
    normalized_stderr = native_output.err.replace("\\", "/").casefold()
    local_path_canaries = (
        _VIDEO_RELATIVE_PATH.rsplit("/", 1)[-1],
        workspace_root.name,
        str(workspace_root.resolve()),
        str(Path(__file__).resolve().parents[2]),
    )
    assert all(
        canary.replace("\\", "/").casefold() not in normalized_stderr
        for canary in local_path_canaries
    )
