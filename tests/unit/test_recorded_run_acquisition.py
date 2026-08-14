from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from labcourt.adapters.opencv_video import BGR8Frame, DecoderMetadata
from labcourt.adapters.recorded_run_acquisition import (
    RecordedRunFrameAcquisitionExecutor,
)
from labcourt.contracts.enums import AcquisitionAction
from labcourt.contracts.evidence import RequestMoreFramesParameters
from labcourt.contracts.manifests import (
    RunManifest,
    SoftwareComponentManifest,
    StreamManifest,
)
from labcourt.domain.evidence_authority import derive_evidence_authority
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionExecutorError,
    HearingAcquisitionExecutorFailureCode,
    HearingAcquisitionRecoveryStatus,
)
from tests.unit.test_m4_evidence_authority import _execution
from tests.unit.test_m4_hearing_request import ROOT, _closed_pack


class _Session:
    def __init__(self, frames: tuple[BGR8Frame, ...]) -> None:
        self._frames = frames
        self._position = 0

    def metadata(self) -> DecoderMetadata:
        first = self._frames[0]
        return DecoderMetadata(
            width=float(first.width),
            height=float(first.height),
            frame_count=float(len(self._frames)),
            fps=30.0,
            backend="FAKE",
            codec="RAWB",
        )

    def read_bgr8(
        self,
        *,
        expected_width: int,
        expected_height: int,
        max_frame_pixels: int,
    ) -> BGR8Frame | None:
        del expected_width, expected_height, max_frame_pixels
        if self._position == len(self._frames):
            return None
        frame = self._frames[self._position]
        self._position += 1
        return frame

    def close(self) -> None:
        return None


class _Backend:
    software_component = "fake-opencv"
    library = "fake-video"
    library_version = "1.2.3"
    decoder = "fake-sequential-decoder"
    module_version = "fake-module-7"

    def __init__(self, frames: tuple[BGR8Frame, ...]) -> None:
        self._frames = frames

    def open(self, decoder_path: str) -> _Session:
        assert decoder_path
        return _Session(self._frames)


def _manifest(
    input_sha256: str,
    frame_count: int,
    *,
    width: int = 2,
    height: int = 1,
) -> RunManifest:
    base = RunManifest.model_validate_json(
        (ROOT / "tests/fixtures/m2/run-manifest-fake.json").read_text(encoding="utf-8")
    )
    stream = StreamManifest(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        input_file_sha256=input_sha256,
        fps_num=30,
        fps_den=1,
        timing_mode="CFR",
        timing_authority="TRUSTED_SIDECAR",
        timing_evidence_type="TRUSTED_SIDECAR_JSON",
        timing_evidence_sha256="b" * 64,
        width=width,
        height=height,
        frame_count=frame_count,
        decoder="fake-sequential-decoder",
        decoder_version="fake-module-7",
        backend="FAKE",
        software_component="fake-opencv",
        library="fake-video",
        library_version="1.2.3",
        codec="RAWB",
        color_conversion="BGR_TO_RGB",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    payload = base.model_dump(mode="python", exclude={"manifest_id"})
    payload["streams"] = (stream,)
    payload["software_components"] = {
        "fake-opencv": SoftwareComponentManifest(
            component="fake-opencv",
            package="fake-video",
            version="1.2.3",
            license_id="Apache-2.0",
        )
    }
    return RunManifest.model_validate(payload)


def test_recorded_executor_returns_hash_bound_frames_and_rejects_other_tools(
    tmp_path: Path,
) -> None:
    video = b"sealed-recorded-video"
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "demo.mp4").write_bytes(video)
    frames = tuple(
        BGR8Frame(width=2, height=1, pixels=bytes((3, 2, 1, 6, 5, 4))) for _ in range(100)
    )
    manifest = _manifest(hashlib.sha256(video).hexdigest(), len(frames))
    pack = _closed_pack(manifest)
    authority = derive_evidence_authority(pack)
    parameters = RequestMoreFramesParameters(
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        camera_id="cam-01",
        stream_id="demo-ntsc",
        start_frame=91,
        end_frame_exclusive=95,
        step=2,
    )
    reference = _execution(
        pack,
        AcquisitionAction.REQUEST_MORE_FRAMES,
        parameters=parameters,
    )
    executor = RecordedRunFrameAcquisitionExecutor(
        project_root=tmp_path,
        input_relative_path="inputs/demo.mp4",
        manifest=manifest,
        max_input_bytes=1_024,
        max_frame_pixels=2,
        decoder_backend=_Backend(frames),
    )

    execution = executor.execute(
        reference.request,
        authority,
        idempotency_key=reference.request.request_id,
    )

    assert execution.execution_manifest.tool_id == "recorded-run-request-more-frames"
    assert tuple(frame.frame_index for frame in execution.output_objects.frames) == (91, 93)
    assert execution.output_objects.frames[0].content_sha256 is not None
    assert execution.tool_result.output_refs == execution.output_objects.refs
    assert (
        executor.recover(
            reference.request,
            authority,
            idempotency_key=reference.request.request_id,
        ).status
        == HearingAcquisitionRecoveryStatus.DEFINITELY_NOT_STARTED
    )

    unsupported = _execution(pack, AcquisitionAction.RECROP).request
    with pytest.raises(HearingAcquisitionExecutorError) as raised:
        executor.execute(
            unsupported,
            authority,
            idempotency_key=unsupported.request_id,
        )
    assert raised.value.reason_code == HearingAcquisitionExecutorFailureCode.TOOL_UNAVAILABLE

    overlap = _execution(
        pack,
        AcquisitionAction.REQUEST_MORE_FRAMES,
        parameters=parameters.model_copy(
            update={
                "start_frame": pack.event.trigger_frame,
                "end_frame_exclusive": pack.event.trigger_frame + 1,
                "step": 1,
            }
        ),
    ).request
    with pytest.raises(HearingAcquisitionExecutorError) as overlap_error:
        executor.execute(overlap, authority, idempotency_key=overlap.request_id)
    assert (
        overlap_error.value.reason_code == HearingAcquisitionExecutorFailureCode.AUTHORITY_MISMATCH
    )
