from __future__ import annotations

import pytest

from labcourt.adapters.pixel_observability import score_person_rgb8_observability
from labcourt.contracts.config import ObservabilityWeights
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import ObservationSource
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256


def _weights() -> ObservabilityWeights:
    return ObservabilityWeights(
        person_confidence=0.15,
        keypoint_visibility=0.25,
        frontality=0.20,
        sharpness=0.20,
        exposure=0.10,
        non_occlusion=0.10,
    )


def _frame() -> RGB8Frame:
    pixels = bytes(
        channel for y in range(8) for x in range(8) for channel in ((x * 31 + y * 7) % 256,) * 3
    )
    frame = FrameRef(
        camera_id="cam-01",
        stream_id="stream-01",
        frame_index=0,
        fps_num=24,
        fps_den=1,
        width=8,
        height=8,
        content_sha256=rgb8_pixel_sha256(8, 8, pixels),
    )
    return RGB8Frame(frame=frame, pixels=pixels)


def _person(frame: RGB8Frame) -> Detection:
    return Detection(
        detection_id="person-001",
        frame_id=frame.frame.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=1, y1=1, x2=7, y2=7),
        score=0.9,
        track_ref="cam-01:epoch-01:1",
        model_manifest_id="1" * 64,
    )


def test_rgb8_observability_is_deterministic_and_retains_components() -> None:
    frame = _frame()
    person = _person(frame)

    first = score_person_rgb8_observability(frame, person, _weights())
    second = score_person_rgb8_observability(frame, person, _weights())

    assert first == second
    assert first.source == ObservationSource.PIXEL_COMPUTED
    assert first.components.person_confidence == 0.9
    assert first.components.keypoint_visibility == 0.0
    assert first.components.frontality == 0.0
    assert first.components.sharpness > 0.0
    assert first.components.exposure > 0.0
    assert first.components.non_occlusion == 1.0
    assert 0.0 < first.total < 1.0


def test_rgb8_observability_rejects_cross_frame_and_non_person_inputs() -> None:
    frame = _frame()
    person = _person(frame)
    other = person.model_copy(update={"frame_id": "cam-01:stream-01:1"})
    with pytest.raises(ValueError, match="another frame"):
        score_person_rgb8_observability(frame, other, _weights())

    goggles = person.model_copy(update={"label": "goggles", "track_ref": None})
    with pytest.raises(TypeError, match="person Detection"):
        score_person_rgb8_observability(frame, goggles, _weights())
