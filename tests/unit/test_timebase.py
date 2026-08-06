import json
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from labcourt.contracts.frames import FrameRef
from labcourt.domain.timebase import seconds_to_frames, timestamp_ms

FIXTURE = Path(__file__).parents[1] / "fixtures" / "m0" / "frame-ref-ntsc.json"


def test_ntsc_fixture_uses_exact_rational_time() -> None:
    frame = FrameRef.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
    assert frame.frame_id == "cam-01:demo-ntsc:1798"
    assert frame.timestamp_ms == 59_993
    assert frame.timestamp_ms == timestamp_ms(1798, 30000, 1001)


def test_seconds_to_frames_rounds_up() -> None:
    assert seconds_to_frames("0.1", 30000, 1001) == 3
    assert seconds_to_frames(5, 30, 1) == 150
    assert seconds_to_frames(0, 30, 1) == 0


@given(
    frame=st.integers(min_value=0, max_value=10**9),
    delta=st.integers(min_value=0, max_value=10**5),
    fps_num=st.integers(min_value=1, max_value=120_000),
    fps_den=st.integers(min_value=1, max_value=10_000),
)
def test_timestamp_is_monotonic(
    frame: int,
    delta: int,
    fps_num: int,
    fps_den: int,
) -> None:
    assert timestamp_ms(frame + delta, fps_num, fps_den) >= timestamp_ms(frame, fps_num, fps_den)


def test_fixture_is_plain_json() -> None:
    assert isinstance(json.loads(FIXTURE.read_text(encoding="utf-8")), dict)
