"""Exact frame-time conversion without wall clocks or binary float drift."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction


def _validate_fps(fps_num: int, fps_den: int) -> None:
    if (
        not isinstance(fps_num, int)
        or isinstance(fps_num, bool)
        or not isinstance(fps_den, int)
        or isinstance(fps_den, bool)
    ):
        raise TypeError("FPS numerator and denominator must be integers")
    if fps_num <= 0 or fps_den <= 0:
        raise ValueError("FPS numerator and denominator must be positive")


def timestamp_ms(frame_index: int, fps_num: int, fps_den: int) -> int:
    _validate_fps(fps_num, fps_den)
    if not isinstance(frame_index, int) or isinstance(frame_index, bool):
        raise TypeError("frame_index must be an integer")
    if frame_index < 0:
        raise ValueError("frame_index must be a non-negative integer")
    return (frame_index * 1000 * fps_den) // fps_num


def seconds_to_frames(
    seconds: Decimal | Fraction | str | int | float,
    fps_num: int,
    fps_den: int,
) -> int:
    """Round up so the resolved frame dwell is never shorter than configured."""

    _validate_fps(fps_num, fps_den)
    if isinstance(seconds, bool):
        raise TypeError("seconds must be numeric, not bool")
    if isinstance(seconds, Fraction):
        duration = seconds
    elif isinstance(seconds, Decimal):
        duration = Fraction(seconds)
    elif isinstance(seconds, float):
        duration = Fraction(Decimal(str(seconds)))
    else:
        duration = Fraction(seconds)
    if duration < 0:
        raise ValueError("seconds must be non-negative")
    frames = duration * fps_num / fps_den
    return (frames.numerator + frames.denominator - 1) // frames.denominator


def duration_ms(
    start_frame: int,
    end_frame_exclusive: int,
    fps_num: int,
    fps_den: int,
) -> int:
    if (
        not isinstance(start_frame, int)
        or isinstance(start_frame, bool)
        or not isinstance(end_frame_exclusive, int)
        or isinstance(end_frame_exclusive, bool)
    ):
        raise TypeError("frame interval bounds must be integers")
    if start_frame < 0 or end_frame_exclusive <= start_frame:
        raise ValueError("frame interval must be non-empty and non-negative")
    return timestamp_ms(end_frame_exclusive - start_frame, fps_num, fps_den)
