from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from labcourt.adapters.in_memory_raw_cache import InMemoryRawFrameCache
from labcourt.contracts.frames import FrameRef
from labcourt.exceptions import BudgetExceeded, EvidenceMissing
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 7, 27, 16, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _frame(frame_index: int, value: int = 7) -> RGB8Frame:
    pixels = bytes([value, value + 1, value + 2]) * 4
    return RGB8Frame(
        frame=FrameRef(
            camera_id="cam-01",
            stream_id="stream-01",
            frame_index=frame_index,
            fps_num=30,
            fps_den=1,
            width=2,
            height=2,
            content_sha256=rgb8_pixel_sha256(2, 2, pixels),
        ),
        pixels=pixels,
    )


def test_raw_frame_cache_is_idempotent_and_expires_without_persistence() -> None:
    clock = _Clock()
    cache = InMemoryRawFrameCache(
        ttl_seconds=60,
        max_bytes=24,
        max_frames=2,
        clock=clock,
    )
    frame = _frame(1)

    first = cache.put(frame)
    replay = cache.put(frame)
    loaded = cache.get(frame.frame.frame_id)
    clock.now += timedelta(seconds=60)

    assert replay == first
    assert loaded == frame
    assert cache.purge_expired() == (frame.frame.frame_id,)
    with pytest.raises(EvidenceMissing, match="TTL expired"):
        cache.get(frame.frame.frame_id)


def test_raw_frame_cache_fails_closed_at_capacity_and_after_close() -> None:
    clock = _Clock()
    cache = InMemoryRawFrameCache(
        ttl_seconds=60,
        max_bytes=12,
        max_frames=1,
        clock=clock,
    )
    cache.put(_frame(1))

    with pytest.raises(BudgetExceeded, match="capacity"):
        cache.put(_frame(2, value=11))

    cache.close()
    cache.close()
    with pytest.raises(EvidenceMissing, match="closed"):
        cache.get("cam-01:stream-01:1")


def test_raw_frame_cache_rejects_naive_clock() -> None:
    cache = InMemoryRawFrameCache(
        ttl_seconds=60,
        max_bytes=12,
        max_frames=1,
        clock=lambda: datetime(2026, 7, 27),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        cache.put(_frame(1))
