"""Bounded, zero-on-release RAM cache for EPHEMERAL_RAW RGB8 frames."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock

from labcourt.contracts.frames import FrameRef
from labcourt.contracts.references import parse_frame_id
from labcourt.exceptions import BudgetExceeded, ContractViolation, EvidenceMissing
from labcourt.ports.pixels import RGB8Frame
from labcourt.ports.raw_frame_cache import RawFrameLease


@dataclass(slots=True)
class _Entry:
    frame: FrameRef
    pixels: bytearray
    expires_at: datetime


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("raw cache clock must return datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("raw cache clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


class InMemoryRawFrameCache:
    """Keep raw pixels only in bounded process memory and erase released buffers."""

    __slots__ = (
        "_clock",
        "_closed",
        "_entries",
        "_lock",
        "_max_bytes",
        "_max_frames",
        "_size_bytes",
        "_ttl",
    )

    def __init__(
        self,
        *,
        ttl_seconds: int,
        max_bytes: int,
        max_frames: int,
        clock: Callable[[], datetime],
    ) -> None:
        for name, value in (
            ("ttl_seconds", ttl_seconds),
            ("max_bytes", max_bytes),
            ("max_frames", max_frames),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._ttl = timedelta(seconds=ttl_seconds)
        self._max_bytes = max_bytes
        self._max_frames = max_frames
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._size_bytes = 0
        self._closed = False
        self._lock = RLock()

    def put(self, frame: RGB8Frame) -> RawFrameLease:
        if not isinstance(frame, RGB8Frame):
            raise TypeError("raw cache accepts only validated RGB8Frame values")
        now = _aware_utc(self._clock())
        with self._lock:
            self._require_open()
            self._purge_expired_locked(now)
            existing = self._entries.get(frame.frame.frame_id)
            if existing is not None:
                if existing.frame != frame.frame or bytes(existing.pixels) != frame.pixels:
                    raise ContractViolation("raw frame ID cannot be rebound to different pixels")
                return self._lease(existing)
            frame_size = len(frame.pixels)
            if (
                len(self._entries) + 1 > self._max_frames
                or self._size_bytes + frame_size > self._max_bytes
            ):
                raise BudgetExceeded("raw frame cache capacity exceeded")
            entry = _Entry(
                frame=frame.frame,
                pixels=bytearray(frame.pixels),
                expires_at=now + self._ttl,
            )
            self._entries[frame.frame.frame_id] = entry
            self._size_bytes += frame_size
            return self._lease(entry)

    def get(self, frame_id: str) -> RGB8Frame:
        parse_frame_id(frame_id)
        now = _aware_utc(self._clock())
        with self._lock:
            self._require_open()
            self._purge_expired_locked(now)
            entry = self._entries.get(frame_id)
            if entry is None:
                raise EvidenceMissing("raw frame is unavailable or its TTL expired")
            return RGB8Frame(frame=entry.frame, pixels=bytes(entry.pixels))

    def purge_expired(self) -> tuple[str, ...]:
        now = _aware_utc(self._clock())
        with self._lock:
            self._require_open()
            return self._purge_expired_locked(now)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            for entry in self._entries.values():
                self._erase(entry)
            self._entries.clear()
            self._size_bytes = 0
            self._closed = True

    def __enter__(self) -> InMemoryRawFrameCache:
        with self._lock:
            self._require_open()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def _purge_expired_locked(self, now: datetime) -> tuple[str, ...]:
        expired = tuple(
            sorted(frame_id for frame_id, entry in self._entries.items() if entry.expires_at <= now)
        )
        for frame_id in expired:
            entry = self._entries.pop(frame_id)
            self._size_bytes -= len(entry.pixels)
            self._erase(entry)
        return expired

    @staticmethod
    def _erase(entry: _Entry) -> None:
        entry.pixels[:] = b"\x00" * len(entry.pixels)

    @staticmethod
    def _lease(entry: _Entry) -> RawFrameLease:
        return RawFrameLease(
            frame_id=entry.frame.frame_id,
            size_bytes=len(entry.pixels),
            expires_at=entry.expires_at,
        )

    def _require_open(self) -> None:
        if self._closed:
            raise EvidenceMissing("raw frame cache is closed")


__all__ = ["InMemoryRawFrameCache"]
