"""TTL-bound local cache port for raw RGB8 pixels that must never be persisted."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from labcourt.ports.pixels import RGB8Frame


@dataclass(frozen=True, slots=True)
class RawFrameLease:
    """Opaque lifetime receipt for one in-memory raw frame."""

    frame_id: str
    size_bytes: int
    expires_at: datetime


class RawFrameCache(Protocol):
    def put(self, frame: RGB8Frame) -> RawFrameLease: ...

    def get(self, frame_id: str) -> RGB8Frame: ...

    def purge_expired(self) -> tuple[str, ...]: ...

    def close(self) -> None: ...


__all__ = ["RawFrameCache", "RawFrameLease"]
