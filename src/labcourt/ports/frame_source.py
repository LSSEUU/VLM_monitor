"""Frame input port."""

from collections.abc import Iterator, Sequence
from typing import Protocol

from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.frames import FrameData


class FrameSource(Protocol):
    def iter_frames(self) -> Iterator[FrameBundle]: ...

    def get_frame(self, frame_id: str) -> FrameData: ...

    def get_range(
        self,
        camera_id: str,
        stream_id: str,
        start: int,
        end: int,
        step: int = 1,
    ) -> Sequence[FrameData]: ...
