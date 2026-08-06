"""Perception capability port."""

from collections.abc import Sequence
from typing import Protocol

from labcourt.contracts.detections import Detection
from labcourt.contracts.evidence import Crop
from labcourt.contracts.frames import FrameData


class PerceptionProvider(Protocol):
    def detect(self, frame: FrameData) -> Sequence[Detection]: ...

    def redetect(self, crop: Crop, prompts: Sequence[str]) -> Sequence[Detection]: ...
