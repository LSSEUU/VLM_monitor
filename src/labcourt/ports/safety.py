"""Certified safety-signal port."""

from collections.abc import Sequence
from typing import Protocol

from labcourt.contracts.events import SafetySignal
from labcourt.contracts.frames import FrameRef


class SafetySignalProvider(Protocol):
    def signals_for_frame(self, frame: FrameRef) -> Sequence[SafetySignal]: ...
