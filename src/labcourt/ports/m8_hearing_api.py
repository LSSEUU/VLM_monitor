"""Additive read/start ports for exposing the frozen M4 hearing through M8."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.hearing import HearingSession
from labcourt.contracts.m8_hearing_api import M8HearingStartRequestV1, M8HearingViewV1


class M8HearingRuntime(Protocol):
    """One explicitly configured run; model routing is fixed at construction."""

    @property
    def run_id(self) -> str: ...

    def view(self, case_id: str) -> M8HearingViewV1: ...

    def start(self, request: M8HearingStartRequestV1) -> M8HearingViewV1: ...


class M8HearingSessionLocator(Protocol):
    """Read-only lookup needed after an M4 session reaches a terminal checkpoint."""

    def load_hearing_for_case(self, run_id: str, case_id: str) -> HearingSession | None: ...


__all__ = ["M8HearingRuntime", "M8HearingSessionLocator"]
