"""In-process, authority-derived progress for the existing Pilot pipeline."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, TypeAlias

PilotProgressStage: TypeAlias = Literal["VIDEO", "PERCEPTION", "EVIDENCE", "SCREENING", "REPORT"]
PilotProgressState: TypeAlias = Literal["RUNNING", "COMPLETE"]
PilotProgressUnit: TypeAlias = Literal["FRAME"]


@dataclass(frozen=True, slots=True)
class PilotProgressUpdate:
    """One truthful stage update; frame counts come from verified media and worker replies."""

    stage: PilotProgressStage
    state: PilotProgressState
    completed_units: int | None = None
    total_units: int | None = None
    unit: PilotProgressUnit | None = None

    def __post_init__(self) -> None:
        values = (self.completed_units, self.total_units, self.unit)
        if all(value is None for value in values):
            return
        if any(value is None for value in values):
            raise ValueError("Pilot progress counters must be supplied as one complete group")
        if self.stage != "PERCEPTION" or self.unit != "FRAME":
            raise ValueError("only Pilot perception may expose objective FRAME progress")
        if not isinstance(self.completed_units, int) or isinstance(self.completed_units, bool):
            raise TypeError("Pilot completed units must be an integer")
        if not isinstance(self.total_units, int) or isinstance(self.total_units, bool):
            raise TypeError("Pilot total units must be an integer")
        if self.completed_units < 0 or self.total_units <= 0:
            raise ValueError("Pilot progress counters must be positive and bounded")
        if self.completed_units > self.total_units:
            raise ValueError("Pilot completed units cannot exceed total units")


PilotProgressObserver: TypeAlias = Callable[[PilotProgressUpdate], None]


def publish_pilot_progress(
    observer: PilotProgressObserver | None,
    *,
    stage: PilotProgressStage,
    state: PilotProgressState,
    completed_units: int | None = None,
    total_units: int | None = None,
    unit: PilotProgressUnit | None = None,
) -> None:
    """Notify an optional observer without changing the historical default path."""

    if observer is None:
        return
    observer(
        PilotProgressUpdate(
            stage=stage,
            state=state,
            completed_units=completed_units,
            total_units=total_units,
            unit=unit,
        )
    )


__all__ = [
    "PilotProgressObserver",
    "PilotProgressStage",
    "PilotProgressState",
    "PilotProgressUnit",
    "PilotProgressUpdate",
    "publish_pilot_progress",
]
