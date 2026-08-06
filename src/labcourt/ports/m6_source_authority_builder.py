"""Typed, unsealed replay inputs accepted by the M6 source builder."""

from __future__ import annotations

from dataclasses import dataclass, field

from labcourt.contracts.m6_replay_locked import (
    M6HistoricalCausalCut,
    M6LockedDetectionInput,
    M6LockedEmbeddingInput,
    M6LockedFrameInput,
    M6LockedModelCallInput,
    M6LockedToolResultInput,
)
from labcourt.contracts.references import require_reference_token


def _require_typed_tuple(
    value: object,
    item_type: type[object],
    label: str,
) -> None:
    if not isinstance(value, tuple) or any(not isinstance(item, item_type) for item in value):
        raise TypeError(f"{label} must be a tuple of {item_type.__name__}")


@dataclass(frozen=True, slots=True)
class M6ReplayInputSelection:
    """Replay inventory before authority/report hashes can be bound.

    Unlike ``M6ReplayInputClosureAuthority``, this DTO has no placeholder hash
    fields. The source builder derives every circular authority reference only
    after validating the source Case and terminal report.
    """

    sample_id: str
    source_run_id: str
    source_case_id: str
    source_case_revision: int
    frames: tuple[M6LockedFrameInput, ...]
    detections: tuple[M6LockedDetectionInput, ...] = ()
    model_calls: tuple[M6LockedModelCallInput, ...] = ()
    embeddings: tuple[M6LockedEmbeddingInput, ...] = ()
    tool_results: tuple[M6LockedToolResultInput, ...] = ()
    historical_cut: M6HistoricalCausalCut = field(default_factory=M6HistoricalCausalCut)

    def __post_init__(self) -> None:
        for value, label in (
            (self.sample_id, "M6 replay sample_id"),
            (self.source_run_id, "M6 replay source_run_id"),
            (self.source_case_id, "M6 replay source_case_id"),
        ):
            require_reference_token(value, label)
        if (
            not isinstance(self.source_case_revision, int)
            or isinstance(self.source_case_revision, bool)
            or self.source_case_revision <= 0
        ):
            raise ValueError("M6 replay source_case_revision must be positive")
        _require_typed_tuple(self.frames, M6LockedFrameInput, "frames")
        if not self.frames:
            raise ValueError("M6 replay selection requires at least one Frame")
        _require_typed_tuple(self.detections, M6LockedDetectionInput, "detections")
        _require_typed_tuple(self.model_calls, M6LockedModelCallInput, "model_calls")
        _require_typed_tuple(self.embeddings, M6LockedEmbeddingInput, "embeddings")
        _require_typed_tuple(self.tool_results, M6LockedToolResultInput, "tool_results")
        if not isinstance(self.historical_cut, M6HistoricalCausalCut):
            raise TypeError("historical_cut must be an M6HistoricalCausalCut")


__all__ = ["M6ReplayInputSelection"]
