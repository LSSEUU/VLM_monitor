"""Typed physical observations accepted by M6 challenge selection."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.m6_regression_selection import (
    M6SyntheticChallengeScenarioAuthority,
)


def _require_sha256(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class M6ChallengeScenarioObservation:
    """One canonical scenario document read through a bounded adapter."""

    scenario: M6SyntheticChallengeScenarioAuthority
    canonical_document: str
    content_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.scenario, M6SyntheticChallengeScenarioAuthority):
            raise TypeError("M6 challenge observation requires a typed scenario")
        if not isinstance(self.canonical_document, str) or not self.canonical_document:
            raise ValueError("M6 challenge observation requires a canonical document")
        _require_sha256(self.content_sha256, "M6 challenge scenario content")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes <= 0
        ):
            raise ValueError("M6 challenge scenario size must be positive")


__all__ = ["M6ChallengeScenarioObservation"]
