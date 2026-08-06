"""Trusted source-projection boundary for M6 locked replay."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class M6ReplayLockedSourceProjection:
    """One trusted source projection reconstructed from an immutable read cut."""

    source_identity_sha256: str
    closure: M6ReplayInputClosureAuthority
    source_snapshot: M6CaseReplaySnapshot

    def __post_init__(self) -> None:
        if not _is_sha256(self.source_identity_sha256):
            raise ValueError("M6 locked source identity must be a SHA-256")
        if (
            type(self.closure) is not M6ReplayInputClosureAuthority
            or type(self.source_snapshot) is not M6CaseReplaySnapshot
        ):
            raise TypeError("M6 locked source projection requires exact contract types")
        try:
            closure = M6ReplayInputClosureAuthority.model_validate(
                self.closure.model_dump(mode="json", exclude_computed_fields=True)
            )
            snapshot = M6CaseReplaySnapshot.model_validate(
                self.source_snapshot.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            raise ValueError("M6 locked source projection is not canonical") from None
        if (
            closure != self.closure
            or snapshot != self.source_snapshot
            or snapshot.sample_id != closure.sample_id
            or snapshot.source_run_id != closure.source_run_id
            or snapshot.source_case_id != closure.source_case_id
            or snapshot.source_case_revision != closure.source_case_revision
            or snapshot.source_case_document_sha256 != closure.source_case_document_sha256
            or snapshot.manifest_id != closure.source_manifest_id
        ):
            raise ValueError("M6 locked source snapshot differs from its exact closure")


@runtime_checkable
class M6ReplayLockedSourceProjectionProvider(Protocol):
    """Reconstruct one fresh projection from the provider's immutable source cut."""

    def load_source_projection(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedSourceProjection: ...


__all__ = [
    "M6ReplayLockedSourceProjection",
    "M6ReplayLockedSourceProjectionProvider",
]
