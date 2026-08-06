"""Atomic observations required to seal M6 source authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from labcourt.contracts.cases import Case
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.storage import ArtifactVerification, ClosureReport


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class M6CurrentPackObservation:
    """One pack, closure, and raw Crop reads from the same transaction."""

    pack: EvidencePack
    current_closure: ClosureReport
    crop_verifications: tuple[ArtifactVerification, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.pack, EvidencePack) or not isinstance(
            self.current_closure, ClosureReport
        ):
            raise TypeError("M6 current-pack observation requires typed documents")
        if not isinstance(self.crop_verifications, tuple):
            raise TypeError("M6 current-pack Crop verifications must be a tuple")
        if any(not isinstance(item, ArtifactVerification) for item in self.crop_verifications):
            raise TypeError("M6 current-pack observation requires typed Crop verifications")
        keys = tuple(item.artifact_ref.sort_key for item in self.crop_verifications)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M6 current-pack Crop verifications must be unique and ordered")


@dataclass(frozen=True, slots=True)
class M6GateSourceObservation:
    """One Case and all reviewed packs observed under one SQLite writer lock."""

    source_case: Case
    source_case_revision: int
    source_case_document_sha256: str
    audit_head_sequence: int
    audit_head_hash: str
    packs: tuple[M6CurrentPackObservation, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source_case, Case):
            raise TypeError("M6 Gate source observation requires a typed Case")
        if (
            not isinstance(self.source_case_revision, int)
            or isinstance(self.source_case_revision, bool)
            or self.source_case_revision <= 0
        ):
            raise ValueError("M6 Gate source Case revision must be positive")
        _require_sha256(self.source_case_document_sha256, "M6 source Case document")
        if (
            not isinstance(self.audit_head_sequence, int)
            or isinstance(self.audit_head_sequence, bool)
            or self.audit_head_sequence < -1
        ):
            raise ValueError("M6 Gate source audit sequence must be at least -1")
        _require_sha256(self.audit_head_hash, "M6 source audit head")
        if not isinstance(self.packs, tuple):
            raise TypeError("M6 Gate source pack observations must be a tuple")
        if any(not isinstance(item, M6CurrentPackObservation) for item in self.packs):
            raise TypeError("M6 Gate source observation requires typed pack observations")
        keys = tuple((item.pack.pack_id, item.pack.version) for item in self.packs)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M6 Gate source pack observations must be unique and ordered")


class M6GateSourceObserver(Protocol):
    """Observe one current Gate source without a retention interleaving."""

    def observe_m6_gate_source(
        self,
        run_id: str,
        case_id: str,
        source_case_revision: int | None = None,
    ) -> M6GateSourceObservation: ...


__all__ = [
    "M6CurrentPackObservation",
    "M6GateSourceObservation",
    "M6GateSourceObserver",
]
