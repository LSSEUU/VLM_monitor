"""Source-seal adapter used by the precomputed M6 candidate materializer."""

from __future__ import annotations

from pathlib import Path

from labcourt.adapters.storage.m6_source_authority_store import (
    ReadonlyM6SourceAuthorityStore,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority_store import M6SourceAuthoritySeal


class ReadonlyM6UpgradeCandidateSourceSealProvider:
    """Load one exact closure-scoped source seal without directory scanning."""

    __slots__ = ("_store",)

    def __init__(self, source_authority_root: str | Path) -> None:
        self._store = ReadonlyM6SourceAuthorityStore(source_authority_root)

    def load_source_seal(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6SourceAuthoritySeal:
        return self._store.load(closure).seal


__all__ = ["ReadonlyM6UpgradeCandidateSourceSealProvider"]
