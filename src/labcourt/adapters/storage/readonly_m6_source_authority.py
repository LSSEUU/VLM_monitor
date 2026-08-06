"""Resolve one persisted M6 source seal against a same-snapshot identity."""

from __future__ import annotations

from pathlib import Path

from labcourt.application.m6_source_authority import (
    M6ValidatedSourceAuthority,
    assemble_m6_validated_source_authority,
)
from labcourt.contracts.config import AppConfig
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority

from ._m6_snapshot_identity import capture_m6_readonly_snapshot_identity
from .m6_source_authority_store import ReadonlyM6SourceAuthorityStore
from .readonly_sqlite import ReadOnlySnapshotError


class ReadonlyM6SealedSourceAuthorityRepository:
    """Read a fixed closure-scoped seal without scanning for alternatives."""

    __slots__ = ("_config", "_snapshot", "_store")

    def __init__(
        self,
        snapshot: str | Path,
        *,
        store_root: str | Path,
        config: AppConfig,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be a fully resolved AppConfig")
        self._snapshot = Path(snapshot).absolute()
        self._store = ReadonlyM6SourceAuthorityStore(store_root)
        self._config = AppConfig.model_validate(config.model_dump(mode="json"))

    def load_validated_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ValidatedSourceAuthority:
        before = capture_m6_readonly_snapshot_identity(self._snapshot)
        stored = self._store.load(closure)
        after = capture_m6_readonly_snapshot_identity(self._snapshot)
        if after != before:
            raise ReadOnlySnapshotError("DATABASE_CHANGED_DURING_M6_SOURCE_SEAL_READ")
        return assemble_m6_validated_source_authority(
            closure=closure,
            snapshot=stored.to_source_snapshot(before.identity_sha256),
            config=self._config,
        )


__all__ = ["ReadonlyM6SealedSourceAuthorityRepository"]
