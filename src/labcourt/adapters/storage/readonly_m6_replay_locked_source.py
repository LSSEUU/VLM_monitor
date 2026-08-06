"""Read-only SQLite adapter for fresh M6 locked source projections."""

from __future__ import annotations

from pathlib import Path

from labcourt.contracts.config import AppConfig
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)
from labcourt.ports.m6_replay_locked_source import M6ReplayLockedSourceProjection

from .readonly_m6_projection_context import (
    ReadonlyM6SqliteProjectionAssemblyRepository,
)


class ReadonlyM6ReplayLockedSourceProjectionRepository:
    """Adapt the six-reader source assembly to the narrow locked-source port."""

    __slots__ = ("_assembly",)

    def __init__(
        self,
        snapshot: str | Path,
        *,
        config: AppConfig,
        source_authority_root: str | Path | None = None,
    ) -> None:
        self._assembly = ReadonlyM6SqliteProjectionAssemblyRepository(
            snapshot,
            config=config,
            source_authority_root=source_authority_root,
        )

    def load_source_projection(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedSourceProjection:
        assembly = self._assembly.assemble(closure)
        return M6ReplayLockedSourceProjection(
            source_identity_sha256=assembly.source_identity_sha256,
            closure=assembly.closure,
            source_snapshot=assembly.case_replay_snapshot,
        )

    def load_fast_terminal_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedFastTerminalSource:
        return self._assembly.assemble_fast_terminal(closure)

    def load_m4_gate_terminal_source(
        self,
        closure: M6ReplayInputClosureAuthority,
    ) -> M6ReplayLockedM4GateTerminalSource:
        return self._assembly.assemble_m4_gate_terminal(closure)


__all__ = ["ReadonlyM6ReplayLockedSourceProjectionRepository"]
