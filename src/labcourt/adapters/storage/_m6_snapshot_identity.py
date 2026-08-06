"""Common physical identity for one private M6 SQLite snapshot."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from labcourt.contracts.canonical import sha256_hex

from .readonly_sqlite import ReadOnlySnapshotError


@dataclass(frozen=True, slots=True)
class M6ReadonlySnapshotIdentity:
    """Stable identity of the exact private file used by all M6 readers."""

    device: int
    inode: int
    size_bytes: int
    modified_ns: int

    @property
    def identity_sha256(self) -> str:
        return sha256_hex(
            [
                "m6-readonly-snapshot-identity",
                1,
                self.device,
                self.inode,
                self.size_bytes,
                self.modified_ns,
            ]
        )


def capture_m6_readonly_snapshot_identity(
    snapshot: str | Path,
) -> M6ReadonlySnapshotIdentity:
    """Reject aliases and return the common identity used across M6 adapters."""

    path = Path(snapshot).absolute()
    try:
        info = os.lstat(path)
    except OSError:
        raise ReadOnlySnapshotError("DATABASE_STAT_FAILED") from None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or int(info.st_nlink) != 1:
        raise ReadOnlySnapshotError("DATABASE_FILE_UNSAFE")
    return M6ReadonlySnapshotIdentity(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        size_bytes=int(info.st_size),
        modified_ns=int(info.st_mtime_ns),
    )


__all__ = [
    "M6ReadonlySnapshotIdentity",
    "capture_m6_readonly_snapshot_identity",
]
