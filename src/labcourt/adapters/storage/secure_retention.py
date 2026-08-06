"""Handle-anchored retention file operations backed by ``SecureWorkspace``."""

from __future__ import annotations

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.exceptions import (
    ArtifactIntegrityViolation,
    PathBoundaryViolation,
)
from labcourt.ports.retention import PurgeLease


class SecureRetentionFileOps:
    """Move verified media into run-scoped trash and irreversibly unlink it."""

    __slots__ = ("_workspace",)

    def __init__(self, workspace: SecureWorkspace) -> None:
        if not isinstance(workspace, SecureWorkspace):
            raise TypeError("workspace must be a SecureWorkspace")
        self._workspace = workspace

    def stage_for_purge(self, lease: PurgeLease) -> None:
        if not isinstance(lease, PurgeLease):
            raise TypeError("lease must be a PurgeLease")
        self._ensure_trash_directories(lease)
        moved = self._workspace.move_verified(
            lease.source_relative_path,
            lease.trash_relative_path,
            lease.media_sha256,
        )
        self._validate_receipt(
            moved.relative_path,
            moved.sha256,
            lease,
            operation="move",
        )

    def destroy_purged(self, lease: PurgeLease) -> None:
        if not isinstance(lease, PurgeLease):
            raise TypeError("lease must be a PurgeLease")
        self._ensure_trash_directories(lease)
        try:
            deleted = self._workspace.delete_verified_trash(
                lease.trash_relative_path,
                lease.media_sha256,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return
            raise
        self._validate_receipt(
            deleted.relative_path,
            deleted.sha256,
            lease,
            operation="delete",
        )

    def _ensure_trash_directories(self, lease: PurgeLease) -> None:
        for relative_path in (".trash", f".trash/{lease.run_id}"):
            self._workspace.ensure_private_directory(relative_path)

    @staticmethod
    def _validate_receipt(
        relative_path: str,
        media_sha256: str,
        lease: PurgeLease,
        *,
        operation: str,
    ) -> None:
        if relative_path != lease.trash_relative_path:
            raise PathBoundaryViolation(
                f"RETENTION_{operation.upper()}_RECEIPT_PATH_MISMATCH",
                lease.trash_relative_path,
            )
        if media_sha256 != lease.media_sha256:
            raise ArtifactIntegrityViolation(
                f"RETENTION_{operation.upper()}_RECEIPT_HASH_MISMATCH",
                lease.trash_relative_path,
            )


__all__ = ["SecureRetentionFileOps"]
