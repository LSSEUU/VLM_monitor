from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from labcourt.adapters.storage.secure_retention import SecureRetentionFileOps
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import PathBoundaryViolation
from labcourt.ports.retention import PurgeLease

RUN_ID = "run-01"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_secure_retention_stages_and_destroys_by_verified_canonical_lease(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    data = b"privacy-sensitive redacted evidence"
    media_sha256 = _digest(data)
    source = f"{RUN_ID}/frames/{media_sha256}.png"
    trash = f".trash/{RUN_ID}/{media_sha256}.png"
    lease = PurgeLease(
        run_id=RUN_ID,
        media_sha256=media_sha256,
        source_relative_path=source,
        trash_relative_path=trash,
        crop_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id="c" * 64),),
        intent_audit_sequence=7,
    )

    with SecureWorkspace(root, max_file_bytes=4096) as workspace:
        for directory in (RUN_ID, f"{RUN_ID}/frames"):
            workspace.create_directory(directory)
        workspace.create_new(source, data, media_sha256)
        file_ops = SecureRetentionFileOps(workspace)

        file_ops.stage_for_purge(lease)
        assert workspace.read_verified(trash, media_sha256).bytes == data
        assert not (root / Path(source)).exists()

        file_ops.stage_for_purge(lease)
        file_ops.destroy_purged(lease)
        assert not (root / Path(trash)).exists()

        # A crash after unlink but before repository cleanup acknowledgement is retried.
        file_ops.destroy_purged(lease)


def test_secure_retention_rejects_an_existing_nonprivate_trash_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    trash_root = root / ".trash"
    trash_root.mkdir()
    if os.name != "nt":
        trash_root.chmod(0o755)
    data = b"private media"
    media_sha256 = _digest(data)
    lease = PurgeLease(
        run_id=RUN_ID,
        media_sha256=media_sha256,
        source_relative_path=f"{RUN_ID}/frames/{media_sha256}.png",
        trash_relative_path=f".trash/{RUN_ID}/{media_sha256}.png",
        crop_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id="c" * 64),),
        intent_audit_sequence=7,
    )

    with SecureWorkspace(root, max_file_bytes=4096) as workspace:
        for directory in (RUN_ID, f"{RUN_ID}/frames"):
            workspace.ensure_private_directory(directory)
        workspace.create_new(lease.source_relative_path, data, media_sha256)
        with pytest.raises(PathBoundaryViolation) as captured:
            SecureRetentionFileOps(workspace).stage_for_purge(lease)

    assert captured.value.reason_code == "DIRECTORY_NOT_PRIVATE"
