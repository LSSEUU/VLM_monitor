from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from labcourt.adapters.storage.m4_json_projector import M4JsonProjector
from labcourt.adapters.storage.readonly_m4_artifacts import ReadonlyM4ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.application.m4_current_projection_validation import (
    M4CurrentProjectionValidator,
)
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationBudget
from labcourt.services.m4_projection import rebuild_m4_projection
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_readonly_projection import _started_hearing


def _fingerprint(root: Path) -> tuple[tuple[str, int, int, str], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            int(path.stat().st_size),
            int(path.stat().st_mtime_ns),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    )


def test_current_projection_validation_reuses_snapshot_and_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = _started_hearing(tmp_path)
    output_root = tmp_path / "projection-output"
    rebuild_m4_projection(
        run_id=RUN_ID,
        database_path=started.database,
        workspace_root=output_root,
    )

    def fail_publish(*args: object, **kwargs: object) -> object:
        raise AssertionError("read-only validation must never publish")

    monkeypatch.setattr(M4JsonProjector, "publish", fail_publish)
    before_projection = _fingerprint(output_root)
    before_database = _fingerprint(started.database.parent)
    with readonly_sqlite_snapshot(started.database) as snapshot_database:
        authority = ReadonlyM4ArtifactRepository(snapshot_database).scan(RUN_ID)
        with SecureWorkspace(output_root, max_file_bytes=64 * 1024 * 1024) as workspace:
            result = M4CurrentProjectionValidator(
                artifact_reader=workspace,
                budget=M4ArtifactValidationBudget(),
            ).validate(RUN_ID, authority)

    assert result.issues == ()
    assert result.projection_documents == len(authority.documents)
    assert result.projection_files == len(authority.documents) + 2
    assert _fingerprint(output_root) == before_projection
    assert _fingerprint(started.database.parent) == before_database
