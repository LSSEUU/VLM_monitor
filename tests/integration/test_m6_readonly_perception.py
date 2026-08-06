from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_m6_perception import (
    ReadonlyM6PerceptionAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_perception_authority import (
    M6PerceptionAuthorityError,
    M6PerceptionAuthorityErrorCode,
)
from labcourt.contracts.detections import Detection
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_replay_locked import (
    M6LockedDetectionInput,
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from tests.integration.test_m2_sqlite_repository import (
    RUN_ID,
    _frame,
    _manifest,
    _register_case,
    _repository,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source_fingerprint(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.name: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in root.iterdir()
        if path.is_file()
    }


def _closure(
    database: Path,
    *,
    frames: tuple[FrameRef, ...],
    detections: tuple[Detection, ...],
    with_case: bool,
) -> M6ReplayInputClosureAuthority:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        manifest_row = connection.execute(
            """
            SELECT rm.document_sha256
            FROM runs AS r
            JOIN run_manifests AS rm ON rm.manifest_id = r.manifest_id
            WHERE r.run_id = ?
            """,
            (RUN_ID,),
        ).fetchone()
        assert manifest_row is not None
        frame_documents = {
            str(row["frame_id"]): str(row["document_sha256"])
            for row in connection.execute(
                "SELECT frame_id, document_sha256 FROM frames WHERE run_id = ?",
                (RUN_ID,),
            ).fetchall()
        }
        detection_documents = {
            str(row["detection_id"]): str(row["document_sha256"])
            for row in connection.execute(
                "SELECT detection_id, document_sha256 FROM detections WHERE run_id = ?",
                (RUN_ID,),
            ).fetchall()
        }
        source_case_id: str | None
        source_case_revision: int | None
        source_case_document_sha256: str | None
        if with_case:
            case_row = connection.execute(
                """
                SELECT case_id, revision, document_sha256
                FROM case_versions
                WHERE run_id = ? ORDER BY revision DESC LIMIT 1
                """,
                (RUN_ID,),
            ).fetchone()
            assert case_row is not None
            source_case_id = str(case_row["case_id"])
            source_case_revision = int(case_row["revision"])
            source_case_document_sha256 = str(case_row["document_sha256"])
        else:
            source_case_id = None
            source_case_revision = None
            source_case_document_sha256 = None
    return M6ReplayInputClosureAuthority(
        sample_id="sample-readonly-perception",
        source_run_id=RUN_ID,
        source_case_id=source_case_id,
        source_case_revision=source_case_revision,
        source_case_document_sha256=source_case_document_sha256,
        source_manifest_id=_manifest().manifest_id,
        source_manifest_document_sha256=str(manifest_row["document_sha256"]),
        input_authority_id=_sha("input-authority"),
        input_authority_document_sha256=_sha("input-authority-document"),
        source_validation_report_id=_sha("validation-report"),
        source_validation_report_document_sha256=_sha("validation-report-document"),
        frames=tuple(
            M6LockedFrameInput(
                frame_id=frame.frame_id,
                document_sha256=frame_documents.get(frame.frame_id, _sha("missing-frame")),
                content_sha256=frame.content_sha256 or _sha("missing-content"),
            )
            for frame in frames
        ),
        detections=tuple(
            M6LockedDetectionInput(
                detection_id=detection.detection_id,
                frame_id=detection.frame_id,
                document_sha256=detection_documents.get(
                    detection.detection_id,
                    _sha("missing-detection"),
                ),
                model_manifest_id=detection.model_manifest_id,
            )
            for detection in detections
        ),
    )


def test_repository_resolves_exact_perception_without_writes_or_sidecars(
    tmp_path: Path,
) -> None:
    database, repository = _repository(tmp_path)
    _register_case(repository)
    frame = _frame()
    from tests.integration.test_m2_sqlite_repository import _detection

    detection = _detection()
    closure = _closure(
        database,
        frames=(frame,),
        detections=(detection,),
        with_case=True,
    )
    source_before = _source_fingerprint(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        private_before = {path.name for path in snapshot.parent.iterdir()}
        authority = ReadonlyM6PerceptionAuthorityRepository(snapshot)
        resolved = authority.assemble(closure)
        private_after = {path.name for path in snapshot.parent.iterdir()}

    assert resolved.frames == (frame,)
    assert resolved.detections == (detection,)
    assert private_after == private_before
    assert _source_fingerprint(tmp_path) == source_before


def test_repository_reports_missing_closure_frame_with_typed_failure(tmp_path: Path) -> None:
    database, _repository_instance = _repository(tmp_path)
    missing = _frame().model_copy(update={"frame_index": 91})
    closure = _closure(
        database,
        frames=(missing,),
        detections=(),
        with_case=False,
    )

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM6PerceptionAuthorityRepository(snapshot)
        with pytest.raises(M6PerceptionAuthorityError) as raised:
            authority.assemble(closure)

    assert raised.value.code == M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_MISSING


def test_repository_rejects_frame_that_exists_only_in_another_run(tmp_path: Path) -> None:
    database, repository = _repository(tmp_path)
    repository.register_run("run-02", _manifest())
    foreign = _frame().model_copy(update={"frame_index": 91})
    repository.register_frame("run-02", foreign)
    closure = _closure(
        database,
        frames=(foreign,),
        detections=(),
        with_case=False,
    )

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM6PerceptionAuthorityRepository(snapshot)
        with pytest.raises(M6PerceptionAuthorityError) as raised:
            authority.assemble(closure)

    assert raised.value.code == M6PerceptionAuthorityErrorCode.FRAME_AUTHORITY_SCOPE_MISMATCH
