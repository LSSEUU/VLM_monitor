from __future__ import annotations

import hashlib
import inspect
import sqlite3
from pathlib import Path

import pytest

import labcourt.adapters.storage._sqlite_m6_upgrade_frame_document as frame_document
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_frame_document import (
    M6SQLiteFrameDocumentError,
    M6SQLiteFrameDocumentFailureCode,
    M6SQLiteFramePhysicalPlan,
    plan_m6_sqlite_frame_physical_identity,
)
from labcourt.application.m6_upgrade_physical_resolution import (
    resolve_m6_upgrade_frame_physical_ref,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.pixels import (
    LCPIX1_RGB8_HEADER_SIZE_BYTES,
    RGB8Frame,
    rgb8_pixel_sha256,
)
from tests.integration import test_m3_sqlite_repository as m3_fixture

RUN_ID = "run-frame-plan"
MANIFEST_ID = "a" * 64
PIXELS = bytes((1, 2, 3, 4, 5, 6))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _frame(*, content_sha256: str | None = None) -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="stream-01",
        frame_index=7,
        fps_num=30,
        fps_den=1,
        width=2,
        height=1,
        content_sha256=(
            rgb8_pixel_sha256(2, 1, PIXELS) if content_sha256 is None else content_sha256
        ),
    )


def _connection(
    *,
    frame: FrameRef | None = None,
    document: str | None = None,
    document_sha256: str | None = None,
    row_manifest_id: str = MANIFEST_ID,
    width: int | None = None,
    duplicate: bool = False,
    begin: bool = True,
) -> sqlite3.Connection:
    controlled_frame = frame or _frame()
    canonical_document = document or canonical_json(controlled_frame.model_dump(mode="json"))
    stored_sha256 = document_sha256 or _sha256(canonical_document)
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE runs(run_id TEXT NOT NULL, manifest_id TEXT NOT NULL);
        CREATE TABLE frames(
            run_id TEXT NOT NULL,
            frame_id TEXT NOT NULL,
            manifest_id TEXT NOT NULL,
            camera_id TEXT NOT NULL,
            stream_id TEXT NOT NULL,
            frame_index INTEGER NOT NULL,
            fps_num INTEGER NOT NULL,
            fps_den INTEGER NOT NULL,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL,
            document_json TEXT NOT NULL,
            document_sha256 TEXT NOT NULL
        );
        """
    )
    connection.execute("INSERT INTO runs VALUES (?, ?)", (RUN_ID, MANIFEST_ID))
    values = (
        RUN_ID,
        controlled_frame.frame_id,
        row_manifest_id,
        controlled_frame.camera_id,
        controlled_frame.stream_id,
        controlled_frame.frame_index,
        controlled_frame.fps_num,
        controlled_frame.fps_den,
        controlled_frame.width if width is None else width,
        controlled_frame.height,
        controlled_frame.content_sha256,
        canonical_document,
        stored_sha256,
    )
    connection.execute(
        "INSERT INTO frames VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        values,
    )
    if duplicate:
        connection.execute(
            "INSERT INTO frames VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values,
        )
    if begin:
        connection.execute("BEGIN")
        assert connection.in_transaction
    return connection


class _PixelProvider:
    def __init__(self, value: RGB8Frame) -> None:
        self.value = value
        self.calls: list[str] = []

    def read_rgb8(self, frame_id: str) -> RGB8Frame:
        self.calls.append(frame_id)
        return self.value


def _failure(
    connection: sqlite3.Connection,
    *,
    run_id: str = RUN_ID,
    manifest_id: str = MANIFEST_ID,
    frame_id: str | None = None,
) -> M6SQLiteFrameDocumentError:
    with pytest.raises(M6SQLiteFrameDocumentError) as raised:
        plan_m6_sqlite_frame_physical_identity(
            connection=connection,
            expected_run_id=run_id,
            expected_manifest_id=manifest_id,
            frame_id=frame_id or _frame().frame_id,
        )
    return raised.value


def test_frame_plan_reads_canonical_authority_without_pixels_and_matches_later_verification() -> (
    None
):
    frame = _frame()
    connection = _connection(frame=frame)
    try:
        plan = plan_m6_sqlite_frame_physical_identity(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            frame_id=frame.frame_id,
        )
    finally:
        connection.rollback()
        connection.close()

    assert isinstance(plan, M6SQLiteFramePhysicalPlan)
    assert plan.frame_authority.run_id == RUN_ID
    assert plan.frame_authority.manifest_id == MANIFEST_ID
    assert plan.frame_authority.frame_id == frame.frame_id
    assert plan.frame_authority.content_sha256 == frame.content_sha256
    assert plan.frame_authority.canonical_document == canonical_json(frame.model_dump(mode="json"))
    assert plan.frame_authority.document_sha256 == _sha256(plan.frame_authority.canonical_document)
    planned = plan.planned_artifact_ref
    assert planned.source == M6UpgradePhysicalArtifactSource.M2_PERCEPTION
    assert planned.kind == M6UpgradePhysicalArtifactKind.FRAME
    assert planned.artifact_id == frame.frame_id
    assert planned.container_id is None
    assert planned.document_sha256 == plan.frame_authority.document_sha256
    assert planned.content_sha256 == frame.content_sha256
    assert planned.size_bytes == LCPIX1_RGB8_HEADER_SIZE_BYTES + frame.width * frame.height * 3

    provider = _PixelProvider(RGB8Frame(frame=frame, pixels=PIXELS))
    verified = resolve_m6_upgrade_frame_physical_ref(
        expected_run_id=RUN_ID,
        expected_frame_id=frame.frame_id,
        authority=plan.frame_authority,
        provider=provider,
    )
    assert verified == planned
    assert provider.calls == [frame.frame_id]
    assert "provider" not in inspect.signature(plan_m6_sqlite_frame_physical_identity).parameters


def test_frame_plan_requires_a_caller_owned_transaction() -> None:
    connection = _connection(begin=False)
    try:
        failure = _failure(connection)
    finally:
        connection.close()
    assert failure.reason_code == M6SQLiteFrameDocumentFailureCode.TRANSACTION_REQUIRED


def test_frame_plan_reads_the_live_wal_b_connection(tmp_path: Path) -> None:
    database, _repository_instance = m3_fixture._repository(tmp_path)
    frame = m3_fixture._frame()
    keeper = sqlite3.connect(database, isolation_level=None)
    try:
        keeper.execute("PRAGMA wal_autocheckpoint = 0")
        manifest_row = keeper.execute(
            "SELECT manifest_id FROM runs WHERE run_id = ?",
            (m3_fixture.RUN_ID,),
        ).fetchone()
        assert manifest_row is not None
        manifest_id = str(manifest_row[0])
        document = canonical_json(frame.model_dump(mode="json"))
        keeper.execute("BEGIN")
        keeper.execute(
            """
            INSERT INTO frames(
                run_id, frame_id, manifest_id, camera_id, stream_id,
                frame_index, fps_num, fps_den, width, height,
                content_sha256, document_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                m3_fixture.RUN_ID,
                frame.frame_id,
                manifest_id,
                frame.camera_id,
                frame.stream_id,
                frame.frame_index,
                frame.fps_num,
                frame.fps_den,
                frame.width,
                frame.height,
                frame.content_sha256,
                document,
                _sha256(document),
            ),
        )
        keeper.commit()
        wal = database.with_name(f"{database.name}-wal")
        assert wal.is_file() and wal.stat().st_size > 0

        with m6_live_committed_read_cut(database, m3_fixture.BUSY_TIMEOUT_MS) as cut:
            with cut.selector() as selector:
                selected = selector.execute(
                    "SELECT COUNT(*) AS count FROM frames WHERE run_id = ?",
                    (m3_fixture.RUN_ID,),
                )
                selected_row = selected.fetchone()
                assert selected_row is not None
                assert selected_row["count"] == 1
            with cut.reader() as reader:
                plan = plan_m6_sqlite_frame_physical_identity(
                    connection=reader,
                    expected_run_id=m3_fixture.RUN_ID,
                    expected_manifest_id=manifest_id,
                    frame_id=frame.frame_id,
                )
            with cut.writer() as writer:
                writer_row = writer.execute("SELECT 1 AS value").fetchone()
                assert writer_row is not None
                assert writer_row["value"] == 1
    finally:
        keeper.close()

    assert plan.frame_authority.run_id == m3_fixture.RUN_ID
    assert plan.frame_authority.manifest_id == manifest_id
    assert plan.planned_artifact_ref.artifact_id == frame.frame_id


@pytest.mark.parametrize(
    ("run_id", "manifest_id", "frame_id", "expected"),
    (
        (
            "missing-run",
            MANIFEST_ID,
            _frame().frame_id,
            M6SQLiteFrameDocumentFailureCode.SCOPE_NOT_FOUND,
        ),
        (
            RUN_ID,
            "b" * 64,
            _frame().frame_id,
            M6SQLiteFrameDocumentFailureCode.SCOPE_MISMATCH,
        ),
        (
            RUN_ID,
            MANIFEST_ID,
            "cam-01:stream-01:8",
            M6SQLiteFrameDocumentFailureCode.DOCUMENT_NOT_FOUND,
        ),
    ),
)
def test_frame_plan_distinguishes_scope_and_document_absence(
    run_id: str,
    manifest_id: str,
    frame_id: str,
    expected: M6SQLiteFrameDocumentFailureCode,
) -> None:
    connection = _connection()
    try:
        failure = _failure(
            connection,
            run_id=run_id,
            manifest_id=manifest_id,
            frame_id=frame_id,
        )
    finally:
        connection.rollback()
        connection.close()
    assert failure.reason_code == expected


def test_frame_plan_preflights_document_size_before_typed_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _connection(document="not-json-at-all")
    monkeypatch.setattr(frame_document, "MAX_M6_SQLITE_FRAME_DOCUMENT_BYTES", 4)
    try:
        failure = _failure(connection)
    finally:
        connection.rollback()
        connection.close()
    assert failure.reason_code == M6SQLiteFrameDocumentFailureCode.DOCUMENT_TOO_LARGE


def test_frame_plan_uses_sqlite_octet_length_metadata_shortcut() -> None:
    if sqlite3.sqlite_version_info < frame_document._SQLITE_OCTET_LENGTH_MIN_VERSION:
        pytest.skip("SQLite octet_length is unavailable")
    connection = _connection()
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        plan_m6_sqlite_frame_physical_identity(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            frame_id=_frame().frame_id,
        )
        bytecode = connection.execute(
            """
            EXPLAIN
            SELECT octet_length(document_json)
            FROM frames
            WHERE run_id = ? AND frame_id = ?
            """,
            (RUN_ID, _frame().frame_id),
        ).fetchall()
    finally:
        connection.rollback()
        connection.close()

    assert any("octet_length(document_json)" in statement for statement in statements)
    document_column_ops = [row for row in bytecode if row[1] == "Column" and row[3] == 11]
    assert document_column_ops
    assert all(int(row[6]) & 0x40 for row in document_column_ops)


def test_frame_plan_has_a_pre_343_incremental_blob_size_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(frame_document, "_USE_SQLITE_OCTET_LENGTH", False)
    connection = _connection()
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        plan = plan_m6_sqlite_frame_physical_identity(
            connection=connection,
            expected_run_id=RUN_ID,
            expected_manifest_id=MANIFEST_ID,
            frame_id=_frame().frame_id,
        )
    finally:
        connection.rollback()
        connection.close()

    assert plan.frame_authority.frame_id == _frame().frame_id
    assert all("octet_length" not in statement for statement in statements)


@pytest.mark.parametrize(
    "connection_factory",
    (
        lambda: _connection(width=3),
        lambda: _connection(document_sha256="f" * 64),
        lambda: _connection(row_manifest_id="f" * 64),
    ),
)
def test_frame_plan_rejects_index_hash_and_row_scope_forgery(
    connection_factory: object,
) -> None:
    assert callable(connection_factory)
    connection = connection_factory()
    try:
        failure = _failure(connection)
    finally:
        connection.rollback()
        connection.close()
    assert failure.reason_code in {
        M6SQLiteFrameDocumentFailureCode.INDEX_BINDING_MISMATCH,
        M6SQLiteFrameDocumentFailureCode.SCOPE_MISMATCH,
    }


def test_frame_plan_rejects_noncanonical_document_and_duplicate_rows() -> None:
    frame = _frame()
    canonical = canonical_json(frame.model_dump(mode="json"))
    noncanonical = _connection(document=canonical + " ")
    try:
        invalid = _failure(noncanonical)
    finally:
        noncanonical.rollback()
        noncanonical.close()
    assert invalid.reason_code == M6SQLiteFrameDocumentFailureCode.DOCUMENT_INVALID

    duplicate = _connection(duplicate=True)
    try:
        repeated = _failure(duplicate)
    finally:
        duplicate.rollback()
        duplicate.close()
    assert repeated.reason_code == M6SQLiteFrameDocumentFailureCode.ROW_LIMIT_EXCEEDED


def test_frame_plan_errors_are_typed_payload_free_and_invalid_arguments_fail_closed() -> None:
    error = M6SQLiteFrameDocumentError(M6SQLiteFrameDocumentFailureCode.INDEX_BINDING_MISMATCH)
    assert error.args == ("M6 SQLite Frame document failed: INDEX_BINDING_MISMATCH",)
    assert vars(error) == {"reason_code": error.reason_code}

    connection = _connection()
    try:
        failure = _failure(connection, frame_id="../invalid")
    finally:
        connection.rollback()
        connection.close()
    assert failure.reason_code == M6SQLiteFrameDocumentFailureCode.INVALID_ARGUMENT
    assert "../invalid" not in str(failure)

    closed = _connection()
    closed.close()
    closed_failure = _failure(closed)
    assert closed_failure.reason_code == M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED

    with pytest.raises(TypeError, match="reason_code"):
        M6SQLiteFrameDocumentError("INDEX_BINDING_MISMATCH")  # type: ignore[arg-type]
