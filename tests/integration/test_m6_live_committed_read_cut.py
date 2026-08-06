from __future__ import annotations

import copy
import gc
import pickle
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from labcourt.adapters.storage import MigrationRunner
from labcourt.adapters.storage import _sqlite_m6_live_read_cut as live_read_cut_module
from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LivePendingSelector,
    M6LiveReadCutError,
    M6LiveReadCutFailureCode,
    M6LiveReader,
    M6LiveWriter,
    m6_live_committed_read_cut,
)

BUSY_TIMEOUT_MS = 5_000


def _assert_sealed_handle(value: object) -> None:
    assert not hasattr(value, "__dict__")
    assert not any(
        isinstance(referent, (sqlite3.Connection, sqlite3.Cursor))
        for referent in gc.get_referents(value)
    )
    for operation in (
        lambda: copy.copy(value),
        lambda: copy.deepcopy(value),
        lambda: pickle.dumps(value),
    ):
        with pytest.raises(TypeError):
            operation()


def _assert_traceback_has_no_live_sqlite_authority(error: BaseException) -> None:
    module_path = Path(live_read_cut_module.__file__).resolve()
    forbidden_holder_names = {
        "_CursorRecord",
        "_M6LiveCommittedReadCutOwner",
        "_M6LiveCutContextRecord",
        "_M6LivePhaseContextRecord",
        "_M6SQLiteCapabilityBroker",
    }
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if Path(frame.f_code.co_filename).resolve() == module_path:
            for value in frame.f_locals.values():
                assert not isinstance(value, (sqlite3.Blob, sqlite3.Connection, sqlite3.Cursor))
                assert type(value).__name__ not in forbidden_holder_names
        traceback = traceback.tb_next


class _HostileStatement(str):
    def strip(self, _characters: str | None = None) -> str:
        raise RuntimeError("secret statement payload")


class _HostileBind:
    def __conform__(self, _protocol: object) -> object:
        raise ValueError("secret bind payload")


class _HostilePath(str):
    def __fspath__(self) -> str:
        raise RuntimeError("secret path payload")


def test_error_reason_code_is_closed() -> None:
    with pytest.raises(TypeError, match="reason_code"):
        M6LiveReadCutError("WRITER_REJECTED")  # type: ignore[arg-type]


@pytest.mark.parametrize("constructor", (M6LivePendingSelector, M6LiveWriter))
def test_exported_sql_capabilities_cannot_wrap_a_raw_connection(
    constructor: type[object],
) -> None:
    class AuthorizerTrackingConnection(sqlite3.Connection):
        authorizer_calls = 0

        def set_authorizer(self, authorizer_callback: object) -> None:
            self.authorizer_calls += 1
            super().set_authorizer(authorizer_callback)  # type: ignore[arg-type]

    connection = sqlite3.connect(":memory:", factory=AuthorizerTrackingConnection)
    assert isinstance(connection, AuthorizerTrackingConnection)
    try:
        with pytest.raises(TypeError) as rejected:
            constructor(connection)
        assert rejected.value.__cause__ is None
        assert rejected.value.__context__ is None
        _assert_traceback_has_no_live_sqlite_authority(rejected.value)
        assert connection.authorizer_calls == 0
    finally:
        connection.close()


def test_cut_factory_rejects_hostile_and_raw_arguments_without_retaining_them() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        for database_path, busy_timeout in (
            (_HostilePath("secret.sqlite3"), BUSY_TIMEOUT_MS),
            (connection, BUSY_TIMEOUT_MS),
            (Path("safe.sqlite3"), True),
        ):
            with pytest.raises(M6LiveReadCutError) as rejected:
                m6_live_committed_read_cut(  # type: ignore[arg-type]
                    database_path,
                    busy_timeout,
                )
            assert rejected.value.reason_code == M6LiveReadCutFailureCode.INVALID_ARGUMENT
            assert rejected.value.__cause__ is None
            assert rejected.value.__context__ is None
            _assert_traceback_has_no_live_sqlite_authority(rejected.value)
    finally:
        connection.close()


def test_typed_failures_do_not_retain_live_sqlite_authority_in_module_tracebacks(
    tmp_path: Path,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    try:
        with (
            pytest.raises(M6LiveReadCutError) as cut_failed,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with pytest.raises(M6LiveReadCutError) as premature, cut.reader():
                pass
            _assert_traceback_has_no_live_sqlite_authority(premature.value)

            with cut.selector() as selector:
                with pytest.raises(M6LiveReadCutError) as selector_rejected:
                    selector.execute(
                        "INSERT INTO m6_live_read_cut_probe(key, value) VALUES ('early', 'x')"
                    )
                _assert_traceback_has_no_live_sqlite_authority(selector_rejected.value)

            with (
                pytest.raises(M6LiveReadCutError) as reader_poisoned,
                cut.reader() as reader,
            ):
                closed = reader.execute("SELECT 1")
                closed.close()
                with pytest.raises(M6LiveReadCutError) as stale_cursor:
                    closed.fetchone()
                _assert_traceback_has_no_live_sqlite_authority(stale_cursor.value)

                with pytest.raises(M6LiveReadCutError) as reader_rejected:
                    reader.execute("COMMIT")
                _assert_traceback_has_no_live_sqlite_authority(reader_rejected.value)

            _assert_traceback_has_no_live_sqlite_authority(reader_poisoned.value)
        _assert_traceback_has_no_live_sqlite_authority(cut_failed.value)
    finally:
        keeper.close()

    with (
        pytest.raises(M6LiveReadCutError) as incomplete,
        m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        cut.selector(),
    ):
        pass
    _assert_traceback_has_no_live_sqlite_authority(incomplete.value)


def _live_wal_database(tmp_path: Path) -> tuple[Path, sqlite3.Connection]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    keeper = sqlite3.connect(database, isolation_level=None)
    keeper.execute("PRAGMA wal_autocheckpoint = 0")
    keeper.execute("CREATE TABLE m6_live_read_cut_probe(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    keeper.execute(
        "INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)",
        ("committed-before-cut", "visible-from-wal"),
    )
    assert keeper.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    wal = database.with_name(f"{database.name}-wal")
    assert wal.is_file() and wal.stat().st_size > 0
    return database, keeper


def test_live_cut_reads_committed_wal_with_hardened_nonimmutable_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    real_connect = sqlite3.connect
    opened_uris: list[str] = []

    def tracked_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        if args and kwargs.get("uri") is True and isinstance(args[0], str):
            opened_uris.append(args[0])
        return real_connect(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(live_read_cut_module.sqlite3, "connect", tracked_connect)
    try:
        cut_context = m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS)
        _assert_sealed_handle(cut_context)
        assert not hasattr(cut_context, "gen")
        with cut_context as cut:
            _assert_sealed_handle(cut)
            assert not hasattr(cut, "_owner")
            assert not hasattr(cut, "_owner_abort")
            assert not hasattr(cut, "_owner_finish")
            assert not hasattr(cut, "_owner_close_writer")
            with pytest.raises(M6LiveReadCutError) as premature_read, cut.reader():
                pass
            assert premature_read.value.reason_code == (
                M6LiveReadCutFailureCode.READ_BEFORE_SELECTION_CLOSE
            )

            selector_context = cut.selector()
            _assert_sealed_handle(selector_context)
            assert not hasattr(selector_context, "gen")
            with selector_context as selector:
                _assert_sealed_handle(selector)
                with pytest.raises(AttributeError):
                    selector._revoke = lambda: None  # type: ignore[method-assign]
                selected = selector.execute(
                    """
                    SELECT value FROM m6_live_read_cut_probe WHERE key = ?
                    UNION ALL SELECT 'second-row'
                    """,
                    ("committed-before-cut",),
                )
                assert tuple(selected.fetchone()) == ("visible-from-wal",)
                assert not hasattr(selected, "connection")

            reader_context = cut.reader()
            _assert_sealed_handle(reader_context)
            assert not hasattr(reader_context, "gen")
            with reader_context as reader:
                assert isinstance(reader, M6LiveReader)
                assert not isinstance(reader, sqlite3.Connection)
                _assert_sealed_handle(reader)
                for forbidden_api in (
                    "backup",
                    "blobopen",
                    "close",
                    "commit",
                    "create_aggregate",
                    "create_collation",
                    "create_function",
                    "cursor",
                    "deserialize",
                    "enable_load_extension",
                    "executemany",
                    "interrupt",
                    "rollback",
                    "serialize",
                    "set_authorizer",
                    "set_progress_handler",
                    "set_trace_callback",
                ):
                    assert not hasattr(reader, forbidden_api)
                with pytest.raises(M6LiveReadCutError) as stale_selector_cursor:
                    selected.fetchone()
                assert stale_selector_cursor.value.reason_code == (
                    M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
                )
                assert reader.in_transaction
                result = reader.execute(
                    """
                    WITH selected(value) AS (
                        SELECT value FROM m6_live_read_cut_probe WHERE key = ?
                    )
                    SELECT value FROM selected UNION ALL SELECT 'second-row'
                    """,
                    ("committed-before-cut",),
                )
                _assert_sealed_handle(result)
                assert not hasattr(result, "connection")
                assert tuple(result.fetchone()) == ("visible-from-wal",)
                assert [tuple(row) for row in result.fetchmany(1)] == [("second-row",)]
                assert result.fetchall() == []
                iterated = reader.execute("SELECT 1 AS value UNION ALL SELECT 2")
                assert [tuple(row) for row in iterated] == [(1,), (2,)]
                closed = reader.execute("SELECT 3 AS value")
                closed.close()
                with pytest.raises(M6LiveReadCutError) as explicitly_closed:
                    closed.fetchone()
                assert explicitly_closed.value.reason_code == (
                    M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
                )

                with pytest.raises(M6LiveReadCutError) as premature, cut.writer():
                    pass
                assert premature.value.reason_code == (
                    M6LiveReadCutFailureCode.WRITE_BEFORE_READ_CLOSE
                )

            with pytest.raises(M6LiveReadCutError) as stale_reader:
                reader.execute("SELECT 1")
            assert stale_reader.value.reason_code == (
                M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            )
            with pytest.raises(M6LiveReadCutError) as stale_reader_cursor:
                result.fetchone()
            assert stale_reader_cursor.value.reason_code == (
                M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            )

            writer_context = cut.writer()
            _assert_sealed_handle(writer_context)
            assert not hasattr(writer_context, "gen")
            with writer_context as writer:
                _assert_sealed_handle(writer)
                with pytest.raises(AttributeError):
                    writer._revoke = lambda: None  # type: ignore[method-assign]
                assert not hasattr(writer, "commit")
                assert not hasattr(writer, "rollback")
                assert not hasattr(writer, "close")
                observed_writer_pragmas = (
                    int(writer.execute("PRAGMA foreign_keys").fetchone()[0]),
                    str(writer.execute("PRAGMA journal_mode").fetchone()[0]),
                    int(writer.execute("PRAGMA synchronous").fetchone()[0]),
                    int(writer.execute("PRAGMA trusted_schema").fetchone()[0]),
                    int(writer.execute("PRAGMA recursive_triggers").fetchone()[0]),
                )
                assert observed_writer_pragmas == (1, "wal", 2, 0, 1)
                returning_cursor = writer.execute(
                    """
                    INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)
                    RETURNING value
                    """,
                    ("written-after-read-close", "durable"),
                )
            with pytest.raises(M6LiveReadCutError) as stale_writer:
                writer.execute("SELECT 1")
            assert stale_writer.value.reason_code == (
                M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            )
            with pytest.raises(M6LiveReadCutError) as stale_writer_cursor:
                returning_cursor.fetchone()
            assert stale_writer_cursor.value.reason_code == (
                M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            )
    finally:
        keeper.close()

    read_uris = [uri for uri in opened_uris if "mode=ro" in uri]
    assert len(read_uris) == 1
    assert "immutable=" not in read_uris[0]
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT value FROM m6_live_read_cut_probe WHERE key = ?",
            ("written-after-read-close",),
        ).fetchone() == ("durable",)


def test_selector_authorizer_denial_is_sticky_and_aborts_the_cut(tmp_path: Path) -> None:
    database, keeper = _live_wal_database(tmp_path)
    try:
        with (
            pytest.raises(M6LiveReadCutError) as poisoned,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
            cut.selector() as selector,
        ):
            with pytest.raises(M6LiveReadCutError) as rejected:
                selector.execute(
                    "INSERT INTO m6_live_read_cut_probe(key, value) VALUES ('early', 'x')"
                )
            assert rejected.value.reason_code == M6LiveReadCutFailureCode.CAPABILITY_REJECTED
            _assert_traceback_has_no_live_sqlite_authority(rejected.value)
    finally:
        keeper.close()

    assert poisoned.value.reason_code == M6LiveReadCutFailureCode.CAPABILITY_REJECTED
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT value FROM m6_live_read_cut_probe WHERE key = 'early'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize("phase", ("selector", "reader", "writer"))
@pytest.mark.parametrize("repeat_enter", (False, True))
def test_abandoned_phase_context_revokes_capability_and_releases_writer_lock(
    tmp_path: Path,
    phase: str,
    repeat_enter: bool,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    cut_context = m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS)
    cut = cut_context.__enter__()
    try:
        if phase in {"reader", "writer"}:
            with cut.selector():
                pass
        if phase == "writer":
            with cut.reader():
                pass
        if phase == "selector":
            phase_context = cut.selector()
        elif phase == "reader":
            phase_context = cut.reader()
        else:
            phase_context = cut.writer()
        capability = phase_context.__enter__()
        if phase == "writer":
            capability.execute(
                "INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)",
                ("abandoned-writer", "not-durable"),
            )
        if repeat_enter:
            try:
                phase_context.__enter__()
            except M6LiveReadCutError as repeated:
                assert repeated.reason_code == M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            else:
                pytest.fail("a phase context must be one-use")

        del phase_context
        gc.collect()

        with pytest.raises(M6LiveReadCutError) as stale:
            capability.execute("SELECT 1")
        assert stale.value.reason_code == M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED

        competitor = sqlite3.connect(database, isolation_level=None, timeout=0.1)
        try:
            competitor.execute("BEGIN IMMEDIATE")
            competitor.rollback()
        finally:
            competitor.close()

        with pytest.raises(M6LiveReadCutError) as incomplete:
            cut_context.__exit__(None, None, None)
        assert incomplete.value.reason_code == M6LiveReadCutFailureCode.CUT_INCOMPLETE
    finally:
        keeper.close()

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT value FROM m6_live_read_cut_probe WHERE key = 'abandoned-writer'"
            ).fetchone()
            is None
        )


def test_writer_fence_blocks_competitor_until_read_closes_and_a_commits(
    tmp_path: Path,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    competitor_attempted = Event()
    competitor_committed = Event()

    def compete() -> None:
        connection = sqlite3.connect(
            database,
            timeout=BUSY_TIMEOUT_MS / 1_000,
            isolation_level=None,
        )
        try:
            connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            competitor_attempted.set()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)",
                ("competing-writer", "committed-last"),
            )
            connection.commit()
            competitor_committed.set()
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
                with cut.selector() as selector:
                    assert (
                        selector.execute("SELECT COUNT(*) FROM m6_live_read_cut_probe").fetchone()
                        is not None
                    )
                with cut.reader() as reader:
                    future = executor.submit(compete)
                    assert competitor_attempted.wait(timeout=2)
                    assert not competitor_committed.wait(timeout=0.2)
                    assert tuple(
                        reader.execute(
                            "SELECT value FROM m6_live_read_cut_probe WHERE key = ?",
                            ("committed-before-cut",),
                        ).fetchone()
                    ) == ("visible-from-wal",)

                with cut.writer() as writer:
                    writer.execute(
                        "INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)",
                        ("cut-writer", "committed-first"),
                    )
                    assert not competitor_committed.wait(timeout=0.2)

                    uncommitted_reader = sqlite3.connect(
                        f"{database.absolute().as_uri()}?mode=ro",
                        uri=True,
                        isolation_level=None,
                    )
                    try:
                        uncommitted_reader.execute("PRAGMA query_only = ON")
                        uncommitted_reader.execute("BEGIN")
                        assert (
                            uncommitted_reader.execute(
                                "SELECT value FROM m6_live_read_cut_probe WHERE key = ?",
                                ("cut-writer",),
                            ).fetchone()
                            is None
                        )
                    finally:
                        uncommitted_reader.close()

            assert competitor_committed.wait(timeout=5)
            future.result(timeout=5)
    finally:
        keeper.close()

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT key FROM m6_live_read_cut_probe WHERE key IN (?, ?) ORDER BY key",
            ("competing-writer", "cut-writer"),
        ).fetchall()
    assert rows == [("competing-writer",), ("cut-writer",)]


@pytest.mark.parametrize(
    "statement",
    (
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT nested_guard",
        "ATTACH DATABASE ':memory:' AS attached_guard",
    ),
)
def test_writer_authorizer_denial_is_sticky_and_outer_failure_rolls_back(
    tmp_path: Path,
    statement: str,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    competitor_attempted = Event()
    competitor_committed = Event()

    def compete() -> None:
        connection = sqlite3.connect(
            database,
            timeout=BUSY_TIMEOUT_MS / 1_000,
            isolation_level=None,
        )
        try:
            connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            competitor_attempted.set()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)",
                ("competitor-after-abort", "durable"),
            )
            connection.commit()
            competitor_committed.set()
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with (
                pytest.raises(M6LiveReadCutError) as poisoned,
                m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
            ):
                with cut.selector():
                    pass
                with cut.reader():
                    pass
                with cut.writer() as writer:
                    cursor = writer.execute(
                        "INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)",
                        ("must-roll-back", "not-durable"),
                    )
                    assert not hasattr(cursor, "connection")
                    future = executor.submit(compete)
                    assert competitor_attempted.wait(timeout=2)
                    with pytest.raises(M6LiveReadCutError) as rejected:
                        writer.execute(statement)
                    assert rejected.value.reason_code == (
                        M6LiveReadCutFailureCode.CAPABILITY_REJECTED
                    )
                    with pytest.raises(M6LiveReadCutError) as sticky:
                        _ = writer.in_transaction
                    assert sticky.value.reason_code == (
                        M6LiveReadCutFailureCode.CAPABILITY_REJECTED
                    )
                    assert not competitor_committed.wait(timeout=0.2)

            assert poisoned.value.reason_code == M6LiveReadCutFailureCode.CAPABILITY_REJECTED
            assert competitor_committed.wait(timeout=5)
            future.result(timeout=5)
    finally:
        keeper.close()

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT value FROM m6_live_read_cut_probe WHERE key = 'must-roll-back'"
            ).fetchone()
            is None
        )
        assert connection.execute(
            "SELECT value FROM m6_live_read_cut_probe WHERE key = 'competitor-after-abort'"
        ).fetchone() == ("durable",)


def test_caught_writer_storage_failure_is_sticky_and_cannot_commit_partial_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class PostWriteFailingConnection(sqlite3.Connection):
        fail_after_write = False

        def execute(
            self,
            sql: str,
            parameters: object = (),
        ) -> sqlite3.Cursor:
            cursor = super().execute(sql, parameters)  # type: ignore[arg-type]
            if self.fail_after_write and sql.lstrip().upper().startswith("INSERT"):
                raise RuntimeError("secret post-write payload")
            return cursor

    failing_writer = sqlite3.connect(
        database,
        timeout=BUSY_TIMEOUT_MS / 1_000,
        isolation_level=None,
        factory=PostWriteFailingConnection,
    )
    assert isinstance(failing_writer, PostWriteFailingConnection)
    failing_writer.row_factory = sqlite3.Row
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_connection",
        lambda *_args, **_kwargs: failing_writer,
    )
    try:
        with (
            pytest.raises(M6LiveReadCutError) as poisoned,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader():
                pass
            with cut.writer() as writer:
                failing_writer.fail_after_write = True
                with pytest.raises(M6LiveReadCutError) as rejected:
                    writer.execute(
                        "INSERT INTO m6_live_read_cut_probe(key, value) VALUES (?, ?)",
                        ("must-roll-back-after-storage-failure", "not-durable"),
                    )
                assert rejected.value.reason_code == (M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
                assert rejected.value.__cause__ is None
                assert rejected.value.__context__ is None
                _assert_traceback_has_no_live_sqlite_authority(rejected.value)
    finally:
        keeper.close()

    assert poisoned.value.reason_code == M6LiveReadCutFailureCode.CAPABILITY_REJECTED
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT value FROM m6_live_read_cut_probe WHERE key = ?",
                ("must-roll-back-after-storage-failure",),
            ).fetchone()
            is None
        )


def test_writer_capability_is_revoked_when_its_body_failure_is_caught(
    tmp_path: Path,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    try:
        with (
            pytest.raises(M6LiveReadCutError) as incomplete,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader():
                pass
            try:
                with cut.writer() as writer:
                    cursor = writer.execute("SELECT 1")
                    raise RuntimeError("caught writer body failure")
            except RuntimeError:
                pass

            with pytest.raises(M6LiveReadCutError) as stale_writer:
                writer.execute("SELECT 1")
            assert stale_writer.value.reason_code == (
                M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            )
            with pytest.raises(M6LiveReadCutError) as stale_cursor:
                cursor.fetchone()
            assert stale_cursor.value.reason_code == (
                M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            )
    finally:
        keeper.close()

    assert incomplete.value.reason_code == M6LiveReadCutFailureCode.CUT_INCOMPLETE


@pytest.mark.parametrize(
    "statement",
    (
        "PRAGMA query_only",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT reader_escape",
        "RELEASE reader_escape",
        "ATTACH DATABASE ':memory:' AS reader_escape",
        "DETACH DATABASE reader_escape",
        "INSERT INTO m6_live_read_cut_probe VALUES ('forbidden-insert', 'x')",
        "UPDATE m6_live_read_cut_probe SET value = 'x'",
        "DELETE FROM m6_live_read_cut_probe",
        "CREATE TABLE forbidden_table(value TEXT)",
        "CREATE TEMP TABLE forbidden_temp(value TEXT)",
        "ANALYZE",
        "VACUUM",
        "SELECT load_extension('forbidden-extension')",
    ),
)
def test_reader_default_deny_is_typed_sticky_and_never_opens_writer(
    tmp_path: Path,
    statement: str,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    reader: M6LiveReader | None = None
    try:
        with (
            pytest.raises(M6LiveReadCutError) as poisoned,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader() as opened:
                reader = opened
                with pytest.raises(M6LiveReadCutError) as rejected:
                    reader.execute(statement)
                assert rejected.value.reason_code == (
                    M6LiveReadCutFailureCode.READER_REJECTED
                    if statement == "VACUUM"
                    else M6LiveReadCutFailureCode.CAPABILITY_REJECTED
                )
                assert rejected.value.__cause__ is None
                assert rejected.value.__context__ is None
    finally:
        keeper.close()

    assert poisoned.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED
    assert reader is not None
    with pytest.raises(M6LiveReadCutError) as stale:
        reader.execute("SELECT 1")
    assert stale.value.reason_code == M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT value FROM m6_live_read_cut_probe WHERE key = 'forbidden-insert'"
            ).fetchone()
            is None
        )


def test_reader_document_length_is_fixed_allowlisted_and_never_returns_blob(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    keeper = sqlite3.connect(database, isolation_level=None)
    keeper.execute("PRAGMA journal_mode = WAL")
    keeper.execute("CREATE TABLE frames(document_json TEXT NOT NULL)")
    keeper.execute("CREATE TABLE evidence_packs(pack_json TEXT NOT NULL)")
    document = '{"frame":"fixed"}'
    rowid = keeper.execute(
        "INSERT INTO frames(document_json) VALUES (?)",
        (document,),
    ).lastrowid
    assert isinstance(rowid, int)
    pack_document = '{"pack":"selected-case-authority"}'
    pack_rowid = keeper.execute(
        "INSERT INTO evidence_packs(pack_json) VALUES (?)",
        (pack_document,),
    ).lastrowid
    assert isinstance(pack_rowid, int)
    try:
        with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
            with cut.selector():
                pass
            with cut.reader() as reader:
                assert reader.document_octet_length(
                    M6LiveDocumentColumn.FRAME_DOCUMENT,
                    rowid,
                ) == len(document.encode("utf-8"))
                assert reader.document_octet_length(
                    M6LiveDocumentColumn.EVIDENCE_PACK_DOCUMENT,
                    pack_rowid,
                ) == len(pack_document.encode("utf-8"))
                assert not hasattr(reader, "blobopen")
            with cut.writer():
                pass
    finally:
        keeper.close()


def test_reader_acquisition_document_lengths_use_real_incremental_blobs(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    keeper = sqlite3.connect(database, isolation_level=None)
    keeper.execute("PRAGMA journal_mode = WAL")
    keeper.execute("CREATE TABLE m4_acquisition_requests(request_json TEXT NOT NULL)")
    keeper.execute(
        """
        CREATE TABLE m4_acquisition_execution_claims(
            request_json TEXT NOT NULL,
            claim_json TEXT NOT NULL
        )
        """
    )
    keeper.execute("CREATE TABLE m4_tool_execution_manifests(manifest_json TEXT NOT NULL)")
    keeper.execute(
        """
        CREATE TABLE m4_acquisition_execution_publications(
            publication_json TEXT NOT NULL
        )
        """
    )
    keeper.execute("CREATE TABLE m4_tool_execution_receipts(receipt_json TEXT NOT NULL)")
    keeper.execute("CREATE TABLE m4_evidence_pack_derivations(derivation_json TEXT NOT NULL)")

    acquisition_request = '{"request":"source-authority"}'
    acquisition_request_rowid = keeper.execute(
        "INSERT INTO m4_acquisition_requests(request_json) VALUES (?)",
        (acquisition_request,),
    ).lastrowid
    claim_request = '{"request":"claim-frozen-authority-with-distinct-length"}'
    claim = '{"claim":"execution-authority"}'
    claim_rowid = keeper.execute(
        """
        INSERT INTO m4_acquisition_execution_claims(request_json, claim_json)
        VALUES (?, ?)
        """,
        (claim_request, claim),
    ).lastrowid
    manifest = '{"manifest":"tool-authority"}'
    manifest_rowid = keeper.execute(
        "INSERT INTO m4_tool_execution_manifests(manifest_json) VALUES (?)",
        (manifest,),
    ).lastrowid
    publication = '{"publication":"committed-result-authority"}'
    publication_rowid = keeper.execute(
        """
        INSERT INTO m4_acquisition_execution_publications(publication_json)
        VALUES (?)
        """,
        (publication,),
    ).lastrowid
    receipt = '{"receipt":"tool-execution-authority"}'
    receipt_rowid = keeper.execute(
        "INSERT INTO m4_tool_execution_receipts(receipt_json) VALUES (?)",
        (receipt,),
    ).lastrowid
    derivation = '{"derivation":"evidence-pack-authority"}'
    derivation_rowid = keeper.execute(
        "INSERT INTO m4_evidence_pack_derivations(derivation_json) VALUES (?)",
        (derivation,),
    ).lastrowid

    expected = (
        (
            M6LiveDocumentColumn.M4_ACQUISITION_REQUEST_DOCUMENT,
            acquisition_request_rowid,
            acquisition_request,
        ),
        (
            M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_REQUEST_DOCUMENT,
            claim_rowid,
            claim_request,
        ),
        (
            M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_DOCUMENT,
            claim_rowid,
            claim,
        ),
        (
            M6LiveDocumentColumn.M4_TOOL_EXECUTION_MANIFEST_DOCUMENT,
            manifest_rowid,
            manifest,
        ),
        (
            M6LiveDocumentColumn.M4_ACQUISITION_PUBLICATION_DOCUMENT,
            publication_rowid,
            publication,
        ),
        (
            M6LiveDocumentColumn.M4_TOOL_EXECUTION_RECEIPT_DOCUMENT,
            receipt_rowid,
            receipt,
        ),
        (
            M6LiveDocumentColumn.M4_EVIDENCE_PACK_DERIVATION_DOCUMENT,
            derivation_rowid,
            derivation,
        ),
    )
    assert all(isinstance(rowid, int) for _, rowid, _ in expected)
    try:
        with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
            with cut.selector():
                pass
            with cut.reader() as reader:
                for route, rowid, document in expected:
                    assert isinstance(rowid, int)
                    assert reader.document_octet_length(route, rowid) == len(
                        document.encode("utf-8")
                    )
                assert not hasattr(reader, "blobopen")
            with cut.writer():
                pass
    finally:
        keeper.close()


def test_reader_m5_precedent_document_lengths_use_real_incremental_blobs(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    keeper = sqlite3.connect(database, isolation_level=None)
    keeper.execute("PRAGMA journal_mode = WAL")
    keeper.execute("CREATE TABLE precedent_embeddings(embedding_json TEXT NOT NULL)")
    keeper.execute("CREATE TABLE precedents(authority_json TEXT NOT NULL)")
    keeper.execute("CREATE TABLE m5_precedent_exposures(exposure_json TEXT NOT NULL)")
    documents = (
        (
            M6LiveDocumentColumn.M5_PRECEDENT_EMBEDDING_DOCUMENT,
            "precedent_embeddings",
            "embedding_json",
            '{"embedding":"durable-vector-authority"}',
        ),
        (
            M6LiveDocumentColumn.M5_PRECEDENT_AUTHORITY_DOCUMENT,
            "precedents",
            "authority_json",
            '{"precedent":"historical-revision-authority"}',
        ),
        (
            M6LiveDocumentColumn.M5_PRECEDENT_EXPOSURE_DOCUMENT,
            "m5_precedent_exposures",
            "exposure_json",
            '{"exposure":"frozen-candidate-authority"}',
        ),
    )
    expected: list[tuple[M6LiveDocumentColumn, int, str]] = []
    for route, table, column, document in documents:
        rowid = keeper.execute(
            f"INSERT INTO {table}({column}) VALUES (?)",
            (document,),
        ).lastrowid
        assert isinstance(rowid, int)
        expected.append((route, rowid, document))
    try:
        with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
            with cut.selector():
                pass
            with cut.reader() as reader:
                for route, rowid, document in expected:
                    assert reader.document_octet_length(route, rowid) == len(
                        document.encode("utf-8")
                    )
                assert not hasattr(reader, "blobopen")
            with cut.writer():
                pass
    finally:
        keeper.close()


def test_reader_gate_document_lengths_use_real_incremental_blobs(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    keeper = sqlite3.connect(database, isolation_level=None)
    keeper.execute("PRAGMA journal_mode = WAL")
    keeper.execute("CREATE TABLE verdicts(verdict_json TEXT NOT NULL)")
    keeper.execute("CREATE TABLE procedural_reviews(review_json TEXT NOT NULL)")
    keeper.execute("CREATE TABLE m4_hearing_verdict_bindings(binding_json TEXT NOT NULL)")
    documents = (
        (
            M6LiveDocumentColumn.M4_VERDICT_DOCUMENT,
            "verdicts",
            "verdict_json",
            '{"verdict":"terminal-authority"}',
        ),
        (
            M6LiveDocumentColumn.M4_PROCEDURAL_REVIEW_DOCUMENT,
            "procedural_reviews",
            "review_json",
            '{"review":"gate-authority"}',
        ),
        (
            M6LiveDocumentColumn.M4_HEARING_VERDICT_BINDING_DOCUMENT,
            "m4_hearing_verdict_bindings",
            "binding_json",
            '{"binding":"record-verdict-authority"}',
        ),
    )
    expected: list[tuple[M6LiveDocumentColumn, int, str]] = []
    for route, table, column, document in documents:
        rowid = keeper.execute(
            f"INSERT INTO {table}({column}) VALUES (?)",
            (document,),
        ).lastrowid
        assert isinstance(rowid, int)
        expected.append((route, rowid, document))
    try:
        with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
            with cut.selector():
                pass
            with cut.reader() as reader:
                for route, rowid, document in expected:
                    assert reader.document_octet_length(route, rowid) == len(
                        document.encode("utf-8")
                    )
                assert not hasattr(reader, "blobopen")
            with cut.writer():
                pass
    finally:
        keeper.close()


def test_caught_reader_failure_keeps_cut_failed_and_writer_unavailable(
    tmp_path: Path,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    try:
        with (
            pytest.raises(M6LiveReadCutError) as incomplete,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with pytest.raises(M6LiveReadCutError) as poisoned, cut.reader() as reader:
                with pytest.raises(M6LiveReadCutError) as rejected:
                    reader.execute("COMMIT")
                assert rejected.value.reason_code == (M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
            assert poisoned.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED
            with pytest.raises(M6LiveReadCutError) as writer_rejected, cut.writer():
                pass
            assert writer_rejected.value.reason_code == (
                M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED
            )
    finally:
        keeper.close()

    assert incomplete.value.reason_code == M6LiveReadCutFailureCode.CUT_INCOMPLETE


@pytest.mark.parametrize(
    ("statement", "parameters", "expected"),
    (
        (
            _HostileStatement("SELECT 1"),
            (),
            M6LiveReadCutFailureCode.CAPABILITY_REJECTED,
        ),
        (
            "SELECT ?",
            (_HostileBind(),),
            M6LiveReadCutFailureCode.READER_REJECTED,
        ),
        (
            "SELECT ?",
            (1 << 100,),
            M6LiveReadCutFailureCode.READER_REJECTED,
        ),
    ),
)
def test_hostile_execute_inputs_are_payload_free_and_sticky(
    tmp_path: Path,
    statement: object,
    parameters: tuple[object, ...],
    expected: M6LiveReadCutFailureCode,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    try:
        with (
            pytest.raises(M6LiveReadCutError) as poisoned,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader() as reader:
                with pytest.raises(M6LiveReadCutError) as rejected:
                    reader.execute(statement, parameters)  # type: ignore[arg-type]
                assert rejected.value.reason_code == expected
                assert rejected.value.__cause__ is None
                assert rejected.value.__context__ is None
                assert "secret" not in str(rejected.value).lower()
                _assert_traceback_has_no_live_sqlite_authority(rejected.value)
    finally:
        keeper.close()

    assert poisoned.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED


@pytest.mark.parametrize("operation", ("execute", "fetchmany", "document_length"))
def test_reader_rejects_raw_authority_arguments_without_retaining_them(
    tmp_path: Path,
    operation: str,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    foreign_connection = sqlite3.connect(":memory:")
    try:
        with (
            pytest.raises(M6LiveReadCutError) as poisoned,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader() as reader:
                cursor = reader.execute("SELECT 1")
                with pytest.raises(M6LiveReadCutError) as rejected:
                    if operation == "execute":
                        reader.execute(foreign_connection)  # type: ignore[arg-type]
                    elif operation == "fetchmany":
                        cursor.fetchmany(foreign_connection)  # type: ignore[arg-type]
                    else:
                        reader.document_octet_length(  # type: ignore[arg-type]
                            foreign_connection,
                            1,
                        )
                assert rejected.value.reason_code == (M6LiveReadCutFailureCode.CAPABILITY_REJECTED)
                assert rejected.value.__cause__ is None
                assert rejected.value.__context__ is None
                _assert_traceback_has_no_live_sqlite_authority(rejected.value)
    finally:
        foreign_connection.close()
        keeper.close()

    assert poisoned.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED


def test_reader_storage_runtime_error_is_payload_free_sticky_and_closes_b(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class ExecuteFailingReader(sqlite3.Connection):
        fail_execute = False
        close_called = False

        def execute(
            self,
            sql: str,
            parameters: object = (),
        ) -> sqlite3.Cursor:
            if self.fail_execute:
                raise RuntimeError("secret reader payload")
            return super().execute(sql, parameters)  # type: ignore[arg-type]

        def close(self) -> None:
            self.close_called = True
            super().close()

    failing_reader = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=ExecuteFailingReader,
    )
    assert isinstance(failing_reader, ExecuteFailingReader)
    failing_reader.row_factory = sqlite3.Row
    failing_reader.execute("BEGIN")
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_committed_reader",
        lambda _database, _timeout: failing_reader,
    )
    try:
        with (
            pytest.raises(M6LiveReadCutError) as poisoned,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader() as reader:
                failing_reader.fail_execute = True
                with pytest.raises(M6LiveReadCutError) as rejected:
                    reader.execute("SELECT 1")
                assert rejected.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED
                assert rejected.value.__cause__ is None
                assert rejected.value.__context__ is None
                assert "secret" not in str(rejected.value).lower()
    finally:
        keeper.close()

    assert poisoned.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED
    assert poisoned.value.__cause__ is None
    assert poisoned.value.__context__ is None
    assert failing_reader.close_called


def test_abandoned_reader_cursor_is_closed_before_reader_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class TrackingCursor(sqlite3.Cursor):
        closed = False

        def close(self) -> None:
            self.closed = True
            super().close()

    class TrackingReader(sqlite3.Connection):
        created: list[TrackingCursor]

        def execute(
            self,
            sql: str,
            parameters: object = (),
        ) -> sqlite3.Cursor:
            cursor = self.cursor(factory=TrackingCursor)
            assert isinstance(cursor, TrackingCursor)
            self.created.append(cursor)
            return cursor.execute(sql, parameters)  # type: ignore[arg-type]

    tracking_reader = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=TrackingReader,
    )
    assert isinstance(tracking_reader, TrackingReader)
    tracking_reader.created = []
    tracking_reader.row_factory = sqlite3.Row
    sqlite3.Connection.execute(tracking_reader, "BEGIN")
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_committed_reader",
        lambda _database, _timeout: tracking_reader,
    )
    try:
        with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
            with cut.selector():
                pass
            with cut.reader() as reader:
                for _ in range(100):
                    assert tuple(reader.execute("SELECT 1").fetchone()) == (1,)
                gc.collect()
                assert len(tracking_reader.created) == 100
                assert all(cursor.closed for cursor in tracking_reader.created)
            with cut.writer():
                pass
    finally:
        keeper.close()


def test_reader_close_is_attempted_even_when_rollback_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class RollbackFailingReader(sqlite3.Connection):
        close_called = False

        def rollback(self) -> None:
            raise RuntimeError("secret rollback payload")

        def close(self) -> None:
            self.close_called = True
            super().close()

    failing_reader = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=RollbackFailingReader,
    )
    assert isinstance(failing_reader, RollbackFailingReader)
    failing_reader.row_factory = sqlite3.Row
    failing_reader.execute("BEGIN")
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_committed_reader",
        lambda _database, _timeout: failing_reader,
    )
    try:
        with (
            pytest.raises(M6LiveReadCutError) as rejected,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader():
                pass
    finally:
        keeper.close()

    assert rejected.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED
    assert failing_reader.close_called


def test_reader_cleanup_failures_do_not_replace_a_body_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class CleanupFailingReader(sqlite3.Connection):
        rollback_called = False
        close_called = False

        def rollback(self) -> None:
            self.rollback_called = True
            super().rollback()
            raise RuntimeError("secret rollback payload")

        def close(self) -> None:
            self.close_called = True
            super().close()
            raise RuntimeError("secret close payload")

    failing_reader = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=CleanupFailingReader,
    )
    assert isinstance(failing_reader, CleanupFailingReader)
    failing_reader.row_factory = sqlite3.Row
    failing_reader.execute("BEGIN")
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_committed_reader",
        lambda _database, _timeout: failing_reader,
    )
    try:
        with (
            pytest.raises(RuntimeError, match="verification body failed") as body_failure,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader():
                raise RuntimeError("verification body failed")
    finally:
        keeper.close()

    assert str(body_failure.value) == "verification body failed"
    assert failing_reader.rollback_called
    assert failing_reader.close_called


def test_reader_attempts_rollback_when_transaction_state_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class StateFailingReader(sqlite3.Connection):
        fail_state_read = False
        rollback_called = False
        close_called = False

        @property
        def in_transaction(self) -> bool:
            if self.fail_state_read:
                raise RuntimeError("secret transaction-state payload")
            return super().in_transaction

        def rollback(self) -> None:
            self.rollback_called = True
            super().rollback()

        def close(self) -> None:
            self.close_called = True
            super().close()

    failing_reader = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=StateFailingReader,
    )
    assert isinstance(failing_reader, StateFailingReader)
    failing_reader.row_factory = sqlite3.Row
    failing_reader.execute("BEGIN")
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_committed_reader",
        lambda _database, _timeout: failing_reader,
    )
    try:
        with (
            pytest.raises(M6LiveReadCutError) as rejected,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader() as reader:
                assert tuple(reader.execute("SELECT 1").fetchone()) == (1,)
                failing_reader.fail_state_read = True
    finally:
        keeper.close()

    assert rejected.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED
    assert failing_reader.rollback_called
    assert failing_reader.close_called


def test_outer_abort_attempts_rollback_when_writer_transaction_state_is_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class StateFailingWriter(sqlite3.Connection):
        fail_state_read = False
        rollback_called = False
        close_called = False

        @property
        def in_transaction(self) -> bool:
            if self.fail_state_read:
                raise RuntimeError("secret writer-state payload")
            return super().in_transaction

        def rollback(self) -> None:
            self.rollback_called = True
            super().rollback()

        def close(self) -> None:
            self.close_called = True
            super().close()

    failing_writer = sqlite3.connect(
        database,
        timeout=BUSY_TIMEOUT_MS / 1_000,
        isolation_level=None,
        factory=StateFailingWriter,
    )
    assert isinstance(failing_writer, StateFailingWriter)
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_connection",
        lambda *_args, **_kwargs: failing_writer,
    )
    try:
        with (
            pytest.raises(RuntimeError, match="force cut abort"),
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS),
        ):
            failing_writer.fail_state_read = True
            raise RuntimeError("force cut abort")
    finally:
        keeper.close()

    assert failing_writer.rollback_called
    assert failing_writer.close_called


def test_reader_close_is_attempted_when_authorizer_revoke_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, keeper = _live_wal_database(tmp_path)

    class RevokeFailingReader(sqlite3.Connection):
        close_called = False

        def set_authorizer(self, authorizer_callback: object) -> None:
            if authorizer_callback is None:
                raise RuntimeError("secret authorizer payload")
            super().set_authorizer(authorizer_callback)  # type: ignore[arg-type]

        def close(self) -> None:
            self.close_called = True
            super().close()

    failing_reader = sqlite3.connect(
        ":memory:",
        isolation_level=None,
        factory=RevokeFailingReader,
    )
    assert isinstance(failing_reader, RevokeFailingReader)
    failing_reader.row_factory = sqlite3.Row
    failing_reader.execute("BEGIN")
    monkeypatch.setattr(
        live_read_cut_module,
        "_open_committed_reader",
        lambda _database, _timeout: failing_reader,
    )
    try:
        with (
            pytest.raises(M6LiveReadCutError) as rejected,
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader():
                pass
    finally:
        keeper.close()

    assert rejected.value.reason_code == M6LiveReadCutFailureCode.READER_REJECTED
    assert rejected.value.__cause__ is None
    assert rejected.value.__context__ is None
    assert failing_reader.close_called


def test_cut_rolls_back_a_and_closes_b_when_read_phase_fails(tmp_path: Path) -> None:
    database, keeper = _live_wal_database(tmp_path)
    reader: M6LiveReader | None = None
    try:
        with (
            pytest.raises(RuntimeError, match="verification failed"),
            m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut,
        ):
            with cut.selector():
                pass
            with cut.reader() as opened:
                reader = opened
                raise RuntimeError("verification failed")
    finally:
        keeper.close()

    assert reader is not None
    with pytest.raises(M6LiveReadCutError) as stale:
        reader.execute("SELECT 1")
    assert stale.value.reason_code == M6LiveReadCutFailureCode.PHASE_ALREADY_CONSUMED

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reopened:
            assert tuple(reopened.execute("SELECT 1").fetchone()) == (1,)
        with cut.writer():
            pass


def test_writer_lock_failure_is_typed_and_does_not_disclose_sqlite_or_path_text(
    tmp_path: Path,
) -> None:
    database, keeper = _live_wal_database(tmp_path)
    blocker = sqlite3.connect(database, isolation_level=None)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with (
            pytest.raises(M6LiveReadCutError) as rejected,
            m6_live_committed_read_cut(database, 1),
        ):
            pass
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()
        keeper.close()

    assert rejected.value.reason_code == M6LiveReadCutFailureCode.WRITER_LOCK_UNAVAILABLE
    assert str(database) not in str(rejected.value)
    assert "database is locked" not in str(rejected.value).lower()
