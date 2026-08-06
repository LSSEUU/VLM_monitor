from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage._sqlite_m5_precedent_causal_ledger import (
    append_m5_precedent_causal_event,
    m5_precedent_authority_causal_source,
)
from labcourt.adapters.storage.readonly_m5_artifacts import (
    M5AuthorityBudgetExceeded,
    ReadonlyM5ArtifactRepository,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.adapters.storage.sqlite_schema import m5_authority_installed
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    record_m5_precedent_citation,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationBudget,
    M5ArtifactValidationIssueCode,
    M5PrecedentCausalLedgerReasonCode,
)
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
    M5PrecedentCausalEventSourceKind,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from tests.integration.test_m5_sqlite_precedents import (
    BUSY_TIMEOUT_MS,
    NOW,
    RUN_ID,
    SQLiteM5Repository,
    _authority,
    _clock,
    _config,
    _install,
    _query,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _event_rows(database: Path) -> tuple[sqlite3.Row, ...]:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        return tuple(
            connection.execute(
                "SELECT * FROM m5_precedent_causal_events ORDER BY sequence"
            ).fetchall()
        )


def _events(database: Path) -> tuple[M5PrecedentCausalEvent, ...]:
    return tuple(
        M5PrecedentCausalEvent.model_validate_json(row["event_json"])
        for row in _event_rows(database)
    )


def _drop_trigger(connection: sqlite3.Connection, name: str) -> str:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
        (name,),
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    connection.execute(f'DROP TRIGGER "{name}"')
    return row[0]


def _delete_event(database: Path, source_id: str) -> None:
    with sqlite3.connect(database) as connection:
        trigger = _drop_trigger(connection, "m5_precedent_causal_events_no_delete")
        cursor = connection.execute(
            "DELETE FROM m5_precedent_causal_events WHERE source_id = ?",
            (source_id,),
        )
        assert cursor.rowcount == 1
        connection.execute(trigger)


def _event_values(event: M5PrecedentCausalEvent) -> tuple[object, ...]:
    raw = canonical_json(event.model_dump(mode="json"))
    return (
        event.run_id,
        event.sequence,
        event.event_id,
        event.source_identity_sha256,
        event.event_kind.value,
        event.source_id,
        event.precedent_id,
        event.precedent_authority_id,
        event.precedent_revision,
        event.citation_kind.value if event.citation_kind is not None else None,
        event.manifest_id,
        event.source_document_sha256,
        event.previous_event_sha256,
        event.event_sha256,
        raw,
        hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )


def _insert_event(connection: sqlite3.Connection, event: M5PrecedentCausalEvent) -> None:
    connection.execute(
        """
        INSERT INTO m5_precedent_causal_events(
            run_id, sequence, event_id, source_identity_sha256,
            event_kind, source_id, precedent_id, precedent_authority_id,
            precedent_revision, citation_kind, manifest_id,
            source_document_sha256, previous_event_sha256, event_sha256,
            event_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        _event_values(event),
    )


def _replace_event(connection: sqlite3.Connection, event: M5PrecedentCausalEvent) -> None:
    values = _event_values(event)
    cursor = connection.execute(
        """
        UPDATE m5_precedent_causal_events
        SET event_id = ?, source_identity_sha256 = ?, event_kind = ?, source_id = ?,
            precedent_id = ?, precedent_authority_id = ?, precedent_revision = ?,
            citation_kind = ?, manifest_id = ?, source_document_sha256 = ?,
            previous_event_sha256 = ?, event_sha256 = ?, event_json = ?,
            document_sha256 = ?
        WHERE run_id = ? AND sequence = ?
        """,
        (
            *values[2:16],
            event.run_id,
            event.sequence,
        ),
    )
    assert cursor.rowcount == 1


def _tamper_event(database: Path, event: M5PrecedentCausalEvent) -> None:
    with sqlite3.connect(database) as connection:
        trigger = _drop_trigger(connection, "m5_precedent_causal_events_no_update")
        _replace_event(connection, event)
        connection.execute(trigger)


def _remove_event_uniqueness_and_replace(
    database: Path,
    event: M5PrecedentCausalEvent,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        trigger_rows = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type = 'trigger' AND tbl_name = 'm5_precedent_causal_events'
            ORDER BY name
            """
        ).fetchall()
        assert len(trigger_rows) == 7
        triggers = tuple((str(row[0]), str(row[1])) for row in trigger_rows)
        indexes = tuple(
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'index' AND tbl_name = 'm5_precedent_causal_events'
                  AND sql IS NOT NULL
                ORDER BY name
                """
            )
        )
        table_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'm5_precedent_causal_events'
            """
        ).fetchone()
        assert table_row is not None and isinstance(table_row[0], str)
        table_sql = table_row[0]
        for clause in (
            "    UNIQUE (run_id, event_id),\n",
            "    UNIQUE (run_id, source_identity_sha256),\n",
            "    UNIQUE (run_id, event_sha256),\n",
            "    UNIQUE (run_id, event_kind, source_id),\n",
        ):
            assert clause in table_sql
            table_sql = table_sql.replace(clause, "")
        for name, _sql in triggers:
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "ALTER TABLE m5_precedent_causal_events RENAME TO m5_precedent_causal_events_old"
        )
        connection.execute(table_sql)
        connection.execute(
            """
            INSERT INTO m5_precedent_causal_events
            SELECT * FROM m5_precedent_causal_events_old
            """
        )
        connection.execute("DROP TABLE m5_precedent_causal_events_old")
        _replace_event(connection, event)
        for _name, sql in indexes:
            connection.execute(sql)
        for _name, sql in triggers:
            connection.execute(sql)


def _duplicate_citation_source_without_uniqueness(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        table_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'precedent_citations'
            """
        ).fetchone()
        assert table_row is not None and isinstance(table_row[0], str)
        table_sql = table_row[0]
        for clause in (
            "    PRIMARY KEY (run_id, citation_id),\n",
            "    UNIQUE (run_id, commit_id),\n",
            "    UNIQUE (run_id, case_id, precedent_id, query_id),\n",
        ):
            assert clause in table_sql
            table_sql = table_sql.replace(clause, "")
        triggers = tuple(
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'trigger' AND tbl_name = 'precedent_citations'
                ORDER BY name
                """
            )
        )
        indexes = tuple(
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'index' AND tbl_name = 'precedent_citations'
                  AND sql IS NOT NULL
                ORDER BY name
                """
            )
        )
        for name, _sql in triggers:
            connection.execute(f'DROP TRIGGER "{name}"')
        for name, _sql in indexes:
            connection.execute(f'DROP INDEX "{name}"')
        connection.execute("ALTER TABLE precedent_citations RENAME TO precedent_citations_old")
        connection.execute(table_sql)
        connection.execute("INSERT INTO precedent_citations SELECT * FROM precedent_citations_old")
        connection.execute("INSERT INTO precedent_citations SELECT * FROM precedent_citations_old")
        connection.execute("DROP TABLE precedent_citations_old")
        for _name, sql in indexes:
            connection.execute(sql)
        for _name, sql in triggers:
            connection.execute(sql)
        assert m5_authority_installed(connection)


def _append_two_authorities(
    tmp_path: Path,
) -> tuple[Path, SQLiteM5Repository, object, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first = _authority(manifest, "precedent-causal-a")
    second = _authority(manifest, "precedent-causal-b")
    repository.append_authority(first, None)
    repository.append_authority(second, None)
    return database, repository, first, second


def test_authority_and_direct_citation_events_form_one_exact_replayable_chain(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-direct")
    repository.append_authority(authority, None)
    result = ExactM5PrecedentRetrievalService().retrieve(
        _query(manifest, case_id),
        repository.list_for_retrieval(_query(manifest, case_id)),
    )
    commit = record_m5_precedent_citation(
        result=result,
        precedent_id=authority.precedent.precedent_id,
        cited_at=NOW,
    )
    repository.commit_citation(commit)

    events = _events(database)
    assert tuple(event.sequence for event in events) == (1, 2)
    assert tuple(event.event_kind for event in events) == (
        M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
        M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
    )
    assert events[0].previous_event_sha256 == "0" * 64
    assert events[1].previous_event_sha256 == events[0].event_sha256
    assert events[1].citation_kind == M5PrecedentCausalEventSourceKind.DIRECT

    assert repository.append_authority(authority, None) == authority
    assert repository.commit_citation(commit) == commit
    assert _events(database) == events


def test_causal_event_participates_in_authority_count_budget(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    repository.append_authority(
        _authority(manifest, "precedent-causal-budget"),
        None,
    )

    readonly = ReadonlyM5ArtifactRepository(
        database,
        config=_config(),
        budget=M5ArtifactValidationBudget(max_authority_records=2),
    )
    preflight = readonly.preflight(RUN_ID)
    inventory = {item.authority_kind: item.count for item in preflight.traversed}
    assert inventory[M5AuthorityKind.PRECEDENT_EMBEDDING] == 1
    assert inventory[M5AuthorityKind.PRECEDENT] == 1
    assert inventory[M5AuthorityKind.PRECEDENT_CAUSAL_EVENT] == 1
    assert preflight.authority_rows == 3
    with pytest.raises(M5AuthorityBudgetExceeded) as captured:
        readonly.scan(RUN_ID)
    assert (
        M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED
        in captured.value.issue_codes
    )


def test_replay_and_append_reject_corruption_outside_the_target_event(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authorities = tuple(
        _authority(manifest, f"precedent-causal-full-chain-{ordinal}") for ordinal in range(1, 5)
    )
    for authority in authorities[:3]:
        repository.append_authority(authority, None)
    with sqlite3.connect(database) as connection:
        source_counts = (
            connection.execute("SELECT COUNT(*) FROM precedents").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM precedent_embeddings").fetchone()[0],
        )

    first = _events(database)[0]
    corrupted_first = first.model_copy(
        update={"source_document_sha256": _sha("self-consistent-corrupted-first-event")}
    )
    assert corrupted_first.event_sha256 != first.event_sha256
    _tamper_event(database, corrupted_first)
    corrupted_rows = tuple(tuple(row) for row in _event_rows(database))

    with pytest.raises(RepositoryIntegrityError, match="causal event chain"):
        repository.append_authority(authorities[2], None)
    with pytest.raises(RepositoryIntegrityError, match="causal event chain"):
        repository.append_authority(authorities[3], None)

    assert tuple(tuple(row) for row in _event_rows(database)) == corrupted_rows
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM precedents").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM precedent_embeddings").fetchone()[0],
        ) == source_counts


def test_exact_authority_replay_requires_event_and_never_repairs_it(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-missing-authority")
    repository.append_authority(authority, None)
    _delete_event(database, authority.authority_id)

    with pytest.raises(RepositoryIntegrityError, match="exactly one event"):
        repository.get_precedent(RUN_ID, authority.precedent.precedent_id)
    with pytest.raises(RepositoryIntegrityError, match="exactly one event"):
        repository.append_authority(authority, None)
    assert _event_rows(database) == ()


def test_direct_helper_cannot_repair_a_committed_source_missing_its_event(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-helper-repair")
    repository.append_authority(authority, None)
    _delete_event(database, authority.authority_id)
    callback_calls = 0

    def forbidden_source_insert() -> None:
        nonlocal callback_calls
        callback_calls += 1
        raise AssertionError("source callback must not run for a committed orphan")

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        source_row = connection.execute(
            """
            SELECT manifest_id, document_sha256 FROM precedents
            WHERE run_id = ? AND authority_id = ?
            """,
            (RUN_ID, authority.authority_id),
        ).fetchone()
        assert source_row is not None
        connection.execute("BEGIN")
        with pytest.raises(RepositoryIntegrityError, match="exactly one event"):
            append_m5_precedent_causal_event(
                connection,
                source=m5_precedent_authority_causal_source(
                    authority,
                    manifest_id=str(source_row["manifest_id"]),
                    source_document_sha256=str(source_row["document_sha256"]),
                ),
                insert_source=forbidden_source_insert,
                fault_scope="test.forbidden_repair",
                fault=lambda _phase: None,
            )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM m5_precedent_causal_events WHERE run_id = ?",
                (RUN_ID,),
            ).fetchone()[0]
            == 0
        )
    assert callback_calls == 0


@pytest.mark.parametrize(
    "phase",
    (
        "precedent.append.authority.before_causal_event",
        "precedent.append.authority.after_causal_event",
    ),
)
def test_authority_event_boundary_fault_rolls_back_source_and_event(
    tmp_path: Path,
    phase: str,
) -> None:
    database, _case_id, manifest = _install(tmp_path)

    def fail_at(observed: str) -> None:
        if observed == phase:
            raise RuntimeError("injected authority causal event fault")

    repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="causal event fault"):
        repository.append_authority(
            _authority(manifest, "precedent-causal-authority-fault"),
            None,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM precedent_embeddings").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            0,
        )


@pytest.mark.parametrize(
    "phase",
    (
        "precedent.import.authority.2.before_causal_event",
        "precedent.import.authority.2.after_causal_event",
    ),
)
def test_import_nth_event_boundary_fault_rolls_back_the_complete_batch(
    tmp_path: Path,
    phase: str,
) -> None:
    database, _case_id, manifest = _install(tmp_path)

    def fail_at(observed: str) -> None:
        if observed == phase:
            raise RuntimeError("injected import causal event fault")

    repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        fault_injector=fail_at,
    )
    authorities = (
        _authority(manifest, "precedent-causal-import-a"),
        _authority(manifest, "precedent-causal-import-b"),
        _authority(manifest, "precedent-causal-import-c"),
    )
    with pytest.raises(RuntimeError, match="import causal event fault"):
        repository.append_authorities(RUN_ID, authorities)
    with sqlite3.connect(database) as connection:
        for table in (
            "precedents",
            "precedent_embeddings",
            "m5_precedent_causal_events",
        ):
            assert connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone() == (0,)


def test_exact_citation_replay_requires_event_and_never_repairs_it(tmp_path: Path) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-missing-citation")
    repository.append_authority(authority, None)
    query = _query(manifest, case_id)
    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    commit = record_m5_precedent_citation(
        result=result,
        precedent_id=authority.precedent.precedent_id,
        cited_at=NOW,
    )
    repository.commit_citation(commit)
    _delete_event(database, commit.citation.citation_id)

    with pytest.raises(RepositoryIntegrityError, match="exactly one event"):
        repository.commit_citation(commit)
    assert len(_event_rows(database)) == 1


def test_sql_causal_guards_reject_bad_source_sequence_and_mutation(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-sql")
    repository.append_authority(authority, None)
    first = _events(database)[0]
    bad_source = M5PrecedentCausalEvent(
        run_id=RUN_ID,
        sequence=2,
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
        source_id=_sha("missing-citation"),
        precedent_id=authority.precedent.precedent_id,
        precedent_authority_id=authority.authority_id,
        precedent_revision=authority.revision,
        citation_kind=M5PrecedentCausalEventSourceKind.DIRECT,
        manifest_id=manifest.manifest_id,
        source_document_sha256=_sha("missing-citation-document"),
        previous_event_sha256=first.event_sha256,
    )
    bad_sequence = bad_source.model_copy(update={"sequence": 3})
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_event(connection, bad_source)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_event(connection, bad_sequence)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m5_precedent_causal_events SET sequence = 2 WHERE sequence = 1"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m5_precedent_causal_events")


def test_readonly_reports_missing_and_orphan_events_bidirectionally(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-readonly-missing")
    repository.append_authority(authority, None)
    _delete_event(database, authority.authority_id)
    missing = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_MISSING in {
        failure.reason_code for failure in missing.failures
    }

    orphan_root = tmp_path / "orphan"
    orphan_root.mkdir()
    other_database, _other_case_id, other_manifest = _install(orphan_root)
    other_repository = SQLiteM5Repository(other_database, BUSY_TIMEOUT_MS, _clock)
    other = _authority(other_manifest, "precedent-causal-readonly-orphan")
    other_repository.append_authority(other, None)
    first = _events(other_database)[0]
    orphan = M5PrecedentCausalEvent(
        run_id=RUN_ID,
        sequence=2,
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED,
        source_id=_sha("orphan-citation"),
        precedent_id=other.precedent.precedent_id,
        precedent_authority_id=other.authority_id,
        precedent_revision=other.revision,
        citation_kind=M5PrecedentCausalEventSourceKind.DIRECT,
        manifest_id=other_manifest.manifest_id,
        source_document_sha256=_sha("orphan-citation-document"),
        previous_event_sha256=first.event_sha256,
    )
    with sqlite3.connect(other_database) as connection:
        trigger = _drop_trigger(
            connection,
            "m5_precedent_causal_events_validate_source",
        )
        _insert_event(connection, orphan)
        connection.execute(trigger)
    extra = ReadonlyM5ArtifactRepository(other_database, config=_config()).scan(RUN_ID)
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_ORPHAN in {
        failure.reason_code for failure in extra.failures
    }


def test_readonly_duplicate_attack_is_not_hidden_by_equal_total_counts(tmp_path: Path) -> None:
    database, _repository, first, _second = _append_two_authorities(tmp_path)
    first_event, second_event = _events(database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT manifest_id, document_sha256 FROM precedents WHERE authority_id = ?",
            (first.authority_id,),
        ).fetchone()
    assert row is not None
    duplicate = M5PrecedentCausalEvent(
        run_id=RUN_ID,
        sequence=2,
        event_kind=M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED,
        source_id=first.authority_id,
        precedent_id=first.precedent.precedent_id,
        precedent_authority_id=first.authority_id,
        precedent_revision=first.revision,
        citation_kind=None,
        manifest_id=str(row[0]),
        source_document_sha256=str(row[1]),
        previous_event_sha256=first_event.event_sha256,
    )
    assert duplicate.event_id == first_event.event_id
    assert duplicate.event_sha256 != second_event.event_sha256
    _remove_event_uniqueness_and_replace(database, duplicate)

    snapshot = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    inventory = {item.authority_kind: item.count for item in snapshot.traversed}
    assert inventory[M5AuthorityKind.PRECEDENT] == 2
    assert inventory[M5AuthorityKind.PRECEDENT_CAUSAL_EVENT] == 2
    reasons = {failure.reason_code for failure in snapshot.failures}
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_DUPLICATE in reasons
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_MISSING in reasons


def test_readonly_rejects_duplicate_source_hidden_by_unique_key_count(tmp_path: Path) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-duplicate-source")
    repository.append_authority(authority, None)
    query = _query(manifest, case_id)
    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    commit = record_m5_precedent_citation(
        result=result,
        precedent_id=authority.precedent.precedent_id,
        cited_at=NOW,
    )
    repository.commit_citation(commit)
    _duplicate_citation_source_without_uniqueness(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedent_citations").fetchone() == (2,)
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            2,
        )
    snapshot = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    inventory = {item.authority_kind: item.count for item in snapshot.traversed}
    assert inventory[M5AuthorityKind.PRECEDENT_CITATION] == 2
    assert inventory[M5AuthorityKind.PRECEDENT_CAUSAL_EVENT] == 2
    reasons = {failure.reason_code for failure in snapshot.failures}
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_SOURCE_DUPLICATE in reasons
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID in reasons


def test_readonly_rejects_self_consistent_source_mismatch_and_broken_chain(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-causal-source-mismatch")
    repository.append_authority(authority, None)
    mismatch = _events(database)[0].model_copy(
        update={"source_document_sha256": _sha("self-consistent-wrong-source")}
    )
    _tamper_event(database, mismatch)
    mismatch_snapshot = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_SOURCE_MISMATCH in {
        failure.reason_code for failure in mismatch_snapshot.failures
    }

    chain_database, _chain_repository, _first, _second = _append_two_authorities(tmp_path / "chain")
    first_event, second_event = _events(chain_database)
    broken = second_event.model_copy(
        update={"previous_event_sha256": _sha("broken-but-rehashed-predecessor")}
    )
    assert broken.event_sha256 != second_event.event_sha256
    assert broken.previous_event_sha256 != first_event.event_sha256
    _tamper_event(chain_database, broken)
    chain_snapshot = ReadonlyM5ArtifactRepository(
        chain_database,
        config=_config(),
    ).scan(RUN_ID)
    assert M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID in {
        failure.reason_code for failure in chain_snapshot.failures
    }
    assert not any(
        failure.authority_kind == M5AuthorityKind.PRECEDENT_CAUSAL_EVENT
        and failure.reason_code in {"CANONICAL_DOCUMENT_INVALID", "INDEX_BINDING_MISMATCH"}
        for failure in chain_snapshot.failures
    )
