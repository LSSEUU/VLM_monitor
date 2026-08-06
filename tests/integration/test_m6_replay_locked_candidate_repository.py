from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m6_replay_locked_candidate import (
    SQLiteM6ReplayLockedCandidateRepository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    build_m6_replay_locked_fast_terminal_candidate,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import TimelineEntry
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedCandidateWrite,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
)
from tests.unit.test_m6_replay_locked_fast_terminal import _execution


@dataclass(frozen=True, slots=True)
class _Runtime:
    database: Path
    scope: M6ReplayLockedExecutionScopeAuthority
    pending: M6ReplayLockedPendingSampleCommitmentAuthority
    write: M6ReplayLockedCandidateWrite
    repository: SQLiteM6ReplayLockedCandidateRepository


def _runtime(
    tmp_path: Path,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> _Runtime:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    scope, pending, source = _execution()
    candidate = build_m6_replay_locked_fast_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    write = M6ReplayLockedCandidateWrite(
        case=candidate.case,
        canonical_document=candidate.canonical_case_document,
    )
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.locked_manifest,
    )
    return _Runtime(
        database=database,
        scope=scope,
        pending=pending,
        write=write,
        repository=SQLiteM6ReplayLockedCandidateRepository(
            database,
            BUSY_TIMEOUT_MS,
            fault_injector=fault_injector,
        ),
    )


def _counts(database: Path) -> tuple[int, int, int, int, str]:
    with sqlite3.connect(database) as connection:
        candidate_count = int(
            connection.execute("SELECT COUNT(*) FROM m6_replay_locked_candidate_cases").fetchone()[
                0
            ]
        )
        audit_count = int(connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0])
        revision, sequence, entry_hash = connection.execute(
            "SELECT revision, audit_head_sequence, audit_head_hash FROM runs"
        ).fetchone()
    return candidate_count, audit_count, int(revision), int(sequence), str(entry_hash)


def test_candidate_case_and_case_created_audit_commit_atomically(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)

    runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)

    stored = runtime.repository.load_stored_candidate_case(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )
    head = runtime.repository.load_candidate_audit_head(runtime.scope.candidate_run_id)
    assert stored.case == runtime.write.case
    assert stored.canonical_document == runtime.write.canonical_document
    assert stored.execution_scope_authority_id == runtime.scope.execution_scope_authority_id
    assert stored.pending_commitment_authority_id == (
        runtime.pending.pending_commitment_authority_id
    )
    assert stored.ledger_sequence == runtime.pending.ledger_sequence == 0
    assert stored.case_audit_sequence == head.sequence == 0
    assert stored.case_audit_entry_hash == head.entry_hash
    assert head.run_revision == 1
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_exact_candidate_retry_is_a_zero_write_success(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)
    before = _counts(runtime.database)

    runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)

    assert _counts(runtime.database) == before


def test_scope_or_pending_drift_rejects_before_any_sqlite_change(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    foreign = runtime.pending.model_copy(update={"source_catalog_entry_id": "f" * 64})

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.repository.publish_candidate(runtime.scope, foreign, runtime.write)

    assert raised.value.reason_code == M6ReplayLockedCandidateFailureCode.CANDIDATE_CONFLICT
    assert _counts(runtime.database)[:4] == (0, 0, 0, -1)


@pytest.mark.parametrize(
    "fault_phase",
    (
        "m6_replay_locked_candidate.after_audit",
        "m6_replay_locked_candidate.after_candidate",
        "m6_replay_locked_candidate.before_commit",
    ),
)
def test_fault_at_each_atomic_boundary_rolls_back_audit_row_and_head(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    def fault(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("synthetic candidate persistence fault")

    runtime = _runtime(tmp_path, fault_injector=fault)

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)

    assert raised.value.reason_code == M6ReplayLockedCandidateFailureCode.STORAGE_REJECTED
    assert _counts(runtime.database)[:4] == (0, 0, 0, -1)


def test_unrelated_audit_tail_cannot_be_claimed_as_the_pending_candidate(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    SQLiteEvidenceRepository(runtime.database, BUSY_TIMEOUT_MS).create_or_get_case(
        runtime.scope.candidate_run_id,
        runtime.write.case.event,
    )
    before = _counts(runtime.database)

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)

    assert raised.value.reason_code == (M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID)
    assert _counts(runtime.database) == before
    assert before[:4] == (0, 1, 1, 0)

    with pytest.raises(M6ReplayLockedCandidateError) as head_error:
        runtime.repository.load_candidate_audit_head(runtime.scope.candidate_run_id)
    assert head_error.value.reason_code == (
        M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID
    )


def test_unknown_candidate_run_is_not_reported_as_a_storage_outage(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)

    with pytest.raises(M6ReplayLockedCandidateError) as row_error:
        runtime.repository.load_stored_candidate_case("unknown-run", runtime.pending.sample_id)
    with pytest.raises(M6ReplayLockedCandidateError) as head_error:
        runtime.repository.load_candidate_audit_head("unknown-run")

    assert row_error.value.reason_code == M6ReplayLockedCandidateFailureCode.NOT_FOUND
    assert head_error.value.reason_code == M6ReplayLockedCandidateFailureCode.NOT_FOUND


def test_reader_rejects_noncanonical_or_digest_drift_in_stored_case(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)
    with sqlite3.connect(runtime.database) as connection:
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_replay_locked_candidate_cases_no_update'
            """
        ).fetchone()
        assert trigger_sql is not None
        connection.execute("DROP TRIGGER m6_replay_locked_candidate_cases_no_update")
        connection.execute(
            """
            UPDATE m6_replay_locked_candidate_cases
            SET case_json = replace(
                case_json,
                'READY_FOR_ALERT_POLICY',
                'REWORK_REQUIRED'
                )
            """
        )
        connection.execute(str(trigger_sql[0]))

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.repository.load_stored_candidate_case(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )

    assert raised.value.reason_code == (M6ReplayLockedCandidateFailureCode.STORED_AUTHORITY_INVALID)


def test_candidate_rows_are_append_only_even_under_replace(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)

    with sqlite3.connect(runtime.database) as connection:
        row = connection.execute("SELECT * FROM m6_replay_locked_candidate_cases").fetchone()
        assert row is not None
        placeholders = ", ".join("?" for _item in row)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                f"INSERT OR REPLACE INTO m6_replay_locked_candidate_cases VALUES ({placeholders})",
                row,
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE m6_replay_locked_candidate_cases SET case_revision = 1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m6_replay_locked_candidate_cases")
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_replay_locked_candidate_cases"
        ).fetchone() == (1,)


def test_python_write_boundary_rejects_a_nonterminal_timeline(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    foreign_case = runtime.write.case.model_copy(
        update={
            "timeline": (
                TimelineEntry(
                    sequence=0,
                    action="CASE_CREATED",
                    stage="EVIDENCE",
                    object_ref=runtime.write.case.case_id,
                ),
            )
        }
    )
    foreign_document = canonical_json(foreign_case.model_dump(mode="json"))

    with pytest.raises(ValueError, match="bindings differ"):
        M6ReplayLockedCandidateWrite(
            case=foreign_case,
            canonical_document=foreign_document,
        )


def test_sql_trigger_rejects_an_object_disguised_as_an_empty_timeline(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.repository.publish_candidate(runtime.scope, runtime.pending, runtime.write)

    with sqlite3.connect(runtime.database) as connection:
        columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_info(m6_replay_locked_candidate_cases)")
        )
        row = connection.execute(
            f"SELECT {', '.join(columns)} FROM m6_replay_locked_candidate_cases"
        ).fetchone()
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_replay_locked_candidate_cases_no_delete'
            """
        ).fetchone()
        assert row is not None and trigger_sql is not None
        connection.execute("DROP TRIGGER m6_replay_locked_candidate_cases_no_delete")
        connection.execute("DELETE FROM m6_replay_locked_candidate_cases")
        connection.execute(str(trigger_sql[0]))
        values = dict(zip(columns, row, strict=True))
        original = str(values["case_json"])
        values["case_json"] = original.replace('"timeline":[]', '"timeline":{}')
        assert values["case_json"] != original
        placeholders = ", ".join("?" for _column in columns)

        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 replay-locked candidate Case",
        ):
            connection.execute(
                f"""
                INSERT INTO m6_replay_locked_candidate_cases(
                    {", ".join(columns)}
                ) VALUES ({placeholders})
                """,
                tuple(values[column] for column in columns),
            )

        values["case_json"] = original.replace('"input_tokens":0', '"input_tokens":1')
        assert values["case_json"] != original
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 replay-locked candidate Case",
        ):
            connection.execute(
                f"""
                INSERT INTO m6_replay_locked_candidate_cases(
                    {", ".join(columns)}
                ) VALUES ({placeholders})
                """,
                tuple(values[column] for column in columns),
            )
