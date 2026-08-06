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
from labcourt.application.m6_replay_locked_m4_terminal import (
    build_m6_replay_locked_m4_gate_terminal_candidate,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateError,
    M6ReplayLockedCandidateFailureCode,
    M6ReplayLockedM4CandidateWrite,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
)
from tests.unit.test_m6_replay_locked_m4_terminal import _execution


@dataclass(frozen=True, slots=True)
class _Runtime:
    database: Path
    scope: M6ReplayLockedExecutionScopeAuthority
    pending: M6ReplayLockedPendingSampleCommitmentAuthority
    write: M6ReplayLockedM4CandidateWrite
    repository: SQLiteM6ReplayLockedCandidateRepository


def _runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> _Runtime:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    scope, pending, source = _execution(monkeypatch)
    candidate = build_m6_replay_locked_m4_gate_terminal_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=source,
    )
    write = M6ReplayLockedM4CandidateWrite(
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


def _counts(database: Path) -> tuple[int, int, int, int, int]:
    with sqlite3.connect(database) as connection:
        fast = int(
            connection.execute("SELECT COUNT(*) FROM m6_replay_locked_candidate_cases").fetchone()[
                0
            ]
        )
        m4 = int(
            connection.execute(
                "SELECT COUNT(*) FROM m6_replay_locked_m4_candidate_cases"
            ).fetchone()[0]
        )
        audits = int(connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0])
        revision, sequence = connection.execute(
            "SELECT revision, audit_head_sequence FROM runs"
        ).fetchone()
    return fast, m4, audits, int(revision), int(sequence)


def test_m4_candidate_and_case_created_audit_commit_as_one_terminal_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, monkeypatch)

    runtime.repository.publish_m4_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )

    stored = runtime.repository.load_stored_candidate_case(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )
    head = runtime.repository.load_candidate_audit_head(runtime.scope.candidate_run_id)
    assert stored.route == (M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE)
    assert stored.case == runtime.write.case
    assert stored.canonical_document == runtime.write.canonical_document
    assert stored.execution_scope_authority_id == runtime.scope.execution_scope_authority_id
    assert stored.pending_commitment_authority_id == (
        runtime.pending.pending_commitment_authority_id
    )
    assert stored.case_audit_sequence == head.sequence == 0
    assert stored.case_audit_entry_hash == head.entry_hash
    assert _counts(runtime.database) == (0, 1, 1, 1, 0)
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_exact_m4_candidate_retry_is_zero_write_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, monkeypatch)
    runtime.repository.publish_m4_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )
    before = _counts(runtime.database)

    runtime.repository.publish_m4_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )

    assert _counts(runtime.database) == before


@pytest.mark.parametrize(
    "fault_phase",
    (
        "m6_replay_locked_candidate.after_audit",
        "m6_replay_locked_candidate.after_candidate",
        "m6_replay_locked_candidate.before_commit",
    ),
)
def test_m4_fault_at_each_atomic_boundary_rolls_back_case_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_phase: str,
) -> None:
    def fault(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("synthetic M4 candidate persistence fault")

    runtime = _runtime(tmp_path, monkeypatch, fault_injector=fault)

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.repository.publish_m4_candidate(
            runtime.scope,
            runtime.pending,
            runtime.write,
        )

    assert raised.value.reason_code == M6ReplayLockedCandidateFailureCode.STORAGE_REJECTED
    assert _counts(runtime.database) == (0, 0, 0, 0, -1)


def test_m4_publish_entry_rejects_a_fast_route_before_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, monkeypatch)
    fast_pending = runtime.pending.model_copy(
        update={"route": M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE}
    )

    with pytest.raises(M6ReplayLockedCandidateError) as raised:
        runtime.repository.publish_m4_candidate(
            runtime.scope,
            fast_pending,
            runtime.write,
        )

    assert raised.value.reason_code == M6ReplayLockedCandidateFailureCode.CANDIDATE_CONFLICT
    assert _counts(runtime.database) == (0, 0, 0, 0, -1)
