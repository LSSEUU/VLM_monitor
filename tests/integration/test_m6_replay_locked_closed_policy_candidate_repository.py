from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m6_replay_locked_closed_policy_candidate import (
    SQLiteM6ReplayLockedClosedPolicyCandidateRepository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_replay_locked_closed_candidate_observation import (
    build_m6_replay_locked_closed_candidate_observation,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateError,
    M6ReplayLockedClosedCandidateFailureCode,
    M6ReplayLockedClosedCandidateObservation,
    M6ReplayLockedClosedCandidateWrite,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    BUSY_TIMEOUT_MS,
)
from tests.unit.test_m6_replay_locked_closed_policy_execution import (
    _terminal_facts,
)
from tests.unit.test_m6_semantic_projection import _snapshot

_TABLE = "m6_replay_locked_closed_policy_candidate_cases"


@dataclass(frozen=True, slots=True)
class _Runtime:
    database: Path
    scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2
    pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2
    expected_observation: M6ReplayLockedClosedCandidateObservation
    write: M6ReplayLockedClosedCandidateWrite
    repository: SQLiteM6ReplayLockedClosedPolicyCandidateRepository


def _runtime(
    tmp_path: Path,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> _Runtime:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    scope, _catalog, _cut, pending, _proof, observation, _head = _terminal_facts()  # type: ignore[no-untyped-call]
    binding = observation.closed_candidate_binding
    write = M6ReplayLockedClosedCandidateWrite(
        transient_ready_case=binding.transient_ready_case,
        candidate_alert_policy=binding.candidate_alert_policy,
        closed_candidate_case=binding.closed_candidate_case,
        canonical_alert_policy_document=canonical_json(
            binding.candidate_alert_policy.model_dump(mode="json")
        ),
        canonical_closed_case_document=canonical_json(
            binding.closed_candidate_case.model_dump(mode="json")
        ),
    )
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.pre_policy_execution_scope.locked_manifest,
    )
    return _Runtime(
        database=database,
        scope=scope,
        pending=pending,
        expected_observation=observation,
        write=write,
        repository=SQLiteM6ReplayLockedClosedPolicyCandidateRepository(
            database,
            BUSY_TIMEOUT_MS,
            fault_injector=fault_injector,
        ),
    )


def _counts(database: Path) -> tuple[int, int, int, int, int, int, str]:
    with sqlite3.connect(database) as connection:
        closed = int(connection.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()[0])
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
        revision, sequence, entry_hash = connection.execute(
            "SELECT revision, audit_head_sequence, audit_head_hash FROM runs"
        ).fetchone()
    return (
        closed,
        fast,
        m4,
        audits,
        int(revision),
        int(sequence),
        str(entry_hash),
    )


def test_policy_and_closed_case_commit_atomically_without_a_ready_body(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)

    runtime.repository.publish_closed_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )

    stored = runtime.repository.load_stored_closed_candidate(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )
    head = runtime.repository.load_closed_candidate_audit_head(runtime.scope.candidate_run_id)
    assert stored.candidate_alert_policy == runtime.write.candidate_alert_policy
    assert stored.closed_candidate_case == runtime.write.closed_candidate_case
    assert stored.canonical_alert_policy_document == runtime.write.canonical_alert_policy_document
    assert stored.canonical_closed_case_document == runtime.write.canonical_closed_case_document
    assert stored.execution_scope_authority_id == runtime.scope.execution_scope_authority_id
    assert stored.pending_commitment_authority_id == (
        runtime.pending.pending_commitment_authority_id
    )
    assert stored.case_audit_sequence == head.sequence == 0
    assert stored.case_audit_entry_hash == head.entry_hash
    assert head.run_revision == 1
    assert _counts(runtime.database)[:6] == (1, 0, 0, 1, 1, 0)
    with sqlite3.connect(runtime.database) as connection:
        columns = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({_TABLE})"))
        row = connection.execute(
            f"""
            SELECT route, pre_policy_route, status, case_revision,
                   case_json, alert_policy_json
            FROM {_TABLE}
            """
        ).fetchone()
        audit = connection.execute(
            """
            SELECT action, object_kind, object_id, before_sha256, after_sha256
            FROM audit_entries
            """
        ).fetchone()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert all("ready" not in column.lower() for column in columns)
    assert row == (
        "ALERT_POLICY_CLOSED",
        runtime.pending.pre_policy_route.value,
        "CLOSED",
        1,
        runtime.write.canonical_closed_case_document,
        runtime.write.canonical_alert_policy_document,
    )
    assert audit == (
        "CASE_CREATED",
        "CASE",
        runtime.write.closed_candidate_case.case_id,
        None,
        stored.closed_candidate_case_document_sha256,
    )


def test_exact_closed_candidate_retry_is_a_zero_write_success(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    runtime.repository.publish_closed_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )
    before = _counts(runtime.database)
    stored_before = runtime.repository.load_stored_closed_candidate(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )

    runtime.repository.publish_closed_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )

    assert _counts(runtime.database) == before
    assert (
        runtime.repository.load_stored_closed_candidate(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )
        == stored_before
    )


@pytest.mark.parametrize(
    "fault_phase",
    (
        "m6_replay_locked_closed_policy_candidate.after_audit",
        "m6_replay_locked_closed_policy_candidate.after_candidate",
        "m6_replay_locked_closed_policy_candidate.before_commit",
    ),
)
def test_fault_at_each_atomic_boundary_rolls_back_policy_case_audit_and_head(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    def fault(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("synthetic CLOSED-policy persistence fault")

    runtime = _runtime(tmp_path, fault_injector=fault)

    with pytest.raises(M6ReplayLockedClosedCandidateError) as raised:
        runtime.repository.publish_closed_candidate(
            runtime.scope,
            runtime.pending,
            runtime.write,
        )

    assert raised.value.reason_code == (M6ReplayLockedClosedCandidateFailureCode.STORAGE_REJECTED)
    assert _counts(runtime.database)[:6] == (0, 0, 0, 0, 0, -1)


def test_recovery_rebuilds_observation_from_durable_bodies_without_policy_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path)
    runtime.repository.publish_closed_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )
    stored = runtime.repository.load_stored_closed_candidate(
        runtime.scope.candidate_run_id,
        runtime.pending.sample_id,
    )
    pre_policy_snapshot = _snapshot(
        runtime.write.transient_ready_case,
        revision=1,
    ).model_copy(update={"sample_id": runtime.pending.sample_id})

    def forbid_policy_execution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("recovery must not execute alert policy")

    monkeypatch.setattr(
        "labcourt.application.m6_replay_locked_alert_policy."
        "build_m6_replay_locked_closed_policy_candidate",
        forbid_policy_execution,
    )

    observed = build_m6_replay_locked_closed_candidate_observation(
        execution_scope=runtime.scope,
        pending_commitment=runtime.pending,
        stored_candidate=stored,
        pre_policy_candidate_snapshot=pre_policy_snapshot,
    )

    binding = observed.closed_candidate_binding
    assert binding.transient_ready_case == runtime.write.transient_ready_case
    assert binding.candidate_alert_policy == runtime.write.candidate_alert_policy
    assert binding.closed_candidate_case == runtime.write.closed_candidate_case
    assert binding.persisted_candidate_case.case_audit_entry_hash == (stored.case_audit_entry_hash)
    assert observed.candidate_snapshot == runtime.expected_observation.candidate_snapshot


def test_unknown_run_and_corrupt_stored_digest_are_typed_failures(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)

    with pytest.raises(M6ReplayLockedClosedCandidateError) as unknown_row:
        runtime.repository.load_stored_closed_candidate(
            "unknown-run",
            runtime.pending.sample_id,
        )
    with pytest.raises(M6ReplayLockedClosedCandidateError) as unknown_head:
        runtime.repository.load_closed_candidate_audit_head("unknown-run")

    assert unknown_row.value.reason_code == M6ReplayLockedClosedCandidateFailureCode.NOT_FOUND
    assert unknown_head.value.reason_code == M6ReplayLockedClosedCandidateFailureCode.NOT_FOUND

    runtime.repository.publish_closed_candidate(
        runtime.scope,
        runtime.pending,
        runtime.write,
    )
    with sqlite3.connect(runtime.database) as connection:
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_replay_locked_closed_policy_candidate_cases_no_update'
            """
        ).fetchone()
        assert trigger_sql is not None
        connection.execute("DROP TRIGGER m6_replay_locked_closed_policy_candidate_cases_no_update")
        connection.execute(
            f"UPDATE {_TABLE} SET case_document_sha256 = ?",
            ("f" * 64,),
        )
        connection.execute(str(trigger_sql[0]))

    with pytest.raises(M6ReplayLockedClosedCandidateError) as corrupt:
        runtime.repository.load_stored_closed_candidate(
            runtime.scope.candidate_run_id,
            runtime.pending.sample_id,
        )

    assert corrupt.value.reason_code == (
        M6ReplayLockedClosedCandidateFailureCode.STORED_AUTHORITY_INVALID
    )
