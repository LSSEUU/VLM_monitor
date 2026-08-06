from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from labcourt.adapters.storage._m6_snapshot_identity import (
    capture_m6_readonly_snapshot_identity,
)
from labcourt.adapters.storage.m6_replay_locked_closed_policy_execution_scope_store import (
    M6ReplayLockedClosedPolicyExecutionScopePublisher,
    ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore,
)
from labcourt.adapters.storage.m6_replay_locked_closed_policy_ledger import (
    FilesystemM6ReplayLockedClosedPolicyLedgerRepository,
)
from labcourt.adapters.storage.readonly_m6_replay_locked_closed_pre_policy_source import (
    ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository,
)
from labcourt.adapters.storage.readonly_m6_replay_locked_policy_source import (
    ReadonlyM6ReplayLockedAlertPolicySourceRepository,
)
from labcourt.adapters.storage.sqlite_m6_replay_locked_closed_policy_candidate import (
    SQLiteM6ReplayLockedClosedPolicyCandidateRepository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_replay_locked_closed_policy_execution_coordinator import (
    M6ReplayLockedClosedPolicyExecutionCoordinatorService,
)
from labcourt.application.m6_replay_locked_closed_policy_m4_executor import (
    M6ReplayLockedClosedPolicyM4SampleExecutorService,
)
from labcourt.application.m6_replay_locked_closed_policy_routed_executor import (
    M6ReplayLockedClosedPolicyRoutedSampleExecutorService,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.ports.m6_replay_locked_closed_policy_coordinator import (
    M6ReplayLockedClosedPolicyCoordinatorError,
    M6ReplayLockedClosedPolicyCoordinatorFailureCode,
)
from labcourt.ports.m6_replay_locked_closed_policy_ledger import (
    M6ReplayLockedClosedPolicyLedgerStatus,
)
from labcourt.ports.m6_replay_locked_closed_policy_sample_executor import (
    M6ReplayLockedClosedPolicySampleExecutorError,
    M6ReplayLockedClosedPolicySampleExecutorFailureCode,
)
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS
from tests.integration.test_m6_replay_locked_closed_policy_fast_e2e import (
    _CountingPolicySources,
    _CountingPrePolicySources,
    _document,
    _execution_cut,
)
from tests.integration.test_m6_replay_locked_closed_pre_policy_source_repository import (
    _published_m4_projection_source,
)


@dataclass(slots=True)
class _NeverFastExecutor:
    calls: int = 0

    def execute_sample(
        self,
        _scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        _pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        _closure: M6ReplayInputClosureAuthority,
    ) -> None:
        self.calls += 1
        raise M6ReplayLockedClosedPolicySampleExecutorError(
            M6ReplayLockedClosedPolicySampleExecutorFailureCode.UNSUPPORTED_ROUTE
        )


@dataclass(slots=True)
class _FailAfterCandidateCommit:
    inner: M6ReplayLockedClosedPolicyRoutedSampleExecutorService
    calls: int = 0
    fail_once: bool = True

    def execute_sample(
        self,
        scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        closure: M6ReplayInputClosureAuthority,
    ) -> None:
        self.calls += 1
        self.inner.execute_sample(scope, pending, closure)
        if self.fail_once:
            self.fail_once = False
            raise M6ReplayLockedClosedPolicySampleExecutorError(
                M6ReplayLockedClosedPolicySampleExecutorFailureCode.STORAGE_REJECTED
            )


def test_real_m4_closed_policy_recovers_after_candidate_commit_and_seals_read_only(
    tmp_path: Path,
) -> None:
    source_fixture_root = tmp_path / "source"
    source_fixture_root.mkdir()
    (
        source_database,
        source_root,
        config,
        _closure,
        stored_catalog,
        _cut,
        scope,
        pending,
    ) = _execution_cut(
        source_fixture_root,
        published_source=_published_m4_projection_source,
        candidate_run_id="m6-closed-policy-m4-candidate",
        supported_pre_policy_routes=(
            M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE,
        ),
    )
    assert pending.pre_policy_route is (
        M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    )
    source_identity_before = capture_m6_readonly_snapshot_identity(source_database)
    policy_sources = _CountingPolicySources(
        ReadonlyM6ReplayLockedAlertPolicySourceRepository(
            source_database,
            store_root=source_root,
            config=config,
        )
    )
    pre_policy_sources = _CountingPrePolicySources(
        ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository(
            source_database,
            store_root=source_root,
            config=config,
        )
    )

    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir()
    M6ReplayLockedClosedPolicyExecutionScopePublisher(ledger_root).publish(
        scope,
        _document(scope),
    )
    ledger = FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        ledger_root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(ledger_root),
    )
    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    candidate_database = candidate_root / "labcourt.sqlite3"
    assert MigrationRunner(candidate_database, BUSY_TIMEOUT_MS).apply_all() == tuple(range(1, 19))
    SQLiteEvidenceRepository(candidate_database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.pre_policy_execution_scope.locked_manifest,
    )
    candidates = SQLiteM6ReplayLockedClosedPolicyCandidateRepository(
        candidate_database,
        BUSY_TIMEOUT_MS,
    )
    never_fast = _NeverFastExecutor()
    routed = M6ReplayLockedClosedPolicyRoutedSampleExecutorService(
        fast_executor=never_fast,
        m4_executor=M6ReplayLockedClosedPolicyM4SampleExecutorService(
            pre_policy_source_provider=pre_policy_sources,
            candidate_publisher=candidates,
        ),
    )
    crash_once = _FailAfterCandidateCommit(routed)
    coordinator = M6ReplayLockedClosedPolicyExecutionCoordinatorService(
        ledger_repository=ledger,
        policy_source_provider=policy_sources,
        pre_policy_source_provider=pre_policy_sources,
        sample_executor=crash_once,
        stored_candidate_provider=candidates,
        candidate_audit_head_provider=candidates,
    )

    with pytest.raises(M6ReplayLockedClosedPolicyCoordinatorError) as crashed:
        coordinator.run_to_terminal(scope, stored_catalog)

    assert crashed.value.reason_code is (
        M6ReplayLockedClosedPolicyCoordinatorFailureCode.STORAGE_REJECTED
    )
    assert ledger.resume(scope).status is M6ReplayLockedClosedPolicyLedgerStatus.PENDING
    assert crash_once.calls == 1
    assert never_fast.calls == 0
    assert (
        candidates.load_stored_closed_candidate(
            scope.candidate_run_id,
            pending.sample_id,
        ).pre_policy_route
        is M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    )

    seal = coordinator.run_to_terminal(scope, stored_catalog)
    source_reads = (policy_sources.read_count, pre_policy_sources.read_count)
    restarted_ledger = FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        ledger_root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(ledger_root),
    )
    exact_retry = M6ReplayLockedClosedPolicyExecutionCoordinatorService(
        ledger_repository=restarted_ledger,
        policy_source_provider=policy_sources,
        pre_policy_source_provider=pre_policy_sources,
        sample_executor=crash_once,
        stored_candidate_provider=candidates,
        candidate_audit_head_provider=candidates,
    ).run_to_terminal(scope, stored_catalog)

    assert exact_retry == seal
    assert restarted_ledger.resume(scope).status is (M6ReplayLockedClosedPolicyLedgerStatus.SEALED)
    assert source_reads == (3, 4)
    assert (policy_sources.read_count, pre_policy_sources.read_count) == source_reads
    assert crash_once.calls == 1
    assert never_fast.calls == 0
    assert seal.sample_execution_count == 1
    assert seal.sample_executions[0].pending_commitment.pre_policy_route is (
        M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE
    )
    assert seal.sample_executions[0].candidate_semantic_case_hash == (
        seal.sample_executions[0].source_semantic_case_hash
    )
    assert seal.run_trap_seal.clean
    assert capture_m6_readonly_snapshot_identity(source_database) == source_identity_before

    with sqlite3.connect(candidate_database) as connection:
        counts = tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "m6_replay_locked_closed_policy_candidate_cases",
                "m6_replay_locked_candidate_cases",
                "m6_replay_locked_m4_candidate_cases",
                "cases",
                "alert_outbox",
                "alert_cooldowns",
            )
        )
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    assert counts == (1, 0, 0, 0, 0, 0)
    assert foreign_keys == []
