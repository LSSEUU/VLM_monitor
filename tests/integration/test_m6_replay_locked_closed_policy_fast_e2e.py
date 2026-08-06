from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

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
from labcourt.adapters.storage.m6_source_authority_store import (
    ReadonlyM6SourceAuthorityStore,
)
from labcourt.adapters.storage.readonly_m6_regression_source_scope import (
    ReadonlyM6RegressionSourceScopeRepository,
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
from labcourt.application.m6_regression_source_catalog import (
    build_m6_regression_source_catalog,
)
from labcourt.application.m6_replay_locked_closed_candidate_observation import (
    build_m6_replay_locked_closed_candidate_observation,
)
from labcourt.application.m6_replay_locked_closed_policy_execution import (
    build_m6_replay_locked_closed_policy_execution_scope,
    build_m6_replay_locked_closed_policy_execution_seal,
    build_m6_replay_locked_closed_policy_pending_commitment,
    build_m6_replay_locked_closed_policy_sample_record,
)
from labcourt.application.m6_replay_locked_closed_policy_execution_coordinator import (
    M6ReplayLockedClosedPolicyExecutionCoordinatorService,
)
from labcourt.application.m6_replay_locked_closed_policy_fast_executor import (
    M6ReplayLockedClosedPolicyFastSampleExecutorService,
)
from labcourt.application.m6_replay_locked_execution_scope import (
    build_m6_replay_locked_execution_scope,
)
from labcourt.application.m6_replay_locked_fast_terminal import (
    build_m6_replay_locked_closed_policy_fast_pre_policy_candidate,
)
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.application.m6_replay_locked_source_determinism import (
    prove_m6_replay_locked_closed_policy_source_determinism,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus, ReproducibilityMode
from labcourt.contracts.m6_regression import (
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionExecutionEntry,
    M6RegressionPolicyAuthority,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionComponentAuthority,
    M6ReplayLockedExecutionRoute,
)
from labcourt.ports.m6_regression_dataset import M6RegressionSealedSourceObservation
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_closed_policy_ledger import (
    M6ReplayLockedClosedPolicyLedgerStatus,
)
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyPrePolicySource,
)
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
)
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, RUN_ID
from tests.integration.test_m6_replay_locked_closed_pre_policy_source_repository import (
    _published_projection_source,
)


def _document(value: object) -> str:
    return canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]


@dataclass(slots=True)
class _CountingPolicySources:
    repository: ReadonlyM6ReplayLockedAlertPolicySourceRepository
    read_count: int = 0

    def load_alert_policy_source(
        self,
        closure: object,
    ) -> M6ReplayLockedAlertPolicySourceObservation:
        self.read_count += 1
        return self.repository.load_alert_policy_source(closure)  # type: ignore[arg-type]


@dataclass(slots=True)
class _CountingPrePolicySources:
    repository: ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository
    read_count: int = 0

    def load_closed_policy_pre_policy_source(
        self,
        closure: object,
        source_binding: object,
    ) -> M6ReplayLockedClosedPolicyPrePolicySource:
        self.read_count += 1
        return self.repository.load_closed_policy_pre_policy_source(  # type: ignore[arg-type]
            closure,
            source_binding,
        )


def _execution_cut(
    tmp_path: Path,
    *,
    published_source=_published_projection_source,  # type: ignore[no-untyped-def]
    candidate_run_id: str = "m6-closed-policy-fast-candidate",
    supported_pre_policy_routes: tuple[M6ReplayLockedExecutionRoute, ...] = (
        M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE,
    ),
):  # type: ignore[no-untyped-def]
    source_database, source_root, bundle, config = published_source(tmp_path)
    closure = bundle.replay_input_closure
    stored_source = ReadonlyM6SourceAuthorityStore(source_root).load(closure)
    source_scope = ReadonlyM6RegressionSourceScopeRepository(
        source_database,
        config=config,
    ).observe(
        RUN_ID,
        m5_validation_report=stored_source.source_validation_report,
        m5_validation_report_document=(stored_source.source_validation_report_document),
    )
    sealed_source = M6RegressionSealedSourceObservation(
        replay_input_closure=stored_source.replay_input_closure,
        replay_input_authority=stored_source.replay_input_authority,
        source_validation_report=stored_source.source_validation_report,
        source_case=stored_source.source_case,
        source_manifest=stored_source.source_manifest,
        source_seal=stored_source.seal,
        replay_input_closure_document=stored_source.replay_input_closure_document,
        replay_input_authority_document=stored_source.replay_input_authority_document,
        source_validation_report_document=(stored_source.source_validation_report_document),
        source_case_document=stored_source.source_case_document,
        source_manifest_document=stored_source.source_manifest_document,
        source_seal_document=_document(stored_source.seal),
    )
    catalog_bundle = build_m6_regression_source_catalog(
        run_scopes=(source_scope,),
        sealed_sources=(sealed_source,),
    )
    catalog_document = catalog_bundle.execution_source_catalog_document
    stored_catalog = M6StoredRegressionExecutionSourceCatalog(
        source_catalog=catalog_bundle.execution_source_catalog,
        canonical_document=catalog_document,
        content_sha256=catalog_bundle.execution_source_catalog_content_sha256,
        size_bytes=len(catalog_document.encode("utf-8")),
    )
    dataset = M6RegressionExecutionDatasetSnapshot(
        baseline_manifest_id=bundle.source_manifest.manifest_id,
        source_catalog_authority_id=(stored_catalog.source_catalog.source_catalog_authority_id),
        source_catalog_document_sha256=stored_catalog.content_sha256,
        entries=tuple(
            M6RegressionExecutionEntry(
                sample_id=item.sample_id,
                input_authority_id=item.input_authority_id,
                input_authority_document_sha256=(item.input_authority_document_sha256),
                replay_input_closure_authority_id=(
                    item.replay_input_closure.replay_input_closure_authority_id
                ),
                replay_input_closure_document_sha256=(
                    item.replay_input_closure.replay_input_closure_document_sha256
                ),
            )
            for item in stored_catalog.source_catalog.entries
        ),
    )
    command = M6RegressionRunCommand(
        mode=ReproducibilityMode.REPLAY_LOCKED,
        execution_dataset_snapshot_id=dataset.execution_dataset_snapshot_id,
        baseline_manifest_id=bundle.source_manifest.manifest_id,
        candidate_manifest_id=bundle.source_manifest.manifest_id,
        policy_authority=M6RegressionPolicyAuthority(
            config_sha256=config.config_sha256,
            policy_version="m6-replay-locked-closed-policy-v2",
            maximum_machine_flip_rate=0.05,
            gold_set_max_accuracy_drop=0.0,
        ),
    )
    pre_policy_component = M6ReplayLockedExecutionComponentAuthority(
        version="0.1.0",
        code_commit=bundle.source_manifest.code_commit,
        supported_routes=supported_pre_policy_routes,
    )
    pre_policy_scope = build_m6_replay_locked_execution_scope(
        candidate_run_id=candidate_run_id,
        command=command,
        execution_dataset=dataset,
        stored_source_catalog=stored_catalog,
        locked_manifest=bundle.source_manifest,
        locked_config=config,
        execution_component=pre_policy_component,
    )
    component = M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(
        version=pre_policy_component.version,
        code_commit=pre_policy_component.code_commit,
        pre_policy_component_authority_id=(pre_policy_component.component_authority_id),
        supported_pre_policy_routes=pre_policy_component.supported_routes,
    )
    scope = build_m6_replay_locked_closed_policy_execution_scope(
        pre_policy_execution_scope=pre_policy_scope,
        execution_component=component,
    )
    policy_observation = ReadonlyM6ReplayLockedAlertPolicySourceRepository(
        source_database,
        store_root=source_root,
        config=config,
    ).load_alert_policy_source(closure)
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=policy_observation)
    pending = build_m6_replay_locked_closed_policy_pending_commitment(
        execution_scope=scope,
        stored_source_catalog=stored_catalog,
        policy_causal_cut=cut,
        ledger_sequence=0,
        previous_ledger_entry_hash=AUDIT_GENESIS_HASH,
    )
    return (
        source_database,
        source_root,
        config,
        closure,
        stored_catalog,
        cut,
        scope,
        pending,
    )


def test_real_fast_closed_policy_replay_reaches_pending_record_and_seal(
    tmp_path: Path,
) -> None:
    (
        source_database,
        source_root,
        config,
        closure,
        stored_catalog,
        cut,
        scope,
        pending,
    ) = _execution_cut(tmp_path)
    source_identity_before = capture_m6_readonly_snapshot_identity(source_database)
    source_provider = ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository(
        source_database,
        store_root=source_root,
        config=config,
    )

    ledger_root = tmp_path / "closed-policy-ledger"
    ledger_root.mkdir()
    M6ReplayLockedClosedPolicyExecutionScopePublisher(ledger_root).publish(
        scope,
        _document(scope),
    )
    ledger = FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        ledger_root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(ledger_root),
    )
    pending_state = ledger.persist_pending(scope, pending, _document(pending))
    assert pending_state.status is M6ReplayLockedClosedPolicyLedgerStatus.PENDING

    candidate_root = tmp_path / "candidate-output"
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
    M6ReplayLockedClosedPolicyFastSampleExecutorService(
        pre_policy_source_provider=source_provider,
        candidate_publisher=candidates,
    ).execute_sample(scope, pending, closure)

    proof = prove_m6_replay_locked_closed_policy_source_determinism(
        execution_scope=scope,
        pending_commitment=pending,
        closure=closure,
        policy_causal_cut=cut,
        projection_provider=source_provider,
    )
    safe_source = source_provider.load_closed_policy_pre_policy_source(
        closure,
        pending.source_binding,
    )
    pre_policy_candidate = build_m6_replay_locked_closed_policy_fast_pre_policy_candidate(
        execution_scope=scope,
        pending_commitment=pending,
        source=safe_source,
    )
    stored_candidate = candidates.load_stored_closed_candidate(
        scope.candidate_run_id,
        pending.sample_id,
    )
    observation = build_m6_replay_locked_closed_candidate_observation(
        execution_scope=scope,
        pending_commitment=pending,
        stored_candidate=stored_candidate,
        pre_policy_candidate_snapshot=pre_policy_candidate.candidate_snapshot,
    )
    record = build_m6_replay_locked_closed_policy_sample_record(
        execution_scope=scope,
        stored_source_catalog=stored_catalog,
        pending_commitment=pending,
        source_determinism=proof,
        policy_causal_cut=cut,
        candidate_observation=observation,
    )
    ready_to_seal = ledger.append_record(scope, record, _document(record))
    assert ready_to_seal.status is M6ReplayLockedClosedPolicyLedgerStatus.READY_TO_SEAL
    head = candidates.load_closed_candidate_audit_head(scope.candidate_run_id)
    seal = build_m6_replay_locked_closed_policy_execution_seal(
        execution_scope=scope,
        sample_records=(record,),
        candidate_audit_head=head,
    )
    sealed = ledger.seal(scope, seal, _document(seal))
    restarted = FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        ledger_root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(ledger_root),
    ).resume(scope)

    assert sealed == restarted
    assert restarted.status is M6ReplayLockedClosedPolicyLedgerStatus.SEALED
    assert restarted.execution_seal == seal
    assert proof.first_source_snapshot_id == proof.second_source_snapshot_id
    assert proof.first_semantic_case_hash == proof.second_semantic_case_hash
    assert proof.first_source_snapshot_id != safe_source.source_snapshot.snapshot_id
    assert record.candidate_semantic_case_hash == record.source_semantic_case_hash
    assert observation.closed_candidate_binding.transient_ready_case == pre_policy_candidate.case
    assert observation.closed_candidate_binding.closed_candidate_case.status is CaseStatus.CLOSED
    assert observation.closed_candidate_binding.persisted_candidate_case.case_revision == 1
    assert head.run_revision == 1
    assert head.sequence == 0
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
        columns = tuple(
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(m6_replay_locked_closed_policy_candidate_cases)"
            )
        )
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    assert counts == (1, 0, 0, 0, 0, 0)
    assert all("ready" not in column.lower() for column in columns)
    assert foreign_keys == []


def test_real_fast_closed_policy_coordinator_recovers_and_retries_read_only(
    tmp_path: Path,
) -> None:
    (
        source_database,
        source_root,
        config,
        _closure,
        stored_catalog,
        _cut,
        scope,
        _pending,
    ) = _execution_cut(tmp_path)
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

    ledger_root = tmp_path / "coordinator-ledger"
    ledger_root.mkdir()
    M6ReplayLockedClosedPolicyExecutionScopePublisher(ledger_root).publish(
        scope,
        _document(scope),
    )
    ledger = FilesystemM6ReplayLockedClosedPolicyLedgerRepository(
        ledger_root,
        scope_provider=ReadonlyM6ReplayLockedClosedPolicyExecutionScopeStore(ledger_root),
    )
    candidate_root = tmp_path / "coordinator-candidate-output"
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
    executor = M6ReplayLockedClosedPolicyFastSampleExecutorService(
        pre_policy_source_provider=pre_policy_sources,
        candidate_publisher=candidates,
    )
    coordinator = M6ReplayLockedClosedPolicyExecutionCoordinatorService(
        ledger_repository=ledger,
        policy_source_provider=policy_sources,
        pre_policy_source_provider=pre_policy_sources,
        sample_executor=executor,
        stored_candidate_provider=candidates,
        candidate_audit_head_provider=candidates,
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
        sample_executor=executor,
        stored_candidate_provider=candidates,
        candidate_audit_head_provider=candidates,
    ).run_to_terminal(scope, stored_catalog)

    assert exact_retry == seal
    assert restarted_ledger.resume(scope).status is (M6ReplayLockedClosedPolicyLedgerStatus.SEALED)
    assert source_reads == (2, 4)
    assert (policy_sources.read_count, pre_policy_sources.read_count) == source_reads
    assert seal.sample_execution_count == 1
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
        columns = tuple(
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(m6_replay_locked_closed_policy_candidate_cases)"
            )
        )
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    assert counts == (1, 0, 0, 0, 0, 0)
    assert all("ready" not in column.lower() for column in columns)
    assert foreign_keys == []
