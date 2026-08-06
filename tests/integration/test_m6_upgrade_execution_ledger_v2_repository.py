from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.storage import sqlite_m6_upgrade_execution_ledger_v2 as v2_repository
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    SQLiteM6UpgradeExecutionLedgerV2Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation import (
    SQLiteM6UpgradeExecutionObservationRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment import (
    SQLiteM6UpgradePendingSampleCommitmentRepository,
)
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, SQLiteEvidenceRepository
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeSampleExecutionObservationAuthority,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
    M6UpgradeExecutionLedgerV2Status,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import _v2_inventory
from tests.integration.test_m6_upgrade_observation_backed_ledger_migration import (
    _insert_commitment,
)
from tests.integration.test_m6_upgrade_pending_sample_commitment_repository import (
    _commitment_for_record,
    _no_case_bundle_for_entry,
)

BUSY_TIMEOUT_MS = 2_000


def _pipeline() -> tuple[
    M6UpgradeExecutionScopeAuthority,
    tuple[M6UpgradeSampleExecutionObservationAuthority, ...],
    tuple[M6UpgradeSampleExecutionRecordV2, ...],
    tuple[M6UpgradePendingSampleCommitmentAuthority, ...],
]:
    source = _v2_inventory()
    scope = source.execution_ledger.execution_scope
    observations: list[M6UpgradeSampleExecutionObservationAuthority] = []
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    commitments: list[M6UpgradePendingSampleCommitmentAuthority] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for sequence, source_record in enumerate(source.execution_ledger.sample_executions):
        observation, record, commitment = _no_case_bundle_for_entry(
            scope,
            entry_index=sequence,
            previous_record_id=previous,
            source_record=source_record,
        )
        observations.append(observation)
        records.append(record)
        commitments.append(commitment)
        previous = record.sample_execution_record_id
    return scope, tuple(observations), tuple(records), tuple(commitments)


def _cross_container_cardinality_bundle() -> tuple[
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradePendingSampleCommitmentAuthority,
]:
    scope, _observations, records, _commitments = _pipeline()
    first = records[0]
    second = records[1]
    first_frame_link = next(
        link for link in first.artifact_links if link.artifact.kind.value == "FRAME"
    )
    second_frame_link = next(
        link for link in second.artifact_links if link.artifact.kind.value == "FRAME"
    )
    detection_link = next(
        link for link in first.artifact_links if link.artifact.kind.value == "DETECTION"
    )
    duplicate_detection = detection_link.artifact.model_copy(
        update={"container_id": second_frame_link.artifact.artifact_id}
    )
    linked = (
        (first_frame_link.usage, first_frame_link.artifact),
        (second_frame_link.usage, second_frame_link.artifact),
        (detection_link.usage, detection_link.artifact),
        (detection_link.usage, duplicate_detection),
    )
    links = tuple(
        M6UpgradeSampleArtifactLink(ordinal=index, usage=usage, artifact=artifact)
        for index, (usage, artifact) in enumerate(
            sorted(linked, key=lambda item: item[1].physical_key)
        )
    )
    observed = (
        (first_frame_link.usage, first_frame_link.artifact),
        (second_frame_link.usage, second_frame_link.artifact),
        (detection_link.usage, detection_link.artifact),
    )
    artifacts = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=artifact.source,
                    kind=artifact.kind,
                    artifact_id=artifact.artifact_id,
                    usage=usage,
                )
                for usage, artifact in observed
            ),
            key=lambda item: item.sort_key,
        )
    )
    observation = M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        ledger_sequence=0,
        outcome=first.outcome,
        candidate_case=None,
        artifacts=artifacts,
        model_calls=(),
    )
    record = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        outcome=first.outcome,
        candidate_case=None,
        artifact_links=links,
        ledger_sequence=0,
        previous_ledger_entry_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
        observation_authority_id=observation.observation_authority_id,
    )
    return observation, _commitment_for_record(record)


class MutableExactSampleArtifactVerifier:
    def __init__(self, records: tuple[M6UpgradeSampleExecutionRecordV2, ...]) -> None:
        self._closures = {
            record.sample_execution_record_id: tuple(
                link.artifact for link in record.artifact_links
            )
            for record in records
        }
        self.override: tuple[M6UpgradePhysicalArtifactRef, ...] | None = None
        self.calls: list[M6UpgradeSampleExecutionRecord] = []

    def verify_m6_upgrade_sample_artifacts(
        self,
        record: M6UpgradeSampleExecutionRecord,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        self.calls.append(record)
        if self.override is not None:
            return self.override
        return self._closures[record.sample_execution_record_id]


def _initialize(
    database: Path,
    *,
    verifier: MutableExactSampleArtifactVerifier | None,
    fault_injector: Callable[[str], None] | None = None,
    busy_timeout_ms: int = BUSY_TIMEOUT_MS,
) -> tuple[
    SQLiteM6UpgradeExecutionLedgerV2Repository,
    SQLiteM6UpgradePendingSampleCommitmentRepository,
    M6UpgradeExecutionScopeAuthority,
]:
    scope, _observations, _records, _commitments = _pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    ledger = SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        busy_timeout_ms,
        sample_artifact_verifier=verifier,
        fault_injector=fault_injector,
    )
    assert ledger.begin_execution(scope) == scope
    commitment_repository = SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    )
    return ledger, commitment_repository, scope


def _persist_pending(
    database: Path,
    commitment_repository: SQLiteM6UpgradePendingSampleCommitmentRepository,
    sequence: int,
) -> M6UpgradePendingSampleCommitmentAuthority:
    _scope, observations, _records, commitments = _pipeline()
    observation = observations[sequence]
    commitment = commitments[sequence]
    assert (
        SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(observation)
        == observation
    )
    assert commitment_repository.append(commitment) == commitment
    return commitment


def _assert_failure(
    expected: M6UpgradeExecutionLedgerV2FailureCode,
    operation: Callable[[], object],
) -> None:
    with pytest.raises(M6UpgradeExecutionLedgerV2Error) as rejected:
        operation()
    assert rejected.value.reason_code == expected


def _ledger_counts(database: Path) -> tuple[int, int, int]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "m6_upgrade_physical_artifact_refs",
                "m6_upgrade_sample_artifact_links",
                "m6_upgrade_sample_executions",
            )
        )  # type: ignore[return-value]


def test_three_sample_pipeline_exports_every_durable_state_and_seals(
    tmp_path: Path,
) -> None:
    expected_scope, observations, records, expected_commitments = _pipeline()
    verifier = MutableExactSampleArtifactVerifier(records)
    database = tmp_path / "labcourt.sqlite3"
    ledger, commitments, scope = _initialize(database, verifier=verifier)
    assert scope == expected_scope

    initial = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert initial.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION
    assert initial.committed_sample_count == 0
    assert initial.ledger_head_hash == M6_UPGRADE_LEDGER_GENESIS_HASH
    assert initial.next_execution_entry == scope.execution_dataset.entries[0]

    for sequence, expected_record in enumerate(records):
        assert (
            SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(
                observations[sequence]
            )
            == observations[sequence]
        )
        observed = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
        assert observed.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_COMMITMENT
        assert observed.pending_observation == observations[sequence]
        assert observed.pending_commitment is None

        commitment = expected_commitments[sequence]
        commitments.append(commitment)
        committed = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
        assert committed.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND
        assert committed.pending_observation == observations[sequence]
        assert committed.pending_commitment == commitment

        assert ledger.append_committed_sample(commitment) == expected_record
        next_state = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
        assert next_state.committed_sample_count == sequence + 1
        assert next_state.ledger_head_hash == expected_record.sample_execution_record_id
        if sequence + 1 == len(records):
            assert next_state.status == M6UpgradeExecutionLedgerV2Status.READY_TO_SEAL
            assert next_state.next_execution_entry is None
        else:
            assert next_state.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION
            assert next_state.next_execution_entry == scope.execution_dataset.entries[sequence + 1]

    seal = ledger.seal(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert seal.sample_executions == records
    assert seal.schema_version == "m6-upgrade-execution-ledger-seal-v2"
    assert ledger.seal(scope.candidate_run_id, scope.execution_scope_authority_id) == seal
    assert ledger.load_sealed(scope.candidate_run_id, scope.execution_scope_authority_id) == seal
    sealed = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert sealed.status == M6UpgradeExecutionLedgerV2Status.SEALED
    assert sealed.seal == seal
    assert verifier.calls == list(records)


def test_second_sample_consumes_the_exact_v2_chain_head(tmp_path: Path) -> None:
    _scope, _observations, records, _expected_commitments = _pipeline()
    verifier = MutableExactSampleArtifactVerifier(records)
    database = tmp_path / "labcourt.sqlite3"
    ledger, commitments, _scope = _initialize(database, verifier=verifier)

    first = _persist_pending(database, commitments, 0)
    assert ledger.append_committed_sample(first) == records[0]
    second = _persist_pending(database, commitments, 1)
    assert second.sample_execution_record.previous_ledger_entry_hash == (
        records[0].sample_execution_record_id
    )
    assert ledger.append_committed_sample(second) == records[1]
    assert verifier.calls == [records[0], records[1]]


def test_exact_committed_retry_after_seal_reverifies_physical_artifacts(
    tmp_path: Path,
) -> None:
    _scope, _observations, records, _expected_commitments = _pipeline()
    verifier = MutableExactSampleArtifactVerifier(records)
    database = tmp_path / "labcourt.sqlite3"
    ledger, commitments, scope = _initialize(database, verifier=verifier)
    persisted: list[M6UpgradePendingSampleCommitmentAuthority] = []
    for sequence in range(len(records)):
        commitment = _persist_pending(database, commitments, sequence)
        persisted.append(commitment)
        ledger.append_committed_sample(commitment)
    ledger.seal(scope.candidate_run_id, scope.execution_scope_authority_id)

    calls_before_retry = len(verifier.calls)
    assert ledger.append_committed_sample(persisted[0]) == records[0]
    assert len(verifier.calls) == calls_before_retry + 1
    assert verifier.calls[-1] == records[0]

    source = records[-1]
    unpersisted_record = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=source.execution_scope_authority_id,
        candidate_run_id=source.candidate_run_id,
        command_id=source.command_id,
        execution_dataset_snapshot_id=source.execution_dataset_snapshot_id,
        execution_entry=source.execution_entry,
        outcome=source.outcome,
        candidate_case=source.candidate_case,
        artifact_links=source.artifact_links,
        ledger_sequence=len(records),
        previous_ledger_entry_hash=source.sample_execution_record_id,
        observation_authority_id=source.observation_authority_id,
    )
    calls_before_new_write = len(verifier.calls)
    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.LEDGER_SEALED,
        lambda: ledger.append_committed_sample(_commitment_for_record(unpersisted_record)),
    )
    assert len(verifier.calls) == calls_before_new_write

    verifier.override = tuple(link.artifact for link in records[1].artifact_links)
    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED,
        lambda: ledger.append_committed_sample(persisted[0]),
    )


def test_different_commitment_for_the_same_sequence_conflicts_before_verifier(
    tmp_path: Path,
) -> None:
    _scope, _observations, records, _expected_commitments = _pipeline()
    record = records[0]
    verifier = MutableExactSampleArtifactVerifier(records)
    database = tmp_path / "labcourt.sqlite3"
    ledger, commitments, _scope = _initialize(database, verifier=verifier)
    _persist_pending(database, commitments, 0)

    changed_artifact = record.artifact_links[0].artifact.model_copy(
        update={"size_bytes": record.artifact_links[0].artifact.size_bytes + 1}
    )
    changed_links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=link.ordinal,
            usage=link.usage,
            artifact=changed_artifact if link.ordinal == 0 else link.artifact,
        )
        for link in record.artifact_links
    )
    changed_commitment = _commitment_for_record(
        M6UpgradeSampleExecutionRecordV2(
            execution_scope_authority_id=record.execution_scope_authority_id,
            candidate_run_id=record.candidate_run_id,
            command_id=record.command_id,
            execution_dataset_snapshot_id=record.execution_dataset_snapshot_id,
            execution_entry=record.execution_entry,
            outcome=record.outcome,
            candidate_case=record.candidate_case,
            artifact_links=changed_links,
            ledger_sequence=record.ledger_sequence,
            previous_ledger_entry_hash=record.previous_ledger_entry_hash,
            observation_authority_id=record.observation_authority_id,
        )
    )

    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.COMMITMENT_CONFLICT,
        lambda: ledger.append_committed_sample(changed_commitment),
    )
    assert verifier.calls == []
    assert _ledger_counts(database)[2] == 0


def test_missing_verifier_and_physical_drift_fail_without_ledger_writes(
    tmp_path: Path,
) -> None:
    _scope, _observations, records, _expected_commitments = _pipeline()

    missing_database = tmp_path / "missing" / "labcourt.sqlite3"
    missing_database.parent.mkdir()
    missing, missing_commitments, _scope = _initialize(missing_database, verifier=None)
    missing_commitment = _persist_pending(missing_database, missing_commitments, 0)
    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED,
        lambda: missing.append_committed_sample(missing_commitment),
    )
    assert _ledger_counts(missing_database) == (0, 0, 0)

    drift_database = tmp_path / "drift" / "labcourt.sqlite3"
    drift_database.parent.mkdir()
    verifier = MutableExactSampleArtifactVerifier(records)
    drift, drift_commitments, _scope = _initialize(drift_database, verifier=verifier)
    drift_commitment = _persist_pending(drift_database, drift_commitments, 0)
    verifier.override = tuple(link.artifact for link in records[1].artifact_links)
    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED,
        lambda: drift.append_committed_sample(drift_commitment),
    )
    assert _ledger_counts(drift_database) == (0, 0, 0)


def test_resume_rejects_normalized_observation_tamper(tmp_path: Path) -> None:
    _pipeline_scope, observations, records, _expected_commitments = _pipeline()
    database = tmp_path / "labcourt.sqlite3"
    ledger, _commitments, scope = _initialize(
        database,
        verifier=MutableExactSampleArtifactVerifier(records),
    )
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(observations[0])
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            DROP TRIGGER m6_upgrade_sample_execution_observations_no_update;
            CREATE TRIGGER m6_upgrade_sample_execution_observations_no_update
            BEFORE UPDATE ON m6_upgrade_sample_execution_observations
            BEGIN
                SELECT 1;
            END;
            """
        )
        connection.execute(
            """
            UPDATE m6_upgrade_sample_execution_observations
            SET command_id = ? WHERE run_id = ? AND ledger_sequence = 0
            """,
            ("f" * 64, scope.candidate_run_id),
        )

    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID,
        lambda: ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id),
    )


@pytest.mark.parametrize(
    "fault_phase",
    (
        "append_committed_sample.after_refs",
        "append_committed_sample.after_links",
        "append_committed_sample.after_sample",
        "append_committed_sample.before_commit",
    ),
)
def test_append_fault_rolls_back_refs_links_and_sample_but_keeps_commitment(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    _pipeline_scope, _observations, records, _expected_commitments = _pipeline()

    def fail_at(phase: str) -> None:
        if phase == f"m6_upgrade_execution_ledger_v2.{fault_phase}":
            raise RuntimeError("simulated V2 ledger crash")

    database = tmp_path / "labcourt.sqlite3"
    verifier = MutableExactSampleArtifactVerifier(records)
    ledger, commitments, scope = _initialize(
        database,
        verifier=verifier,
        fault_injector=fail_at,
    )
    commitment = _persist_pending(database, commitments, 0)

    with pytest.raises(RuntimeError, match="simulated V2 ledger crash"):
        ledger.append_committed_sample(commitment)
    assert _ledger_counts(database) == (0, 0, 0)

    recovered = SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    state = recovered.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert state.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND
    assert state.pending_commitment == commitment
    assert recovered.append_committed_sample(commitment) == (records[0])


def test_writer_lock_is_typed_and_retryable(tmp_path: Path) -> None:
    _pipeline_scope, _observations, records, _expected_commitments = _pipeline()
    database = tmp_path / "labcourt.sqlite3"
    verifier = MutableExactSampleArtifactVerifier(records)
    ledger, commitments, _scope = _initialize(database, verifier=verifier)
    commitment = _persist_pending(database, commitments, 0)
    locked = SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        1,
        sample_artifact_verifier=verifier,
    )
    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED,
            lambda: locked.append_committed_sample(commitment),
        )
    finally:
        blocker.rollback()
        blocker.close()

    assert ledger.append_committed_sample(commitment) == (records[0])


def test_incomplete_and_unsealed_operations_are_typed(tmp_path: Path) -> None:
    _pipeline_scope, _observations, records, _expected_commitments = _pipeline()
    database = tmp_path / "labcourt.sqlite3"
    ledger, _commitments, scope = _initialize(
        database,
        verifier=MutableExactSampleArtifactVerifier(records),
    )

    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.LEDGER_INCOMPLETE,
        lambda: ledger.seal(scope.candidate_run_id, scope.execution_scope_authority_id),
    )
    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.LEDGER_NOT_SEALED,
        lambda: ledger.load_sealed(scope.candidate_run_id, scope.execution_scope_authority_id),
    )


def test_constructor_forwards_the_custom_clock_as_a_clock(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observations, records, _commitments = _pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )

    def fixed_clock() -> datetime:
        return datetime(2026, 8, 3, 12, 0, tzinfo=UTC)

    repository = SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=fixed_clock,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
    )

    assert repository._clock is fixed_clock
    assert repository.begin_execution(scope) == scope


def test_observation_aggregate_budget_fails_before_any_raw_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scope, observations, records, _commitments = _pipeline()
    database = tmp_path / "labcourt.sqlite3"
    ledger, _commitment_repository, scope = _initialize(
        database,
        verifier=MutableExactSampleArtifactVerifier(records),
    )
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(observations[0])
    with sqlite3.connect(database) as connection:
        stored_bytes = int(
            connection.execute(
                """
                SELECT SUM(size_bytes) FROM m6_upgrade_sample_execution_observations
                WHERE run_id = ?
                """,
                (scope.candidate_run_id,),
            ).fetchone()[0]
        )
    assert stored_bytes > 1
    monkeypatch.setattr(
        v2_repository,
        "MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES",
        stored_bytes - 1,
    )

    def raw_parser_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("observation raw parser ran before aggregate byte preflight")

    monkeypatch.setattr(v2_repository, "observation_from_connection", raw_parser_must_not_run)
    _assert_failure(
        M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE,
        lambda: ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id),
    )


def test_cross_container_logical_duplicate_is_rejected_by_resume_and_append(
    tmp_path: Path,
) -> None:
    _scope, _observations, records, _commitments = _pipeline()
    database = tmp_path / "labcourt.sqlite3"
    verifier = MutableExactSampleArtifactVerifier(records)
    ledger, _commitment_repository, scope = _initialize(database, verifier=verifier)
    observation, commitment = _cross_container_cardinality_bundle()
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(observation)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master WHERE type = 'trigger'
              AND name = 'm6_upgrade_pending_sample_commitments_validate'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("DROP TRIGGER m6_upgrade_pending_sample_commitments_validate")
        _insert_commitment(connection, commitment)
        connection.execute(str(trigger[0]))

    operations = (
        lambda: ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id),
        lambda: ledger.append_committed_sample(commitment),
    )
    for operation in operations:
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID,
            operation,
        )
    assert verifier.calls == []
    assert _ledger_counts(database) == (0, 0, 0)
