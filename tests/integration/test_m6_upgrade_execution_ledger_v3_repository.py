from __future__ import annotations

import sqlite3
import traceback
from pathlib import Path

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_execution_ledger_v3_codec as v3_codec
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    SQLiteM6UpgradeExecutionLedgerV2Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Status,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import _v2_inventory
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    _canonical_document,
)
from tests.integration.test_m6_upgrade_execution_ledger_v2_repository import (
    BUSY_TIMEOUT_MS,
    MutableExactSampleArtifactVerifier,
)
from tests.integration.test_m6_upgrade_pending_sample_commitment_repository import (
    _commitment_for_record,
    _no_case_bundle_for_entry,
)


def _assert_payload_free_failure(error: BaseException, *, forbidden: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert forbidden not in "".join(traceback.format_exception(error))
    repository_frames = []
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_code.co_filename.endswith(
            (
                "sqlite_m6_upgrade_execution_ledger_v3.py",
                "sqlite_m6_upgrade_pending_sample_commitment_v3.py",
            )
        ):
            repository_frames.append(current.tb_frame)
        current = current.tb_next
    assert repository_frames
    assert all("self" not in frame.f_locals for frame in repository_frames)


def _v3_pipeline() -> tuple[
    M6UpgradeExecutionScopeAuthority,
    tuple[M6UpgradeSampleExecutionObservationAuthorityV2, ...],
    tuple[M6UpgradeSampleExecutionRecordV2, ...],
    tuple[M6UpgradePendingSampleCommitmentAuthority, ...],
]:
    source = _v2_inventory()
    scope = source.execution_ledger.execution_scope
    observations: list[M6UpgradeSampleExecutionObservationAuthorityV2] = []
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    commitments: list[M6UpgradePendingSampleCommitmentAuthority] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for sequence, source_record in enumerate(source.execution_ledger.sample_executions):
        observation_v1, record_v1_bound, _commitment = _no_case_bundle_for_entry(
            scope,
            entry_index=sequence,
            previous_record_id=previous,
            source_record=source_record,
        )
        observation = M6UpgradeSampleExecutionObservationAuthorityV2(
            **observation_v1.model_dump(
                mode="python",
                exclude={"schema_version"},
                exclude_computed_fields=True,
            ),
            selected_case_audit_anchor=None,
        )
        record = record_v1_bound.model_copy(
            update={"observation_authority_id": observation.observation_authority_id}
        )
        commitment = _commitment_for_record(record)
        observations.append(observation)
        records.append(record)
        commitments.append(commitment)
        previous = record.sample_execution_record_id
    return scope, tuple(observations), tuple(records), tuple(commitments)


def test_v3_three_sample_pipeline_recovers_all_five_states_and_seals(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, observations, records, commitments = _v3_pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    verifier = MutableExactSampleArtifactVerifier(records)
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    observation_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitment_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert ledger.begin_execution(scope) == scope
    assert (
        ledger.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ).status
        == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION
    )

    for sequence, (observation, record, commitment) in enumerate(
        zip(observations, records, commitments, strict=True)
    ):
        assert observation_repository.append(observation) == observation
        assert observation_repository.append(observation) == observation
        ready_for_commitment = ledger.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        assert ready_for_commitment.status == (
            M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT
        )
        assert ready_for_commitment.pending_observation == observation

        assert commitment_repository.append(commitment) == commitment
        assert commitment_repository.append(commitment) == commitment
        assert (
            commitment_repository.load(
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
                sequence,
            )
            == commitment
        )
        ready_for_ledger = ledger.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        assert ready_for_ledger.status == (M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND)
        assert ready_for_ledger.pending_commitment == commitment

        assert ledger.append_committed_sample(commitment) == record
        assert ledger.append_committed_sample(commitment) == record
        assert (
            observation_repository.load(
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
                sequence,
            )
            == observation
        )
        resumed = ledger.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        expected_status = (
            M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL
            if sequence + 1 == len(records)
            else M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION
        )
        assert resumed.status == expected_status
        assert resumed.committed_sample_count == sequence + 1

    seal = ledger.seal(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert seal.sample_executions == records
    assert ledger.seal(scope.candidate_run_id, scope.execution_scope_authority_id) == seal
    assert ledger.load_sealed(scope.candidate_run_id, scope.execution_scope_authority_id) == seal
    resumed = ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert resumed.status == M6UpgradeExecutionLedgerV3Status.SEALED
    assert resumed.seal == seal
    assert commitment_repository.append(commitments[-1]) == commitments[-1]


def _initialize_first_pending_observation(
    database: Path,
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    tuple[M6UpgradeSampleExecutionRecordV2, ...],
    M6UpgradePendingSampleCommitmentAuthority,
]:
    scope, observations, records, commitments = _v3_pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS).begin_execution(scope)
    SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(observations[0])
    return scope, records, commitments[0]


def test_v3_begin_is_new_exact_conflict_and_protocol_isolated_without_child_scan(
    tmp_path: Path,
) -> None:
    v3_workspace = tmp_path / "v3"
    v3_workspace.mkdir()
    v3_database = v3_workspace / "labcourt.sqlite3"
    scope, _observations, records, _commitments = _v3_pipeline()
    MigrationRunner(v3_database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(v3_database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(v3_database, BUSY_TIMEOUT_MS)

    assert ledger.begin_execution(scope) == scope
    orphan_artifact = records[0].artifact_links[0].artifact
    with sqlite3.connect(v3_database) as connection:
        connection.row_factory = sqlite3.Row
        ledger._append_artifact(
            connection,
            run_id=scope.candidate_run_id,
            execution_scope_authority_id=scope.execution_scope_authority_id,
            artifact=orphan_artifact,
        )
    assert ledger.begin_execution(scope) == scope

    conflicting_component = scope.execution_component.model_copy(
        update={"version": f"{scope.execution_component.version}-conflict"}
    )
    _raw, component_sha256, component_size = _canonical_document(conflicting_component)
    conflicting_scope = scope.model_copy(
        update={
            "execution_component": conflicting_component,
            "execution_component_content_sha256": component_sha256,
            "execution_component_size_bytes": component_size,
        }
    )
    assert conflicting_scope.execution_scope_authority_id != scope.execution_scope_authority_id
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as conflict:
        ledger.begin_execution(conflicting_scope)
    assert conflict.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.SCOPE_CONFLICT
    _assert_payload_free_failure(conflict.value, forbidden=scope.candidate_run_id)

    v2_workspace = tmp_path / "v2"
    v2_workspace.mkdir()
    v2_database = v2_workspace / "labcourt.sqlite3"
    MigrationRunner(v2_database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(v2_database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    SQLiteM6UpgradeExecutionLedgerV2Repository(
        v2_database,
        BUSY_TIMEOUT_MS,
    ).begin_execution(scope)
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as protocol_error:
        SQLiteM6UpgradeExecutionLedgerV3Repository(
            v2_database,
            BUSY_TIMEOUT_MS,
        ).begin_execution(scope)
    assert protocol_error.value.reason_code == (
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED
    )
    _assert_payload_free_failure(protocol_error.value, forbidden=scope.candidate_run_id)


def test_v3_begin_exact_retry_checks_scope_budget_before_raw_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observations, _records, _commitments = _v3_pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    ).begin_execution(scope)
    with sqlite3.connect(database) as connection:
        stored_size = connection.execute(
            """
            SELECT size_bytes FROM m6_upgrade_execution_scopes
            WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()[0]
    assert isinstance(stored_size, int) and stored_size > 1
    monkeypatch.setattr(v3_codec, "MAX_M6_UPGRADE_SCOPE_BYTES", stored_size - 1)

    def raw_parser_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scope raw parser ran before byte-budget preflight")

    monkeypatch.setattr(v3_codec, "scope_from_row", raw_parser_must_not_run)
    statements: list[str] = []
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)
    original_connection = ledger._connection

    def traced_connection() -> sqlite3.Connection:
        connection = original_connection()
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(ledger, "_connection", traced_connection)
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as rejected:
        ledger.begin_execution(scope)
    assert rejected.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE
    _assert_payload_free_failure(rejected.value, forbidden=scope.candidate_run_id)
    normalized = tuple(" ".join(statement.upper().split()) for statement in statements)
    assert not any(
        "SELECT * FROM M6_UPGRADE_EXECUTION_SCOPES" in statement for statement in normalized
    )


def test_v3_pending_begin_retry_preflights_scope_before_raw_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _observations, _records, _commitments = _v3_pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert repository.begin_execution(scope) == scope
    with sqlite3.connect(database) as connection:
        stored_size = connection.execute(
            """
            SELECT size_bytes FROM m6_upgrade_execution_scopes
            WHERE run_id = ?
            """,
            (scope.candidate_run_id,),
        ).fetchone()[0]
    assert isinstance(stored_size, int) and stored_size > 1
    monkeypatch.setattr(v3_codec, "MAX_M6_UPGRADE_SCOPE_BYTES", stored_size - 1)

    def raw_parser_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scope raw parser ran before byte-budget preflight")

    monkeypatch.setattr(v3_codec, "scope_from_row", raw_parser_must_not_run)
    statements: list[str] = []
    original_connection = repository._connection

    def traced_connection() -> sqlite3.Connection:
        connection = original_connection()
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(repository, "_connection", traced_connection)
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as rejected:
        repository.begin_execution(scope)
    assert rejected.value.reason_code == (
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE
    )
    _assert_payload_free_failure(rejected.value, forbidden=scope.candidate_run_id)
    normalized = tuple(" ".join(statement.upper().split()) for statement in statements)
    assert not any(
        "SELECT * FROM M6_UPGRADE_EXECUTION_SCOPES" in statement for statement in normalized
    )


@pytest.mark.parametrize("fault_phase", ("append.after_insert", "append.before_commit"))
def test_v3_pending_commitment_faults_roll_back_and_retry(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    workspace = tmp_path / fault_phase.replace(".", "-")
    workspace.mkdir()
    database = workspace / "labcourt.sqlite3"
    scope, _records, commitment = _initialize_first_pending_observation(database)

    def fail_at(phase: str) -> None:
        if phase == f"m6_upgrade_pending_sample_commitment_v3.{fault_phase}":
            raise RuntimeError("simulated V3 pending commitment crash")

    failed = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=fail_at,
    )
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as rejected:
        failed.append(commitment)
    assert (
        rejected.value.reason_code == M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
    )
    _assert_payload_free_failure(
        rejected.value,
        forbidden="simulated V3 pending commitment crash",
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments"
        ).fetchone() == (0,)
    recovered = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    assert recovered.append(commitment) == commitment
    assert (
        recovered.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
        == commitment
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
def test_v3_ledger_append_faults_roll_back_refs_links_and_record(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    workspace = tmp_path / fault_phase.replace(".", "-")
    workspace.mkdir()
    database = workspace / "labcourt.sqlite3"
    _scope, records, commitment = _initialize_first_pending_observation(database)
    SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(commitment)

    def fail_at(phase: str) -> None:
        if phase == f"m6_upgrade_execution_ledger_v3.{fault_phase}":
            raise RuntimeError("simulated V3 ledger append crash")

    failed = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
        fault_injector=fail_at,
    )
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as rejected:
        failed.append_committed_sample(commitment)
    assert rejected.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
    _assert_payload_free_failure(
        rejected.value,
        forbidden="simulated V3 ledger append crash",
    )
    with sqlite3.connect(database) as connection:
        assert tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "m6_upgrade_physical_artifact_refs",
                "m6_upgrade_sample_artifact_links",
                "m6_upgrade_sample_executions",
            )
        ) == (0, 0, 0)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments"
        ).fetchone() == (1,)
    recovered = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
    )
    assert recovered.append_committed_sample(commitment) == records[0]


def test_v3_verifier_cannot_forge_reason_code_and_failed_append_is_retryable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, records, commitment = _initialize_first_pending_observation(database)
    SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    ).append(commitment)

    class ForgeOnceVerifier:
        def __init__(self) -> None:
            self.calls = 0

        def verify_m6_upgrade_sample_artifacts(
            self,
            record: M6UpgradeSampleExecutionRecord,
        ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
            self.calls += 1
            if self.calls == 1:
                raise M6UpgradeExecutionLedgerV3Error(
                    M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED
                )
            return tuple(link.artifact for link in record.artifact_links)

    verifier = ForgeOnceVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as rejected:
        ledger.append_committed_sample(commitment)
    assert rejected.value.reason_code == (
        M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED
    )
    _assert_payload_free_failure(rejected.value, forbidden="LEDGER_SEALED")
    assert scope.candidate_run_id not in "".join(traceback.format_exception(rejected.value))
    with sqlite3.connect(database) as connection:
        assert tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "m6_upgrade_physical_artifact_refs",
                "m6_upgrade_sample_artifact_links",
                "m6_upgrade_sample_executions",
            )
        ) == (0, 0, 0)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments"
        ).fetchone() == (1,)
    assert (
        ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id).status
        == M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND
    )
    assert ledger.append_committed_sample(commitment) == records[0]
    assert verifier.calls == 2


def test_v3_pending_and_ledger_writer_locks_are_typed_and_retryable(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _scope, records, commitment = _initialize_first_pending_observation(database)
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(database, 1)
    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(M6UpgradePendingSampleCommitmentError) as pending_error:
            pending.append(commitment)
    finally:
        blocker.rollback()
        blocker.close()
    assert (
        pending_error.value.reason_code
        == M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
    )
    _assert_payload_free_failure(pending_error.value, forbidden="database is locked")
    assert pending.append(commitment) == commitment

    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        1,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
    )
    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(M6UpgradeExecutionLedgerV3Error) as ledger_error:
            ledger.append_committed_sample(commitment)
    finally:
        blocker.rollback()
        blocker.close()
    assert ledger_error.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
    _assert_payload_free_failure(ledger_error.value, forbidden="database is locked")
    assert ledger.append_committed_sample(commitment) == records[0]


def test_v3_state_rejects_orphan_physical_refs_and_pending_record_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    orphan_workspace = tmp_path / "orphan"
    orphan_workspace.mkdir()
    orphan_database = orphan_workspace / "labcourt.sqlite3"
    scope, records, commitment = _initialize_first_pending_observation(orphan_database)
    pending = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        orphan_database,
        BUSY_TIMEOUT_MS,
    )
    pending.append(commitment)
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        orphan_database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=MutableExactSampleArtifactVerifier(records),
    )
    ledger.append_committed_sample(commitment)
    first_ref_ids = {link.artifact.artifact_ref_id for link in records[0].artifact_links}
    orphan_artifact = next(
        link.artifact
        for link in records[1].artifact_links
        if link.artifact.artifact_ref_id not in first_ref_ids
    )
    with sqlite3.connect(orphan_database) as connection:
        connection.row_factory = sqlite3.Row
        ledger._append_artifact(
            connection,
            run_id=scope.candidate_run_id,
            execution_scope_authority_id=scope.execution_scope_authority_id,
            artifact=orphan_artifact,
        )
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as orphan_error:
        ledger.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert (
        orphan_error.value.reason_code
        == M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID
    )

    budget_workspace = tmp_path / "budget"
    budget_workspace.mkdir()
    budget_database = budget_workspace / "labcourt.sqlite3"
    budget_scope, _budget_records, budget_commitment = _initialize_first_pending_observation(
        budget_database
    )
    SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        budget_database,
        BUSY_TIMEOUT_MS,
    ).append(budget_commitment)
    with sqlite3.connect(budget_database) as connection:
        stored_size = connection.execute(
            """
            SELECT sample_execution_record_size_bytes
            FROM m6_upgrade_pending_sample_commitments
            WHERE run_id = ? AND ledger_sequence = 0
            """,
            (budget_scope.candidate_run_id,),
        ).fetchone()[0]
    assert isinstance(stored_size, int)
    monkeypatch.setattr(v3_codec, "MAX_M6_UPGRADE_PENDING_RECORD_BYTES", stored_size - 1)
    budget_ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        budget_database,
        BUSY_TIMEOUT_MS,
    )
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as budget_error:
        budget_ledger.resume(
            budget_scope.candidate_run_id,
            budget_scope.execution_scope_authority_id,
        )
    assert (
        budget_error.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE
    )


@pytest.mark.parametrize("fault_phase", ("seal.after_insert", "seal.before_commit"))
def test_v3_seal_faults_roll_back_and_exact_retry_recovers(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    workspace = tmp_path / fault_phase.replace(".", "-")
    workspace.mkdir()
    database = workspace / "labcourt.sqlite3"
    scope, observations, records, commitments = _v3_pipeline()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    verifier = MutableExactSampleArtifactVerifier(records)
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    ledger.begin_execution(scope)
    observation_repository = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitment_repository = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    for observation, commitment in zip(observations, commitments, strict=True):
        observation_repository.append(observation)
        commitment_repository.append(commitment)
        ledger.append_committed_sample(commitment)

    def fail_at(phase: str) -> None:
        if phase == f"m6_upgrade_execution_ledger_v3.{fault_phase}":
            raise RuntimeError("simulated V3 seal crash")

    failed = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=fail_at,
    )
    with pytest.raises(M6UpgradeExecutionLedgerV3Error) as rejected:
        failed.seal(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert rejected.value.reason_code == M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
    _assert_payload_free_failure(
        rejected.value,
        forbidden="simulated V3 seal crash",
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_execution_ledger_seals"
        ).fetchone() == (0,)
    recovered = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)
    seal = recovered.seal(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert seal.sample_executions == records
    assert recovered.seal(scope.candidate_run_id, scope.execution_scope_authority_id) == seal
