from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage import (
    sqlite_m6_upgrade_execution_observation as observation_repository_module,
)
from labcourt.adapters.storage import (
    sqlite_m6_upgrade_pending_sample_commitment as commitment_repository_module,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_execution_observation_codec import (
    MAX_M6_UPGRADE_OBSERVATION_BYTES,
    observation_document,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger import (
    SQLiteM6UpgradeExecutionLedgerRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    SQLiteM6UpgradeExecutionLedgerV2Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation import (
    SQLiteM6UpgradeExecutionObservationRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment import (
    SQLiteM6UpgradePendingSampleCommitmentRepository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.storage.sqlite_schema import (
    M6_UPGRADE_EXECUTION_OBSERVATION_INDEXES,
    M6_UPGRADE_EXECUTION_OBSERVATION_TABLES,
    M6_UPGRADE_EXECUTION_OBSERVATION_TRIGGERS,
    m6_upgrade_ledger_installed,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
    M6UpgradeSampleExecutionObservationAuthority,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    _insert_link,
    _insert_ref,
    _insert_sample,
    _single_no_case_execution,
)
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
    _verifier,
)

BUSY_TIMEOUT_MS = 2_000


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _observation(
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    ledger_sequence: int = 0,
    entry_index: int | None = None,
) -> M6UpgradeSampleExecutionObservationAuthority:
    selected_index = ledger_sequence if entry_index is None else entry_index
    return M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[selected_index],
        ledger_sequence=ledger_sequence,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifacts=(
            M6UpgradeObservedArtifactIdentity(
                source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
                kind=M6UpgradePhysicalArtifactKind.FRAME,
                artifact_id=f"camera-observation:stream-observation:{selected_index}",
                usage=M6UpgradeArtifactUsage.CONSUMED,
            ),
        ),
        model_calls=(),
    )


def _v2_no_case_bundle(
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    ledger_sequence: int,
    previous_record_id: str,
) -> tuple[
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionRecordV2,
    M6UpgradePendingSampleCommitmentAuthority,
]:
    _source_scope, source_records = _scope_and_no_case_records()
    artifact = source_records[ledger_sequence].artifact_links[0].artifact
    observation = M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[ledger_sequence],
        ledger_sequence=ledger_sequence,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifacts=(
            M6UpgradeObservedArtifactIdentity(
                source=artifact.source,
                kind=artifact.kind,
                artifact_id=artifact.artifact_id,
                usage=M6UpgradeArtifactUsage.CONSUMED,
            ),
        ),
        model_calls=(),
    )
    record = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[ledger_sequence],
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifact_links=(
            M6UpgradeSampleArtifactLink(
                ordinal=0,
                usage=M6UpgradeArtifactUsage.CONSUMED,
                artifact=artifact,
            ),
        ),
        ledger_sequence=ledger_sequence,
        previous_ledger_entry_hash=previous_record_id,
        observation_authority_id=observation.observation_authority_id,
    )
    record_json = canonical_json(record.model_dump(mode="json"))
    commitment = M6UpgradePendingSampleCommitmentAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=ledger_sequence,
        observation_authority_id=observation.observation_authority_id,
        sample_execution_record=record,
        sample_execution_record_document_sha256=_sha(record_json),
        sample_execution_record_size_bytes=len(record_json.encode("utf-8")),
    )
    return observation, record, commitment


def _prepare(
    database: Path,
    *,
    scope: M6UpgradeExecutionScopeAuthority | None = None,
    fault_injector: Callable[[str], None] | None = None,
    busy_timeout_ms: int = BUSY_TIMEOUT_MS,
) -> tuple[
    SQLiteM6UpgradeExecutionObservationRepository,
    M6UpgradeExecutionScopeAuthority,
]:
    controlled_scope = scope or _inventory().execution_ledger.execution_scope
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        controlled_scope.candidate_run_id,
        controlled_scope.candidate_manifest,
    )
    repository = SQLiteM6UpgradeExecutionObservationRepository(
        database,
        busy_timeout_ms,
        fault_injector=fault_injector,
    )
    repository.begin_execution(controlled_scope)
    return repository, controlled_scope


def _table_counts(database: Path) -> tuple[int, int, int]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "m6_upgrade_observed_non_model_artifacts",
                "m6_upgrade_observed_model_calls",
                "m6_upgrade_sample_execution_observations",
            )
        )  # type: ignore[return-value]


def _insert_children(
    connection: sqlite3.Connection,
    observation: M6UpgradeSampleExecutionObservationAuthority,
) -> None:
    connection.executemany(
        """
        INSERT INTO m6_upgrade_observed_non_model_artifacts(
            run_id, observation_authority_id, ordinal,
            source, kind, artifact_id, usage
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            (
                observation.candidate_run_id,
                observation.observation_authority_id,
                ordinal,
                artifact.source.value,
                artifact.kind.value,
                artifact.artifact_id,
                artifact.usage.value,
            )
            for ordinal, artifact in enumerate(observation.artifacts)
        ),
    )
    connection.executemany(
        """
        INSERT INTO m6_upgrade_observed_model_calls(
            run_id, observation_authority_id, ordinal,
            request_id, layer, role, attempt_index,
            result_kind, provider_invoked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            (
                observation.candidate_run_id,
                observation.observation_authority_id,
                ordinal,
                call.request_id,
                call.layer.value,
                call.role.value,
                call.attempt_index,
                call.result_kind.value,
                int(call.provider_invoked),
            )
            for ordinal, call in enumerate(observation.model_calls)
        ),
    )


def _insert_parent(
    connection: sqlite3.Connection,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    *,
    raw: str | None = None,
) -> None:
    document = raw or canonical_json(observation.model_dump(mode="json"))
    candidate_case = observation.candidate_case
    connection.execute(
        """
        INSERT INTO m6_upgrade_sample_execution_observations(
            run_id, execution_scope_authority_id, ledger_sequence,
            observation_authority_id, command_id,
            execution_dataset_snapshot_id, execution_entry_id,
            sample_id, outcome, case_id, case_revision,
            case_document_sha256, case_audit_sequence,
            case_audit_entry_hash, artifact_count, model_call_count,
            observation_json, document_sha256, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            observation.candidate_run_id,
            observation.execution_scope_authority_id,
            observation.ledger_sequence,
            observation.observation_authority_id,
            observation.command_id,
            observation.execution_dataset_snapshot_id,
            observation.execution_entry.execution_entry_id,
            observation.execution_entry.sample_id,
            observation.outcome.value,
            candidate_case.case_id if candidate_case is not None else None,
            candidate_case.case_revision if candidate_case is not None else None,
            candidate_case.case_document_sha256 if candidate_case is not None else None,
            candidate_case.case_audit_sequence if candidate_case is not None else None,
            candidate_case.case_audit_entry_hash if candidate_case is not None else None,
            len(observation.artifacts),
            len(observation.model_calls),
            document,
            _sha(document),
            len(document.encode("utf-8")),
        ),
    )


def _rewrite_without_append_only_trigger(
    database: Path,
    *,
    trigger: str,
    statement: str,
    parameters: tuple[object, ...],
    ignore_checks: bool = False,
) -> None:
    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger,),
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute(f'DROP TRIGGER "{trigger}"')
        if ignore_checks:
            connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(statement, parameters)
        if ignore_checks:
            connection.execute("PRAGMA ignore_check_constraints = OFF")
        connection.execute(str(trigger_sql[0]))


def _replace_trigger_fragment_once(
    connection: sqlite3.Connection,
    *,
    trigger_name: str,
    expected: str,
    replacement: str,
) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
        (trigger_name,),
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    trigger_sql = str(row[0]).replace("\r\n", "\n")
    assert trigger_sql.count(expected) == 1
    connection.execute(f'DROP TRIGGER "{trigger_name}"')
    connection.execute(trigger_sql.replace(expected, replacement, 1))


def test_fresh_migration_registers_every_observation_security_object(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()

    expected = {
        *(("table", name) for name in M6_UPGRADE_EXECUTION_OBSERVATION_TABLES),
        *(("index", name) for name in M6_UPGRADE_EXECUTION_OBSERVATION_INDEXES),
        *(("trigger", name) for name in M6_UPGRADE_EXECUTION_OBSERVATION_TRIGGERS),
        *(
            ("trigger", f"{table}_{operation}")
            for table in M6_UPGRADE_EXECUTION_OBSERVATION_TABLES
            for operation in ("no_replace", "no_update", "no_delete")
        ),
    }
    with sqlite3.connect(database) as connection:
        observed = {
            (str(row[0]), str(row[1]))
            for row in connection.execute("SELECT type, name FROM sqlite_master")
        }
        assert expected <= observed
        assert m6_upgrade_ledger_installed(connection)


@pytest.mark.parametrize(
    ("object_type", "object_name"),
    (
        ("table", "m6_upgrade_observed_model_calls"),
        ("index", "uq_m6_upgrade_execution_observation_id"),
        ("trigger", "m6_upgrade_sample_execution_observations_validate"),
        ("trigger", "m6_upgrade_observed_non_model_artifacts_no_update"),
    ),
)
def test_installation_check_rejects_a_missing_observation_object(
    tmp_path: Path,
    object_type: str,
    object_name: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    with sqlite3.connect(database) as connection:
        connection.execute(f'DROP {object_type.upper()} "{object_name}"')
        assert not m6_upgrade_ledger_installed(connection)


def test_append_load_and_exact_pending_retry_are_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    observation = _observation(scope)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT protocol_version FROM m6_upgrade_execution_ledger_protocols WHERE run_id = ?",
            (scope.candidate_run_id,),
        ).fetchone() == ("v2",)

    assert repository.append(observation) == observation
    assert (
        repository.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
        == observation
    )
    assert repository.append(observation) == observation
    assert _table_counts(database) == (1, 0, 1)


def test_new_observation_is_projected_into_the_global_inventory_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    observation = _observation(scope)
    _raw, _sha256, size_bytes = observation_document(observation)
    assert size_bytes > 1
    monkeypatch.setattr(
        observation_repository_module,
        "MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES",
        size_bytes - 1,
    )

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(observation)

    assert rejected.value.reason_code == M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE
    assert _table_counts(database) == (0, 0, 0)


def test_scope_is_size_preflighted_before_raw_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    monkeypatch.setattr(observation_repository_module, "MAX_M6_UPGRADE_SCOPE_BYTES", 1)

    def forbidden_parse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("oversized scope reached Pydantic")

    monkeypatch.setattr(
        M6UpgradeExecutionScopeAuthority,
        "model_validate_json",
        forbidden_parse,
    )
    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(_observation(scope))

    assert rejected.value.reason_code == M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE


def test_exact_retry_preflights_global_observation_bytes_before_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    observation = _observation(scope)
    repository.append(observation)
    _raw, _sha256, size_bytes = observation_document(observation)
    monkeypatch.setattr(
        commitment_repository_module,
        "MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES",
        size_bytes - 1,
    )

    def forbidden_parse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("oversized observation inventory reached Pydantic")

    monkeypatch.setattr(
        M6UpgradeSampleExecutionObservationAuthority,
        "model_validate_json",
        forbidden_parse,
    )
    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(observation)

    assert rejected.value.reason_code == M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE


@pytest.mark.parametrize(
    ("table", "trigger_name"),
    (
        (
            "m6_upgrade_sample_executions",
            "m6_upgrade_sample_executions_no_delete",
        ),
        (
            "m6_upgrade_pending_sample_commitments",
            "m6_upgrade_pending_sample_commitments_no_delete",
        ),
    ),
)
def test_exact_pending_retry_revalidates_the_complete_committed_prefix(
    tmp_path: Path,
    table: str,
    trigger_name: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    first_observation, first_record, first_commitment = _v2_no_case_bundle(
        scope,
        ledger_sequence=0,
        previous_record_id="0" * 64,
    )
    verifier = _verifier((first_record,))
    commitment_repository = SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        BUSY_TIMEOUT_MS,
    )
    ledger_repository = SQLiteM6UpgradeExecutionLedgerV2Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    repository.append(first_observation)
    commitment_repository.append(first_commitment)
    ledger_repository.append_committed_sample(first_commitment)
    pending, _second_record, _second_commitment = _v2_no_case_bundle(
        scope,
        ledger_sequence=1,
        previous_record_id=first_record.sample_execution_record_id,
    )
    repository.append(pending)

    with sqlite3.connect(database) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger_name,),
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(
            f"DELETE FROM {table} WHERE run_id = ? AND ledger_sequence = 0",
            (scope.candidate_run_id,),
        )
        connection.execute(trigger[0])

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(pending)

    assert (
        rejected.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID
    )


def test_second_pending_observation_is_rejected_without_child_leak(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    repository.append(_observation(scope))

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(_observation(scope, ledger_sequence=1))

    assert (
        rejected.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.PENDING_OBSERVATION_EXISTS
    )
    assert _table_counts(database) == (1, 0, 1)


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    (
        (
            lambda observation, scope: observation.model_copy(
                update={"execution_scope_authority_id": "f" * 64}
            ),
            M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH,
        ),
        (
            lambda _observation, scope: globals()["_observation"](scope, ledger_sequence=1),
            M6UpgradeExecutionObservationFailureCode.OBSERVATION_OUT_OF_ORDER,
        ),
        (
            lambda _observation, scope: globals()["_observation"](
                scope, ledger_sequence=0, entry_index=1
            ),
            M6UpgradeExecutionObservationFailureCode.OBSERVATION_OUT_OF_ORDER,
        ),
        (
            lambda observation, scope: observation.model_copy(update={"command_id": "f" * 64}),
            M6UpgradeExecutionObservationFailureCode.OBSERVATION_OUT_OF_ORDER,
        ),
        (
            lambda observation, scope: observation.model_copy(
                update={"execution_dataset_snapshot_id": "f" * 64}
            ),
            M6UpgradeExecutionObservationFailureCode.OBSERVATION_OUT_OF_ORDER,
        ),
    ),
)
def test_scope_sequence_entry_and_command_drift_fail_before_writes(
    tmp_path: Path,
    mutator: Callable[
        [M6UpgradeSampleExecutionObservationAuthority, M6UpgradeExecutionScopeAuthority],
        M6UpgradeSampleExecutionObservationAuthority,
    ],
    expected_code: M6UpgradeExecutionObservationFailureCode,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    observation = mutator(_observation(scope), scope)

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(observation)

    assert rejected.value.reason_code == expected_code
    assert _table_counts(database) == (0, 0, 0)


@pytest.mark.parametrize(
    "fault_phase",
    (
        "append.after_artifacts",
        "append.after_model_calls",
        "append.after_observation",
        "append.before_commit",
    ),
)
def test_all_observation_fault_phases_roll_back_children_and_parent(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    def fail_at(phase: str) -> None:
        if phase == f"m6_upgrade_execution_observation.{fault_phase}":
            raise RuntimeError("simulated observation process crash")

    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database, fault_injector=fail_at)
    observation = _observation(scope)

    with pytest.raises(RuntimeError, match="simulated observation process crash"):
        repository.append(observation)

    assert _table_counts(database) == (0, 0, 0)
    recovered = SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS)
    assert recovered.append(observation) == observation


@pytest.mark.parametrize("tamper", ("json", "child"))
def test_stored_json_and_normalized_child_tamper_fail_closed(
    tmp_path: Path,
    tamper: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    observation = _observation(scope)
    repository.append(observation)

    if tamper == "json":
        raw = "{}"
        _rewrite_without_append_only_trigger(
            database,
            trigger="m6_upgrade_sample_execution_observations_no_update",
            statement="""
                UPDATE m6_upgrade_sample_execution_observations
                SET observation_json = ?, document_sha256 = ?, size_bytes = ?
                WHERE run_id = ? AND ledger_sequence = 0
            """,
            parameters=(raw, _sha(raw), len(raw), scope.candidate_run_id),
        )
    else:
        _rewrite_without_append_only_trigger(
            database,
            trigger="m6_upgrade_observed_non_model_artifacts_no_update",
            statement="""
                UPDATE m6_upgrade_observed_non_model_artifacts
                SET artifact_id = 'camera-tampered:stream-tampered:99'
                WHERE run_id = ? AND ordinal = 0
            """,
            parameters=(scope.candidate_run_id,),
        )

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
    assert (
        rejected.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID
    )


def test_oversized_stored_json_is_rejected_before_contract_parsing(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    repository.append(_observation(scope))
    oversized = MAX_M6_UPGRADE_OBSERVATION_BYTES + 1
    _rewrite_without_append_only_trigger(
        database,
        trigger="m6_upgrade_sample_execution_observations_no_update",
        statement="""
            UPDATE m6_upgrade_sample_execution_observations
            SET observation_json = CAST(zeroblob(?) AS TEXT),
                document_sha256 = ?, size_bytes = ?
            WHERE run_id = ? AND ledger_sequence = 0
        """,
        parameters=(oversized, "f" * 64, oversized, scope.candidate_run_id),
        ignore_checks=True,
    )

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.load(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            0,
        )
    assert rejected.value.reason_code == M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE


@pytest.mark.parametrize(
    "malformation",
    ("missing_child", "missing_json_field", "missing_child_json_field"),
)
def test_direct_sql_rejects_missing_child_and_nullable_json_bypasses(
    tmp_path: Path,
    malformation: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, scope = _prepare(database)
    observation = _observation(scope)
    raw: str | None = None
    if malformation in {"missing_json_field", "missing_child_json_field"}:
        payload = observation.model_dump(mode="json")
        if malformation == "missing_json_field":
            del payload["command_id"]
        else:
            del payload["artifacts"][0]["usage"]
        raw = canonical_json(payload)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        if malformation != "missing_child":
            _insert_children(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_parent(connection, observation, raw=raw)
        connection.rollback()

    assert _table_counts(database) == (0, 0, 0)


@pytest.mark.parametrize("budget", ("observation_bytes", "non_model_children"))
def test_direct_sql_observation_trigger_projects_global_inventory_before_parent_insert(
    tmp_path: Path,
    budget: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, scope = _prepare(database)
    observation = _observation(scope)
    raw = canonical_json(observation.model_dump(mode="json"))
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        if budget == "observation_bytes":
            projected = len(raw.encode("utf-8"))
            expected = "), 0) + NEW.size_bytes <= 268435456"
            replacement = f"), 0) + NEW.size_bytes <= {projected - 1}"
        else:
            expected = (
                "FROM m6_upgrade_observed_non_model_artifacts AS artifact\n"
                "        WHERE artifact.run_id = NEW.run_id\n"
                "    ) <= 270000"
            )
            replacement = (
                "FROM m6_upgrade_observed_non_model_artifacts AS artifact\n"
                "        WHERE artifact.run_id = NEW.run_id\n"
                "    ) <= 0"
            )
        _replace_trigger_fragment_once(
            connection,
            trigger_name="m6_upgrade_sample_execution_observations_validate",
            expected=expected,
            replacement=replacement,
        )
        _insert_children(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_parent(connection, observation)
        connection.rollback()

    assert _table_counts(database) == (0, 0, 0)


def test_direct_sql_cannot_append_an_extra_child_after_parent_commit(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope = _prepare(database)
    observation = _observation(scope)
    repository.append(observation)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 observed non-model"):
            connection.execute(
                """
                INSERT INTO m6_upgrade_observed_non_model_artifacts(
                    run_id, observation_authority_id, ordinal,
                    source, kind, artifact_id, usage
                ) VALUES (?, ?, 1, 'M2_PERCEPTION', 'DETECTION',
                          'detection-extra', 'PRODUCED')
                """,
                (scope.candidate_run_id, observation.observation_authority_id),
            )

    assert _table_counts(database) == (1, 0, 1)


def test_v2_protocol_rejects_the_legacy_ledger_writer_and_late_children(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, records = _scope_and_no_case_records()
    observation_repository, _scope = _prepare(database, scope=scope)
    observation = _observation(scope)
    observation_repository.append(observation)
    ledger_repository = SQLiteM6UpgradeExecutionLedgerRepository(database, BUSY_TIMEOUT_MS)
    verifier = _verifier(records)
    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        ledger_repository.append_sample(records[0], verifier)
    assert (
        rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 observed non-model"):
            connection.execute(
                """
                INSERT INTO m6_upgrade_observed_non_model_artifacts(
                    run_id, observation_authority_id, ordinal,
                    source, kind, artifact_id, usage
                ) VALUES (?, ?, 1, 'M2_PERCEPTION', 'DETECTION',
                          'detection-after-observation', 'PRODUCED')
                """,
                (scope.candidate_run_id, observation.observation_authority_id),
            )

    assert _table_counts(database) == (1, 0, 1)


def test_legacy_sample_without_observation_is_blocked_before_v1_record_parsing(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, record = _single_no_case_execution()
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    ledger_repository = SQLiteM6UpgradeExecutionLedgerRepository(database, BUSY_TIMEOUT_MS)
    ledger_repository.begin_execution(scope)
    repository = SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for link in record.artifact_links:
            _insert_ref(connection, scope, link)
            _insert_link(connection, scope, record, link)
        _insert_sample(connection, scope, record)

    with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
        repository.append(_observation(scope))

    assert (
        rejected.value.reason_code
        == M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED
    )
    assert _table_counts(database) == (0, 0, 0)


def test_writer_lock_contention_is_reported_as_typed_storage_rejection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, scope = _prepare(database)
    repository = SQLiteM6UpgradeExecutionObservationRepository(database, 1)
    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(M6UpgradeExecutionObservationError) as rejected:
            repository.append(_observation(scope))
        assert (
            rejected.value.reason_code == M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED
        )
    finally:
        blocker.rollback()
        blocker.close()

    assert repository.append(_observation(scope)) == _observation(scope)


def test_direct_sql_outcome_and_case_json_drift_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, scope = _prepare(database)
    observation = _observation(scope)
    payload = observation.model_dump(mode="json")
    payload["outcome"] = M6ReplayExecutionOutcome.CASE_REPLAYED.value
    payload["candidate_case"] = {
        "case_id": "forged-case",
        "case_revision": 1,
        "case_document_sha256": "a" * 64,
        "case_audit_sequence": 0,
        "case_audit_entry_hash": "b" * 64,
    }
    raw = canonical_json(payload)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_children(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample execution observation",
        ):
            _insert_parent(connection, observation, raw=raw)
        connection.rollback()

    assert _table_counts(database) == (0, 0, 0)
