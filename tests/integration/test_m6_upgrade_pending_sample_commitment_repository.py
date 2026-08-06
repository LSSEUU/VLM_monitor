from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage import (
    _sqlite_m6_upgrade_pending_sample_commitment_codec as codec,
)
from labcourt.adapters.storage import _sqlite_m6_upgrade_v2_prefix as prefix_validator
from labcourt.adapters.storage import (
    sqlite_m6_upgrade_pending_sample_commitment as commitment_repository_module,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger import (
    SQLiteM6UpgradeExecutionLedgerRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation import (
    SQLiteM6UpgradeExecutionObservationRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment import (
    SQLiteM6UpgradePendingSampleCommitmentRepository,
    _observation_closes_record,
)
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, SQLiteEvidenceRepository
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionLedgerSealV2,
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
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import _v2_inventory
from tests.contract.test_m6_upgrade_pending_sample_commitment_contracts import _commitment
from tests.integration.test_m6_upgrade_observation_backed_ledger_migration import (
    _insert_commitment,
    _insert_refs_and_links,
    _insert_v2_sample,
    _insert_v2_seal,
)

BUSY_TIMEOUT_MS = 2_000
PENDING_COMMITMENT_VALIDATE_TRIGGER = "m6_upgrade_pending_sample_commitments_validate"
PENDING_COMMITMENT_REJECTION = "invalid M6 upgrade pending sample commitment"


def _sha(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _database(tmp_path: Path, label: str) -> Path:
    directory = tmp_path / label
    directory.mkdir()
    return directory / "labcourt.sqlite3"


def _commitment_for_record(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradePendingSampleCommitmentAuthority:
    record_json = canonical_json(record.model_dump(mode="json"))
    return M6UpgradePendingSampleCommitmentAuthority(
        execution_scope_authority_id=record.execution_scope_authority_id,
        candidate_run_id=record.candidate_run_id,
        command_id=record.command_id,
        execution_dataset_snapshot_id=record.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=record.ledger_sequence,
        observation_authority_id=record.observation_authority_id,
        sample_execution_record=record,
        sample_execution_record_document_sha256=_sha(record_json),
        sample_execution_record_size_bytes=len(record_json.encode("utf-8")),
    )


def _no_case_bundle_for_entry(
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    entry_index: int,
    previous_record_id: str,
    source_record: M6UpgradeSampleExecutionRecordV2,
) -> tuple[
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionRecordV2,
    M6UpgradePendingSampleCommitmentAuthority,
]:
    artifact_links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=ordinal,
            usage=link.usage,
            artifact=link.artifact,
        )
        for ordinal, link in enumerate(
            link
            for link in source_record.artifact_links
            if link.artifact.kind
            in {
                M6UpgradePhysicalArtifactKind.FRAME,
                M6UpgradePhysicalArtifactKind.DETECTION,
            }
        )
    )
    artifacts = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=link.artifact.source,
                    kind=link.artifact.kind,
                    artifact_id=link.artifact.artifact_id,
                    usage=link.usage,
                )
                for link in artifact_links
            ),
            key=lambda artifact: artifact.sort_key,
        )
    )
    observation = M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[entry_index],
        ledger_sequence=entry_index,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifacts=artifacts,
        model_calls=(),
    )
    record = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[entry_index],
        outcome=observation.outcome,
        candidate_case=None,
        artifact_links=artifact_links,
        ledger_sequence=entry_index,
        previous_ledger_entry_hash=previous_record_id,
        observation_authority_id=observation.observation_authority_id,
    )
    return observation, record, _commitment_for_record(record)


def _prepare(
    database: Path,
    *,
    append_observation: bool = True,
    observation: M6UpgradeSampleExecutionObservationAuthority | None = None,
    fault_injector: Callable[[str], None] | None = None,
    busy_timeout_ms: int = BUSY_TIMEOUT_MS,
) -> tuple[
    SQLiteM6UpgradePendingSampleCommitmentRepository,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradePendingSampleCommitmentAuthority,
]:
    inventory = _v2_inventory()
    scope = inventory.execution_ledger.execution_scope
    selected_observation = observation or inventory.execution_observations[0]
    commitment = _commitment()
    database.parent.mkdir(parents=True, exist_ok=True)
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    repository = SQLiteM6UpgradePendingSampleCommitmentRepository(
        database,
        busy_timeout_ms,
        fault_injector=fault_injector,
    )
    repository.begin_execution(scope)
    if append_observation:
        SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(
            selected_observation
        )
    return repository, scope, selected_observation, commitment


def _consume_sample_direct(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecordV2,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)


def _insert_case_binding_authority(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
    binding: M6UpgradeCandidateCaseBinding,
) -> None:
    case = binding
    manifest_id = scope.candidate_manifest.manifest_id
    event_sha256 = _sha(f"event:{case.case_id}")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        audit_trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'audit_entries_m6_require_next'
            """
        ).fetchone()
        assert audit_trigger is not None and isinstance(audit_trigger[0], str)
        connection.execute("DROP TRIGGER audit_entries_m6_require_next")
        connection.execute(
            """
            INSERT INTO audit_entries(
                run_id, sequence, manifest_id, actor, action, object_kind,
                object_id, before_sha256, after_sha256, recorded_at,
                prev_entry_hash, entry_hash, entry_json, document_sha256
            ) VALUES (?, ?, ?, 'test', 'CREATE', 'CASE', ?, NULL, ?,
                      '2026-01-01T00:00:00Z', ?, ?, '{}', ?)
            """,
            (
                scope.candidate_run_id,
                case.case_audit_sequence,
                manifest_id,
                case.case_id,
                case.case_document_sha256,
                "0" * 64,
                case.case_audit_entry_hash,
                _sha("{}"),
            ),
        )
        connection.execute(audit_trigger[0])
        connection.execute(
            """
            INSERT INTO cases(
                run_id, case_id, event_id, manifest_id, status,
                current_revision, latest_pack_id, latest_pack_version,
                event_json, event_sha256, created_audit_sequence
            ) VALUES (?, ?, ?, ?, 'OPEN', ?, NULL, NULL, '{}', ?, ?)
            """,
            (
                scope.candidate_run_id,
                case.case_id,
                f"event-{case.case_id}",
                manifest_id,
                case.case_revision,
                event_sha256,
                case.case_audit_sequence,
            ),
        )
        connection.execute(
            """
            INSERT INTO case_versions(
                run_id, case_id, revision, status, case_json,
                document_sha256, audit_sequence
            ) VALUES (?, ?, ?, 'OPEN', '{}', ?, ?)
            """,
            (
                scope.candidate_run_id,
                case.case_id,
                case.case_revision,
                case.case_document_sha256,
                case.case_audit_sequence,
            ),
        )


def _commitment_count(database: Path) -> int:
    with sqlite3.connect(database) as connection:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments"
            ).fetchone()[0]
        )


def _replace_pending_validate_trigger_expression_once(
    database: Path,
    *,
    target: str,
    replacement: str,
) -> None:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (PENDING_COMMITMENT_VALIDATE_TRIGGER,),
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        trigger_sql = row[0]
        assert trigger_sql.count(target) == 1
        rewritten = trigger_sql.replace(target, replacement, 1)
        connection.execute(f'DROP TRIGGER "{PENDING_COMMITMENT_VALIDATE_TRIGGER}"')
        connection.execute(rewritten)


def _assert_direct_commitment_rejected(
    database: Path,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
) -> None:
    count_before = _commitment_count(database)
    with (
        pytest.raises(sqlite3.IntegrityError, match=PENDING_COMMITMENT_REJECTION),
        sqlite3.connect(database) as connection,
    ):
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_commitment(connection, commitment)
    assert _commitment_count(database) == count_before


def _rewrite_commitment_row(
    database: Path,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> None:
    with sqlite3.connect(database) as connection:
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_pending_sample_commitments_no_update'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("DROP TRIGGER m6_upgrade_pending_sample_commitments_no_update")
        connection.execute(statement, parameters)
        connection.execute(str(trigger[0]))


def _rewrite_without_update_trigger(
    database: Path,
    *,
    trigger_name: str,
    statement: str,
    parameters: tuple[object, ...],
) -> None:
    with sqlite3.connect(database) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (trigger_name,),
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(statement, parameters)
        connection.execute(str(trigger[0]))


def _assert_code(
    expected: M6UpgradePendingSampleCommitmentFailureCode,
    operation: Callable[[], object],
) -> None:
    with pytest.raises(M6UpgradePendingSampleCommitmentError) as rejected:
        operation()
    assert rejected.value.reason_code == expected


def test_append_load_and_exact_retry_are_byte_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope, _observation, commitment = _prepare(database)

    assert repository.append(commitment) == commitment
    assert (
        repository.load(scope.candidate_run_id, scope.execution_scope_authority_id, 0) == commitment
    )
    assert repository.append(commitment) == commitment
    assert _commitment_count(database) == 1


def test_same_key_with_different_exact_record_is_a_conflict(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, _observation, commitment = _prepare(database)
    repository.append(commitment)
    record = commitment.sample_execution_record
    frame = next(
        link
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    changed_artifact = frame.artifact.model_copy(
        update={"size_bytes": frame.artifact.size_bytes + 1}
    )
    changed_links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=link.ordinal,
            usage=link.usage,
            artifact=changed_artifact if link.ordinal == frame.ordinal else link.artifact,
        )
        for link in record.artifact_links
    )
    changed = _commitment_for_record(record.model_copy(update={"artifact_links": changed_links}))

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT,
        lambda: repository.append(changed),
    )
    assert _commitment_count(database) == 1


def test_scope_missing_mismatch_and_v1_protocol_are_distinct(tmp_path: Path) -> None:
    commitment = _commitment()
    missing_database = _database(tmp_path, "missing")
    MigrationRunner(missing_database, BUSY_TIMEOUT_MS).apply_all()
    missing = SQLiteM6UpgradePendingSampleCommitmentRepository(
        missing_database,
        BUSY_TIMEOUT_MS,
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND,
        lambda: missing.append(commitment),
    )

    database = _database(tmp_path, "v2")
    repository, scope, _observation, _commitment_value = _prepare(database)
    forged_scope = "f" * 64
    if forged_scope == scope.execution_scope_authority_id:
        forged_scope = "e" * 64
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH,
        lambda: repository.load(scope.candidate_run_id, forged_scope, 0),
    )

    legacy_database = _database(tmp_path, "v1")
    inventory = _v2_inventory()
    legacy_scope = inventory.execution_ledger.execution_scope
    MigrationRunner(legacy_database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(legacy_database, BUSY_TIMEOUT_MS).register_run(
        legacy_scope.candidate_run_id,
        legacy_scope.candidate_manifest,
    )
    SQLiteM6UpgradeExecutionLedgerRepository(
        legacy_database,
        BUSY_TIMEOUT_MS,
    ).begin_execution(legacy_scope)
    legacy = SQLiteM6UpgradePendingSampleCommitmentRepository(
        legacy_database,
        BUSY_TIMEOUT_MS,
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED,
        lambda: legacy.append(commitment),
    )


def test_scope_document_is_size_preflighted_before_raw_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, _observation, commitment = _prepare(database)
    monkeypatch.setattr(commitment_repository_module, "MAX_M6_UPGRADE_SCOPE_BYTES", 1)

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE,
        lambda: repository.append(commitment),
    )


@pytest.mark.parametrize(
    "budget_name",
    (
        "MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES",
        "MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES",
        "MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES",
    ),
)
def test_candidate_commitment_is_projected_into_every_global_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope, _observation_value, commitment = _prepare(database)
    documents = codec.pending_sample_commitment_documents(commitment)
    if budget_name == "MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES":
        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT size_bytes FROM m6_upgrade_execution_scopes WHERE run_id = ?",
                (scope.candidate_run_id,),
            ).fetchone()
        assert row is not None
        projected_bytes = int(row[0]) + documents.sample_execution_record_size_bytes
    elif budget_name == "MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES":
        projected_bytes = documents.size_bytes
    else:
        projected_bytes = documents.sample_execution_record_size_bytes
    assert projected_bytes > 1
    monkeypatch.setattr(
        commitment_repository_module,
        budget_name,
        projected_bytes - 1,
    )

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE,
        lambda: repository.append(commitment),
    )
    assert _commitment_count(database) == 0


def test_missing_and_mismatched_observation_fail_before_write(tmp_path: Path) -> None:
    missing_database = _database(tmp_path, "missing")
    missing, _scope, _observation, commitment = _prepare(
        missing_database,
        append_observation=False,
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_NOT_FOUND,
        lambda: missing.append(commitment),
    )
    assert _commitment_count(missing_database) == 0

    mismatch_database = _database(tmp_path, "mismatch")
    inventory = _v2_inventory()
    original = inventory.execution_observations[0]
    changed_artifacts = tuple(
        artifact.model_copy(update={"artifact_id": f"{artifact.artifact_id}-mismatch"})
        if artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
        else artifact
        for artifact in original.artifacts
    )
    mismatched_observation = original.model_copy(update={"artifacts": changed_artifacts})
    mismatch, _scope, _observation, commitment = _prepare(
        mismatch_database,
        observation=mismatched_observation,
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_MISMATCH,
        lambda: mismatch.append(commitment),
    )
    assert _commitment_count(mismatch_database) == 0


def test_non_model_and_model_request_sets_are_closed_before_insert(tmp_path: Path) -> None:
    inventory = _v2_inventory()
    source_record = inventory.execution_ledger.sample_executions[0]

    detection = next(
        link
        for link in source_record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    changed_detection = detection.artifact.model_copy(
        update={"artifact_id": f"{detection.artifact.artifact_id}-mismatch"}
    )
    changed_links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=link.ordinal,
            usage=link.usage,
            artifact=(changed_detection if link.ordinal == detection.ordinal else link.artifact),
        )
        for link in source_record.artifact_links
    )
    non_model_record = source_record.model_copy(update={"artifact_links": changed_links})
    non_model_commitment = _commitment_for_record(non_model_record)
    non_model_database = _database(tmp_path, "non-model")
    non_model_repo, _scope, _observation, _commitment_value = _prepare(non_model_database)
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_MISMATCH,
        lambda: non_model_repo.append(non_model_commitment),
    )

    model_observation = inventory.execution_observations[1]
    model_source_record = inventory.execution_ledger.sample_executions[1]
    assert _observation_closes_record(
        model_observation,
        _commitment_for_record(model_source_record),
    )
    request = next(
        link
        for link in model_source_record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
    )
    retained = tuple(
        link for link in model_source_record.artifact_links if link.ordinal != request.ordinal
    )
    reindexed = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=index,
            usage=link.usage,
            artifact=link.artifact,
        )
        for index, link in enumerate(retained)
    )
    model_record = model_source_record.model_copy(update={"artifact_links": reindexed})
    model_commitment = _commitment_for_record(model_record)
    assert not _observation_closes_record(model_observation, model_commitment)


def test_duplicate_logical_detection_across_containers_is_rejected_before_insert(
    tmp_path: Path,
) -> None:
    inventory = _v2_inventory()
    source_record = inventory.execution_ledger.sample_executions[0]
    source_observation = inventory.execution_observations[0]
    frame = next(
        link
        for link in source_record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    detection = next(
        link
        for link in source_record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    second_frame = frame.artifact.model_copy(
        update={"artifact_id": "camera-challeng-copy:stream:0"}
    )
    duplicate_detection = detection.artifact.model_copy(
        update={"container_id": second_frame.artifact_id}
    )
    physical_items = (
        (frame.usage, frame.artifact),
        (frame.usage, second_frame),
        (detection.usage, detection.artifact),
        (detection.usage, duplicate_detection),
    )
    links = tuple(
        M6UpgradeSampleArtifactLink(ordinal=ordinal, usage=usage, artifact=artifact)
        for ordinal, (usage, artifact) in enumerate(
            sorted(physical_items, key=lambda item: item[1].physical_key)
        )
    )
    logical_artifacts: dict[tuple[object, ...], M6UpgradeObservedArtifactIdentity] = {}
    for link in links:
        observed = M6UpgradeObservedArtifactIdentity(
            source=link.artifact.source,
            kind=link.artifact.kind,
            artifact_id=link.artifact.artifact_id,
            usage=link.usage,
        )
        logical_artifacts.setdefault(
            (observed.source, observed.kind, observed.artifact_id, observed.usage),
            observed,
        )
    observation_payload = source_observation.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    observation_payload["artifacts"] = tuple(
        sorted(logical_artifacts.values(), key=lambda artifact: artifact.sort_key)
    )
    observation = M6UpgradeSampleExecutionObservationAuthority.model_validate(observation_payload)
    record_payload = source_record.model_dump(mode="python", exclude_computed_fields=True)
    record_payload.update(
        artifact_links=links,
        observation_authority_id=observation.observation_authority_id,
    )
    record = M6UpgradeSampleExecutionRecordV2.model_validate(record_payload)
    commitment = _commitment_for_record(record)
    assert len(observation.artifacts) == 3
    assert len(record.artifact_links) == 4
    assert not _observation_closes_record(observation, commitment)

    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, _observation, _commitment_value = _prepare(
        database,
        observation=observation,
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_MISMATCH,
        lambda: repository.append(commitment),
    )
    assert _commitment_count(database) == 0


def _prepare_second_sample(
    database: Path,
) -> tuple[
    SQLiteM6UpgradePendingSampleCommitmentRepository,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradePendingSampleCommitmentAuthority,
]:
    repository, scope, _observation, first = _prepare(database)
    repository.append(first)
    inventory = _v2_inventory()
    _consume_sample_direct(database, scope, inventory.execution_ledger.sample_executions[0])
    observation, _record, commitment = _no_case_bundle_for_entry(
        scope,
        entry_index=1,
        previous_record_id=inventory.execution_ledger.sample_executions[
            0
        ].sample_execution_record_id,
        source_record=inventory.execution_ledger.sample_executions[1],
    )
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(observation)
    return repository, scope, commitment


def test_second_sample_uses_v2_prefix_and_exact_previous_head(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope, second = _prepare_second_sample(database)

    assert repository.append(second) == second
    assert repository.load(scope.candidate_run_id, scope.execution_scope_authority_id, 1) == second


def _prepare_duplicate_case_commitment(
    database: Path,
) -> tuple[
    SQLiteM6UpgradePendingSampleCommitmentRepository,
    M6UpgradePendingSampleCommitmentAuthority,
]:
    repository, scope, _observation_value, first = _prepare(database)
    inventory = _v2_inventory()
    repository.append(first)
    _consume_sample_direct(database, scope, inventory.execution_ledger.sample_executions[0])

    second = _commitment(1)
    assert second.sample_execution_record.candidate_case is not None
    _insert_case_binding_authority(
        database,
        scope,
        second.sample_execution_record.candidate_case,
    )
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(
        inventory.execution_observations[1]
    )
    repository.append(second)
    _consume_sample_direct(database, scope, second.sample_execution_record)

    duplicate_observation = inventory.execution_observations[2].model_copy(
        update={"candidate_case": second.sample_execution_record.candidate_case}
    )
    duplicate_record = inventory.execution_ledger.sample_executions[2].model_copy(
        update={
            "candidate_case": second.sample_execution_record.candidate_case,
            "observation_authority_id": duplicate_observation.observation_authority_id,
        }
    )
    duplicate = _commitment_for_record(duplicate_record)
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(
        duplicate_observation
    )
    return repository, duplicate


def test_commitment_rejects_a_duplicate_case_before_it_becomes_durable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, duplicate = _prepare_duplicate_case_commitment(database)

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT,
        lambda: repository.append(duplicate),
    )
    assert _commitment_count(database) == 2


def _prepare_physical_key_conflict_commitment(
    database: Path,
) -> tuple[
    SQLiteM6UpgradePendingSampleCommitmentRepository,
    M6UpgradePendingSampleCommitmentAuthority,
]:
    repository, scope, _observation_value, first = _prepare(database)
    inventory = _v2_inventory()
    repository.append(first)
    _consume_sample_direct(database, scope, inventory.execution_ledger.sample_executions[0])

    first_record = first.sample_execution_record
    conflicting_frame = next(
        link.artifact
        for link in first_record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    ).model_copy(
        update={
            "size_bytes": next(
                link.artifact.size_bytes
                for link in first_record.artifact_links
                if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
            )
            + 1
        }
    )
    changed_links = tuple(
        M6UpgradeSampleArtifactLink(
            ordinal=link.ordinal,
            usage=link.usage,
            artifact=(
                conflicting_frame
                if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
                else link.artifact
            ),
        )
        for link in first_record.artifact_links
    )
    observed_artifacts = tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=link.artifact.source,
                    kind=link.artifact.kind,
                    artifact_id=link.artifact.artifact_id,
                    usage=link.usage,
                )
                for link in changed_links
            ),
            key=lambda item: item.sort_key,
        )
    )
    conflicting_observation = M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[1],
        ledger_sequence=1,
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifacts=observed_artifacts,
        model_calls=(),
    )
    conflicting_record = M6UpgradeSampleExecutionRecordV2(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[1],
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifact_links=changed_links,
        ledger_sequence=1,
        previous_ledger_entry_hash=first_record.sample_execution_record_id,
        observation_authority_id=conflicting_observation.observation_authority_id,
    )
    conflicting = _commitment_for_record(conflicting_record)
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(
        conflicting_observation
    )
    return repository, conflicting


def test_commitment_rejects_a_cross_sample_physical_key_conflict_before_insert(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, conflicting = _prepare_physical_key_conflict_commitment(database)

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT,
        lambda: repository.append(conflicting),
    )
    assert _commitment_count(database) == 1


def test_commitment_rejects_the_global_link_budget_before_insert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, second = _prepare_second_sample(database)
    first_link_count = _commitment().sample_execution_record.artifact_link_count
    monkeypatch.setattr(
        prefix_validator,
        "MAX_M6_UPGRADE_LEDGER_LINKS",
        first_link_count,
    )

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT,
        lambda: repository.append(second),
    )
    assert _commitment_count(database) == 1


def test_direct_sql_cannot_persist_a_duplicate_candidate_case(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, duplicate = _prepare_duplicate_case_commitment(database)

    _assert_direct_commitment_rejected(database, duplicate)


def test_direct_sql_cannot_persist_a_cross_sample_physical_key_conflict(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, conflicting = _prepare_physical_key_conflict_commitment(database)

    _assert_direct_commitment_rejected(database, conflicting)


def test_direct_sql_accepts_an_exact_reused_physical_reference(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope, _observation_value, first = _prepare(database)
    repository.append(first)
    _consume_sample_direct(database, scope, first.sample_execution_record)
    observation, _record, exact_reuse = _no_case_bundle_for_entry(
        scope,
        entry_index=1,
        previous_record_id=first.sample_execution_record_id,
        source_record=first.sample_execution_record,
    )
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(observation)
    count_before = _commitment_count(database)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_commitment(connection, exact_reuse)

    assert _commitment_count(database) == count_before + 1


def test_direct_sql_cannot_exceed_the_global_link_budget(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, _scope, second = _prepare_second_sample(database)
    with sqlite3.connect(database) as connection:
        existing_link_count = int(
            connection.execute(
                """
                SELECT COALESCE(SUM(artifact_link_count), 0)
                FROM m6_upgrade_sample_executions
                WHERE run_id = ?
                """,
                (second.candidate_run_id,),
            ).fetchone()[0]
        )
    projected = existing_link_count + second.sample_execution_record.artifact_link_count
    assert projected > second.sample_execution_record.artifact_link_count
    _replace_pending_validate_trigger_expression_once(
        database,
        target="250000",
        replacement=str(projected - 1),
    )

    _assert_direct_commitment_rejected(database, second)


@pytest.mark.parametrize(
    ("budget_kind", "limit_expression"),
    (
        ("scope-and-records", "    ) <= {limit}"),
        ("commitment-inventory", "), 0) + NEW.size_bytes <= {limit}"),
        (
            "embedded-record-inventory",
            "), 0) + NEW.sample_execution_record_size_bytes <= {limit}",
        ),
    ),
)
def test_direct_sql_cannot_exceed_any_global_pending_byte_budget(
    tmp_path: Path,
    budget_kind: str,
    limit_expression: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, scope, second = _prepare_second_sample(database)
    documents = codec.pending_sample_commitment_documents(second)
    with sqlite3.connect(database) as connection:
        if budget_kind == "scope-and-records":
            scope_size = int(
                connection.execute(
                    """
                    SELECT size_bytes FROM m6_upgrade_execution_scopes
                    WHERE run_id = ? AND execution_scope_authority_id = ?
                    """,
                    (scope.candidate_run_id, scope.execution_scope_authority_id),
                ).fetchone()[0]
            )
            existing_size = int(
                connection.execute(
                    """
                    SELECT COALESCE(SUM(record_size_bytes), 0)
                    FROM m6_upgrade_sample_executions WHERE run_id = ?
                    """,
                    (scope.candidate_run_id,),
                ).fetchone()[0]
            )
            candidate_size = documents.sample_execution_record_size_bytes
            projected = scope_size + existing_size + candidate_size
        elif budget_kind == "commitment-inventory":
            existing_size = int(
                connection.execute(
                    """
                    SELECT COALESCE(SUM(size_bytes), 0)
                    FROM m6_upgrade_pending_sample_commitments WHERE run_id = ?
                    """,
                    (scope.candidate_run_id,),
                ).fetchone()[0]
            )
            candidate_size = documents.size_bytes
            projected = existing_size + candidate_size
        else:
            existing_size = int(
                connection.execute(
                    """
                    SELECT COALESCE(SUM(sample_execution_record_size_bytes), 0)
                    FROM m6_upgrade_pending_sample_commitments WHERE run_id = ?
                    """,
                    (scope.candidate_run_id,),
                ).fetchone()[0]
            )
            candidate_size = documents.sample_execution_record_size_bytes
            projected = existing_size + candidate_size
    assert projected > candidate_size
    _replace_pending_validate_trigger_expression_once(
        database,
        target=limit_expression.format(limit=268_435_456),
        replacement=limit_expression.format(limit=projected - 1),
    )

    _assert_direct_commitment_rejected(database, second)


def test_wrong_second_sample_previous_head_is_out_of_order(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, second = _prepare_second_sample(database)
    wrong_hash = "f" * 64
    if wrong_hash == second.sample_execution_record.previous_ledger_entry_hash:
        wrong_hash = "e" * 64
    changed_record = second.sample_execution_record.model_copy(
        update={"previous_ledger_entry_hash": wrong_hash}
    )
    changed = _commitment_for_record(changed_record)

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_OUT_OF_ORDER,
        lambda: repository.append(changed),
    )
    assert _commitment_count(database) == 1


def test_next_commitment_revalidates_every_prior_observation(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope, second = _prepare_second_sample(database)
    first_observation_id = _v2_inventory().execution_observations[0].observation_authority_id
    _rewrite_without_update_trigger(
        database,
        trigger_name="m6_upgrade_observed_non_model_artifacts_no_update",
        statement="""
            UPDATE m6_upgrade_observed_non_model_artifacts
            SET artifact_id = 'challenge-00-detection-prior-tamper'
            WHERE run_id = ? AND observation_authority_id = ? AND kind = 'DETECTION'
        """,
        parameters=(scope.candidate_run_id, first_observation_id),
    )

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID,
        lambda: repository.append(second),
    )
    assert _commitment_count(database) == 1


def test_second_pending_commitment_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, _observation, first = _prepare(database)
    repository.append(first)
    inventory = _v2_inventory()
    _observation, _record, second = _no_case_bundle_for_entry(
        inventory.execution_ledger.execution_scope,
        entry_index=1,
        previous_record_id=first.sample_execution_record_id,
        source_record=inventory.execution_ledger.sample_executions[1],
    )

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.PENDING_COMMITMENT_EXISTS,
        lambda: repository.append(second),
    )
    assert _commitment_count(database) == 1


@pytest.mark.parametrize("fault_phase", ("append.after_insert", "append.before_commit"))
def test_fault_phases_roll_back_and_exact_retry_recovers(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    def fail_at(phase: str) -> None:
        if phase == f"m6_upgrade_pending_sample_commitment.{fault_phase}":
            raise RuntimeError("simulated commitment crash")

    database = tmp_path / "labcourt.sqlite3"
    repository, scope, _observation, commitment = _prepare(
        database,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="simulated commitment crash"):
        repository.append(commitment)
    assert _commitment_count(database) == 0

    recovered = SQLiteM6UpgradePendingSampleCommitmentRepository(database, BUSY_TIMEOUT_MS)
    assert recovered.append(commitment) == commitment
    assert (
        recovered.load(scope.candidate_run_id, scope.execution_scope_authority_id, 0) == commitment
    )


def test_writer_lock_is_a_typed_storage_rejection(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    _repository, _scope, _observation, commitment = _prepare(database)
    repository = SQLiteM6UpgradePendingSampleCommitmentRepository(database, 1)
    blocker = sqlite3.connect(database)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        _assert_code(
            M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED,
            lambda: repository.append(commitment),
        )
    finally:
        blocker.rollback()
        blocker.close()
    assert repository.append(commitment) == commitment


def test_load_rejects_stored_normalized_tamper_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tampered_database = _database(tmp_path, "tampered")
    repository, scope, _observation, commitment = _prepare(tampered_database)
    repository.append(commitment)
    _rewrite_commitment_row(
        tampered_database,
        "UPDATE m6_upgrade_pending_sample_commitments SET command_id = ?",
        ("f" * 64,),
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID,
        lambda: repository.load(scope.candidate_run_id, scope.execution_scope_authority_id, 0),
    )

    oversized_database = _database(tmp_path, "oversized")
    repository, scope, _observation, commitment = _prepare(oversized_database)
    repository.append(commitment)
    limit = 128
    raw = '"' + ("x" * limit) + '"'
    monkeypatch.setattr(codec, "MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES", limit)
    _rewrite_commitment_row(
        oversized_database,
        """
        UPDATE m6_upgrade_pending_sample_commitments
        SET commitment_json = ?, document_sha256 = ?, size_bytes = ?
        """,
        (raw, _sha(raw), len(raw.encode("utf-8"))),
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE,
        lambda: repository.load(scope.candidate_run_id, scope.execution_scope_authority_id, 0),
    )


@pytest.mark.parametrize("tamper", ("raw", "normalized"))
def test_exact_retry_revalidates_tampered_observation(
    tmp_path: Path,
    tamper: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope, _observation, commitment = _prepare(database)
    repository.append(commitment)
    if tamper == "raw":
        raw = "{}"
        _rewrite_without_update_trigger(
            database,
            trigger_name="m6_upgrade_sample_execution_observations_no_update",
            statement="""
                UPDATE m6_upgrade_sample_execution_observations
                SET observation_json = ?, document_sha256 = ?, size_bytes = ?
                WHERE run_id = ? AND ledger_sequence = 0
            """,
            parameters=(raw, _sha(raw), len(raw.encode("utf-8")), scope.candidate_run_id),
        )
    else:
        _rewrite_without_update_trigger(
            database,
            trigger_name="m6_upgrade_observed_non_model_artifacts_no_update",
            statement="""
                UPDATE m6_upgrade_observed_non_model_artifacts
                SET artifact_id = 'challenge-00-detection-tampered'
                WHERE run_id = ? AND kind = 'DETECTION'
            """,
            parameters=(scope.candidate_run_id,),
        )

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID,
        lambda: repository.append(commitment),
    )


def test_exact_retry_preflights_aggregate_before_commitment_decoder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, _observation, commitment = _prepare(database)
    repository.append(commitment)
    _rewrite_commitment_row(
        database,
        """
        UPDATE m6_upgrade_pending_sample_commitments
        SET size_bytes = size_bytes + 1
        """,
    )

    def fail_if_decoded(*_args: object, **_kwargs: object) -> None:
        pytest.fail("commitment decoder ran before aggregate preflight")

    monkeypatch.setattr(
        commitment_repository_module,
        "pending_sample_commitment_from_connection",
        fail_if_decoded,
    )
    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID,
        lambda: repository.append(commitment),
    )


def test_direct_sql_cannot_bypass_observation_order_or_append_only(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _scope, _observation, commitment = _prepare(
        database,
        append_observation=False,
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_commitment(connection, commitment)
    repository = SQLiteM6UpgradePendingSampleCommitmentRepository(database, BUSY_TIMEOUT_MS)
    SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(
        _v2_inventory().execution_observations[0]
    )
    repository.append(commitment)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            _insert_commitment(connection, commitment)


def test_exact_retry_survives_seal_but_missing_new_write_is_sealed(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, scope, _observation, first = _prepare(database)
    inventory = _v2_inventory()
    records = [inventory.execution_ledger.sample_executions[0]]
    commitments = [first]
    for index in range(len(scope.execution_dataset.entries)):
        if index:
            observation, record, commitment = _no_case_bundle_for_entry(
                scope,
                entry_index=index,
                previous_record_id=records[-1].sample_execution_record_id,
                source_record=inventory.execution_ledger.sample_executions[index],
            )
            records.append(record)
            commitments.append(commitment)
            SQLiteM6UpgradeExecutionObservationRepository(database, BUSY_TIMEOUT_MS).append(
                observation
            )
        else:
            record = records[0]
            commitment = commitments[0]
        repository.append(commitment)
        _consume_sample_direct(database, scope, record)
    seal = M6UpgradeExecutionLedgerSealV2(
        execution_scope=scope,
        execution_scope_content_sha256=inventory.execution_ledger.execution_scope_content_sha256,
        execution_scope_size_bytes=inventory.execution_ledger.execution_scope_size_bytes,
        source_audit_head_sequence=scope.execution_start_audit_head_sequence,
        source_audit_head_hash=scope.execution_start_audit_head_hash,
        sample_executions=tuple(records),
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_v2_seal(connection, seal)

    assert repository.append(first) == first

    with sqlite3.connect(database) as connection:
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master WHERE type = 'trigger'
              AND name = 'm6_upgrade_pending_sample_commitments_no_delete'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TRIGGER m6_upgrade_pending_sample_commitments_no_delete")
        connection.execute(
            "DELETE FROM m6_upgrade_pending_sample_commitments WHERE ledger_sequence = 0"
        )
        connection.execute(str(trigger[0]))

    _assert_code(
        M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED,
        lambda: repository.append(first),
    )
