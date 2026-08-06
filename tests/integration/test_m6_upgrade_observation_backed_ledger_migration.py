from __future__ import annotations

import hashlib
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeCandidateCaseBinding,
    M6UpgradeExecutionLedgerSealV2,
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
from labcourt.contracts.m6_upgrade_physical import (
    MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES,
    M6UpgradePhysicalArtifactKind,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.integration.test_m2_sqlite_repository import _event
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    AUDIT_GENESIS_HASH,
    BUSY_TIMEOUT_MS,
    MIGRATIONS,
    _canonical_document,
    _insert_link,
    _insert_ref,
    _insert_sample,
    _register_scope,
    _single_no_case_execution,
)
from tests.integration.test_m6_upgrade_execution_observation_repository import (
    _insert_children,
    _insert_parent,
)

_FORGED = "f" * 64


def _sha(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _observed_artifacts(
    record: M6UpgradeSampleExecutionRecord,
    *,
    omit_detection: bool = False,
) -> tuple[M6UpgradeObservedArtifactIdentity, ...]:
    return tuple(
        sorted(
            (
                M6UpgradeObservedArtifactIdentity(
                    source=link.artifact.source,
                    kind=link.artifact.kind,
                    artifact_id=link.artifact.artifact_id,
                    usage=link.usage,
                )
                for link in record.artifact_links
                if not link.artifact.kind.value.startswith("MODEL_")
                and not (
                    omit_detection and link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
                )
            ),
            key=lambda artifact: artifact.sort_key,
        )
    )


def _observation_for(
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecord,
    *,
    candidate_case: M6UpgradeCandidateCaseBinding | None = None,
    omit_detection: bool = False,
) -> M6UpgradeSampleExecutionObservationAuthority:
    outcome = (
        M6ReplayExecutionOutcome.CASE_REPLAYED
        if candidate_case is not None
        else M6ReplayExecutionOutcome.NO_CASE
    )
    return M6UpgradeSampleExecutionObservationAuthority(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=record.ledger_sequence,
        outcome=outcome,
        candidate_case=candidate_case,
        artifacts=_observed_artifacts(record, omit_detection=omit_detection),
        model_calls=(),
    )


def _v2_record(
    scope: M6UpgradeExecutionScopeAuthority,
    source: M6UpgradeSampleExecutionRecord,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    *,
    artifact_links: tuple[M6UpgradeSampleArtifactLink, ...] | None = None,
    bypass_validation: bool = False,
) -> M6UpgradeSampleExecutionRecordV2:
    values = {
        "schema_version": "m6-upgrade-sample-execution-record-v2",
        "execution_scope_authority_id": scope.execution_scope_authority_id,
        "candidate_run_id": scope.candidate_run_id,
        "command_id": scope.command.command_id,
        "execution_dataset_snapshot_id": scope.execution_dataset.execution_dataset_snapshot_id,
        "execution_entry": observation.execution_entry,
        "outcome": observation.outcome,
        "candidate_case": observation.candidate_case,
        "artifact_links": artifact_links or source.artifact_links,
        "ledger_sequence": observation.ledger_sequence,
        "previous_ledger_entry_hash": source.previous_ledger_entry_hash,
        "observation_authority_id": observation.observation_authority_id,
    }
    if bypass_validation:
        return M6UpgradeSampleExecutionRecordV2.model_construct(**values)
    return M6UpgradeSampleExecutionRecordV2(**values)


def _commitment(
    record: M6UpgradeSampleExecutionRecordV2,
    *,
    bypass_validation: bool = False,
) -> M6UpgradePendingSampleCommitmentAuthority:
    record_raw, record_sha256, record_size = _canonical_document(record)
    del record_raw
    values = {
        "schema_version": "m6-upgrade-pending-sample-commitment-authority-v1",
        "execution_scope_authority_id": record.execution_scope_authority_id,
        "candidate_run_id": record.candidate_run_id,
        "command_id": record.command_id,
        "execution_dataset_snapshot_id": record.execution_dataset_snapshot_id,
        "execution_entry": record.execution_entry,
        "ledger_sequence": record.ledger_sequence,
        "observation_authority_id": record.observation_authority_id,
        "sample_execution_record": record,
        "sample_execution_record_document_sha256": record_sha256,
        "sample_execution_record_size_bytes": record_size,
    }
    if bypass_validation:
        return M6UpgradePendingSampleCommitmentAuthority.model_construct(**values)
    return M6UpgradePendingSampleCommitmentAuthority(**values)


def _insert_observation(
    connection: sqlite3.Connection,
    observation: M6UpgradeSampleExecutionObservationAuthority,
) -> None:
    _insert_children(connection, observation)
    _insert_parent(connection, observation)


def _insert_commitment(
    connection: sqlite3.Connection,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
) -> None:
    record_raw, record_sha256, record_size = _canonical_document(commitment.sample_execution_record)
    raw, document_sha256, size_bytes = _canonical_document(commitment)
    assert record_sha256 == commitment.sample_execution_record_document_sha256
    assert record_size == commitment.sample_execution_record_size_bytes
    connection.execute(
        """
        INSERT INTO m6_upgrade_pending_sample_commitments(
            run_id, execution_scope_authority_id, ledger_sequence,
            pending_sample_commitment_authority_id, command_id,
            execution_dataset_snapshot_id, execution_entry_id, sample_id,
            observation_authority_id, sample_execution_record_id,
            sample_execution_record_json,
            sample_execution_record_document_sha256,
            sample_execution_record_size_bytes, commitment_json,
            document_sha256, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            commitment.candidate_run_id,
            commitment.execution_scope_authority_id,
            commitment.ledger_sequence,
            commitment.pending_sample_commitment_authority_id,
            commitment.command_id,
            commitment.execution_dataset_snapshot_id,
            commitment.execution_entry_id,
            commitment.sample_id,
            commitment.observation_authority_id,
            commitment.sample_execution_record_id,
            record_raw,
            commitment.sample_execution_record_document_sha256,
            commitment.sample_execution_record_size_bytes,
            raw,
            document_sha256,
            size_bytes,
        ),
    )


def _insert_commitment_or_replace_with_authority_id(
    connection: sqlite3.Connection,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
    authority_id: str,
) -> None:
    record_raw, record_sha256, record_size = _canonical_document(commitment.sample_execution_record)
    payload = commitment.model_dump(mode="json")
    payload["pending_sample_commitment_authority_id"] = authority_id
    raw = canonical_json(payload)
    connection.execute(
        """
        INSERT OR REPLACE INTO m6_upgrade_pending_sample_commitments(
            run_id, execution_scope_authority_id, ledger_sequence,
            pending_sample_commitment_authority_id, command_id,
            execution_dataset_snapshot_id, execution_entry_id, sample_id,
            observation_authority_id, sample_execution_record_id,
            sample_execution_record_json,
            sample_execution_record_document_sha256,
            sample_execution_record_size_bytes, commitment_json,
            document_sha256, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            commitment.candidate_run_id,
            commitment.execution_scope_authority_id,
            commitment.ledger_sequence,
            authority_id,
            commitment.command_id,
            commitment.execution_dataset_snapshot_id,
            commitment.execution_entry_id,
            commitment.sample_id,
            commitment.observation_authority_id,
            commitment.sample_execution_record_id,
            record_raw,
            record_sha256,
            record_size,
            raw,
            _sha(raw),
            len(raw.encode("utf-8")),
        ),
    )


def _insert_v2_sample(
    connection: sqlite3.Connection,
    record: M6UpgradeSampleExecutionRecordV2,
    *,
    observation_authority_id: str | None = None,
    record_document_sha256: str | None = None,
    raw_override: str | None = None,
) -> None:
    raw, document_sha256, size_bytes = _canonical_document(record)
    if raw_override is not None:
        raw = raw_override
        document_sha256 = _sha(raw)
        size_bytes = len(raw.encode("utf-8"))
    case = record.candidate_case
    connection.execute(
        """
        INSERT INTO m6_upgrade_sample_executions(
            run_id, execution_scope_authority_id, ledger_sequence,
            previous_ledger_entry_hash, command_id,
            execution_dataset_snapshot_id, execution_entry_id, sample_id,
            outcome, case_id, case_revision, case_document_sha256,
            case_audit_sequence, case_audit_entry_hash, artifact_link_count,
            artifact_link_inventory_root_sha256, sample_execution_record_id,
            record_json, record_document_sha256, record_size_bytes,
            record_schema_version, observation_authority_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'v2', ?)
        """,
        (
            record.candidate_run_id,
            record.execution_scope_authority_id,
            record.ledger_sequence,
            record.previous_ledger_entry_hash,
            record.command_id,
            record.execution_dataset_snapshot_id,
            record.execution_entry_id,
            record.sample_id,
            record.outcome.value,
            case.case_id if case is not None else None,
            case.case_revision if case is not None else None,
            case.case_document_sha256 if case is not None else None,
            case.case_audit_sequence if case is not None else None,
            case.case_audit_entry_hash if case is not None else None,
            record.artifact_link_count,
            record.artifact_link_inventory_root_sha256,
            record.sample_execution_record_id,
            raw,
            record_document_sha256 or document_sha256,
            size_bytes,
            observation_authority_id or record.observation_authority_id,
        ),
    )


def _insert_v2_seal(
    connection: sqlite3.Connection,
    seal: M6UpgradeExecutionLedgerSealV2,
    *,
    raw_override: str | None = None,
) -> None:
    raw, document_sha256, size_bytes = _canonical_document(seal)
    if raw_override is not None:
        raw = raw_override
        document_sha256 = _sha(raw)
        size_bytes = len(raw.encode("utf-8"))
    connection.execute(
        """
        INSERT INTO m6_upgrade_execution_ledger_seals(
            run_id, execution_scope_authority_id,
            execution_scope_document_sha256, execution_scope_size_bytes,
            source_audit_head_sequence, source_audit_head_hash,
            sample_execution_count, sample_execution_inventory_root_sha256,
            artifact_link_count, artifact_link_inventory_root_sha256,
            candidate_case_count, candidate_case_inventory_root_sha256,
            ledger_preseal_sequence, ledger_preseal_hash,
            ledger_head_sequence, ledger_seal_authority_id,
            seal_json, document_sha256, size_bytes, seal_schema_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'v2')
        """,
        (
            seal.candidate_run_id,
            seal.execution_scope.execution_scope_authority_id,
            seal.execution_scope_content_sha256,
            seal.execution_scope_size_bytes,
            seal.source_audit_head_sequence,
            seal.source_audit_head_hash,
            seal.sample_execution_count,
            seal.sample_execution_inventory_root_sha256,
            seal.artifact_link_count,
            seal.artifact_link_inventory_root_sha256,
            seal.candidate_case_count,
            seal.candidate_case_inventory_root_sha256,
            seal.ledger_preseal_sequence,
            seal.ledger_preseal_hash,
            seal.ledger_head_sequence,
            seal.ledger_seal_authority_id,
            raw,
            document_sha256,
            size_bytes,
        ),
    )


def _insert_v2_seal_or_replace_with_authority_id(
    connection: sqlite3.Connection,
    seal: M6UpgradeExecutionLedgerSealV2,
    authority_id: str,
) -> None:
    payload = seal.model_dump(mode="json")
    payload["ledger_seal_authority_id"] = authority_id
    raw = canonical_json(payload)
    connection.execute(
        """
        INSERT OR REPLACE INTO m6_upgrade_execution_ledger_seals(
            run_id, execution_scope_authority_id,
            execution_scope_document_sha256, execution_scope_size_bytes,
            source_audit_head_sequence, source_audit_head_hash,
            sample_execution_count, sample_execution_inventory_root_sha256,
            artifact_link_count, artifact_link_inventory_root_sha256,
            candidate_case_count, candidate_case_inventory_root_sha256,
            ledger_preseal_sequence, ledger_preseal_hash,
            ledger_head_sequence, ledger_seal_authority_id,
            seal_json, document_sha256, size_bytes, seal_schema_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'v2')
        """,
        (
            seal.candidate_run_id,
            seal.execution_scope.execution_scope_authority_id,
            seal.execution_scope_content_sha256,
            seal.execution_scope_size_bytes,
            seal.source_audit_head_sequence,
            seal.source_audit_head_hash,
            seal.sample_execution_count,
            seal.sample_execution_inventory_root_sha256,
            seal.artifact_link_count,
            seal.artifact_link_inventory_root_sha256,
            seal.candidate_case_count,
            seal.candidate_case_inventory_root_sha256,
            seal.ledger_preseal_sequence,
            seal.ledger_preseal_hash,
            seal.ledger_head_sequence,
            authority_id,
            raw,
            _sha(raw),
            len(raw.encode("utf-8")),
        ),
    )


def _no_case_bundle(
    *,
    omit_observed_detection: bool = False,
    oversized: bool = False,
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionRecordV2,
    M6UpgradePendingSampleCommitmentAuthority,
    M6UpgradeExecutionLedgerSealV2,
]:
    scope, source = _single_no_case_execution()
    observation = _observation_for(
        scope,
        source,
        omit_detection=omit_observed_detection,
    )
    links = source.artifact_links
    bypass_validation = False
    if oversized:
        frame = next(
            link for link in links if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
        )
        oversized_frame = frame.artifact.model_copy(
            update={"size_bytes": MAX_M6_UPGRADE_SAMPLE_PHYSICAL_BYTES + 1}
        )
        links = tuple(
            M6UpgradeSampleArtifactLink(
                ordinal=link.ordinal,
                usage=link.usage,
                artifact=(oversized_frame if link.ordinal == frame.ordinal else link.artifact),
            )
            for link in links
        )
        bypass_validation = True
    record = _v2_record(
        scope,
        source,
        observation,
        artifact_links=links,
        bypass_validation=bypass_validation,
    )
    commitment = _commitment(record, bypass_validation=bypass_validation)
    scope_raw, scope_sha256, scope_size = _canonical_document(scope)
    del scope_raw
    seal_values = {
        "schema_version": "m6-upgrade-execution-ledger-seal-v2",
        "execution_scope": scope,
        "execution_scope_content_sha256": scope_sha256,
        "execution_scope_size_bytes": scope_size,
        "source_audit_head_sequence": -1,
        "source_audit_head_hash": AUDIT_GENESIS_HASH,
        "sample_executions": (record,),
    }
    seal = (
        M6UpgradeExecutionLedgerSealV2.model_construct(**seal_values)
        if oversized
        else M6UpgradeExecutionLedgerSealV2(**seal_values)
    )
    return scope, observation, record, commitment, seal


def _no_case_bundle_for_run(
    candidate_run_id: str,
) -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionRecordV2,
    M6UpgradePendingSampleCommitmentAuthority,
    M6UpgradeExecutionLedgerSealV2,
]:
    base_scope, source = _single_no_case_execution()
    scope = base_scope.model_copy(update={"candidate_run_id": candidate_run_id})
    observation = _observation_for(scope, source)
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)
    _scope_raw, scope_sha256, scope_size = _canonical_document(scope)
    seal = M6UpgradeExecutionLedgerSealV2(
        execution_scope=scope,
        execution_scope_content_sha256=scope_sha256,
        execution_scope_size_bytes=scope_size,
        source_audit_head_sequence=-1,
        source_audit_head_hash=AUDIT_GENESIS_HASH,
        sample_executions=(record,),
    )
    return scope, observation, record, commitment, seal


def _insert_refs_and_links(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecord,
) -> None:
    for link in record.artifact_links:
        _insert_ref(connection, scope, link)
        _insert_link(connection, scope, record, link)


def _insert_ref_with_raw_json(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    link: M6UpgradeSampleArtifactLink,
    raw: str,
) -> None:
    ref = link.artifact
    connection.execute(
        """
        INSERT INTO m6_upgrade_physical_artifact_refs(
            run_id, execution_scope_authority_id, artifact_ref_id,
            source, kind, artifact_id, container_id,
            artifact_document_sha256, artifact_content_sha256,
            artifact_size_bytes, ref_json, ref_document_sha256,
            ref_size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            ref.artifact_ref_id,
            ref.source.value,
            ref.kind.value,
            ref.artifact_id,
            ref.container_id,
            ref.document_sha256,
            ref.content_sha256,
            ref.size_bytes,
            raw,
            _sha(raw),
            len(raw.encode("utf-8")),
        ),
    )


def _insert_legacy_sample_with_raw_json(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    record: M6UpgradeSampleExecutionRecord,
    raw: str,
) -> None:
    case = record.candidate_case
    connection.execute(
        """
        INSERT INTO m6_upgrade_sample_executions(
            run_id, execution_scope_authority_id, ledger_sequence,
            previous_ledger_entry_hash, command_id,
            execution_dataset_snapshot_id, execution_entry_id, sample_id,
            outcome, case_id, case_revision, case_document_sha256,
            case_audit_sequence, case_audit_entry_hash, artifact_link_count,
            artifact_link_inventory_root_sha256, sample_execution_record_id,
            record_json, record_document_sha256, record_size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            record.ledger_sequence,
            record.previous_ledger_entry_hash,
            record.command_id,
            record.execution_dataset_snapshot_id,
            record.execution_entry_id,
            record.sample_id,
            record.outcome.value,
            case.case_id if case is not None else None,
            case.case_revision if case is not None else None,
            case.case_document_sha256 if case is not None else None,
            case.case_audit_sequence if case is not None else None,
            case.case_audit_entry_hash if case is not None else None,
            record.artifact_link_count,
            record.artifact_link_inventory_root_sha256,
            record.sample_execution_record_id,
            raw,
            _sha(raw),
            len(raw.encode("utf-8")),
        ),
    )


def _insert_v2_protocol_and_scope(
    connection: sqlite3.Connection,
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    raw_override: str | None = None,
) -> None:
    raw, document_sha256, size_bytes = _canonical_document(scope)
    if raw_override is not None:
        raw = raw_override
        document_sha256 = _sha(raw)
        size_bytes = len(raw.encode("utf-8"))
    connection.execute(
        """
        INSERT INTO m6_upgrade_execution_ledger_protocols(
            run_id, execution_scope_authority_id, protocol_version
        ) VALUES (?, ?, 'v2')
        """,
        (scope.candidate_run_id, scope.execution_scope_authority_id),
    )
    connection.execute(
        """
        INSERT INTO m6_upgrade_execution_scopes(
            run_id, execution_scope_authority_id, command_id,
            execution_dataset_snapshot_id, candidate_manifest_id,
            candidate_manifest_document_sha256, candidate_config_sha256,
            execution_component_authority_id, expected_sample_count,
            execution_start_audit_head_sequence,
            execution_start_audit_head_hash, scope_json,
            document_sha256, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            scope.command.command_id,
            scope.execution_dataset.execution_dataset_snapshot_id,
            scope.candidate_manifest.manifest_id,
            scope.candidate_manifest_content_sha256,
            scope.candidate_config.config_sha256,
            scope.execution_component.component_authority_id,
            len(scope.execution_dataset.entries),
            scope.execution_start_audit_head_sequence,
            scope.execution_start_audit_head_hash,
            raw,
            document_sha256,
            size_bytes,
        ),
    )


def _register_v2_scope(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
) -> None:
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_v2_protocol_and_scope(connection, scope)


def _commit_observation_in_its_own_transaction(
    database: Path,
    observation: M6UpgradeSampleExecutionObservationAuthority,
) -> None:
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        connection.commit()


def _assert_pending_commitment_rejected_after_observation_commit(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
    observation: M6UpgradeSampleExecutionObservationAuthority,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
) -> None:
    _register_v2_scope(database, scope)
    _commit_observation_in_its_own_transaction(database, observation)

    with (
        pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ),
        closing(sqlite3.connect(database)) as connection,
    ):
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_commitment(connection, commitment)
        connection.commit()

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments"
        ).fetchone() == (0,)


def _install_migrations_through_0011(tmp_path: Path) -> tuple[Path, Path]:
    copied = tmp_path / "migrations"
    copied.mkdir()
    for version in range(1, 12):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, copied / source.name)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 12))
    return copied, database


def _assert_0012_preflight_rejects_atomically(database: Path, copied: Path) -> None:
    shutil.copy2(next(MIGRATIONS.glob("0012_*.sql")), copied)
    with pytest.raises(MigrationIntegrityError, match=r"migration 0012.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()

    with closing(sqlite3.connect(database)) as connection:
        assert (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 12").fetchone()
            is None
        )
        observed_new_objects = {
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                """
                SELECT type, name
                FROM sqlite_master
                WHERE name IN (
                    'm6_upgrade_observation_backed_ledger_preflight',
                    'm6_upgrade_execution_ledger_protocols',
                    'm6_upgrade_pending_sample_commitments',
                    'm6_upgrade_execution_scopes_require_complete_json',
                    'm6_upgrade_physical_artifact_refs_require_complete_json',
                    'm6_upgrade_sample_artifact_links_require_complete_json'
                )
                """
            )
        }
        assert observed_new_objects == set()
        sample_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(m6_upgrade_sample_executions)")
        }
        seal_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(m6_upgrade_execution_ledger_seals)")
        }
        assert {"record_schema_version", "observation_authority_id"}.isdisjoint(sample_columns)
        assert "seal_schema_version" not in seal_columns


def test_pre_0012_legacy_rows_upgrade_as_v1_without_wire_rewrite(tmp_path: Path) -> None:
    copied = tmp_path / "migrations"
    copied.mkdir()
    for version in range(1, 12):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, copied / source.name)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == tuple(range(1, 12))
    scope, record = _single_no_case_execution()
    _register_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_refs_and_links(connection, scope, record)
        _insert_sample(connection, scope, record)
    shutil.copy2(next(MIGRATIONS.glob("0012_*.sql")), copied)

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (12,)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT record_schema_version, observation_authority_id, record_json
            FROM m6_upgrade_sample_executions
            """
        ).fetchone()
        assert row == (
            "v1",
            None,
            canonical_json(record.model_dump(mode="json")),
        )
        assert connection.execute(
            "SELECT protocol_version FROM m6_upgrade_execution_ledger_protocols"
        ).fetchone() == ("v1",)


def test_pre_0012_pending_observation_upgrades_to_v2_protocol(tmp_path: Path) -> None:
    copied = tmp_path / "migrations"
    copied.mkdir()
    for version in range(1, 12):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, copied / source.name)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, source = _single_no_case_execution()
    observation = _observation_for(scope, source)
    _register_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
    shutil.copy2(next(MIGRATIONS.glob("0012_*.sql")), copied)

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all() == (12,)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT protocol_version FROM m6_upgrade_execution_ledger_protocols"
        ).fetchone() == ("v2",)


def test_0012_preflight_rejects_observation_mixed_with_legacy_sample(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    copied.mkdir()
    for version in range(1, 12):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, copied / source.name)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, record = _single_no_case_execution()
    observation = _observation_for(scope, record)
    _register_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_refs_and_links(connection, scope, record)
        _insert_sample(connection, scope, record)
    shutil.copy2(next(MIGRATIONS.glob("0012_*.sql")), copied)

    with pytest.raises(MigrationIntegrityError, match=r"migration 0012.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()


def test_0012_preflight_rejects_gapped_legacy_artifact_link_ordinals(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "migrations"
    copied.mkdir()
    for version in range(1, 12):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, copied / source.name)
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()
    scope, record = _single_no_case_execution()
    record_values = {name: getattr(record, name) for name in type(record).model_fields}
    record_values["artifact_links"] = (
        record.artifact_links[0],
        record.artifact_links[1].model_copy(update={"ordinal": 2}),
    )
    gapped_record = M6UpgradeSampleExecutionRecord.model_construct(**record_values)
    _register_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_refs_and_links(connection, scope, gapped_record)
        _insert_sample(connection, scope, gapped_record)
    shutil.copy2(next(MIGRATIONS.glob("0012_*.sql")), copied)

    with pytest.raises(MigrationIntegrityError, match=r"migration 0012.*failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied).apply_all()


@pytest.mark.parametrize("malformation", ("physical_ref_json", "sample_record_json"))
def test_0012_preflight_atomically_rejects_historical_incomplete_json_authority(
    tmp_path: Path,
    malformation: str,
) -> None:
    copied, database = _install_migrations_through_0011(tmp_path)
    scope, record = _single_no_case_execution()
    _register_scope(database, scope)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        if malformation == "physical_ref_json":
            _insert_ref_with_raw_json(
                connection,
                scope,
                record.artifact_links[0],
                "{}",
            )
        else:
            _insert_refs_and_links(connection, scope, record)
            record_payload = record.model_dump(mode="json")
            del record_payload["candidate_run_id"]
            _insert_legacy_sample_with_raw_json(
                connection,
                scope,
                record,
                canonical_json(record_payload),
            )
        connection.commit()

    with closing(sqlite3.connect(database)) as connection:
        if malformation == "physical_ref_json":
            assert connection.execute(
                "SELECT ref_json FROM m6_upgrade_physical_artifact_refs"
            ).fetchone() == ("{}",)
        else:
            assert connection.execute(
                "SELECT json_type(record_json, '$.candidate_run_id') "
                "FROM m6_upgrade_sample_executions"
            ).fetchone() == (None,)

    _assert_0012_preflight_rejects_atomically(database, copied)


def test_pending_commitment_rejects_non_model_observation_link_set_drift_across_transactions(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, _record, commitment, _seal = _no_case_bundle(omit_observed_detection=True)

    _assert_pending_commitment_rejected_after_observation_commit(
        database,
        scope,
        observation,
        commitment,
    )


def test_pending_commitment_rejects_gapped_artifact_link_ordinal_across_transactions(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    observation = _observation_for(scope, source)
    links = (
        source.artifact_links[0],
        source.artifact_links[1].model_copy(update={"ordinal": 2}),
    )
    record = _v2_record(
        scope,
        source,
        observation,
        artifact_links=links,
        bypass_validation=True,
    )
    commitment = _commitment(record, bypass_validation=True)

    _assert_pending_commitment_rejected_after_observation_commit(
        database,
        scope,
        observation,
        commitment,
    )


def test_pending_commitment_rejects_reversed_physical_key_order_across_transactions(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    observation = _observation_for(scope, source)
    links = (
        source.artifact_links[1].model_copy(update={"ordinal": 0}),
        source.artifact_links[0].model_copy(update={"ordinal": 1}),
    )
    assert links[0].physical_key > links[1].physical_key
    record = _v2_record(
        scope,
        source,
        observation,
        artifact_links=links,
        bypass_validation=True,
    )
    commitment = _commitment(record, bypass_validation=True)

    _assert_pending_commitment_rejected_after_observation_commit(
        database,
        scope,
        observation,
        commitment,
    )


def test_pending_commitment_rejects_detection_without_candidate_frame_across_transactions(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    observation = _observation_for(scope, source)
    frame_link, detection_link = source.artifact_links
    camera_id, stream_id, _frame_index = frame_link.artifact.artifact_id.split(":")
    missing_frame_id = f"{camera_id}:{stream_id}:999"
    assert all(
        link.artifact.artifact_id != missing_frame_id
        for link in source.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    orphaned_detection = detection_link.artifact.model_copy(
        update={"container_id": missing_frame_id}
    )
    links = (
        frame_link,
        M6UpgradeSampleArtifactLink(
            ordinal=1,
            usage=detection_link.usage,
            artifact=orphaned_detection,
        ),
    )
    record = _v2_record(
        scope,
        source,
        observation,
        artifact_links=links,
        bypass_validation=True,
    )
    commitment = _commitment(record, bypass_validation=True)

    _assert_pending_commitment_rejected_after_observation_commit(
        database,
        scope,
        observation,
        commitment,
    )


@pytest.mark.parametrize("duplicate_kind", ("physical_key", "artifact_ref_id"))
def test_pending_commitment_rejects_candidate_internal_artifact_identity_duplicates(
    tmp_path: Path,
    duplicate_kind: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    observation = _observation_for(scope, source)
    frame_link, detection_link = source.artifact_links
    duplicate_artifact = frame_link.artifact
    if duplicate_kind == "physical_key":
        duplicate_sha256 = _sha("conflicting-frame-physical-content")
        duplicate_artifact = frame_link.artifact.model_copy(
            update={
                "document_sha256": duplicate_sha256,
                "content_sha256": duplicate_sha256,
                "size_bytes": frame_link.artifact.size_bytes + 1,
            }
        )
        assert duplicate_artifact.physical_key == frame_link.artifact.physical_key
        assert duplicate_artifact.artifact_ref_id != frame_link.artifact.artifact_ref_id
    else:
        assert duplicate_artifact.artifact_ref_id == frame_link.artifact.artifact_ref_id

    links = (
        frame_link,
        M6UpgradeSampleArtifactLink(
            ordinal=1,
            usage=frame_link.usage,
            artifact=duplicate_artifact,
        ),
        detection_link.model_copy(update={"ordinal": 2}),
    )
    record = _v2_record(
        scope,
        source,
        observation,
        artifact_links=links,
        bypass_validation=True,
    )
    commitment = _commitment(record, bypass_validation=True)

    _assert_pending_commitment_rejected_after_observation_commit(
        database,
        scope,
        observation,
        commitment,
    )


def test_pending_commitment_accepts_minimal_exact_chain_across_transactions(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, _record, commitment, _seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    _commit_observation_in_its_own_transaction(database, observation)

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_commitment(connection, commitment)
        connection.commit()

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            """
            SELECT pending_sample_commitment_authority_id
            FROM m6_upgrade_pending_sample_commitments
            """
        ).fetchall() == [(commitment.pending_sample_commitment_authority_id,)]


def test_scope_rejects_missing_candidate_run_id_despite_correct_normalized_columns(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, _source = _single_no_case_execution()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    scope_payload = scope.model_dump(mode="json")
    del scope_payload["candidate_run_id"]
    malformed_scope_json = canonical_json(scope_payload)

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade execution scope",
        ):
            _insert_v2_protocol_and_scope(
                connection,
                scope,
                raw_override=malformed_scope_json,
            )

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_execution_scopes"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_execution_ledger_protocols"
        ).fetchone() == (0,)


def test_physical_ref_rejects_empty_json_despite_correct_normalized_columns(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    link = source.artifact_links[0]
    _register_v2_scope(database, scope)
    malformed_ref_json = "{}"

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade physical artifact ref",
        ):
            _insert_ref_with_raw_json(connection, scope, link, malformed_ref_json)

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_physical_artifact_refs"
        ).fetchone() == (0,)


def test_artifact_link_rejects_missing_required_top_level_json_field(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    link = source.artifact_links[0]
    _register_v2_scope(database, scope)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_ref(connection, scope, link)
        connection.commit()

    link_payload = link.model_dump(mode="json")
    del link_payload["artifact_link_id"]
    malformed_link_json = canonical_json(link_payload)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade sample artifact link",
        ):
            connection.execute(
                """
                INSERT INTO m6_upgrade_sample_artifact_links(
                    run_id, execution_entry_id, ordinal, usage, artifact_ref_id,
                    artifact_link_id, link_json, link_document_sha256,
                    link_size_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope.candidate_run_id,
                    source.execution_entry_id,
                    link.ordinal,
                    link.usage.value,
                    link.artifact.artifact_ref_id,
                    link.artifact_link_id,
                    malformed_link_json,
                    _sha(malformed_link_json),
                    len(malformed_link_json.encode("utf-8")),
                ),
            )

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_sample_artifact_links"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_physical_artifact_refs"
        ).fetchone() == (1,)


def test_v2_sample_rejects_missing_candidate_run_id_despite_correct_normalized_columns(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, record, commitment, _seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        for link in record.artifact_links:
            _insert_ref(connection, scope, link)
        connection.commit()

    record_payload = record.model_dump(mode="json")
    del record_payload["candidate_run_id"]
    malformed_record_json = canonical_json(record_payload)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for link in record.artifact_links:
            _insert_link(connection, scope, record, link)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 observation-backed sample execution",
        ):
            _insert_v2_sample(
                connection,
                record,
                raw_override=malformed_record_json,
            )

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_sample_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_sample_artifact_links"
        ).fetchone() == (0,)


def test_v2_seal_rejects_missing_source_audit_head_hash_despite_correct_normalized_columns(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, record, commitment, seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)
        connection.commit()

    seal_payload = seal.model_dump(mode="json")
    del seal_payload["source_audit_head_hash"]
    malformed_seal_json = canonical_json(seal_payload)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade ledger schema-version closure",
        ):
            _insert_v2_seal(
                connection,
                seal,
                raw_override=malformed_seal_json,
            )

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_execution_ledger_seals"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m6_upgrade_sample_executions"
        ).fetchone() == (1,)


def test_minimal_observation_backed_v2_chain_writes_and_seals(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, record, commitment, seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)
        _insert_v2_seal(connection, seal)
        connection.commit()
        assert connection.execute(
            "SELECT record_schema_version, observation_authority_id "
            "FROM m6_upgrade_sample_executions"
        ).fetchone() == ("v2", observation.observation_authority_id)
        assert connection.execute(
            "SELECT seal_schema_version FROM m6_upgrade_execution_ledger_seals"
        ).fetchone() == ("v2",)


@pytest.mark.parametrize(
    "malformation",
    ("missing_observation", "missing_commitment", "wrong_observation", "wrong_commitment"),
)
def test_v2_sample_requires_the_exact_observation_and_commitment(
    tmp_path: Path,
    malformation: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, record, commitment, _seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        if malformation != "missing_observation":
            _insert_observation(connection, observation)
        if malformation not in {"missing_observation", "missing_commitment"}:
            _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 observation-backed sample execution",
        ):
            _insert_v2_sample(
                connection,
                record,
                observation_authority_id=(_FORGED if malformation == "wrong_observation" else None),
                record_document_sha256=(_FORGED if malformation == "wrong_commitment" else None),
            )
        connection.rollback()


def test_v1_sample_cannot_consume_a_pending_observation(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    observation = _observation_for(scope, source)
    _register_v2_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_refs_and_links(connection, scope, source)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 observation-backed sample execution",
        ):
            _insert_sample(connection, scope, source)
        connection.rollback()


def test_pending_commitment_rejects_non_model_observation_link_set_drift(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, _record, commitment, _seal = _no_case_bundle(omit_observed_detection=True)
    _register_v2_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ):
            _insert_commitment(connection, commitment)
        connection.rollback()


def test_pending_commitment_rejects_duplicate_detection_identity_across_containers(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    frame_link = next(
        link
        for link in source.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
    )
    detection_link = next(
        link
        for link in source.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.DETECTION
    )
    camera_id, stream_id, _frame_index = frame_link.artifact.artifact_id.split(":")
    second_frame_id = f"{camera_id}:{stream_id}:1"
    second_frame = frame_link.artifact.model_copy(
        update={
            "artifact_id": second_frame_id,
            "document_sha256": _sha("second-frame-document"),
            "content_sha256": _sha("second-frame-content"),
            "size_bytes": frame_link.artifact.size_bytes + 1,
        }
    )
    duplicate_detection = detection_link.artifact.model_copy(
        update={
            "container_id": second_frame_id,
            "document_sha256": _sha("duplicate-detection"),
            "content_sha256": _sha("duplicate-detection"),
            "size_bytes": detection_link.artifact.size_bytes + 1,
        }
    )
    links = (
        frame_link.model_copy(update={"ordinal": 0}),
        M6UpgradeSampleArtifactLink(
            ordinal=1,
            usage=frame_link.usage,
            artifact=second_frame,
        ),
        detection_link.model_copy(update={"ordinal": 2}),
        M6UpgradeSampleArtifactLink(
            ordinal=3,
            usage=detection_link.usage,
            artifact=duplicate_detection,
        ),
    )
    observed_source = source.model_copy(update={"artifact_links": links[:-1]})
    observation = _observation_for(scope, observed_source)
    record = _v2_record(scope, source, observation, artifact_links=links)
    commitment = _commitment(record)
    _register_v2_scope(database, scope)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ):
            _insert_commitment(connection, commitment)
        connection.rollback()


def test_pending_commitment_rejects_a_gapped_artifact_link_ordinal(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source = _single_no_case_execution()
    observation = _observation_for(scope, source)
    links = (
        source.artifact_links[0],
        source.artifact_links[1].model_copy(update={"ordinal": 2}),
    )
    record = _v2_record(
        scope,
        source,
        observation,
        artifact_links=links,
        bypass_validation=True,
    )
    commitment = _commitment(record, bypass_validation=True)
    _register_v2_scope(database, scope)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ):
            _insert_commitment(connection, commitment)
        connection.rollback()


def test_pending_commitment_rejects_aggregate_physical_bytes_above_256_mib_across_transactions(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, _record, commitment, _seal = _no_case_bundle(oversized=True)

    _assert_pending_commitment_rejected_after_observation_commit(
        database,
        scope,
        observation,
        commitment,
    )


def _candidate_case_binding(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
) -> M6UpgradeCandidateCaseBinding:
    repository = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    event = _event().model_copy(update={"manifest_id": scope.candidate_manifest.manifest_id})
    snapshot = repository.create_or_get_case(scope.candidate_run_id, event)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT version.document_sha256, version.audit_sequence, audit.entry_hash
            FROM case_versions AS version
            JOIN audit_entries AS audit
              ON audit.run_id = version.run_id
             AND audit.sequence = version.audit_sequence
            WHERE version.run_id = ? AND version.case_id = ? AND version.revision = 1
            """,
            (scope.candidate_run_id, snapshot.case.case_id),
        ).fetchone()
    assert row is not None
    return M6UpgradeCandidateCaseBinding(
        case_id=snapshot.case.case_id,
        case_revision=1,
        case_document_sha256=str(row[0]),
        case_audit_sequence=int(row[1]),
        case_audit_entry_hash=str(row[2]),
    )


def test_pending_commitment_rejects_a_model_request_without_runtime_observation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope = _inventory().execution_ledger.execution_scope
    _register_v2_scope(database, scope)
    binding = _candidate_case_binding(database, scope)
    source = next(
        record
        for record in _inventory().execution_ledger.sample_executions
        if record.candidate_case is not None
    ).model_copy(
        update={
            "execution_entry": scope.execution_dataset.entries[0],
            "ledger_sequence": 0,
            "previous_ledger_entry_hash": M6_UPGRADE_LEDGER_GENESIS_HASH,
        }
    )
    observation = _observation_for(scope, source, candidate_case=binding)
    record = _v2_record(scope, source, observation)
    commitment = _commitment(record)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="invalid M6 upgrade pending sample commitment",
        ):
            _insert_commitment(connection, commitment)
        connection.rollback()


def test_v2_seal_rejects_a_pending_observation(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope = _inventory().execution_ledger.execution_scope
    source_records = _inventory().execution_ledger.sample_executions
    _register_v2_scope(database, scope)
    observations: list[M6UpgradeSampleExecutionObservationAuthority] = []
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for sequence, source in enumerate(source_records):
            frame_only = M6UpgradeSampleExecutionRecord.model_construct(
                schema_version="m6-upgrade-sample-execution-record-v1",
                execution_scope_authority_id=scope.execution_scope_authority_id,
                candidate_run_id=scope.candidate_run_id,
                command_id=scope.command.command_id,
                execution_dataset_snapshot_id=(
                    scope.execution_dataset.execution_dataset_snapshot_id
                ),
                execution_entry=scope.execution_dataset.entries[sequence],
                outcome=M6ReplayExecutionOutcome.NO_CASE,
                candidate_case=None,
                artifact_links=(
                    next(
                        link
                        for link in source.artifact_links
                        if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
                    ).model_copy(update={"ordinal": 0}),
                ),
                ledger_sequence=sequence,
                previous_ledger_entry_hash=previous,
            )
            observation = _observation_for(scope, frame_only)
            record = _v2_record(scope, frame_only, observation)
            record = record.model_copy(update={"previous_ledger_entry_hash": previous})
            _insert_observation(connection, observation)
            observations.append(observation)
            if sequence == len(source_records) - 1:
                break
            commitment = _commitment(record)
            _insert_commitment(connection, commitment)
            _insert_refs_and_links(connection, scope, record)
            _insert_v2_sample(connection, record)
            records.append(record)
            previous = record.sample_execution_record_id

        forged_seal = M6UpgradeExecutionLedgerSealV2.model_construct(
            schema_version="m6-upgrade-execution-ledger-seal-v2",
            execution_scope=scope,
            execution_scope_content_sha256=_canonical_document(scope)[1],
            execution_scope_size_bytes=_canonical_document(scope)[2],
            source_audit_head_sequence=-1,
            source_audit_head_hash=AUDIT_GENESIS_HASH,
            sample_executions=tuple(records),
        )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_v2_seal(connection, forged_seal)
        connection.rollback()


def test_pending_commitment_is_append_only(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, _record, commitment, _seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m6_upgrade_pending_sample_commitments SET size_bytes = size_bytes"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m6_upgrade_pending_sample_commitments")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_commitment(connection, commitment)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m6_upgrade_execution_ledger_protocols "
                "SET protocol_version = protocol_version"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m6_upgrade_execution_ledger_protocols")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT INTO m6_upgrade_execution_ledger_protocols(
                    run_id, execution_scope_authority_id, protocol_version
                ) VALUES (?, ?, 'v2')
                """,
                (scope.candidate_run_id, scope.execution_scope_authority_id),
            )
        connection.rollback()


def test_cross_run_replace_cannot_erase_a_pending_commitment(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    bundle_a = _no_case_bundle_for_run("candidate-run-a")
    bundle_b = _no_case_bundle_for_run("candidate-run-b")
    scope_a, observation_a, record_a, commitment_a, _seal_a = bundle_a
    scope_b, observation_b, _record_b, commitment_b, _seal_b = bundle_b
    _register_v2_scope(database, scope_a)
    _register_v2_scope(database, scope_b)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        _insert_observation(connection, observation_a)
        _insert_commitment(connection, commitment_a)
        _insert_refs_and_links(connection, scope_a, record_a)
        _insert_v2_sample(connection, record_a)
        _insert_observation(connection, observation_b)
        connection.commit()

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            _insert_commitment_or_replace_with_authority_id(
                connection,
                commitment_b,
                commitment_a.pending_sample_commitment_authority_id,
            )
        assert connection.execute(
            """
            SELECT run_id, pending_sample_commitment_authority_id
            FROM m6_upgrade_pending_sample_commitments
            """
        ).fetchall() == [
            (
                scope_a.candidate_run_id,
                commitment_a.pending_sample_commitment_authority_id,
            )
        ]


def test_cross_run_replace_cannot_erase_a_sealed_ledger(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    bundle_a = _no_case_bundle_for_run("candidate-run-a")
    bundle_b = _no_case_bundle_for_run("candidate-run-b")
    scope_a, observation_a, record_a, commitment_a, seal_a = bundle_a
    scope_b, observation_b, record_b, commitment_b, seal_b = bundle_b
    _register_v2_scope(database, scope_a)
    _register_v2_scope(database, scope_b)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for scope, observation, record, commitment in (
            (scope_a, observation_a, record_a, commitment_a),
            (scope_b, observation_b, record_b, commitment_b),
        ):
            _insert_observation(connection, observation)
            _insert_commitment(connection, commitment)
            _insert_refs_and_links(connection, scope, record)
            _insert_v2_sample(connection, record)
        _insert_v2_seal(connection, seal_a)
        connection.commit()

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            _insert_v2_seal_or_replace_with_authority_id(
                connection,
                seal_b,
                seal_a.ledger_seal_authority_id,
            )
        assert connection.execute(
            """
            SELECT run_id, ledger_seal_authority_id
            FROM m6_upgrade_execution_ledger_seals
            """
        ).fetchall() == [(scope_a.candidate_run_id, seal_a.ledger_seal_authority_id)]
