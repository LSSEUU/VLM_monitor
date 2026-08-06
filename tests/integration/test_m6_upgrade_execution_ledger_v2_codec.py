from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage import (
    _sqlite_m6_upgrade_execution_ledger_v2_codec as v2_codec,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_execution_ledger_codec import (
    MAX_M6_UPGRADE_RECORD_BYTES,
    MAX_M6_UPGRADE_SEAL_BYTES,
    StoredM6UpgradeScope,
    scope_from_row,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_execution_ledger_v2_codec import (
    record_v2_from_connection,
    records_v2_from_connection,
    seal_v2_from_row,
)
from labcourt.adapters.storage.sqlite_repository import MigrationRunner
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
)
from tests.integration.test_m6_upgrade_execution_ledger_migration import (
    AUDIT_GENESIS_HASH,
    BUSY_TIMEOUT_MS,
    _canonical_document,
    _register_scope,
    _single_no_case_execution,
)
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _scope_and_no_case_records,
)
from tests.integration.test_m6_upgrade_observation_backed_ledger_migration import (
    _commitment,
    _insert_commitment,
    _insert_observation,
    _insert_refs_and_links,
    _insert_v2_sample,
    _insert_v2_seal,
    _no_case_bundle,
    _observation_for,
    _register_v2_scope,
)


def _open(database: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _database(tmp_path: Path, label: str) -> Path:
    workspace = tmp_path / label
    workspace.mkdir()
    return workspace / "labcourt.sqlite3"


def _stored_scope(connection: sqlite3.Connection, run_id: str) -> StoredM6UpgradeScope:
    row = connection.execute(
        "SELECT * FROM m6_upgrade_execution_scopes WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert row is not None
    return scope_from_row(row)


def _install_single_v2(
    database: Path,
    *,
    sealed: bool,
) -> tuple[
    StoredM6UpgradeScope,
    M6UpgradeSampleExecutionRecordV2,
    M6UpgradeExecutionLedgerSealV2,
]:
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, observation, record, commitment, seal = _no_case_bundle()
    _register_v2_scope(database, scope)
    with _open(database) as connection:
        _insert_observation(connection, observation)
        _insert_commitment(connection, commitment)
        _insert_refs_and_links(connection, scope, record)
        _insert_v2_sample(connection, record)
        if sealed:
            _insert_v2_seal(connection, seal)
        stored_scope = _stored_scope(connection, scope.candidate_run_id)
    return stored_scope, record, seal


def _install_v2_prefix(
    database: Path,
) -> tuple[
    StoredM6UpgradeScope,
    tuple[M6UpgradeSampleExecutionRecordV2, ...],
    M6UpgradeExecutionLedgerSealV2,
]:
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, source_records = _scope_and_no_case_records()
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    records: list[M6UpgradeSampleExecutionRecordV2] = []
    observations = []
    commitments = []
    for source in source_records:
        observation = _observation_for(scope, source)
        record = M6UpgradeSampleExecutionRecordV2(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            execution_entry=source.execution_entry,
            outcome=source.outcome,
            candidate_case=source.candidate_case,
            artifact_links=source.artifact_links,
            ledger_sequence=source.ledger_sequence,
            previous_ledger_entry_hash=previous,
            observation_authority_id=observation.observation_authority_id,
        )
        observations.append(observation)
        records.append(record)
        commitments.append(_commitment(record))
        previous = record.sample_execution_record_id

    _scope_raw, scope_sha256, scope_size = _canonical_document(scope)
    seal = M6UpgradeExecutionLedgerSealV2(
        execution_scope=scope,
        execution_scope_content_sha256=scope_sha256,
        execution_scope_size_bytes=scope_size,
        source_audit_head_sequence=-1,
        source_audit_head_hash=AUDIT_GENESIS_HASH,
        sample_executions=tuple(records),
    )
    _register_v2_scope(database, scope)
    with _open(database) as connection:
        for observation, commitment, record in zip(
            observations,
            commitments,
            records,
            strict=True,
        ):
            _insert_observation(connection, observation)
            _insert_commitment(connection, commitment)
            _insert_refs_and_links(connection, scope, record)
            _insert_v2_sample(connection, record)
        _insert_v2_seal(connection, seal)
        stored_scope = _stored_scope(connection, scope.candidate_run_id)
    return stored_scope, tuple(records), seal


def _assert_failure(
    expected: M6UpgradeExecutionLedgerV2FailureCode,
    operation: object,
) -> None:
    assert callable(operation)
    with pytest.raises(M6UpgradeExecutionLedgerV2Error) as rejected:
        operation()
    assert rejected.value.reason_code == expected
    assert vars(rejected.value) == {"reason_code": expected}


def test_v2_codec_loads_one_record_complete_prefix_and_exact_seal(tmp_path: Path) -> None:
    single_database = _database(tmp_path, "single")
    single_scope, single_record, _single_seal = _install_single_v2(
        single_database,
        sealed=False,
    )
    with _open(single_database) as connection:
        assert (
            record_v2_from_connection(
                connection,
                single_record.candidate_run_id,
                single_record.execution_entry_id,
            )
            == single_record
        )
        assert records_v2_from_connection(connection, single_scope) == (single_record,)

    prefix_database = _database(tmp_path, "prefix")
    stored_scope, records, expected_seal = _install_v2_prefix(prefix_database)
    with _open(prefix_database) as connection:
        assert records_v2_from_connection(connection, stored_scope) == records
        row = connection.execute(
            "SELECT * FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
            (stored_scope.authority.candidate_run_id,),
        ).fetchone()
        assert row is not None
        observed_seal = seal_v2_from_row(connection, row, stored_scope, records)
        assert type(observed_seal) is M6UpgradeExecutionLedgerSealV2
        assert observed_seal == expected_seal


def test_v2_codec_rejects_v1_protocol_before_record_or_seal_dispatch(tmp_path: Path) -> None:
    database = _database(tmp_path, "legacy")
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    scope, _record = _single_no_case_execution()
    _register_scope(database, scope)
    with _open(database) as connection:
        stored_scope = _stored_scope(connection, scope.candidate_run_id)
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED,
            lambda: records_v2_from_connection(connection, stored_scope),
        )

    sealed_database = _database(tmp_path, "legacy-dispatch")
    stored_scope, record, _seal = _install_single_v2(sealed_database, sealed=True)
    with _open(sealed_database) as connection:
        connection.execute("DROP TRIGGER m6_upgrade_execution_ledger_protocols_no_update")
        connection.execute(
            "UPDATE m6_upgrade_execution_ledger_protocols SET protocol_version = 'v1'"
        )
        connection.commit()
        seal_row = connection.execute("SELECT * FROM m6_upgrade_execution_ledger_seals").fetchone()
        assert seal_row is not None
        operations = (
            lambda: record_v2_from_connection(
                connection,
                stored_scope.authority.candidate_run_id,
                record.execution_entry_id,
            ),
            lambda: records_v2_from_connection(connection, stored_scope),
            lambda: seal_v2_from_row(
                connection,
                seal_row,
                stored_scope,
                (record,),
            ),
        )
        for operation in operations:
            _assert_failure(
                M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED,
                operation,
            )


@pytest.mark.parametrize(
    ("protocol_version", "record_version", "expected"),
    (
        (
            "future",
            "v2",
            M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID,
        ),
        (
            "v2",
            "future",
            M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID,
        ),
    ),
)
def test_v2_codec_rejects_unknown_protocol_and_record_versions_before_raw_read(
    protocol_version: str,
    record_version: str,
    expected: M6UpgradeExecutionLedgerV2FailureCode,
) -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            """
            CREATE TABLE m6_upgrade_execution_scopes(
                run_id TEXT,
                execution_scope_authority_id TEXT
            );
            CREATE TABLE m6_upgrade_execution_ledger_protocols(
                run_id TEXT,
                execution_scope_authority_id TEXT,
                protocol_version TEXT
            );
            CREATE TABLE m6_upgrade_sample_executions(
                run_id TEXT,
                execution_entry_id TEXT,
                record_schema_version TEXT,
                observation_authority_id TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO m6_upgrade_execution_scopes VALUES ('run', ?)",
            ("a" * 64,),
        )
        connection.execute(
            "INSERT INTO m6_upgrade_execution_ledger_protocols VALUES ('run', ?, ?)",
            ("a" * 64, protocol_version),
        )
        connection.execute(
            "INSERT INTO m6_upgrade_sample_executions VALUES ('run', 'entry', ?, ?)",
            (record_version, "b" * 64),
        )
        _assert_failure(
            expected,
            lambda: record_v2_from_connection(connection, "run", "entry"),
        )
    finally:
        connection.close()


@pytest.mark.parametrize(
    "malformation",
    ("short_version", "missing_observation", "observation_drift", "normalized_drift"),
)
def test_v2_record_codec_rejects_version_observation_and_normalized_column_drift(
    tmp_path: Path,
    malformation: str,
) -> None:
    database = _database(tmp_path, malformation)
    stored_scope, record, _seal = _install_single_v2(database, sealed=False)
    with _open(database) as connection:
        connection.execute("DROP TRIGGER m6_upgrade_sample_executions_no_update")
        if malformation == "short_version":
            connection.execute(
                "UPDATE m6_upgrade_sample_executions SET record_schema_version = 'v1'"
            )
        elif malformation == "missing_observation":
            connection.execute(
                "UPDATE m6_upgrade_sample_executions SET observation_authority_id = NULL"
            )
        elif malformation == "observation_drift":
            connection.execute(
                "UPDATE m6_upgrade_sample_executions SET observation_authority_id = ?",
                ("f" * 64,),
            )
        else:
            connection.execute(
                "UPDATE m6_upgrade_sample_executions SET sample_id = 'normalized-drift'"
            )
        connection.commit()
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID,
            lambda: record_v2_from_connection(
                connection,
                stored_scope.authority.candidate_run_id,
                record.execution_entry_id,
            ),
        )


def test_v2_prefix_codec_rejects_mixed_versions_link_drift_and_broken_chain(
    tmp_path: Path,
) -> None:
    for malformation in ("mixed_version", "link_drift", "broken_chain"):
        database = _database(tmp_path, malformation)
        stored_scope, records, _seal = _install_v2_prefix(database)
        with _open(database) as connection:
            if malformation == "mixed_version":
                connection.execute("DROP TRIGGER m6_upgrade_sample_executions_no_update")
                connection.execute(
                    """
                    UPDATE m6_upgrade_sample_executions
                    SET record_schema_version = 'v1', observation_authority_id = NULL
                    WHERE ledger_sequence = 1
                    """
                )
            elif malformation == "link_drift":
                connection.execute("DROP TRIGGER m6_upgrade_sample_artifact_links_no_update")
                connection.execute(
                    """
                    UPDATE m6_upgrade_sample_artifact_links
                    SET usage = 'PRODUCED'
                    WHERE execution_entry_id = ? AND ordinal = 0
                    """,
                    (records[1].execution_entry_id,),
                )
            else:
                connection.execute("DROP TRIGGER m6_upgrade_sample_executions_no_update")
                changed = records[1].model_copy(update={"previous_ledger_entry_hash": "e" * 64})
                raw, document_sha256, size_bytes = _canonical_document(changed)
                connection.execute(
                    """
                    UPDATE m6_upgrade_sample_executions
                    SET previous_ledger_entry_hash = ?,
                        sample_execution_record_id = ?, record_json = ?,
                        record_document_sha256 = ?, record_size_bytes = ?
                    WHERE ledger_sequence = 1
                    """,
                    (
                        changed.previous_ledger_entry_hash,
                        changed.sample_execution_record_id,
                        raw,
                        document_sha256,
                        size_bytes,
                    ),
                )
            connection.commit()
            with pytest.raises(M6UpgradeExecutionLedgerV2Error) as rejected:
                records_v2_from_connection(connection, stored_scope)
            assert rejected.value.reason_code == (
                M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID
            )


@pytest.mark.parametrize("malformation", ("short_version", "normalized_drift"))
def test_v2_seal_codec_rejects_version_and_normalized_drift(
    tmp_path: Path,
    malformation: str,
) -> None:
    database = _database(tmp_path, f"seal-{malformation}")
    stored_scope, record, _seal = _install_single_v2(database, sealed=True)
    with _open(database) as connection:
        connection.execute("DROP TRIGGER m6_upgrade_execution_ledger_seals_no_update")
        if malformation == "short_version":
            connection.execute(
                "UPDATE m6_upgrade_execution_ledger_seals SET seal_schema_version = 'v1'"
            )
        else:
            connection.execute(
                "UPDATE m6_upgrade_execution_ledger_seals SET ledger_head_sequence = 2"
            )
        connection.commit()
        row = connection.execute("SELECT * FROM m6_upgrade_execution_ledger_seals").fetchone()
        assert row is not None
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID,
            lambda: seal_v2_from_row(connection, row, stored_scope, (record,)),
        )


def test_v2_record_oversize_is_rejected_before_pydantic_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path, "oversized-record")
    stored_scope, record, _seal = _install_single_v2(database, sealed=False)
    with _open(database) as connection:
        connection.execute("DROP TRIGGER m6_upgrade_sample_executions_no_update")
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE m6_upgrade_sample_executions SET record_size_bytes = ?",
            (MAX_M6_UPGRADE_RECORD_BYTES + 1,),
        )
        connection.commit()

        def forbidden_parse(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("oversized record reached Pydantic")

        monkeypatch.setattr(
            M6UpgradeSampleExecutionRecordV2,
            "model_validate_json",
            forbidden_parse,
        )
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE,
            lambda: record_v2_from_connection(
                connection,
                stored_scope.authority.candidate_run_id,
                record.execution_entry_id,
            ),
        )


def test_v2_single_record_ref_inventory_is_rejected_before_ref_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path, "oversized-single-record-ref-inventory")
    stored_scope, record, _seal = _install_single_v2(database, sealed=False)
    with _open(database) as connection:
        row = connection.execute(
            "SELECT ref_size_bytes FROM m6_upgrade_physical_artifact_refs"
        ).fetchone()
        assert row is not None
        ref_size_bytes = int(row["ref_size_bytes"])
        assert ref_size_bytes > 1
        monkeypatch.setattr(
            v2_codec,
            "MAX_M6_UPGRADE_REF_INVENTORY_BYTES",
            ref_size_bytes - 1,
        )

        def forbidden_parse(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("oversized ref inventory reached Pydantic")

        monkeypatch.setattr(
            M6UpgradePhysicalArtifactRef,
            "model_validate_json",
            forbidden_parse,
        )
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE,
            lambda: record_v2_from_connection(
                connection,
                stored_scope.authority.candidate_run_id,
                record.execution_entry_id,
            ),
        )


def test_v2_seal_oversize_is_rejected_before_raw_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path, "oversized-seal")
    stored_scope, record, _seal = _install_single_v2(database, sealed=True)
    with _open(database) as connection:
        connection.execute("DROP TRIGGER m6_upgrade_execution_ledger_seals_no_update")
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE m6_upgrade_execution_ledger_seals SET size_bytes = ?",
            (MAX_M6_UPGRADE_SEAL_BYTES + 1,),
        )
        connection.commit()
        row = connection.execute("SELECT * FROM m6_upgrade_execution_ledger_seals").fetchone()
        assert row is not None

        def forbidden_parse(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("oversized seal reached Pydantic")

        monkeypatch.setattr(
            M6UpgradeExecutionLedgerSealV2,
            "model_validate_json",
            forbidden_parse,
        )
        _assert_failure(
            M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE,
            lambda: seal_v2_from_row(connection, row, stored_scope, (record,)),
        )
